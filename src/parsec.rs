// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use block::Block;
#[cfg(all(test, feature = "mock"))]
use dev_utils::ParsedContents;
use dump_graph;
use error::{Error, Result};
use gossip::split_on_first;
use gossip::{
    Event, EventHash, EventIndex, Graph, IndexedEventRef, PackedEvent, Request, Response,
    UnpackedEvent,
};
use id::{PublicId, SecretId};
use meta_voting::{MetaElectionHandle, MetaElections, MetaEvent, MetaEventBuilder, MetaVote, Step};
#[cfg(all(test, feature = "mock"))]
use mock::{PeerId, Transaction};
use network_event::NetworkEvent;
#[cfg(feature = "malice-detection")]
use observation::UnprovableMalice;
use observation::{Malice, Observation, ObservationHash};
use peer_list::{PeerList, PeerState};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
#[cfg(all(test, feature = "mock"))]
use std::ops::{Deref, DerefMut};
use std::{mem, usize};
use vote::Vote;

type PendingAccusations<T, P> = Vec<(P, Malice<T, P>)>;
#[cfg(feature = "malice-detection")]
type Accusations<T, P> = Vec<(P, Malice<T, P>)>;

/// Returns whether `small` is more than two thirds of `large`.
pub fn is_more_than_two_thirds(small: usize, large: usize) -> bool {
    3 * small > 2 * large
}

/// Number of votes necessary to reach consensus on an `OpaquePayload`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsensusMode {
    /// One vote is enough.
    Single,
    /// Supermajority (more than 2/3) is required.
    Supermajority,
}

impl ConsensusMode {
    pub(crate) fn check(self, did_vote: usize, can_vote: usize) -> bool {
        match self {
            ConsensusMode::Single => did_vote > 0,
            ConsensusMode::Supermajority => is_more_than_two_thirds(did_vote, can_vote),
        }
    }
}

/// The main object which manages creating and receiving gossip about network events from peers, and
/// which provides a sequence of consensused `Block`s by applying the PARSEC algorithm.
///
/// Most public functions return an error if called after the owning node has been removed, i.e.
/// a block with payload `Observation::Remove(our_id)` has been made stable.
pub struct Parsec<T: NetworkEvent, S: SecretId> {
    // The PeerInfo of other nodes.
    peer_list: PeerList<S>,
    // The Gossip graph.
    graph: Graph<T, S::PublicId>,
    // Information about observations stored in the graph, mapped to their hashes.
    observations: BTreeMap<ObservationHash, ObservationInfo<T, S::PublicId>>,
    // Consensused network events that have not been returned via `poll()` yet.
    consensused_blocks: VecDeque<Block<T, S::PublicId>>,
    // The map of meta votes of the events on each consensus block.
    meta_elections: MetaElections<S::PublicId>,
    consensus_mode: ConsensusMode,
    // Accusations to raise at the end of the processing of current gossip message.
    pending_accusations: PendingAccusations<T, S::PublicId>,
    // Peers we accused of unprovable malice.
    #[cfg(feature = "malice-detection")]
    unprovable_offenders: BTreeSet<S::PublicId>,
}

impl<T: NetworkEvent, S: SecretId> Parsec<T, S> {
    /// Creates a new `Parsec` for a peer with the given ID and genesis peer IDs (ours included).
    pub fn from_genesis(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        consensus_mode: ConsensusMode,
    ) -> Self {
        if !genesis_group.contains(our_id.public_id()) {
            log_or_panic!("Genesis group must contain us");
        }

        let mut parsec = Self::empty(our_id, genesis_group, consensus_mode);

        for peer_id in genesis_group {
            parsec
                .peer_list
                .add_peer(peer_id.clone(), PeerState::active());
            parsec
                .peer_list
                .initialise_peer_membership_list(peer_id, genesis_group.iter().cloned())
        }

        parsec
            .meta_elections
            .initialise_current_election(parsec.peer_list.all_ids());

        // Add initial event.
        let event = Event::new_initial(&parsec.peer_list);
        if let Err(error) = parsec.add_event(event) {
            log_or_panic!(
                "{:?} initialising Parsec failed when adding initial event: {:?}",
                parsec.our_pub_id(),
                error
            );
        }

        // Add event carrying genesis observation.
        let genesis_observation = Observation::Genesis(genesis_group.clone());
        let self_parent_hash = parsec.our_last_event_hash();
        let event = Event::new_from_observation(
            self_parent_hash,
            genesis_observation,
            &parsec.graph,
            &parsec.peer_list,
        );

        if let Err(error) = parsec.add_event(event) {
            log_or_panic!(
                "{:?} initialising Parsec failed when adding the genesis observation: {:?}",
                parsec.our_pub_id(),
                error,
            );
        }

        parsec
    }

    /// Creates a new `Parsec` for a peer that is joining an existing section.
    pub fn from_existing(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        section: &BTreeSet<S::PublicId>,
        consensus_mode: ConsensusMode,
    ) -> Self {
        if genesis_group.is_empty() {
            log_or_panic!("Genesis group can't be empty");
        }

        if genesis_group.contains(our_id.public_id()) {
            log_or_panic!("Genesis group can't already contain us");
        }

        if section.is_empty() {
            log_or_panic!("Section can't be empty");
        }

        if section.contains(our_id.public_id()) {
            log_or_panic!("Section can't already contain us");
        }

        let our_public_id = our_id.public_id().clone();
        let mut parsec = Self::empty(our_id, genesis_group, consensus_mode);

        // Add ourselves.
        parsec
            .peer_list
            .add_peer(our_public_id.clone(), PeerState::RECV);

        // Add the genesis group.
        for peer_id in genesis_group {
            parsec
                .peer_list
                .add_peer(peer_id.clone(), PeerState::VOTE | PeerState::SEND);
            parsec
                .peer_list
                .initialise_peer_membership_list(peer_id, genesis_group.iter().cloned());
        }

        // Add the current section members.
        for peer_id in section {
            if genesis_group.contains(peer_id) {
                continue;
            }

            parsec.peer_list.add_peer(peer_id.clone(), PeerState::SEND)
        }

        parsec
            .meta_elections
            .initialise_current_election(parsec.peer_list.all_ids());

        let initial_event = Event::new_initial(&parsec.peer_list);
        if let Err(error) = parsec.add_event(initial_event) {
            log_or_panic!(
                "{:?} initialising Parsec failed when adding initial event: {:?}",
                parsec.our_pub_id(),
                error
            );
        }

        parsec
    }

    // Construct empty `Parsec` with no peers (except us) and no gossip events.
    fn empty(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        consensus_mode: ConsensusMode,
    ) -> Self {
        dump_graph::init();

        Self {
            peer_list: PeerList::new(our_id),
            graph: Graph::new(),
            consensused_blocks: VecDeque::new(),
            observations: BTreeMap::new(),
            meta_elections: MetaElections::new(genesis_group.clone()),
            consensus_mode,
            pending_accusations: vec![],
            #[cfg(feature = "malice-detection")]
            unprovable_offenders: BTreeSet::new(),
        }
    }

    /// Our public ID
    pub fn our_pub_id(&self) -> &S::PublicId {
        self.peer_list.our_pub_id()
    }

    /// Adds a vote for `observation`.  Returns an error if we have already voted for this.
    pub fn vote_for(&mut self, observation: Observation<T, S::PublicId>) -> Result<()> {
        debug!("{:?} voting for {:?}", self.our_pub_id(), observation);

        self.confirm_self_state(PeerState::VOTE)?;

        if self.have_voted_for(&observation) {
            return Err(Error::DuplicateVote);
        }

        let self_parent_hash = self.our_last_event_hash();
        let event = Event::new_from_observation(
            self_parent_hash,
            observation,
            &self.graph,
            &self.peer_list,
        );

        let _ = self.add_event(event)?;
        Ok(())
    }

    /// Returns ids of peers who we can send gossips to. Calling `create_gossip` with a peer id
    /// returned by this function is guaranteed to succeed (assuming no mutation happened in between).
    pub fn gossip_recipients(&self) -> impl Iterator<Item = &S::PublicId> {
        self.peer_list.gossip_recipient_ids()
    }

    /// Creates a new message to be gossiped to a peer containing all gossip events this node thinks
    /// that peer needs.  If `peer_id` is `None`, a message containing all known gossip events is
    /// returned.  If `peer_id` is `Some` and the given peer is not an active node, an error is
    /// returned.
    pub fn create_gossip(&self, peer_id: Option<&S::PublicId>) -> Result<Request<T, S::PublicId>> {
        self.confirm_self_state(PeerState::SEND)?;

        if let Some(recipient_id) = peer_id {
            // We require `PeerState::VOTE` in addition to `PeerState::RECV` here, because if the
            // peer does not have `PeerState::VOTE`, it means we haven't yet reached consensus on
            // adding them to the section so we shouldn't contact them yet.
            self.confirm_peer_state(recipient_id, PeerState::VOTE | PeerState::RECV)?;

            if self.peer_list.last_event(recipient_id).is_some() {
                debug!(
                    "{:?} creating gossip request for {:?}",
                    self.our_pub_id(),
                    recipient_id
                );

                return self
                    .events_to_gossip_to_peer(recipient_id)
                    .map(Request::new);
            }
        }

        debug!(
            "{:?} creating gossip request for {:?}",
            self.our_pub_id(),
            peer_id
        );

        Ok(Request::new(self.graph.iter().map(|e| e.inner()).collect()))
    }

    /// Handles a received `Request` from `src` peer.  Returns a `Response` to be sent back to `src`
    /// or `Err` if the request was not valid or if `src` has been removed already.
    pub fn handle_request(
        &mut self,
        src: &S::PublicId,
        req: Request<T, S::PublicId>,
    ) -> Result<Response<T, S::PublicId>> {
        debug!(
            "{:?} received gossip request from {:?}",
            self.our_pub_id(),
            src
        );
        let forking_peers = self.unpack_and_add_events(src, req.packed_events)?;
        self.create_sync_event(src, true, &forking_peers)?;
        self.create_accusation_events()?;
        self.events_to_gossip_to_peer(src).map(Response::new)
    }

    /// Handles a received `Response` from `src` peer.  Returns `Err` if the response was not valid
    /// or if `src` has been removed already.
    pub fn handle_response(
        &mut self,
        src: &S::PublicId,
        resp: Response<T, S::PublicId>,
    ) -> Result<()> {
        debug!(
            "{:?} received gossip response from {:?}",
            self.our_pub_id(),
            src
        );
        let forking_peers = self.unpack_and_add_events(src, resp.packed_events)?;
        self.create_sync_event(src, false, &forking_peers)?;
        self.create_accusation_events()
    }

    /// Steps the algorithm and returns the next stable block, if any.
    ///
    /// Once we have been removed (i.e. a block with payload `Observation::Remove(our_id)` has been
    /// made stable), then no further blocks will be enqueued.  So, once `poll()` returns such a
    /// block, it will continue to return `None` forever.
    pub fn poll(&mut self) -> Option<Block<T, S::PublicId>> {
        self.consensused_blocks.pop_front()
    }

    /// Check if we can vote (that is, we have reached a consensus on us being full member of the
    /// section).
    pub fn can_vote(&self) -> bool {
        self.peer_list.peer_state(self.our_pub_id()).can_vote()
    }

    /// Checks if the given `observation` has already been voted for by us.
    pub fn have_voted_for(&self, observation: &Observation<T, S::PublicId>) -> bool {
        // TODO: optimize by iterating only `peer_list.our_events`.
        self.graph.iter().any(|event| {
            event.creator() == self.our_pub_id() && event
                .vote()
                .map_or(false, |voted| voted.payload() == observation)
        })
    }

    /// Check if there are any observation that have been voted for but not yet consensused.
    pub fn has_unconsensused_observations(&self) -> bool {
        self.observations.values().any(|info| !info.consensused)
    }

    /// Returns observations voted for by us which haven't been returned by `poll` yet.
    /// This includes observations that are either not yet consensused or that are already
    /// consensused, but not yet popped out of the consensus queue.
    ///
    /// The observations are sorted first by the consensus order, then by the vote order.
    pub fn our_unpolled_observations(&self) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        self.our_consensused_observations()
            .chain(self.our_unconsensused_observations())
    }

    fn our_consensused_observations(&self) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        self.observations.values().filter_map(move |info| {
            if info.created_by_us && info.consensused && self
                .consensused_blocks
                .iter()
                .any(|block| block.payload() == &info.observation)
            {
                Some(&info.observation)
            } else {
                None
            }
        })
    }

    fn our_unconsensused_observations(&self) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        self.observations.values().filter_map(|info| {
            if info.created_by_us && !info.consensused {
                Some(&info.observation)
            } else {
                None
            }
        })
    }

    /// Must only be used for events which have already been added to our graph.
    fn get_known_event(&self, event_index: EventIndex) -> Result<IndexedEventRef<T, S::PublicId>> {
        self.graph.get(event_index).ok_or_else(|| {
            log_or_panic!(
                "{:?} doesn't have event {:?}",
                self.our_pub_id(),
                event_index
            );
            Error::Logic
        })
    }

    fn confirm_peer_state(&self, peer_id: &S::PublicId, required: PeerState) -> Result<()> {
        let actual = self.peer_list.peer_state(peer_id);
        if actual.contains(required) {
            Ok(())
        } else {
            trace!(
                "{:?} detected invalid state of {:?} (required: {:?}, actual: {:?})",
                self.our_pub_id(),
                peer_id,
                required,
                actual,
            );
            Err(Error::InvalidPeerState { required, actual })
        }
    }

    fn confirm_self_state(&self, required: PeerState) -> Result<()> {
        let actual = self.peer_list.our_state();
        if actual.contains(required) {
            Ok(())
        } else {
            trace!(
                "{:?} has invalid state (required: {:?}, actual: {:?})",
                self.our_pub_id(),
                required,
                actual,
            );
            Err(Error::InvalidSelfState { required, actual })
        }
    }

    fn our_last_event_hash(&self) -> EventHash {
        self.peer_list
            .last_event(self.our_pub_id())
            .and_then(|index| self.get_known_event(index).ok())
            .map(|event| *event.hash())
            .unwrap_or_else(|| {
                log_or_panic!(
                    "{:?} has no last event hash.\n{:?}\n",
                    self.our_pub_id(),
                    self.peer_list
                );
                EventHash::ZERO
            })
    }

    fn is_observer(&self, builder: &MetaEventBuilder<T, S::PublicId>) -> bool {
        // An event is an observer if it has a supermajority of observees and its self-parent
        // does not.
        let voter_count = self.voter_count(builder.election());

        if !is_more_than_two_thirds(builder.observee_count(), voter_count) {
            return false;
        }

        let self_parent_index = if let Some(index) = builder.event().self_parent() {
            index
        } else {
            log_or_panic!(
                "{:?} has event {:?} with observations, but not self-parent",
                self.our_pub_id(),
                *builder.event()
            );
            return false;
        };

        let self_parent = if let Ok(event) = self.get_known_event(self_parent_index) {
            event
        } else {
            return false;
        };

        // If self-parent is initial, we don't have to check it's meta-event, as we already know it
        // can not have any observations. Also, we don't assign meta-events to initial events anyway.
        if self_parent.is_initial() {
            return true;
        }

        // If self-parent is earlier in history than the start of the meta-election, it won't have
        // a meta-event; but it also means that it wasn't an observer, so this event is
        if self.meta_elections.start_index(builder.election()) > self_parent.topological_index() {
            return true;
        }

        if let Some(meta_parent) = self
            .meta_elections
            .meta_event(builder.election(), self_parent_index)
        {
            !is_more_than_two_thirds(meta_parent.observees.len(), voter_count)
        } else {
            log_or_panic!(
                "{:?} doesn't have meta-event for event {:?} (self-parent of {:?}) in meta-election {:?}",
                self.our_pub_id(),
                *self_parent,
                builder.event().hash(),
                builder.election(),
            );

            false
        }
    }

    fn unpack_and_add_events(
        &mut self,
        src: &S::PublicId,
        packed_events: Vec<PackedEvent<T, S::PublicId>>,
    ) -> Result<BTreeSet<S::PublicId>> {
        self.confirm_self_state(PeerState::RECV)?;
        self.confirm_peer_state(src, PeerState::SEND)?;

        let mut forking_peers = BTreeSet::new();
        let mut known = Vec::new();

        // Among the packed_events, Keep track of each peer's earliest events' self_parent, as we
        // will use them as bounds in the graph for where we look for malice accusations.
        // NOTE: there is the assumption here that the events arrive in order.
        #[cfg(feature = "malice-detection")]
        let first_event_by_peer_in_packed_event =
            collect_first_self_parents::<T, S>(&packed_events);

        // We split the loop of adding events into sets of linear chunks, where a chunk is sequence
        // of events where other_parent is None. The purpose is to group events where malice is
        // detectable together where the subsequent malice accusation is expected to be.
        for packed_event_chunk in split_on_first(packed_events, |pe| pe.other_parent().is_some()) {
            #[cfg(feature = "malice-detection")]
            let mut first_event_in_chunk = None;
            #[cfg(feature = "malice-detection")]
            let mut some_event_index = None;

            for packed_event in packed_event_chunk {
                match Event::unpack(
                    packed_event.clone(),
                    &self.graph,
                    &self.peer_list,
                    &forking_peers,
                )? {
                    UnpackedEvent::New(event) => {
                        if self
                            .peer_list
                            .events_by_index(event.creator(), event.index_by_creator())
                            .next()
                            .is_some()
                        {
                            let _ = forking_peers.insert(event.creator().clone());
                        }

                        let event_creator = event.creator().clone();
                        let event_index = self.add_event(event)?;

                        // Keep track of these for use after the last event in the chunk
                        #[cfg(feature = "malice-detection")]
                        {
                            some_event_index = Some(event_index.clone());
                            let _ = first_event_in_chunk.get_or_insert(event_index);
                        }

                        // We have received an event of a peer in the message. The peer can now receive
                        // gossips from us as well.
                        self.peer_list
                            .change_peer_state(&event_creator, PeerState::RECV);
                        self.peer_list.record_gossiped_event_by(src, event_index);
                    }
                    UnpackedEvent::Known(index) => {
                        known.push(index);
                    }
                }
            }

            #[cfg(feature = "malice-detection")]
            {
                if let Some(event_index) = some_event_index {
                    self.detect_accomplice(
                        event_index.clone(),
                        first_event_in_chunk.unwrap_or(event_index),
                        &first_event_by_peer_in_packed_event,
                    )?;
                }
            }
        }

        #[cfg(feature = "malice-detection")]
        {
            self.detect_premature_gossip()?;

            for event_index in known {
                self.detect_spam(src, event_index);
            }
        }

        Ok(forking_peers)
    }

    fn add_event(&mut self, event: Event<T, S::PublicId>) -> Result<EventIndex> {
        let our = event.creator() == self.our_pub_id();
        if !our {
            #[cfg(feature = "malice-detection")]
            self.detect_malice_before_process(&event)?;
        }

        self.peer_list.confirm_can_add_event(&event)?;

        if let Some((payload_hash, new_info)) = ObservationInfo::create(&event) {
            let info = self.observations.entry(payload_hash).or_insert(new_info);
            if our {
                info.created_by_us = true;
            }
        }

        let is_initial = event.is_initial();
        let event_index = {
            let event = self.graph.insert(event);
            self.peer_list.add_event(event);
            event.event_index()
        };

        if is_initial {
            return Ok(event_index);
        }

        self.initialise_membership_list(event_index);
        self.process_event(event_index)?;

        if !our {
            #[cfg(feature = "malice-detection")]
            self.detect_malice_after_process(event_index);
        }

        Ok(event_index)
    }

    fn process_event(&mut self, event_index: EventIndex) -> Result<()> {
        if self.peer_list.our_state() == PeerState::inactive() {
            return Ok(());
        }

        let elections: Vec<_> = self.meta_elections.all().collect();
        for election in elections {
            self.create_meta_event(election, event_index)?;
        }

        let creator = self.get_known_event(event_index)?.creator().clone();

        if let Some(payload_hash) = self.compute_consensus(MetaElectionHandle::CURRENT, event_index)
        {
            self.output_consensus_info(&payload_hash);
            self.mark_observation_as_consensused(&payload_hash);

            self.handle_self_consensus(&payload_hash);
            if creator != *self.our_pub_id() {
                self.handle_peer_consensus(&creator, &payload_hash);
            }

            let start_index = self.compute_next_meta_election_start_index();
            let prev_election = self.meta_elections.new_election(
                payload_hash,
                self.peer_list.voter_ids().cloned().collect(),
                start_index,
            );

            self.meta_elections
                .mark_as_decided(prev_election, self.peer_list.our_pub_id());
            self.meta_elections.mark_as_decided(prev_election, &creator);

            let block = self.create_block(&payload_hash)?;
            self.consensused_blocks.push_back(block);

            let current_index = self.get_known_event(event_index)?.topological_index();
            self.restart_consensus(start_index, current_index)?;
        } else if creator != *self.our_pub_id() {
            let undecided: Vec<_> = self.meta_elections.undecided_by(&creator).collect();
            for election in undecided {
                if let Some(payload_hash) = self.compute_consensus(election, event_index) {
                    self.meta_elections.mark_as_decided(election, &creator);
                    self.handle_peer_consensus(&creator, &payload_hash);
                }
            }
        }

        Ok(())
    }

    fn output_consensus_info(&self, payload_hash: &ObservationHash) {
        dump_graph::to_file(
            self.our_pub_id(),
            &self.graph,
            &self.meta_elections,
            &self.peer_list,
            self.observations
                .iter()
                .map(|(hash, info)| (hash, &info.observation))
                .collect(),
        );

        let payload = self
            .observations
            .get(payload_hash)
            .map(|info| &info.observation);
        info!(
            "{:?} got consensus on block {} with payload {:?} and payload hash {:?}",
            self.our_pub_id(),
            self.meta_elections.consensus_history().len() - 1,
            payload,
            payload_hash
        )
    }

    fn mark_observation_as_consensused(&mut self, payload_hash: &ObservationHash) {
        if let Some(info) = self.observations.get_mut(payload_hash) {
            info.consensused = true;
        } else {
            log_or_panic!(
                "{:?} doesn't know about observation with hash {:?}",
                self.peer_list.our_pub_id(),
                payload_hash
            );
        }
    }

    /// Handles consensus reached by us.
    fn handle_self_consensus(&mut self, payload_hash: &ObservationHash) {
        match self
            .observations
            .get(payload_hash)
            .map(|info| info.observation.clone())
        {
            Some(Observation::Add { ref peer_id, .. }) => self.handle_add_peer(peer_id),
            Some(Observation::Remove { ref peer_id, .. }) => self.handle_remove_peer(peer_id),
            Some(Observation::Accusation {
                ref offender,
                ref malice,
            }) => {
                info!(
                    "{:?} removing {:?} due to consensus on accusation of malice {:?}",
                    self.our_pub_id(),
                    offender,
                    malice
                );

                self.handle_remove_peer(offender)
            }
            Some(Observation::Genesis(_)) | Some(Observation::OpaquePayload(_)) => (),
            None => {
                log_or_panic!("Failed to get observation from hash.");
            }
        }
    }

    fn handle_add_peer(&mut self, peer_id: &S::PublicId) {
        // - If we are already full member of the section, we can start sending gossips to
        //   the new peer from this moment.
        // - If we are the new peer, we must wait for the other members to send gossips to
        //   us first.
        //
        // To distinguish between the two, we check whether everyone we reached consensus on
        // adding also reached consensus on adding us.
        let recv = self
            .peer_list
            .iter()
            .filter(|&(id, peer)| {
                // Peers that can vote, which means we got consensus on adding them.
                peer.state().can_vote() &&
                        // Excluding the peer being added.
                        *id != *peer_id &&
                        // And excluding us.
                        *id != *self.our_pub_id()
            }).all(|(_, peer)| {
                // Peers that can receive, which implies they've already sent us at least
                // one message which implies they've already reached consensus on adding us.
                peer.state().can_recv()
            });

        let state = if recv {
            PeerState::VOTE | PeerState::SEND | PeerState::RECV
        } else {
            PeerState::VOTE | PeerState::SEND
        };

        if self.peer_list.has_peer(peer_id) {
            self.peer_list.change_peer_state(peer_id, state);
        } else {
            self.peer_list.add_peer(peer_id.clone(), state);
        }
    }

    fn handle_remove_peer(&mut self, peer_id: &S::PublicId) {
        self.peer_list.remove_peer(peer_id);
        self.meta_elections.handle_peer_removed(peer_id);
    }

    // Handle consensus reached by other peer.
    fn handle_peer_consensus(&mut self, peer_id: &S::PublicId, payload_hash: &ObservationHash) {
        let payload = self
            .observations
            .get(payload_hash)
            .map(|info| info.observation.clone());
        trace!(
            "{:?} detected that {:?} reached consensus on {:?}",
            self.our_pub_id(),
            peer_id,
            payload
        );

        match payload {
            Some(Observation::Add {
                peer_id: ref other_peer_id,
                ..
            }) => self
                .peer_list
                .add_to_peer_membership_list(peer_id, other_peer_id.clone()),
            Some(Observation::Remove {
                peer_id: ref other_peer_id,
                ..
            }) => self
                .peer_list
                .remove_from_peer_membership_list(peer_id, other_peer_id.clone()),
            Some(Observation::Accusation { ref offender, .. }) => self
                .peer_list
                .remove_from_peer_membership_list(peer_id, offender.clone()),
            _ => (),
        }
    }

    fn create_meta_event(
        &mut self,
        election: MetaElectionHandle,
        event_index: EventIndex,
    ) -> Result<()> {
        if self
            .meta_elections
            .meta_event(election, event_index)
            .is_some()
        {
            return Ok(());
        }

        let (meta_event, creator) = {
            let event = self.get_known_event(event_index)?;
            trace!(
                "{:?} creating a meta-event in meta-election {:?} for event {:?}",
                self.our_pub_id(),
                election,
                event
            );
            let mut builder = MetaEvent::build(election, event);

            self.set_interesting_content(&mut builder);
            self.set_observees(&mut builder);
            self.set_meta_votes(&mut builder)?;

            (builder.finish(), event.creator().clone())
        };

        self.meta_elections
            .add_meta_event(election, event_index, creator, meta_event);

        Ok(())
    }

    // Any payloads which this event sees as "interesting".  If this returns a non-empty set, then
    // this event is classed as an interesting one.
    fn set_interesting_content(&self, builder: &mut MetaEventBuilder<T, S::PublicId>) {
        if let Some(payloads_hashes) =
            self.previous_interesting_content(builder.election(), builder.event())
        {
            builder.set_interesting_content(payloads_hashes);
            return;
        }

        let peers_that_can_vote = self.voters(builder.election());
        let start_index = self.meta_elections.start_index(builder.election());

        let mut payloads_set: BTreeSet<_> = self
            .graph
            .iter_from(start_index)
            .filter_map(|event| {
                event
                    .inner()
                    .payload_hash()
                    .map(|payload_hash| (event, payload_hash))
            }).filter(|(_, this_payload_hash)| {
                self.meta_elections.is_interesting_content_candidate(
                    builder.election(),
                    builder.event().creator(),
                    this_payload_hash,
                )
            }).filter(|(event, this_payload_hash)| {
                self.is_interesting_payload(
                    builder,
                    &peers_that_can_vote,
                    this_payload_hash,
                    start_index,
                ) || event.sees_fork()
                    && self.has_interesting_ancestor(builder, this_payload_hash, start_index)
            }).map(|(_, this_payload_hash)| this_payload_hash)
            .cloned()
            .collect();

        // The code above created a set of payloads that are interesting at this event.
        // We will now sort the payloads in the order in which the creator voted for them.
        let mut payloads_hashes = vec![];
        for observation_hash in self
            .peer_list
            .peer_events(builder.event().creator())
            .filter_map(|hash| self.get_known_event(hash).ok())
            .filter_map(|event| event.inner().payload_hash())
        {
            if payloads_set.remove(observation_hash) {
                payloads_hashes.push(*observation_hash);
            }
        }
        // If any payloads are left in the set, it means that the creator hasn't voted for them -
        // we will just append them at the end.
        payloads_hashes.extend(payloads_set);

        builder.set_interesting_content(payloads_hashes);
    }

    // Try to get interesting content of the given event from the previous meta-election.
    fn previous_interesting_content(
        &self,
        election: MetaElectionHandle,
        event: IndexedEventRef<T, S::PublicId>,
    ) -> Option<Vec<ObservationHash>> {
        let prev_election = self.meta_elections.preceding(election)?;

        if self.meta_elections.voter_count(election)
            != self.meta_elections.voter_count(prev_election)
        {
            // Membership change occurred. Can't reuse interesting content.
            return None;
        }

        let prev_meta_event = self
            .meta_elections
            .meta_event(prev_election, event.event_index())?;
        let payloads = prev_meta_event
            .interesting_content
            .iter()
            .filter(|payload| {
                // Filter payloads that are still interesting.
                self.meta_elections.is_interesting_content_candidate(
                    election,
                    event.creator(),
                    payload,
                )
            }).cloned()
            .collect();

        Some(payloads)
    }

    // Returns true if `builder.event()` has an ancestor by a different creator that has `payload`
    // in interesting content
    fn has_interesting_ancestor(
        &self,
        builder: &MetaEventBuilder<T, S::PublicId>,
        payload_hash: &ObservationHash,
        start_index: usize,
    ) -> bool {
        self.graph
            .ancestors(builder.event())
            .take_while(|that_event| that_event.topological_index() >= start_index)
            .filter(|that_event| that_event.creator() != builder.event().creator())
            .any(|that_event| {
                self.meta_elections
                    .meta_event(builder.election(), that_event.event_index())
                    .map(|meta_event| meta_event.interesting_content.contains(payload_hash))
                    .unwrap_or(false)
            })
    }

    // Returns true if enough of `valid_voters` have voted for the indicated payload from the
    // perspective of `builder.event()`.
    fn is_interesting_payload(
        &self,
        builder: &MetaEventBuilder<T, S::PublicId>,
        peers_that_can_vote: &BTreeSet<S::PublicId>,
        payload_hash: &ObservationHash,
        start_index: usize,
    ) -> bool {
        let num_peers_that_did_vote = self.num_creators_of_ancestors_carrying_payload(
            peers_that_can_vote,
            &*builder.event(),
            payload_hash,
            start_index,
        );

        let consensus_mode = if let Some(&Observation::OpaquePayload(_)) = self
            .observations
            .get(payload_hash)
            .map(|info| &info.observation)
        {
            self.consensus_mode
        } else {
            ConsensusMode::Supermajority
        };

        consensus_mode.check(num_peers_that_did_vote, peers_that_can_vote.len())
    }

    fn num_creators_of_ancestors_carrying_payload(
        &self,
        peers_that_can_vote: &BTreeSet<S::PublicId>,
        event: &Event<T, S::PublicId>,
        payload_hash: &ObservationHash,
        start_index: usize,
    ) -> usize {
        let payload = self
            .observations
            .get(payload_hash)
            .map(|info| &info.observation);

        peers_that_can_vote
            .iter()
            .filter(|peer_id| {
                self.graph
                    .iter_from(start_index)
                    .filter(|that_event| that_event.creator() == *peer_id)
                    .any(|that_event| {
                        payload == that_event.vote().map(Vote::payload) && event.sees(that_event)
                    })
            }).count()
    }

    fn set_observees(&self, builder: &mut MetaEventBuilder<T, S::PublicId>) {
        let observees = self
            .meta_elections
            .interesting_events(builder.election())
            .filter_map(|(peer, indices)| {
                let old_index = indices.front()?;
                let old_event = self.get_known_event(*old_index).ok()?;
                if self.strongly_sees(builder.election(), builder.event(), old_event) {
                    Some(peer)
                } else {
                    None
                }
            }).cloned()
            .collect();

        builder.set_observees(observees);
    }

    fn set_meta_votes(&self, builder: &mut MetaEventBuilder<T, S::PublicId>) -> Result<()> {
        let voters = self.voters(builder.election());

        let parent_meta_votes = builder
            .event()
            .self_parent()
            .and_then(|parent_hash| {
                self.meta_elections
                    .meta_votes(builder.election(), parent_hash)
            }).and_then(|parent_meta_votes| {
                if !parent_meta_votes.is_empty() {
                    Some(parent_meta_votes)
                } else {
                    None
                }
            });

        // If self-parent already has meta votes associated with it, derive this event's meta votes
        // from those ones.
        if let Some(parent_meta_votes) = parent_meta_votes {
            for (peer_id, parent_event_votes) in parent_meta_votes {
                let new_meta_votes = {
                    let other_votes = self.collect_other_meta_votes(
                        builder.election(),
                        &voters,
                        &peer_id,
                        &*builder.event(),
                    );
                    let coin_tosses = self.toss_coins(
                        builder.election(),
                        &voters,
                        &peer_id,
                        &parent_event_votes,
                        builder.event(),
                    )?;
                    MetaVote::next(
                        &parent_event_votes,
                        &other_votes,
                        &coin_tosses,
                        voters.len(),
                    )
                };

                builder.add_meta_votes(peer_id.clone(), new_meta_votes);
            }
        } else if self.is_observer(builder) {
            // Start meta votes for this event.
            for peer_id in &voters {
                let other_votes = self.collect_other_meta_votes(
                    builder.election(),
                    &voters,
                    peer_id,
                    &*builder.event(),
                );
                let initial_estimate = builder.has_observee(peer_id);

                builder.add_meta_votes(
                    peer_id.clone(),
                    MetaVote::new(initial_estimate, &other_votes, voters.len()),
                );
            }
        };

        trace!(
            "{:?} has set the meta votes for {:?} in meta-election {:?}",
            self.our_pub_id(),
            *builder.event(),
            builder.election(),
        );

        Ok(())
    }

    fn toss_coins(
        &self,
        election: MetaElectionHandle,
        voters: &BTreeSet<S::PublicId>,
        peer_id: &S::PublicId,
        parent_votes: &[MetaVote],
        event: IndexedEventRef<T, S::PublicId>,
    ) -> Result<BTreeMap<usize, bool>> {
        let mut coin_tosses = BTreeMap::new();
        for parent_vote in parent_votes {
            let _ = self
                .toss_coin(election, voters, peer_id, parent_vote, event)?
                .map(|coin| coin_tosses.insert(parent_vote.round, coin));
        }
        Ok(coin_tosses)
    }

    fn toss_coin(
        &self,
        election: MetaElectionHandle,
        voters: &BTreeSet<S::PublicId>,
        peer_id: &S::PublicId,
        parent_vote: &MetaVote,
        event: IndexedEventRef<T, S::PublicId>,
    ) -> Result<Option<bool>> {
        // Get the round hash.
        let round = if parent_vote.estimates.is_empty() {
            // We're waiting for the coin toss result already.
            if parent_vote.round == 0 {
                // This should never happen as estimates get cleared only in increase step when the
                // step is Step::GenuineFlip and the round gets incremented.
                log_or_panic!(
                    "{:?} missing parent vote estimates at round 0.",
                    self.our_pub_id()
                );
                return Err(Error::Logic);
            }
            parent_vote.round - 1
        } else if parent_vote.step == Step::GenuineFlip {
            parent_vote.round
        } else {
            return Ok(None);
        };
        let round_hash = if let Some(hashes) = self.meta_elections.round_hashes(election, peer_id) {
            hashes[round].value()
        } else {
            log_or_panic!("{:?} missing round hash.", self.our_pub_id());
            return Err(Error::Logic);
        };

        // Get the gradient of leadership.
        let mut peer_id_hashes: Vec<_> = self
            .peer_list
            .peer_id_hashes()
            .filter(|(peer_id, _)| voters.contains(peer_id))
            .collect();
        peer_id_hashes.sort_by(|lhs, rhs| round_hash.xor_cmp(&lhs.1, &rhs.1));

        // Try to get the "most-leader"'s aux value.
        let creator = &peer_id_hashes[0].0;
        if let Some(creator_event_index) = event.last_ancestors().get(creator) {
            if let Some(aux_value) =
                self.aux_value(election, creator, *creator_event_index, peer_id, round)
            {
                return Ok(Some(aux_value));
            }
        }

        // If we've already waited long enough, get the aux value of the highest ranking leader.
        if self.stop_waiting(election, round, event) {
            for (creator, _) in &peer_id_hashes[1..] {
                if let Some(creator_event_index) = event.last_ancestors().get(creator) {
                    if let Some(aux_value) =
                        self.aux_value(election, creator, *creator_event_index, peer_id, round)
                    {
                        return Ok(Some(aux_value));
                    }
                }
            }
        }

        Ok(None)
    }

    // Returns the aux value for the given peer, created by `creator`, at the given round and at
    // the genuine flip step.
    fn aux_value(
        &self,
        election: MetaElectionHandle,
        creator: &S::PublicId,
        creator_event_index: usize,
        peer_id: &S::PublicId,
        round: usize,
    ) -> Option<bool> {
        self.meta_votes_since_round_and_step(
            election,
            creator,
            creator_event_index,
            peer_id,
            round,
            &Step::GenuineFlip,
        ).first()
        .and_then(|meta_vote| meta_vote.aux_value)
    }

    // Skips back through events created by the peer until passed `responsiveness_threshold`
    // response events and sees if the peer had its `aux_value` set at this round.  If so, returns
    // `true`.
    fn stop_waiting(
        &self,
        election: MetaElectionHandle,
        round: usize,
        event: IndexedEventRef<T, S::PublicId>,
    ) -> bool {
        let mut event_index = Some(event.event_index());
        let mut response_count = 0;
        let responsiveness_threshold = self.responsiveness_threshold(election);

        loop {
            if let Some(event) = event_index.and_then(|index| self.get_known_event(index).ok()) {
                if event.is_response() {
                    response_count += 1;
                    if response_count == responsiveness_threshold {
                        break;
                    }
                }
                event_index = event.self_parent();
            } else {
                return false;
            }
        }
        let event_index = match event_index {
            Some(index) => index,
            None => {
                log_or_panic!("{:?} event_index was None.", self.our_pub_id());
                return false;
            }
        };
        self.meta_elections
            .meta_votes(election, event_index)
            .and_then(|meta_votes| meta_votes.get(event.creator()))
            .map_or(false, |event_votes| {
                event_votes
                    .iter()
                    .any(|meta_vote| meta_vote.round == round && meta_vote.aux_value.is_some())
            })
    }

    // Returns the meta votes for the given peer, created by `creator`, since the given round and
    // step.  Starts iterating down the creator's events starting from `creator_event_index`.
    fn meta_votes_since_round_and_step(
        &self,
        election: MetaElectionHandle,
        creator: &S::PublicId,
        creator_event_index: usize,
        peer_id: &S::PublicId,
        round: usize,
        step: &Step,
    ) -> Vec<MetaVote> {
        let mut events = self.peer_list.events_by_index(creator, creator_event_index);

        // Check whether it has at least one item
        let event = if let Some(event) = events.next() {
            event
        } else {
            return vec![];
        };

        if events.next().is_some() {
            // Fork
            return vec![];
        }

        self.meta_elections
            .meta_votes(election, event)
            .and_then(|meta_votes| meta_votes.get(peer_id))
            .map(|meta_votes| {
                meta_votes
                    .iter()
                    .filter(|meta_vote| {
                        meta_vote.round > round
                            || meta_vote.round == round && meta_vote.step >= *step
                    }).cloned()
                    .collect()
            }).unwrap_or_else(|| vec![])
    }

    // Returns the set of meta votes held by all peers other than the creator of `event` which are
    // votes by `peer_id`.
    fn collect_other_meta_votes(
        &self,
        election: MetaElectionHandle,
        voters: &BTreeSet<S::PublicId>,
        peer_id: &S::PublicId,
        event: &Event<T, S::PublicId>,
    ) -> Vec<Vec<MetaVote>> {
        voters
            .iter()
            .filter(|voter_id| *voter_id != event.creator())
            .filter_map(|creator| {
                event
                    .last_ancestors()
                    .get(creator)
                    .map(|creator_event_index| {
                        self.meta_votes_since_round_and_step(
                            election,
                            creator,
                            *creator_event_index,
                            &peer_id,
                            0,
                            &Step::ForcedTrue,
                        )
                    })
            }).collect()
    }

    // Initialise the membership list of the creator of the given event to the same membership list
    // the creator of the other-parent had at the time of the other-parent's creation. Do nothing if
    // the event is not request or response or if the membership list is already initialised.
    fn initialise_membership_list(&mut self, event_index: EventIndex) {
        let (creator, changes) = {
            let event = if let Ok(event) = self.get_known_event(event_index) {
                event
            } else {
                return;
            };

            if event.creator() == self.our_pub_id() {
                return;
            }

            if self
                .peer_list
                .is_peer_membership_list_initialised(event.creator())
            {
                return;
            }

            let other_parent_creator = if let Some(other_parent) = self.graph.other_parent(event) {
                other_parent.inner().creator()
            } else {
                return;
            };

            // Collect all changes to `other_parent_creator`'s membership list seen by `event`.
            let changes: Vec<_> = self
                .peer_list
                .peer_membership_list_changes(other_parent_creator)
                .iter()
                .take_while(|(index, _)| {
                    self.peer_list
                        .events_by_index(other_parent_creator, *index)
                        .filter_map(|hash| self.get_known_event(hash).ok())
                        .any(|other_event| event.sees(other_event))
                }).map(|(_, change)| change.clone())
                .collect();
            (event.creator().clone(), changes)
        };

        for change in changes {
            self.peer_list.change_peer_membership_list(&creator, change);
        }
    }

    // List of voters for the given meta-election.
    fn voters(&self, election: MetaElectionHandle) -> BTreeSet<S::PublicId> {
        self.meta_elections
            .voters(election)
            .cloned()
            .unwrap_or_else(|| self.peer_list.voter_ids().cloned().collect())
    }

    // Number of voters for the given meta-election.
    fn voter_count(&self, election: MetaElectionHandle) -> usize {
        self.meta_elections
            .voters(election)
            .map(|voters| voters.len())
            .unwrap_or_else(|| self.peer_list.voters().count())
    }

    fn compute_consensus(
        &self,
        election: MetaElectionHandle,
        event_index: EventIndex,
    ) -> Option<ObservationHash> {
        let last_meta_votes = self.meta_elections.meta_votes(election, event_index)?;

        let decided_meta_votes = last_meta_votes.iter().filter_map(|(id, event_votes)| {
            event_votes.last().and_then(|v| v.decision).map(|v| (id, v))
        });

        if decided_meta_votes.clone().count() < self.voter_count(election) {
            return None;
        }

        self.meta_elections
            .decided_payload_hash(election)
            .cloned()
            .or_else(|| self.compute_payload_for_consensus(election, decided_meta_votes))
    }

    fn compute_payload_for_consensus<'a, I>(
        &self,
        election: MetaElectionHandle,
        decided_meta_votes: I,
    ) -> Option<ObservationHash>
    where
        I: IntoIterator<Item = (&'a S::PublicId, bool)>,
        S::PublicId: 'a,
    {
        let payloads: Vec<_> = decided_meta_votes
            .into_iter()
            .filter_map(|(id, decision)| {
                if decision {
                    self.meta_elections
                        .first_interesting_content_by(election, &id)
                        .cloned()
                } else {
                    None
                }
            }).collect();

        payloads
            .iter()
            .max_by(|lhs_payload, rhs_payload| {
                let lhs_count = payloads
                    .iter()
                    .filter(|payload_carried| lhs_payload == payload_carried)
                    .count();
                let rhs_count = payloads
                    .iter()
                    .filter(|payload_carried| rhs_payload == payload_carried)
                    .count();
                lhs_count.cmp(&rhs_count)
            }).cloned()
    }

    fn create_block(&self, payload_hash: &ObservationHash) -> Result<Block<T, S::PublicId>> {
        let payload = self
            .observations
            .get(payload_hash)
            .map(|info| info.observation.clone())
            .ok_or_else(|| Error::Logic)?;
        let votes = self
            .graph
            .iter()
            .filter_map(|event| {
                event.vote().and_then(|vote| {
                    if *vote.payload() == payload {
                        Some((event.creator().clone(), vote.clone()))
                    } else {
                        None
                    }
                })
            }).collect();

        Block::new(payload, &votes)
    }

    fn restart_consensus(&mut self, start_index: usize, current_index: usize) -> Result<()> {
        self.meta_elections
            .initialise_current_election(self.peer_list.all_ids());

        if current_index < start_index {
            return Ok(());
        }

        // This makes sure that we only reprocess events between start_index and current_index,
        // inclusive.
        // `collect()` needed because the iterator returned by `iter_from()` borrows `self`
        // immutably, which conflicts with `process_event`.
        let indices: Vec<_> = self
            .graph
            .iter_from(start_index)
            .take(current_index - start_index + 1)
            .map(|event| event.event_index())
            .collect();
        for index in indices {
            // This will reprocess events relevant to the new meta-election, but in the context of
            // all active meta-elections. This is sometimes necessary, as restart_consensus can be
            // called while events are being reprocessed and in such cases we could miss some
            // events when creating meta-events.
            self.process_event(index)?;
        }

        Ok(())
    }

    fn compute_next_meta_election_start_index(&self) -> usize {
        // Find the topological index of the first event that carries unconsensused payload.
        let previous = self.meta_elections.start_index(MetaElectionHandle::CURRENT);
        self.graph
            .iter_from(previous)
            .filter(|event| {
                event
                    .payload_hash()
                    .and_then(|payload_hash| self.observations.get(&payload_hash))
                    .map(|info| !info.consensused)
                    .unwrap_or(false)
            }).map(|indexed_event| indexed_event.topological_index())
            .next()
            .unwrap_or_else(|| self.graph.len())
    }

    // Returns the number of peers that created events which are seen by event X (descendant) and
    // see event Y (ancestor). This means number of peers through which there is a directed path
    // between x and y, excluding peers contains fork.
    fn num_peers_created_events_seen_by_x_that_can_see_y(
        &self,
        x: &Event<T, S::PublicId>,
        y: &Event<T, S::PublicId>,
    ) -> usize {
        x.last_ancestors()
            .iter()
            .filter(|(peer_id, &event_index)| {
                for event_hash in self.peer_list.events_by_index(peer_id, event_index) {
                    if let Ok(event) = self.get_known_event(event_hash) {
                        if x.sees(event) && event.sees(y) {
                            return true;
                        }
                    }
                }
                false
            }).count()
    }

    // Returns whether event X can strongly see the event Y during the evaluation of the given
    // election.
    fn strongly_sees<A, B>(&self, election: MetaElectionHandle, x: A, y: B) -> bool
    where
        A: AsRef<Event<T, S::PublicId>>,
        B: AsRef<Event<T, S::PublicId>>,
    {
        is_more_than_two_thirds(
            self.num_peers_created_events_seen_by_x_that_can_see_y(x.as_ref(), y.as_ref()),
            self.voter_count(election),
        )
    }

    // Constructs a sync event to prove receipt of a `Request` or `Response` (depending on the value
    // of `is_request`) from `src`, then add it to our graph.
    fn create_sync_event(
        &mut self,
        src: &S::PublicId,
        is_request: bool,
        forking_peers: &BTreeSet<S::PublicId>,
    ) -> Result<()> {
        let self_parent = self
            .peer_list
            .last_event(self.our_pub_id())
            .and_then(|index| self.get_known_event(index).ok())
            .map(|event| *event.hash())
            .ok_or_else(|| {
                log_or_panic!("{:?} missing our own last event hash.", self.our_pub_id());
                Error::Logic
            })?;

        let other_parent = self
            .peer_list
            .last_event(src)
            .and_then(|index| self.get_known_event(index).ok())
            .map(|event| *event.hash())
            .ok_or_else(|| {
                log_or_panic!("{:?} missing {:?} last event hash.", self.our_pub_id(), src);
                Error::Logic
            })?;

        let sync_event = if is_request {
            Event::new_from_request(
                self_parent,
                other_parent,
                &self.graph,
                &self.peer_list,
                forking_peers,
            )
        } else {
            Event::new_from_response(
                self_parent,
                other_parent,
                &self.graph,
                &self.peer_list,
                forking_peers,
            )
        };

        let _ = self.add_event(sync_event)?;
        Ok(())
    }

    // Returns an iterator over `self.events` which will yield all the events we think `peer_id`
    // doesn't yet know about.  We should already have checked that we know `peer_id` and that we
    // have recorded at least one event from this peer before calling this function.
    fn events_to_gossip_to_peer(
        &self,
        peer_id: &S::PublicId,
    ) -> Result<Vec<&Event<T, S::PublicId>>> {
        let last_event = if let Some(event_index) = self.peer_list.last_event(peer_id) {
            self.get_known_event(event_index)?
        } else {
            log_or_panic!("{:?} doesn't have peer {:?}", self.our_pub_id(), peer_id);
            return Err(Error::Logic);
        };

        // Events to include in the result. Initially start with including everything...
        let mut inclusion_list = vec![true; self.graph.len()];

        // ...then exclude events that are ancestors of `last_event`, because the peer already has
        // them.
        for event in self.graph.ancestors(last_event) {
            inclusion_list[event.topological_index()] = false;
        }

        Ok(self
            .graph
            .iter()
            .filter(|event| inclusion_list[event.topological_index()])
            .map(|event| event.inner())
            .collect())
    }

    // Get the responsiveness threshold based on the current number of peers.
    fn responsiveness_threshold(&self, election: MetaElectionHandle) -> usize {
        (self.voter_count(election) as f64).log2().ceil() as usize
    }

    fn create_accusation_event(
        &mut self,
        offender: S::PublicId,
        malice: Malice<T, S::PublicId>,
    ) -> Result<()> {
        let event = Event::new_from_observation(
            self.our_last_event_hash(),
            Observation::Accusation { offender, malice },
            &self.graph,
            &self.peer_list,
        );

        let _ = self.add_event(event)?;
        Ok(())
    }

    fn create_accusation_events(&mut self) -> Result<()> {
        let pending_accusations = mem::replace(&mut self.pending_accusations, vec![]);
        for (offender, malice) in pending_accusations {
            self.create_accusation_event(offender, malice)?;
        }

        Ok(())
    }
}

#[cfg(feature = "malice-detection")]
impl<T: NetworkEvent, S: SecretId> Parsec<T, S> {
    fn detect_malice_before_process(&mut self, event: &Event<T, S::PublicId>) -> Result<()> {
        // NOTE: `detect_incorrect_genesis` must come first.
        self.detect_incorrect_genesis(event)?;

        self.detect_other_parent_by_same_creator(event)?;
        self.detect_self_parent_by_different_creator(event)?;

        self.detect_unexpected_genesis(event);
        self.detect_missing_genesis(event);
        self.detect_duplicate_vote(event);
        self.detect_stale_other_parent(event);
        self.detect_fork(event);
        self.detect_invalid_accusation(event);

        // TODO: detect other forms of malice here

        Ok(())
    }

    fn detect_malice_after_process(&mut self, event_index: EventIndex) {
        self.detect_invalid_gossip_creator(event_index);
    }

    // Detect if the event carries an `Observation::Genesis` that doesn't match what we'd expect.
    fn detect_incorrect_genesis(&mut self, event: &Event<T, S::PublicId>) -> Result<()> {
        if let Some(Observation::Genesis(ref group)) = event.vote().map(Vote::payload) {
            if group.iter().collect::<BTreeSet<_>>() != self.genesis_group() {
                // Raise the accusation immediately and return an error, to prevent accepting
                // potentially large number of invalid / spam events into our graph.
                self.create_accusation_event(
                    event.creator().clone(),
                    Malice::IncorrectGenesis(*event.hash()),
                )?;
                return Err(Error::InvalidEvent);
            }
        }

        Ok(())
    }

    // Detect if the event's other_parent has the same creator as this event.
    fn detect_other_parent_by_same_creator(&mut self, event: &Event<T, S::PublicId>) -> Result<()> {
        if let Some(other_parent) = self.graph.other_parent(event) {
            if other_parent.creator() != event.creator() {
                return Ok(());
            }
        } else {
            return Ok(());
        }

        // Raise the accusation immediately and return an error, to prevent accepting
        // potentially large number of invalid / spam events into our graph.
        self.create_accusation_event(
            event.creator().clone(),
            Malice::OtherParentBySameCreator(Box::new(event.pack())),
        )?;
        Err(Error::InvalidEvent)
    }

    // Detect if the event's self_parent has the different creator as this event.
    fn detect_self_parent_by_different_creator(
        &mut self,
        event: &Event<T, S::PublicId>,
    ) -> Result<()> {
        if let Some(self_parent) = self.graph.self_parent(event) {
            if self_parent.creator() == event.creator() {
                return Ok(());
            }
        } else {
            return Ok(());
        }

        // Raise the accusation immediately and return an error, to prevent accepting
        // potentially large number of invalid / spam events into our graph.
        self.create_accusation_event(
            event.creator().clone(),
            Malice::SelfParentByDifferentCreator(Box::new(event.pack())),
        )?;
        Err(Error::InvalidEvent)
    }

    // Detect whether the event carries unexpected `Observation::Genesis`.
    fn detect_unexpected_genesis(&mut self, event: &Event<T, S::PublicId>) {
        let payload = if let Some(payload) = event.vote().map(Vote::payload) {
            payload
        } else {
            return;
        };

        let genesis_group = if let Observation::Genesis(ref group) = *payload {
            group
        } else {
            return;
        };

        // - the creator is not member of the genesis group, or
        // - the self-parent of the event is not initial event
        if !genesis_group.contains(event.creator()) || self
            .graph
            .self_parent(event)
            .map_or(true, |self_parent| !self_parent.is_initial())
        {
            self.accuse(
                event.creator().clone(),
                Malice::UnexpectedGenesis(*event.hash()),
            );
        }
    }

    // Detect when the first event by a peer belonging to genesis doesn't carry genesis
    fn detect_missing_genesis(&mut self, event: &Event<T, S::PublicId>) {
        if event.index_by_creator() != 1 {
            return;
        }

        if let Some(&Observation::Genesis(_)) = event.vote().map(Vote::payload) {
            return;
        }

        if self.genesis_group().contains(event.creator()) {
            self.accuse(
                event.creator().clone(),
                Malice::MissingGenesis(*event.hash()),
            );
        }
    }

    // Detect that if the event carries a vote, there is already one or more votes with the same
    // observation by the same creator.
    fn detect_duplicate_vote(&mut self, event: &Event<T, S::PublicId>) {
        let payload = if let Some(payload) = event.vote().map(Vote::payload) {
            payload
        } else {
            return;
        };

        let other_hash = {
            let mut duplicates = self
                .peer_list
                .peer_events(event.creator())
                .rev()
                .filter_map(|index| self.get_known_event(index).ok())
                .filter(|event| event.vote().map_or(false, |vote| vote.payload() == payload))
                .map(|event| *event.hash())
                .take(2);

            let hash = if let Some(hash) = duplicates.next() {
                // One duplicate found - raise the accusation.
                hash
            } else {
                // No duplicates found - do not raise the accusation.
                return;
            };

            if duplicates.next().is_some() {
                // More than one duplicate found - the accusation should have already been raised,
                // so don't raise it again.
                return;
            }

            hash
        };

        self.accuse(
            event.creator().clone(),
            Malice::DuplicateVote(other_hash, *event.hash()),
        );
    }

    // Detect if the event's other_parent older than first ancestor of self_parent.
    fn detect_stale_other_parent(&mut self, event: &Event<T, S::PublicId>) {
        let (other_parent_index, other_parent_creator) =
            if let Some(other_parent) = self.graph.other_parent(event) {
                (
                    other_parent.index_by_creator(),
                    other_parent.creator().clone(),
                )
            } else {
                return;
            };
        let self_parent_ancestor_index = if let Some(index) =
            self.graph.self_parent(event).and_then(|self_parent| {
                self_parent
                    .inner()
                    .last_ancestors()
                    .get(&other_parent_creator)
            }) {
            *index
        } else {
            return;
        };
        if other_parent_index < self_parent_ancestor_index {
            self.accuse(
                event.creator().clone(),
                Malice::StaleOtherParent(*event.hash()),
            );
        }
    }

    // Detect whether the event incurs a fork.
    fn detect_fork(&mut self, event: &Event<T, S::PublicId>) {
        if self.peer_list.last_event(event.creator()) != event.self_parent() {
            if let Some(self_parent_hash) = self.graph.self_parent(event).map(|event| *event.hash())
            {
                self.accuse(event.creator().clone(), Malice::Fork(self_parent_hash));
            }
        }
    }

    fn detect_invalid_accusation(&mut self, event: &Event<T, S::PublicId>) {
        let their_accusation = match event.vote().map(Vote::payload) {
            Some(&Observation::Accusation {
                ref offender,
                ref malice,
            })
                if malice.is_provable() =>
            {
                (offender, malice)
            }
            _ => return,
        };

        // First try to find the same accusation in our pending accusations...
        let found = self
            .pending_accusations
            .iter()
            .any(|&(ref our_offender, ref our_malice)| {
                their_accusation == (our_offender, our_malice)
            });
        if found {
            return;
        }

        // ...then in our events...
        let found = self
            .peer_list
            .our_events()
            .rev()
            .filter_map(|hash| self.get_known_event(hash).ok())
            .filter_map(|event| {
                if let Some(&Observation::Accusation {
                    ref offender,
                    ref malice,
                }) = event.inner().vote().map(Vote::payload)
                {
                    Some((offender, malice))
                } else {
                    None
                }
            }).any(|our_accusation| their_accusation == our_accusation);
        if found {
            return;
        }

        // ..if not found, their accusation is invalid.
        self.accuse(
            event.creator().clone(),
            Malice::InvalidAccusation(*event.hash()),
        )
    }

    fn detect_invalid_gossip_creator(&mut self, event_index: EventIndex) {
        let accusation = {
            let event = if let Ok(event) = self.get_known_event(event_index) {
                event
            } else {
                return;
            };

            let other_parent = if let Some(parent) = self.graph.other_parent(event) {
                parent
            } else {
                return;
            };

            let membership_list = if let Some(list) = self
                .peer_list
                .peer_membership_list_snapshot_excluding_last_remove(
                    event.creator(),
                    event.index_by_creator(),
                ) {
                list
            } else {
                // The membership list is not yet initialised - skip the detection.
                return;
            };

            if membership_list.contains(other_parent.creator()) {
                None
            } else {
                Some((event.creator().clone(), *event.hash()))
            }
        };

        if let Some((offender, event_hash)) = accusation {
            self.accuse(offender, Malice::InvalidGossipCreator(event_hash))
        }
    }

    fn detect_premature_gossip(&self) -> Result<()> {
        self.confirm_self_state(PeerState::VOTE)
            .map_err(|_| Error::PrematureGossip)
    }

    fn detect_spam(&mut self, src: &S::PublicId, known_event_index: EventIndex) {
        if self.unprovable_offenders.contains(src) {
            // Already accused.
            return;
        }

        let spam = {
            let their_event = self
                .peer_list
                .last_gossiped_event_by(src)
                .and_then(|index| self.get_known_event(index).ok())
                .and_then(|event| self.last_ancestor_by(event, src));
            let their_event = if let Some(their_event) = their_event {
                their_event
            } else {
                return;
            };

            let known_event = if let Ok(event) = self.get_known_event(known_event_index) {
                event
            } else {
                return;
            };

            self.last_ancestor_by(their_event, self.our_pub_id())
                .map(|our_event| self.graph.is_descendant(our_event, known_event))
                .unwrap_or(false)
        };

        if spam {
            let _ = self.unprovable_offenders.insert(src.clone());
            self.accuse(src.clone(), Malice::Unprovable(UnprovableMalice::Spam));
        }
    }

    fn accuse(&mut self, offender: S::PublicId, malice: Malice<T, S::PublicId>) {
        self.pending_accusations.push((offender, malice));
    }

    fn accusations_by_peer_since(
        &self,
        peer: &S::PublicId,
        oldest_event: EventIndex,
    ) -> Accusations<T, S::PublicId> {
        self.graph
            .iter_from(oldest_event.topological_index())
            .filter(|event| event.creator() == peer)
            .filter_map(|event| match event.payload() {
                Some(Observation::Accusation { offender, malice }) => {
                    Some((offender.clone(), malice.clone()))
                }
                _ => None,
            }).collect()
    }

    fn malicious_event_is_ancestor_of_this_event(
        &self,
        malice: &Malice<T, S::PublicId>,
        event: EventIndex,
    ) -> bool {
        let event = if let Some(event) = self.graph.get(event) {
            event
        } else {
            return false;
        };

        match malice {
            Malice::UnexpectedGenesis(hash)
            | Malice::MissingGenesis(hash)
            | Malice::IncorrectGenesis(hash)
            | Malice::StaleOtherParent(hash)
            | Malice::InvalidAccusation(hash)
            | Malice::InvalidGossipCreator(hash) => self
                .graph
                .get_index(hash)
                .and_then(|index| self.graph.get(index))
                .map(|malicious_event| self.graph.is_descendant(event, malicious_event))
                .unwrap_or(false),

            Malice::DuplicateVote(hash0, hash1) => {
                self.graph
                    .get_index(hash0)
                    .and_then(|index| self.graph.get(index))
                    .map(|malicious_event0| self.graph.is_descendant(event, malicious_event0))
                    .unwrap_or(false)
                    && self
                        .graph
                        .get_index(hash1)
                        .and_then(|index| self.graph.get(index))
                        .map(|malicious_event1| self.graph.is_descendant(event, malicious_event1))
                        .unwrap_or(false)
            }
            Malice::Fork(hash) => self
                .graph
                .get_index(hash)
                .and_then(|index| self.graph.get(index))
                .map(|malicious_event| {
                    self.graph.is_descendant(event, malicious_event)
                        && event.is_forking_peer(malicious_event.creator())
                }).unwrap_or(false),
            Malice::OtherParentBySameCreator(packed_event)
            | Malice::SelfParentByDifferentCreator(packed_event) => self
                .graph
                .get_index(&packed_event.hash())
                .and_then(|index| self.graph.get(index))
                .map(|malicious_event| self.graph.is_descendant(event, malicious_event))
                .unwrap_or(false),
            Malice::Unprovable(_) => false,
        }
    }

    fn detect_accomplice(
        &mut self,
        event_index: EventIndex,
        first_event_in_chunk: EventIndex,
        first_event_by_peer_in_packed_event: &BTreeMap<S::PublicId, EventHash>,
    ) -> Result<()> {
        let event_creator = self.get_known_event(event_index)?.creator().clone();
        if self.unprovable_offenders.contains(&event_creator) {
            // Can only accuse the peer once anyway
            return Ok(());
        }

        let starting_index = first_event_by_peer_in_packed_event
            .get(&event_creator)
            .and_then(|event| self.graph.get_index(event))
            .ok_or(Error::Logic)?;

        if self.detect_accomplice_for_pending_events(&event_creator, starting_index)
            || self.detect_accomplice_for_past_events(&event_creator, event_index, starting_index)
        {
            let first_event_in_chunk = self
                .graph
                .get(first_event_in_chunk)
                .map(|e| *e.hash())
                .ok_or(Error::Logic)?;
            let _ = self.unprovable_offenders.insert(event_creator.clone());
            self.accuse(
                event_creator.clone(),
                Malice::Unprovable(UnprovableMalice::Accomplice(first_event_in_chunk)),
            );
        }
        Ok(())
    }

    fn detect_accomplice_for_pending_events(
        &self,
        event_creator: &S::PublicId,
        starting_event: EventIndex,
    ) -> bool {
        let accusations_by_peer_since_starter_event =
            self.accusations_by_peer_since(event_creator, starting_event);

        self.pending_accusations
            .iter()
            .filter(|(off, _)| off != event_creator)
            .any(|pending_accusation| {
                !accusations_by_peer_since_starter_event
                    .iter()
                    .any(|peer_accusation| peer_accusation == pending_accusation)
            })
    }

    fn detect_accomplice_for_past_events(
        &self,
        event_creator: &S::PublicId,
        current_event: EventIndex,
        starting_event: EventIndex,
    ) -> bool {
        let accusations_by_peer_since_starter_event =
            self.accusations_by_peer_since(event_creator, starting_event);

        self.accusations_by_peer_since(self.our_pub_id(), starting_event)
            .iter()
            .filter(|(off, _)| off != event_creator)
            .any(|(offender, malice)| {
                (self.malicious_event_is_ancestor_of_this_event(&malice, current_event)
                    && !accusations_by_peer_since_starter_event
                        .iter()
                        .any(|(off, mal)| (off, mal) == (offender, &malice)))
            })
    }

    fn genesis_group(&self) -> BTreeSet<&S::PublicId> {
        self.graph
            .iter()
            .filter_map(|event| {
                if let Some(&Observation::Genesis(ref gen)) =
                    event.inner().vote().map(Vote::payload)
                {
                    Some(gen.iter().collect())
                } else {
                    None
                }
            }).next()
            .unwrap_or_else(|| self.peer_list.voter_ids().collect())
    }

    // Returns the last ancestor of the given event created by the given peer, if any.
    fn last_ancestor_by<'a>(
        &'a self,
        event: IndexedEventRef<'a, T, S::PublicId>,
        creator: &S::PublicId,
    ) -> Option<IndexedEventRef<'a, T, S::PublicId>> {
        use gossip::LastAncestor;

        match event.last_ancestor_by(creator) {
            LastAncestor::Some(index) => self
                .peer_list
                .events_by_index(creator, index)
                .next()
                .and_then(|index| self.get_known_event(index).ok()),
            LastAncestor::None => None,
            LastAncestor::Fork => self
                .graph
                .ancestors(event)
                .find(|ancestor| ancestor.creator() == creator),
        }
    }
}

impl<T: NetworkEvent, S: SecretId> Drop for Parsec<T, S> {
    fn drop(&mut self) {
        if ::std::thread::panicking() {
            dump_graph::to_file(
                self.our_pub_id(),
                &self.graph,
                &self.meta_elections,
                &self.peer_list,
                self.observations
                    .iter()
                    .map(|(hash, info)| (hash, &info.observation))
                    .collect(),
            );
        }
    }
}

#[derive(Debug)]
struct ObservationInfo<T: NetworkEvent, P: PublicId> {
    observation: Observation<T, P>,
    consensused: bool,
    created_by_us: bool,
}

impl<T: NetworkEvent, P: PublicId> ObservationInfo<T, P> {
    fn create(event: &Event<T, P>) -> Option<(ObservationHash, Self)> {
        event.payload_with_hash().map(|(observation, hash)| {
            (
                *hash,
                Self {
                    observation: observation.clone(),
                    consensused: false,
                    created_by_us: false,
                },
            )
        })
    }
}

#[cfg(all(test, feature = "mock"))]
impl Parsec<Transaction, PeerId> {
    pub(crate) fn from_parsed_contents(mut parsed_contents: ParsedContents) -> Self {
        let mut parsec = Parsec::empty(
            parsed_contents.our_id,
            &BTreeSet::new(),
            ConsensusMode::Supermajority,
        );

        // Populate `observations` cache using `interesting_content`, to support partial graphs...
        for meta_event in parsed_contents
            .meta_elections
            .current_meta_events()
            .values()
        {
            for payload_hash in &meta_event.interesting_content {
                if let Some(payload) = parsed_contents.observation_map.remove(payload_hash) {
                    let obs_info = ObservationInfo {
                        observation: payload,
                        consensused: false,
                        created_by_us: false,
                    };
                    let _ = parsec.observations.insert(*payload_hash, obs_info);
                }
            }
        }

        // ..and also the payloads carried by events.
        let our_pub_id = parsec.our_pub_id().clone();
        for event in &parsed_contents.graph {
            if let Some((payload_hash, new_info)) = ObservationInfo::create(&*event) {
                let info = parsec.observations.entry(payload_hash).or_insert(new_info);
                if *event.creator() == our_pub_id {
                    info.created_by_us = true;
                }
            }
        }

        for consensused in parsed_contents.meta_elections.consensus_history() {
            let _ = parsec
                .observations
                .get_mut(consensused)
                .map(|info| info.consensused = true);
        }

        parsec.graph = parsed_contents.graph;
        parsec.meta_elections = parsed_contents.meta_elections;
        parsec.peer_list = parsed_contents.peer_list;
        parsec
    }
}

/// Wrapper around `Parsec` that exposes additional functionality useful for testing.
#[cfg(all(test, feature = "mock"))]
pub(crate) struct TestParsec<T: NetworkEvent, S: SecretId>(Parsec<T, S>);

#[cfg(feature = "malice-detection")]
fn collect_first_self_parents<T: NetworkEvent, S: SecretId>(
    packed_events: &[PackedEvent<T, S::PublicId>],
) -> BTreeMap<S::PublicId, EventHash> {
    let mut events = BTreeMap::new();
    packed_events.iter().for_each(|event| {
        if let Some(hash) = event.self_parent() {
            let _ = events
                .entry(event.creator().clone())
                .or_insert(hash.clone());
        }
    });
    events
}

#[cfg(all(test, feature = "mock"))]
impl<T: NetworkEvent, S: SecretId> TestParsec<T, S> {
    pub fn from_genesis(our_id: S, genesis_group: &BTreeSet<S::PublicId>) -> Self {
        TestParsec(Parsec::from_genesis(
            our_id,
            genesis_group,
            ConsensusMode::Supermajority,
        ))
    }

    pub fn from_existing(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        section: &BTreeSet<S::PublicId>,
    ) -> Self {
        TestParsec(Parsec::from_existing(
            our_id,
            genesis_group,
            section,
            ConsensusMode::Supermajority,
        ))
    }

    pub fn graph(&self) -> &Graph<T, S::PublicId> {
        &self.0.graph
    }

    pub fn peer_list(&self) -> &PeerList<S> {
        &self.0.peer_list
    }

    pub fn meta_elections(&self) -> &MetaElections<S::PublicId> {
        &self.0.meta_elections
    }

    pub fn consensused_blocks(&self) -> impl Iterator<Item = &Block<T, S::PublicId>> {
        self.0.consensused_blocks.iter()
    }

    /// Adds event into the gossip graph.
    /// Panics if the event wasn't created or unpacked by this instance of parsec.
    pub fn add_event(&mut self, event: Event<T, S::PublicId>) -> Result<()> {
        if event.self_parent_hash() != Some(&EventHash::ZERO) {
            assert_eq!(
                event.self_parent_hash(),
                self.0.graph.self_parent(&event).map(|e| e.inner().hash()),
                "self-parent mismatch"
            );
        }

        if event.other_parent_hash() != Some(&EventHash::ZERO) {
            assert_eq!(
                event.other_parent_hash(),
                self.0.graph.other_parent(&event).map(|e| e.inner().hash()),
                "other-parent mismatch"
            )
        }

        let _ = self.0.add_event(event)?;
        Ok(())
    }

    pub fn create_sync_event(
        &mut self,
        src: &S::PublicId,
        is_request: bool,
        forking_peers: &BTreeSet<S::PublicId>,
    ) -> Result<()> {
        self.0.create_sync_event(src, is_request, forking_peers)
    }

    pub fn change_peer_state(&mut self, peer_id: &S::PublicId, state: PeerState) {
        self.0.peer_list.change_peer_state(peer_id, state)
    }

    #[cfg(feature = "malice-detection")]
    pub fn unpack_and_add_event(&mut self, event: PackedEvent<T, S::PublicId>) -> Result<()> {
        if let UnpackedEvent::New(event) =
            Event::unpack(event, &self.0.graph, &self.0.peer_list, &BTreeSet::new())?
        {
            let _ = self.0.add_event(event)?;
        }

        Ok(())
    }

    #[cfg(feature = "malice-detection")]
    pub fn our_last_event_hash(&self) -> EventHash {
        self.0.our_last_event_hash()
    }

    #[cfg(feature = "malice-detection")]
    pub fn pending_accusations(&self) -> &PendingAccusations<T, S::PublicId> {
        &self.0.pending_accusations
    }

    #[cfg(feature = "malice-detection")]
    pub fn add_peer(&mut self, peer_id: S::PublicId, state: PeerState) {
        self.0.peer_list.add_peer(peer_id, state)
    }

    #[cfg(feature = "malice-detection")]
    pub fn restart_consensus(&mut self) -> Result<()> {
        // `usize::MAX - 1` is somehow arbitrary upper bound that will make `restart_consensus`
        // reprocess everything (`-1` is there to avoid panic due to arithmetic overflow).
        self.0.restart_consensus(0, usize::MAX - 1)
    }
}

#[cfg(all(test, feature = "mock"))]
impl TestParsec<Transaction, PeerId> {
    pub(crate) fn from_parsed_contents(parsed_contents: ParsedContents) -> Self {
        TestParsec(Parsec::from_parsed_contents(parsed_contents))
    }
}

#[cfg(all(test, feature = "mock"))]
impl<T: NetworkEvent, S: SecretId> Deref for TestParsec<T, S> {
    type Target = Parsec<T, S>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(all(test, feature = "mock"))]
impl<T: NetworkEvent, S: SecretId> DerefMut for TestParsec<T, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Assert that the two parsec instances have the same events modulo their insertion order.
#[cfg(all(test, feature = "testing"))]
pub(crate) fn assert_same_events<T: NetworkEvent, S: SecretId>(a: &Parsec<T, S>, b: &Parsec<T, S>) {
    use gossip::GraphSnapshot;

    let a = GraphSnapshot::new(&a.graph);
    let b = GraphSnapshot::new(&b.graph);

    assert_eq!(a, b)
}

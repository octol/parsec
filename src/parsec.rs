// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(all(test, feature = "mock"))]
use crate::dev_utils::ParsedContents;
#[cfg(all(test, feature = "malice-detection", feature = "mock"))]
use crate::gossip::EventHash;
#[cfg(all(test, any(feature = "testing", feature = "mock")))]
use crate::gossip::GraphSnapshot;
#[cfg(feature = "malice-detection")]
use crate::observation::Malice;
use crate::{
    block::{Block, BlockGroup},
    dump_graph,
    error::{Error, Result},
    gossip::{
        Event, EventContextRef, EventIndex, Graph, IndexedEventRef, PackedEvent, Request, Response,
    },
    id::{PublicId, SecretId},
    key_gen::{
        dkg_threshold, message::DkgMessage, parsec_rng::ParsecRng, Ack, AckOutcome, KeyGen, Part,
        PartOutcome,
    },
    meta_voting::{MetaElection, MetaEvent, MetaEventBuilder, MetaVote, Observer},
    network_event::NetworkEvent,
    observation::{
        is_more_than_two_thirds, ConsensusMode, Observation, ObservationHash, ObservationKey,
        ObservationStore,
    },
    parsec_helpers::find_interesting_content_for_event,
    peer_list::{Peer, PeerIndex, PeerIndexMap, PeerIndexSet, PeerList, PeerListChange, PeerState},
};
#[cfg(any(feature = "testing", all(test, feature = "mock")))]
use crate::{
    hash::Hash,
    mock::{PeerId, Transaction},
};
use itertools::Itertools;
#[cfg(any(test, feature = "testing"))]
use std::ops::{Deref, DerefMut};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    iter,
    marker::PhantomData,
    mem,
    num::NonZeroUsize,
    usize,
};

pub(crate) type KeyGenId = usize;

struct VoteStatus {
    payload_key: ObservationKey,
    expected_voters: BTreeSet<PeerIndex>,
    voted: BTreeSet<PeerIndex>,
    consensused: bool,
}

impl VoteStatus {
    fn new<P: PublicId>(event: &Event<P>, voters: BTreeSet<PeerIndex>) -> Self {
        let payload_key = if let Some(payload_key) = event.payload_key() {
            *payload_key
        } else {
            panic!("input event shall be an observation!");
        };
        let mut vote_status = VoteStatus {
            payload_key,
            expected_voters: voters,
            voted: BTreeSet::new(),
            consensused: false,
        };
        let _ = vote_status.add_vote(event);
        vote_status
    }

    fn add_vote<P: PublicId>(&mut self, event: &Event<P>) -> bool {
        if Some(&self.payload_key) == event.payload_key() {
            let _ = self.voted.insert(event.creator());
            true
        } else {
            false
        }
    }

    fn set_consensused(&mut self, payload_key: &ObservationKey) -> bool {
        if &self.payload_key == payload_key {
            self.consensused = true;
        }
        self.consensused
    }

    fn is_unresponsive(&self, peer_index: PeerIndex) -> bool {
        self.consensused
            && self.expected_voters.contains(&peer_index)
            && !self.voted.contains(&peer_index)
    }
}

/// The main object which manages creating and receiving gossip about network events from peers, and
/// which provides a sequence of consensused [Block](struct.Block.html)s by applying the PARSEC
/// algorithm. A `Block`'s payload, described by the [Observation](enum.Observation.html) type, is
/// called an "observation" or a "transaction".
///
/// The struct is generic with regards to two type arguments: one that represents a network event,
/// and one that represents a peer ID on the network. This allows the consumer to customise both
/// what constitutes a transaction that can get consensus, and the way peers are identified. The
/// types have to implement [NetworkEvent](trait.NetworkEvent.html) and
/// [SecretId](trait.SecretId.html) traits, respectively.
///
/// The `Parsec` struct exposes two constructors:
///
/// * [from_genesis](struct.Parsec.html#method.from_genesis), if the owning peer is a part of the
/// genesis group, i.e. the initial group of peers that participate in the network startup
/// * [from_existing](struct.Parsec.html#method.from_existing), if the owning peer is trying to
/// join an already functioning network
///
/// Once the peer becomes a full member of the section,
/// [gossip_recipients](struct.Parsec.html#method.gossip_recipients) will start to return potential
/// partners for gossip. In order to initiate gossip exchange with a partner,
/// [create_gossip](struct.Parsec.html#method.create_gossip) should be called.
///
/// Any messages of type [Request](struct.Request.html) or [Response](struct.Response.html)
/// received by the network layer should be passed to
/// [handle_request](struct.Parsec.html#method.handle_request) and
/// [handle_response](struct.Parsec.html#method.handle_response), respectively.
///
/// If the owning peer needs to propose something to be consensused, it has to call the
/// [vote_for](struct.Parsec.html#method.vote_for) method.
///
/// The [poll](struct.Parsec.html#method.poll) method is used to get the observations in the
/// consensused order.
///
/// Most public methods return an error if called after the owning peer has been removed from the
/// section, i.e. a block with payload `Observation::Remove(our_id)` has been made stable.
///
/// For more details, see the descriptions of methods below.
pub struct Parsec<T: NetworkEvent, S: SecretId> {
    // The PeerInfo of other nodes.
    peer_list: PeerList<S>,
    // Set of active distributed key generation, with a KeyGenId used by `DkgMessage`.
    key_gen: BTreeMap<KeyGenId, KeyGen<S>>,
    // Next KeyGenId
    key_gen_next_id: KeyGenId,
    // The Gossip graph.
    graph: Graph<S::PublicId>,
    // Information about observations stored in the graph, mapped to their hashes.
    observations: ObservationStore<T, S::PublicId>,
    // Consensused network events that have not been returned via `poll()` yet.
    consensused_blocks: VecDeque<BlockGroup<T, S::PublicId>>,
    // The map of meta votes of the events on each consensus block.
    meta_election: MetaElection,
    consensus_mode: ConsensusMode,
    // Dkg messages to raise at the end of processing of current gossip message.
    pending_dkg_msgs: Vec<DkgMessage>,
    // Accusations to raise at the end of the processing of current gossip message.
    #[cfg(feature = "malice-detection")]
    pending_accusations: Accusations<T, S::PublicId>,
    // Events to be inserted into the gossip graph when this node becomes voter.
    pending_events: Vec<PendingEvent<T, S::PublicId>>,
    // True to disable processing consensus on this instance to speed up processing for irrelevant
    // parsec instances.
    #[cfg(any(test, feature = "testing"))]
    ignore_process_events: bool,
    // Provided RNG: Needs to be cryptographically secure RNG as it is used for DKG key generation.
    secure_rng: ParsecRng,
    // Including all on-going, consensused and polled blocks
    vote_status: VecDeque<VoteStatus>,
}

impl<T: NetworkEvent, S: SecretId> Parsec<T, S> {
    /// Creates a new `Parsec` for a peer with the given ID and genesis peer IDs (ours included).
    ///
    /// * `our_id` is the value that will identify the owning peer in the network.
    /// * `genesis_group` is the set of public IDs of the peers that are present at the network
    /// startup.
    /// * `genesis_related_info` extra arbitrary information attached to the genesis event for use
    /// by the client.
    /// * `consensus_mode` determines how many votes are needed for an observation to become a
    /// candidate for consensus. For more details, see [ConsensusMode](enum.ConsensusMode.html)
    /// * `secure_rng` cryptographically secure RNG to use for DKG key generation.
    pub fn from_genesis(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        genesis_related_info: Vec<u8>,
        consensus_mode: ConsensusMode,
        secure_rng: Box<dyn rand::Rng>,
    ) -> Self {
        if !genesis_group.contains(our_id.public_id()) {
            log_or_panic!("Genesis group must contain us");
        }

        let mut peer_list = PeerList::new(our_id);
        let genesis_indices: PeerIndexSet = genesis_group
            .iter()
            .map(|peer_id| {
                if peer_id == peer_list.our_pub_id() {
                    let peer_index = PeerIndex::OUR;
                    peer_list.change_peer_state(peer_index, PeerState::active());
                    peer_index
                } else {
                    peer_list.add_peer(peer_id.clone(), PeerState::active())
                }
            })
            .collect();

        let mut parsec = Self::empty(peer_list, genesis_indices, consensus_mode, secure_rng);

        // Add initial event.
        parsec.add_initial_event();

        // Add event carrying genesis observation.
        let genesis_observation = Observation::Genesis {
            group: genesis_group.clone(),
            related_info: genesis_related_info,
        };
        let event = parsec.our_last_event_index().and_then(|self_parent| {
            parsec.new_event_from_observation(self_parent, genesis_observation)
        });
        if let Err(error) = event.and_then(|event| parsec.add_event(event)) {
            log_or_panic!(
                "{:?} initialising Parsec failed when adding the genesis observation: {:?}",
                parsec.our_pub_id(),
                error,
            );
        }

        parsec
    }

    /// Creates a new `Parsec` for a peer that is joining an existing section.
    ///
    /// * `our_id` is the value that will identify the owning peer in the network.
    /// * `genesis_group` is the set of public IDs of the peers that were present at the section
    /// startup.
    /// * `section` is the set of public IDs of the peers that constitute the section at the time
    /// of joining. They are the peers this `Parsec` instance will accept gossip from.
    /// * `consensus_mode` determines how many votes are needed for an observation to become a
    /// candidate for consensus. For more details, see [ConsensusMode](enum.ConsensusMode.html)
    /// * `secure_rng` cryptographically secure RNG to use for DKG key generation.
    pub fn from_existing(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        section: &BTreeSet<S::PublicId>,
        consensus_mode: ConsensusMode,
        secure_rng: Box<dyn rand::Rng>,
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

        let mut peer_list = PeerList::new(our_id);

        // Add ourselves
        peer_list.change_peer_state(PeerIndex::OUR, PeerState::RECV);

        // Add the genesis group.
        let genesis_indices: PeerIndexSet = genesis_group
            .iter()
            .map(|peer_id| peer_list.add_peer(peer_id.clone(), PeerState::VOTE | PeerState::SEND))
            .collect();

        // Add the current section members.
        for peer_id in section {
            if peer_list.contains(peer_id) {
                continue;
            }
            let _ = peer_list.add_peer(peer_id.clone(), PeerState::SEND);
        }

        Self::empty(peer_list, genesis_indices, consensus_mode, secure_rng)
    }

    // Construct empty `Parsec` with no peers (except us) and no gossip events.
    fn empty(
        peer_list: PeerList<S>,
        genesis_group: PeerIndexSet,
        consensus_mode: ConsensusMode,
        secure_rng: Box<dyn rand::Rng>,
    ) -> Self {
        dump_graph::init();

        Self {
            peer_list,
            key_gen: BTreeMap::new(),
            key_gen_next_id: KeyGenId::default(),
            graph: Graph::new(),
            consensused_blocks: VecDeque::new(),
            observations: BTreeMap::new(),
            meta_election: MetaElection::new(genesis_group),
            consensus_mode,
            pending_dkg_msgs: vec![],
            #[cfg(feature = "malice-detection")]
            pending_accusations: vec![],
            pending_events: vec![],

            #[cfg(any(test, feature = "testing"))]
            ignore_process_events: false,

            secure_rng: ParsecRng::new(secure_rng),
            vote_status: VecDeque::default(),
        }
    }

    /// Returns our public ID
    pub fn our_pub_id(&self) -> &S::PublicId {
        self.peer_list.our_pub_id()
    }

    /// Inserts the owning peer's vote for `observation` into the gossip graph. The subsequent
    /// gossip messages will spread the vote to other peers, eventually making it a candidate for
    /// the next consensused block.
    ///
    /// Returns an error if the owning peer is not a full member of the section yet, if it has
    /// already voted for this `observation`, or if adding a gossip event containing the vote to
    /// the gossip graph failed.
    pub fn vote_for(&mut self, observation: Observation<T, S::PublicId>) -> Result<()> {
        debug!("{:?} voting for {:?}", self.our_pub_id(), observation);

        self.confirm_self_state(PeerState::VOTE)?;

        if self.have_voted_for(&observation) {
            return Err(Error::DuplicateVote);
        }

        self.flush_pending_events()?;

        let self_parent = self.our_last_event_index()?;
        let event = self.new_event_from_observation(self_parent, observation)?;

        let _ = self.add_event(event)?;
        Ok(())
    }

    /// Returns an iterator with the IDs of peers who the owning peer can send gossip messages to.
    /// Calling `create_gossip` with a peer ID returned by this method is guaranteed to succeed
    /// (assuming no section mutation happened in between).
    pub fn gossip_recipients(&self) -> impl Iterator<Item = &S::PublicId> {
        self.peer_list
            .gossip_recipients()
            .map(|(_, peer)| peer.id())
    }

    /// Creates a new message to be gossiped to a peer, containing all gossip events this peer
    /// thinks that peer needs.  If the given peer is not an active node, an error is returned.
    ///
    /// * `peer_id`: the intended recipient of the gossip message
    /// * returns a `Request` to be sent to the intended recipient
    pub fn create_gossip(&mut self, peer_id: &S::PublicId) -> Result<Request<T, S::PublicId>> {
        let peer_index = self.get_peer_index(peer_id)?;
        self.confirm_allowed_to_gossip_to(peer_index)?;

        debug!(
            "{:?} creating gossip request for {:?}",
            self.our_pub_id(),
            peer_id
        );

        let self_parent = self.peer_list.last_event(PeerIndex::OUR).ok_or_else(|| {
            log_or_panic!("{:?} missing our own last event hash.", self.our_pub_id());
            Error::Logic
        })?;
        let sync_event = Event::new_from_requesting(self_parent, peer_id, self.event_context())?;
        let _ = self.add_event(sync_event)?;

        let events = if self.peer_list.last_event(peer_index).is_some() {
            self.events_to_gossip_to_peer(peer_index)?
        } else {
            self.graph.iter().map(|e| e.inner()).collect()
        };
        self.pack_events(events).map(Request::new)
    }

    /// Handles a `Request` the owning peer received from the `src` peer.  Returns a `Response` to
    /// be sent back to `src`, or `Err` if the request was not valid or if `src` has been removed
    /// from the section already.
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

        let src_index = self.get_peer_index(src)?;
        let other_parent = self.unpack_and_add_events(src_index, req.packed_events)?;
        self.create_dkg_events()?;
        #[cfg(feature = "malice-detection")]
        self.create_accusation_events(other_parent)?;
        self.create_sync_event(true, other_parent)?;
        self.flush_pending_events()?;

        let events = self.events_to_gossip_to_peer(src_index)?;
        self.pack_events(events).map(Response::new)
    }

    /// Handles a `Response` the owning peer received from the `src` peer. Returns `Err` if the
    /// response was not valid or if `src` has been removed from the section already.
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

        let src_index = self.get_peer_index(src)?;
        let other_parent = self.unpack_and_add_events(src_index, resp.packed_events)?;
        self.create_dkg_events()?;
        #[cfg(feature = "malice-detection")]
        self.create_accusation_events(other_parent)?;
        self.create_sync_event(false, other_parent)?;
        self.flush_pending_events()
    }

    /// Returns the next stable block, if any. The method might need to be called more than once
    /// for the caller to get all the blocks that have been consensused. A `None` value means that
    /// all the blocks consensused so far have already been returned.
    ///
    /// Once the owning peer has been removed from the section (i.e. a block with payload
    /// `Observation::Remove(our_id)` has been made stable), then no further blocks will be
    /// enqueued. So, once `poll()` returns such a block, it will continue to return `None` forever.
    pub fn poll(&mut self) -> Option<Block<T, S::PublicId>> {
        let mut block_group = self.batch_poll()?;
        let block = block_group.pop_front()?;
        if !block_group.is_empty() {
            self.consensused_blocks.push_front(block_group);
        }
        Some(block)
    }

    /// Returns the next group of stable blocks, if any. The method might need to be called more
    /// than once for the caller to get all the blocks that have been consensused. A `None` value
    /// means that all the blocks consensused so far have already been returned.
    ///
    /// Once the owning peer has been removed from the section (i.e. a block with payload
    /// `Observation::Remove(our_id)` has been made stable), then no further blocks will be
    /// enqueued. So, once `poll()` or `batch_poll()` returns such a block, it will continue to
    /// return `None` forever.
    pub(crate) fn batch_poll(&mut self) -> Option<BlockGroup<T, S::PublicId>> {
        self.consensused_blocks.pop_front()
    }

    /// Check if the owning peer can vote (that is, it has reached a consensus on itself being a
    /// full member of the section).
    pub fn can_vote(&self) -> bool {
        self.peer_list.our_state().can_vote()
    }

    /// Checks if the given `observation` has already been voted for by the owning peer.
    pub fn have_voted_for(&self, observation: &Observation<T, S::PublicId>) -> bool {
        let hash = ObservationHash::from(observation);
        let key = ObservationKey::new(hash, PeerIndex::OUR, self.consensus_mode.of(observation));
        self.observations
            .get(&key)
            .map(|info| info.created_by_us)
            .unwrap_or(false)
    }

    /// Check if there are any observations that have been voted for but not yet polled - that is,
    /// either they haven't been consensused yet or a block containing that observation hasn't yet
    /// been retrieved by calling `poll`.
    pub fn has_unpolled_observations(&self) -> bool {
        self.observations.values().any(|info| !info.consensused)
            || !self.consensused_blocks.is_empty()
    }

    /// Returns observations voted for by the owning peer which haven't been returned as a stable
    /// block by `poll` yet.
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
            if info.created_by_us
                && info.consensused
                && self.has_our_unpolled_blocks(&info.observation)
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

    fn has_our_unpolled_blocks(&self, payload: &Observation<T, S::PublicId>) -> bool {
        let mut matching_blocks = self
            .consensused_blocks
            .iter()
            .flatten()
            .filter(|block| block.payload() == payload);

        // In `Supermajority` mode, check only if the payload matches, as there can be blocks not
        // signed by us, yet with payloads voted for by us.
        // In `Single` mode, on the other hand, check also that we signed it, to avoid false
        // positives when there are blocks with the same payloads but signed by someone else.
        match self.consensus_mode.of(payload) {
            ConsensusMode::Supermajority => matching_blocks.next().is_some(),
            ConsensusMode::Single => {
                matching_blocks.any(|block| block.is_signed_by(self.our_pub_id()))
            }
        }
    }

    /// Must only be used for events which have already been added to our graph.
    fn get_known_event(&self, event_index: EventIndex) -> Result<IndexedEventRef<S::PublicId>> {
        get_known_event(self.our_pub_id(), &self.graph, event_index)
    }

    fn confirm_allowed_to_gossip_to(&self, peer_index: PeerIndex) -> Result<()> {
        self.confirm_self_state(PeerState::SEND)?;
        // We require `PeerState::DKG` in addition to `PeerState::RECV` here, because if the
        // peer does not have `PeerState::DKG`, it means we haven't yet reached consensus on
        // adding them to the section so we shouldn't contact them yet.
        // `PeerState::VOTE` automatically includes `PeerState::DKG`.
        self.confirm_peer_state(peer_index, PeerState::DKG | PeerState::RECV)
    }

    fn confirm_peer_state(&self, peer_index: PeerIndex, required: PeerState) -> Result<()> {
        let actual = self.peer_list.peer_state(peer_index);
        if actual.contains(required) {
            Ok(())
        } else {
            trace!(
                "{:?} detected invalid state of {:?} (required: {:?}, actual: {:?})",
                self.our_pub_id(),
                peer_index,
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

    fn confirm_can_add_event(&self, event: &Event<S::PublicId>) -> Result<()> {
        let peer = self
            .peer_list
            .get(event.creator())
            .ok_or(Error::UnknownPeer)?;

        if event.creator() == PeerIndex::OUR || peer.state().can_send() {
            return Ok(());
        }

        if let Some(removal_event) = peer
            .removal_event()
            .and_then(|event_index| self.graph.get(event_index))
        {
            // If the creator of the event has been removed but they are not yet aware of the
            // removal (that is, we don't know for sure that reached consensus on removing
            // themselves), accept the event.
            if !event.is_descendant_of(removal_event) {
                return Ok(());
            }
        }

        Err(Error::InvalidPeerState {
            required: PeerState::SEND,
            actual: peer.state(),
        })
    }

    fn get_peer_index(&self, peer_id: &S::PublicId) -> Result<PeerIndex> {
        self.peer_list.get_index(peer_id).ok_or(Error::UnknownPeer)
    }

    fn our_last_event_index(&self) -> Result<EventIndex> {
        self.peer_list.last_event(PeerIndex::OUR).ok_or_else(|| {
            log_or_panic!(
                "{:?} has no last event.\n{:?}\n",
                self.our_pub_id(),
                self.peer_list
            );
            Error::Logic
        })
    }

    fn pack_events<'a, I>(&self, events: I) -> Result<Vec<PackedEvent<T, S::PublicId>>>
    where
        I: IntoIterator<Item = &'a Event<S::PublicId>>,
        S::PublicId: 'a,
    {
        events
            .into_iter()
            .map(|event| event.pack(self.event_context()))
            .collect()
    }

    // Returns the list peers which have created forked events, and the event to use as the
    // other-parent when creating our sync event as a result of handling this message.
    fn unpack_and_add_events(
        &mut self,
        src_index: PeerIndex,
        packed_events: Vec<PackedEvent<T, S::PublicId>>,
    ) -> Result<EventIndex> {
        self.confirm_self_state(PeerState::RECV)?;
        self.confirm_peer_state(src_index, PeerState::SEND)?;

        let hash_of_last_event = packed_events
            .last()
            .map(PackedEvent::compute_hash)
            .ok_or_else(|| Error::InvalidMessage)?;
        for packed_event in packed_events {
            if let Some(event) = self.unpack(packed_event)? {
                let event_creator = event.creator();
                let event_index = self.add_event(event)?;

                // We have received an event of a peer in the message. The peer can now receive
                // gossips from us as well.
                self.peer_list
                    .change_peer_state(event_creator, PeerState::RECV);
                self.peer_list
                    .record_gossiped_event_by(src_index, event_index);

                #[cfg(feature = "malice-detection")]
                self.detect_accomplice(event_index)?;
            }
        }

        #[cfg(feature = "malice-detection")]
        self.detect_premature_gossip()?;

        let last_event_index = self
            .graph
            .get_index(&hash_of_last_event)
            .ok_or_else(|| Error::InvalidMessage)?;
        Ok(last_event_index)
    }

    fn unpack(
        &mut self,
        packed_event: PackedEvent<T, S::PublicId>,
    ) -> Result<Option<Event<S::PublicId>>> {
        if let Some(unpacked_event) = Event::unpack(packed_event, self.event_context())? {
            if let Some((payload_key, observation_info)) = unpacked_event.observation_for_store {
                let _ = self
                    .observations
                    .entry(payload_key)
                    .or_insert_with(|| observation_info);
            }
            Ok(Some(unpacked_event.event))
        } else {
            Ok(None)
        }
    }

    fn new_event_from_observation(
        &mut self,
        self_parent: EventIndex,
        observation: Observation<T, S::PublicId>,
    ) -> Result<Event<S::PublicId>> {
        let (event, observation_for_store) =
            Event::new_from_observation(self_parent, observation, self.event_context())?;

        if let Some((payload_key, observation_info)) = observation_for_store {
            let _ = self
                .observations
                .entry(payload_key)
                .or_insert_with(|| observation_info);
        }

        Ok(event)
    }

    fn add_event(&mut self, event: Event<S::PublicId>) -> Result<EventIndex> {
        let our = event.creator() == PeerIndex::OUR;
        if !our {
            #[cfg(feature = "malice-detection")]
            self.detect_malice(&event)?;
        }

        self.confirm_can_add_event(&event)?;

        if our && event.is_initial() {
            log_or_panic!(
                "{:?} attempted to add initial event with add_event. It must be added with add_initial_event instead.",
                self.our_pub_id(),
            );
            return Err(Error::InvalidEvent);
        }

        let unconsensused_payload_key = event
            .payload_key()
            .and_then(|key| self.observations.get_mut(key).map(|info| (key, info)))
            .and_then(|(key, info)| {
                if our {
                    info.created_by_us = true;
                }
                if info.consensused {
                    None
                } else {
                    Some(*key)
                }
            });

        if event.is_observation() {
            self.add_observation_vote(&event);
        }

        let event_index = self.insert_event(event);

        let _ = unconsensused_payload_key.map(|payload_key| {
            self.meta_election
                .add_unconsensused_event(event_index, payload_key);
        });

        #[cfg(any(test, feature = "testing"))]
        let ignore_process_events = self.ignore_process_events;
        #[cfg(not(any(test, feature = "testing")))]
        let ignore_process_events = false;

        if !ignore_process_events {
            self.process_events(event_index.topological_index())?;
        }

        Ok(event_index)
    }

    fn add_observation_vote(&mut self, event: &Event<S::PublicId>) {
        if !self
            .vote_status
            .iter_mut()
            .any(|vote_status| vote_status.add_vote(event))
        {
            let voters: BTreeSet<PeerIndex> = self
                .peer_list
                .voters()
                .map(|(peer_index, _)| peer_index)
                .collect();
            self.vote_status.push_back(VoteStatus::new(event, voters))
        }
    }

    fn set_vote_consensused(&mut self, payload_keys: &Vec<ObservationKey>) {
        for payload_key in payload_keys.iter() {
            let _ = self
                .vote_status
                .iter_mut()
                .any(|vote_status| vote_status.set_consensused(payload_key));
        }
    }

    fn check_vote_status(&mut self) {
        let threshold = ::std::cmp::min(
            self.peer_list.voters().count() / 3,
            self.vote_status.len() / 3,
        );

        // Only keep 10 * threshold consensused voting status and the unconsensused ones among them.
        let mut concensused = self
            .vote_status
            .iter()
            .filter(|vote_status| vote_status.consensused)
            .count();
        while concensused > 10 * threshold {
            if let Some(vote_status) = self.vote_status.pop_front() {
                if vote_status.consensused {
                    concensused -= 1;
                }
            }
        }

        let peers_info: BTreeSet<(PeerIndex, S::PublicId)> = self
            .peer_list
            .voters()
            .map(|(peer_index, peer)| (peer_index, peer.id().clone()))
            .collect();
        for (peer_index, peer_id) in peers_info.iter() {
            if self
                .vote_status
                .iter()
                .filter(|vote_status| vote_status.is_unresponsive(*peer_index))
                .count()
                > threshold
            {
                let _ = self.vote_for(Observation::Remove {
                    peer_id: peer_id.clone(),
                    related_info: Vec::new(),
                });
            }
        }
    }

    // Create initial event for this node and insert it into the graph. This must be called when
    // this node becomes voter.
    fn add_initial_event(&mut self) {
        let event = Event::new_initial(self.event_context());
        let _ = self.insert_event(event);
    }

    fn insert_event(&mut self, event: Event<S::PublicId>) -> EventIndex {
        let event = self.graph.insert(event);
        self.peer_list.add_event(event);
        event.event_index()
    }

    fn process_events(&mut self, mut start_index: usize) -> Result<()> {
        'outer: loop {
            for event_index in self.graph.indices_from(start_index) {
                match self.process_event(event_index)? {
                    PostProcessAction::Restart(new_start_index)
                        if new_start_index <= event_index.topological_index() =>
                    {
                        start_index = new_start_index;
                        continue 'outer;
                    }
                    PostProcessAction::Restart(_) | PostProcessAction::Continue => (),
                }
            }

            break;
        }

        Ok(())
    }

    fn process_event(&mut self, event_index: EventIndex) -> Result<PostProcessAction> {
        if self.peer_list.our_state() == PeerState::inactive() {
            return Ok(PostProcessAction::Continue);
        }

        self.create_needed_meta_event(event_index)?;

        let payload_keys = self.compute_consensus(event_index);
        if payload_keys.is_empty() {
            return Ok(PostProcessAction::Continue);
        }

        self.set_vote_consensused(&payload_keys);

        self.output_consensus_info(&payload_keys);

        let blocks = self.create_blocks(&payload_keys)?;
        if !blocks.is_empty() {
            self.consensused_blocks.push_back(blocks);
        }

        self.mark_observations_as_consensused(&payload_keys);

        let peer_list_changes = payload_keys
            .iter()
            .filter_map(|payload_key| self.handle_consensus(event_index, payload_key))
            .collect();

        self.meta_election
            .new_election(&self.graph, payload_keys, peer_list_changes);

        // Trigger reprocess.
        let start_index = self.meta_election.continue_consensus_start_index();
        Ok(PostProcessAction::Restart(start_index))
    }

    fn output_consensus_info(&self, payload_keys: &[ObservationKey]) {
        dump_graph::to_file(dump_graph::ToFileInfo {
            owner_id: self.our_pub_id(),
            consensus_mode: self.consensus_mode,
            gossip_graph: &self.graph,
            meta_election: &self.meta_election,
            peer_list: &self.peer_list,
            observations: &self.observations,
            secure_rng: &self.secure_rng,
            key_gens_and_next_id: (&self.key_gen, &self.key_gen_next_id),
            info: &dump_graph::DumpGraphContext::ConsensusReached,
        });

        for (index, payload_key) in payload_keys.iter().enumerate() {
            let payload = self
                .observations
                .get(payload_key)
                .map(|info| &info.observation);
            info!(
                "{:?} got consensus on block {} with payload {:?} and payload hash {:?}",
                self.our_pub_id(),
                self.meta_election.consensus_history().len() + index,
                payload,
                payload_key.hash()
            )
        }
    }

    fn mark_observations_as_consensused(&mut self, payload_keys: &[ObservationKey]) {
        for payload_key in payload_keys {
            if let Some(info) = self.observations.get_mut(payload_key) {
                info.consensused = true;
            } else {
                log_or_panic!(
                    "{:?} doesn't know about observation with hash {:?}",
                    self.peer_list.our_pub_id(),
                    payload_key.hash()
                );
            }
        }
    }

    /// Handles consensus reached by us.
    fn handle_consensus(
        &mut self,
        event_index: EventIndex,
        payload_key: &ObservationKey,
    ) -> Option<PeerListChange> {
        match self
            .observations
            .get(payload_key)
            .map(|info| info.observation.clone())
        {
            Some(Observation::Add { ref peer_id, .. }) => self.handle_add_peer(peer_id).into(),
            Some(Observation::Remove { ref peer_id, .. }) => {
                self.handle_remove_peer(event_index, peer_id)
            }
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

                self.handle_remove_peer(event_index, offender)
            }
            Some(Observation::StartDkg(peers)) => {
                if self.handle_dkg_start_consensus(&peers).is_none() {
                    warn!("Not starting DKG on StartDkg consensus because of error");
                }
                None
            }
            Some(Observation::DkgResult { .. }) => {
                log_or_panic!("Unexpected DkgResult consensus.");
                None
            }
            Some(Observation::DkgMessage(msg)) => {
                if self.handle_dkg_message(payload_key, msg.clone()).is_none() {
                    warn!(
                        "Ignoring DkgMessage with Error: key: {:?}, msg: {:?}",
                        payload_key, msg
                    );
                }
                None
            }
            Some(Observation::Genesis { .. }) | Some(Observation::OpaquePayload(_)) => None,
            None => {
                log_or_panic!("Failed to get observation from hash.");
                None
            }
        }
    }

    fn handle_dkg_message(&mut self, payload_key: &ObservationKey, msg: DkgMessage) -> Option<()> {
        let creator_id = self.peer_list.get(payload_key.peer_index()?)?.id().clone();

        match msg {
            DkgMessage::Part { key_gen_id, part } => {
                self.handle_dkg_message_part(&creator_id, key_gen_id, part)
            }
            DkgMessage::Ack { key_gen_id, ack } => {
                self.handle_dkg_message_ack(&creator_id, key_gen_id, ack)
            }
        }
    }

    fn handle_dkg_message_part(
        &mut self,
        creator_id: &S::PublicId,
        key_gen_id: KeyGenId,
        part: Part,
    ) -> Option<()> {
        if let Some(key_gen) = &mut self.key_gen.get_mut(&key_gen_id) {
            let part_result = key_gen
                .handle_part(self.peer_list.our_id(), creator_id, part.clone())
                .map_err(|err| warn!("handle_dkg_message_part error: {:?}", err))
                .ok()?;

            match part_result {
                PartOutcome::Valid(Some(ack)) => {
                    self.pending_dkg_msgs
                        .push(DkgMessage::Ack { key_gen_id, ack });
                }
                PartOutcome::Valid(None) => (),
                PartOutcome::Invalid(fault) => {
                    warn!(
                        "An invalid Part was detected from {:?} with fault {:?}",
                        creator_id, fault
                    );
                }
            }
        }

        Some(())
    }

    fn handle_dkg_message_ack(
        &mut self,
        creator_id: &S::PublicId,
        key_gen_id: KeyGenId,
        ack: Ack,
    ) -> Option<()> {
        if let Some(key_gen) = &mut self.key_gen.get_mut(&key_gen_id) {
            let ack_result = key_gen
                .handle_ack(&self.peer_list.our_id(), creator_id, ack.clone())
                .map_err(|err| warn!("handle_dkg_message_ack error: {:?}", err))
                .ok()?;

            match ack_result {
                AckOutcome::Valid => {
                    if key_gen.is_ready() {
                        debug!(
                            "{:?}: key_gen for block number {} is ready.",
                            self.peer_list.our_pub_id(),
                            key_gen_id
                        );
                        let dkg_result = key_gen.generate().ok()?;

                        self.consensused_blocks.push_back(BlockGroup(
                            iter::once(Block::new_dkg_block(dkg_result)).collect(),
                        ));
                        let _ = self.key_gen.remove(&key_gen_id);
                    }
                }
                AckOutcome::Invalid(fault) => {
                    warn!(
                        "An invalid Ack was detected from {:?} with fault {:?}",
                        creator_id, fault
                    );
                }
            }
        }
        Some(())
    }

    // This function must be called on consensus on a `StartDkg` observation.
    fn handle_dkg_start_consensus(&mut self, peers: &BTreeSet<S::PublicId>) -> Option<()> {
        let state = if self.new_peer_can_recv(self.our_pub_id()) {
            PeerState::DKG | PeerState::SEND | PeerState::RECV
        } else {
            PeerState::DKG | PeerState::SEND
        };

        for peer_id in peers {
            if !self
                .peer_list
                .get_index(peer_id)
                .and_then(|index| self.peer_list.get(index))
                .map(|peer| peer.state().can_dkg())
                .unwrap_or(false)
            {
                let _ = self.add_gossip_peer(peer_id, state);
            }
        }

        let threshold = dkg_threshold(peers.len());
        let (key_gen, part) = KeyGen::new(
            self.peer_list.our_id(),
            peers.clone(),
            threshold,
            &mut self.secure_rng,
        )
        .map_err(|error| {
            error!("Vote for new DKG Error: {}", error);
        })
        .ok()?;

        let key_gen_id = self.key_gen_next_id;
        self.key_gen_next_id += 1;

        if let Some(part) = part {
            self.pending_dkg_msgs
                .push(DkgMessage::Part { key_gen_id, part });
        }
        let _ = self.key_gen.insert(key_gen_id, key_gen);
        Some(())
    }

    fn handle_add_peer(&mut self, peer_id: &S::PublicId) -> PeerListChange {
        let state = if self.new_peer_can_recv(peer_id) {
            PeerState::VOTE | PeerState::SEND | PeerState::RECV
        } else {
            PeerState::VOTE | PeerState::SEND
        };

        let peer_index = self.add_gossip_peer(peer_id, state);
        PeerListChange::Add(peer_index)
    }

    fn new_peer_can_recv(&self, peer_id: &S::PublicId) -> bool {
        // - If we are already full member of the section, we can start sending gossips to
        //   the new peer from this moment.
        // - If we are the new peer, we must wait for the other members to send gossips to
        //   us first.
        //
        // To distinguish between the two, we check whether everyone we reached consensus on
        // adding also reached consensus on adding us.
        self.peer_list
            .iter()
            .filter(|(peer_index, peer)| {
                // Peers that can vote, which means we got consensus on adding them.
                peer.state().can_vote() &&
                        // Excluding us.
                        *peer_index != PeerIndex::OUR &&
                        // Excluding the peer being added.
                        peer.id() != peer_id
            })
            .all(|(_, peer)| {
                // Peers that can receive, which implies they've already sent us at least
                // one message which implies they've already reached consensus on adding us.
                peer.state().can_recv()
            })
    }

    fn add_gossip_peer(&mut self, peer_id: &S::PublicId, state: PeerState) -> PeerIndex {
        let peer_index = if let Some(peer_index) = self.peer_list.get_index(peer_id) {
            self.peer_list.change_peer_state(peer_index, state);
            peer_index
        } else {
            self.peer_list.add_peer(peer_id.clone(), state)
        };

        if peer_index == PeerIndex::OUR && self.peer_list.our_events().next().is_none() {
            self.add_initial_event();
        }

        peer_index
    }

    fn handle_remove_peer(
        &mut self,
        event_index: EventIndex,
        peer_id: &S::PublicId,
    ) -> Option<PeerListChange> {
        self.peer_list.get_index(peer_id).map(|peer_index| {
            self.peer_list.remove_peer(peer_index, event_index);
            PeerListChange::Remove(peer_index)
        })
    }

    fn create_needed_meta_event(&mut self, event_index: EventIndex) -> Result<()> {
        let event = get_known_event(self.our_pub_id(), &self.graph, event_index)?;

        if !event.is_sync_event() || !self.voters().contains(event.creator()) {
            // Only add meta events for sync events created by a valid voter.
            // Other events have no meta event.
            return Ok(());
        }

        trace!(
            "{:?} creating a meta-event for event {:?}",
            self.our_pub_id(),
            event
        );

        let mut builder =
            if let Some(meta_event) = self.meta_election.remove_meta_event(event_index) {
                meta_event.rebuild(event)
            } else {
                MetaEvent::build(event)
            };

        self.set_interesting_content(&mut builder);
        self.set_observer(&mut builder);
        self.set_meta_votes(&mut builder)?;

        self.meta_election.add_meta_event(builder);

        Ok(())
    }

    // Any payloads which this event sees as "interesting".  If this returns a non-empty set, then
    // this event is classed as an interesting one.
    fn set_interesting_content(&self, builder: &mut MetaEventBuilder<S::PublicId>) {
        if !builder.is_new() {
            return;
        }

        let peers_that_can_vote = self.voters();

        let consistent_cmp = |lhs_key: &ObservationKey, rhs_key: &ObservationKey| {
            lhs_key.consistent_cmp(rhs_key, &self.peer_list)
        };

        let is_descendant = |x: IndexedEventRef<_>, y| x.is_descendant_of(y);

        let is_already_interesting_content = |payload_key: &ObservationKey| {
            self.meta_election
                .is_already_interesting_content(builder.event().creator(), payload_key)
        };

        let is_interesting_payload = |payload_key: &ObservationKey| {
            self.is_interesting_payload(builder, &peers_that_can_vote, payload_key)
        };

        let payloads = find_interesting_content_for_event(
            builder.event(),
            self.unconsensused_events(None),
            consistent_cmp,
            is_descendant,
            is_already_interesting_content,
            is_interesting_payload,
        );

        builder.set_interesting_content(payloads);
    }

    // Returns true if enough of `valid_voters` have voted for the indicated payload from the
    // perspective of `builder.event()`.
    fn is_interesting_payload(
        &self,
        builder: &MetaEventBuilder<S::PublicId>,
        peers_that_can_vote: &PeerIndexSet,
        payload_key: &ObservationKey,
    ) -> bool {
        match payload_key.consensus_mode() {
            ConsensusMode::Single => {
                let num_ancestor_peers =
                    self.num_creators_of_ancestors(peers_that_can_vote, &*builder.event());
                is_more_than_two_thirds(num_ancestor_peers, peers_that_can_vote.len())
                    && self.has_ancestor_carrying_payload(builder.event(), payload_key)
            }
            ConsensusMode::Supermajority => {
                let num_peers_that_did_vote = self.num_creators_of_ancestors_carrying_payload(
                    peers_that_can_vote,
                    builder.event(),
                    payload_key,
                );
                is_more_than_two_thirds(num_peers_that_did_vote, peers_that_can_vote.len())
            }
        }
    }

    // Number of unique peers that created at least one ancestor of the given event.
    fn num_creators_of_ancestors(
        &self,
        peers_that_can_vote: &PeerIndexSet,
        event: &Event<S::PublicId>,
    ) -> usize {
        event
            .last_ancestors()
            .filter(|(peer_index, _)| peers_that_can_vote.contains(*peer_index))
            .count()
    }

    // Number of unique peers that created at least one ancestor of the given event that carries the
    // given payload.
    fn num_creators_of_ancestors_carrying_payload(
        &self,
        peers_that_can_vote: &PeerIndexSet,
        event: IndexedEventRef<S::PublicId>,
        payload_key: &ObservationKey,
    ) -> usize {
        let unconsensused_events = self.unconsensused_events(Some(payload_key)).collect_vec();

        peers_that_can_vote
            .iter()
            .filter(|peer_index| {
                unconsensused_events.iter().any(|that_event| {
                    that_event.creator() == *peer_index && event.is_descendant_of(*that_event)
                })
            })
            .count()
    }

    // At least one ancestor of the given event carries the given payload.
    fn has_ancestor_carrying_payload(
        &self,
        event: IndexedEventRef<S::PublicId>,
        payload_key: &ObservationKey,
    ) -> bool {
        self.unconsensused_events(Some(payload_key))
            .any(|that_event| event.is_descendant_of(that_event))
    }

    fn set_observer(&self, builder: &mut MetaEventBuilder<S::PublicId>) {
        // An event is an observer if it has a supermajority of observees and its self-parent
        // does not.

        if self.is_descendant_of_observer(builder.event()) {
            builder.set_observer(Observer::Ancestor);
            return;
        }

        let voter_count = self.voter_count();
        let observees: PeerIndexSet = self
            .meta_election
            .interesting_events()
            .filter_map(|(peer_index, event_indices)| {
                let event_index = event_indices.first()?;
                let event = self.get_known_event(*event_index).ok()?;
                if self.strongly_sees(builder.event(), event) {
                    Some(peer_index)
                } else {
                    None
                }
            })
            .collect();

        if is_more_than_two_thirds(observees.len(), voter_count) {
            builder.set_observer(Observer::This(observees));
        } else {
            builder.set_observer(Observer::None);
        }
    }

    fn is_descendant_of_observer(&self, event: IndexedEventRef<S::PublicId>) -> bool {
        self.graph
            .self_sync_parent(event)
            .and_then(|self_parent| self.meta_election.meta_event(self_parent.event_index()))
            .map(|meta_parent| meta_parent.is_observer() || meta_parent.has_ancestor_observer())
            .unwrap_or(false)
    }

    fn set_meta_votes(&self, builder: &mut MetaEventBuilder<S::PublicId>) -> Result<()> {
        let parent_meta_votes = self
            .graph
            .self_sync_parent(builder.event())
            .and_then(|parent| {
                self.meta_election
                    .populated_meta_votes(parent.event_index())
            });

        if parent_meta_votes.is_none() && !builder.is_observer() {
            // No meta votes to set for this event
            return Ok(());
        }

        let voters = self.voters();
        let voters_len = match NonZeroUsize::new(voters.len()) {
            Some(num) => num,
            None => {
                log_or_panic!("{:?} has no voters", self.our_pub_id());
                return Ok(());
            }
        };

        let is_voter = voters.contains(builder.event().creator());
        if !is_voter {
            // This event wasn't created by a valid voter. It has no meta_votes.
            return Ok(());
        }

        let ancestors_meta_votes =
            self.other_voting_ancestors_meta_votes(&voters, &builder.event());

        if let Some(parent_meta_votes) = parent_meta_votes {
            // Parent has meta votes: Derive this event's meta votes from them.

            // Calculating the meta-votes is a three step process:
            // 1. First calculate temporary meta-votes without using coin tosses.
            // 2. Then calculate the coin toss results using the temporary meta-votes.
            // 3. Finally calculate the final meta-votes using the temporary meta-votes and the
            //    coin toss results.
            // The reason to do it this way is that sometimes we need the meta-votes for the current
            // event when tossing the coins.
            let temp_votes: PeerIndexMap<_> = parent_meta_votes
                .into_iter()
                .map(|(peer_index, parent_votes)| {
                    let other_votes = Self::peer_meta_votes(&ancestors_meta_votes, peer_index);
                    let temp_votes = MetaVote::next_temp(parent_votes, &other_votes, voters_len);

                    (peer_index, temp_votes)
                })
                .collect();

            for (peer_index, temp_votes) in &temp_votes {
                let coin_tosses = self.toss_coins(&voters, peer_index, temp_votes)?;
                let final_meta_votes = MetaVote::next_final(temp_votes, &coin_tosses, voters_len);

                builder.add_meta_votes(peer_index, final_meta_votes);
            }
        } else {
            // Start meta votes for this observer event.
            for peer_index in voters {
                let new_meta_votes = {
                    let other_votes = Self::peer_meta_votes(&ancestors_meta_votes, peer_index);
                    let initial_estimate = builder.has_observee(peer_index);

                    MetaVote::new_for_observer(initial_estimate, &other_votes, voters_len)
                };

                builder.add_meta_votes(peer_index, new_meta_votes);
            }
        }

        trace!(
            "{:?} has set the meta votes for {:?}",
            self.our_pub_id(),
            *builder.event(),
        );

        Ok(())
    }

    fn toss_coins(
        &self,
        voters: &PeerIndexSet,
        peer_index: PeerIndex,
        temp_votes: &[MetaVote],
    ) -> Result<BTreeMap<usize, bool>> {
        let mut coin_tosses = BTreeMap::new();
        for temp_vote in temp_votes {
            if let Some(coin) = self.toss_coin(voters, peer_index, temp_vote)? {
                let _ = coin_tosses.insert(temp_vote.round, coin);
            }
        }
        Ok(coin_tosses)
    }

    fn toss_coin(
        &self,
        _voters: &PeerIndexSet,
        _peer_index: PeerIndex,
        temp_vote: &MetaVote,
    ) -> Result<Option<bool>> {
        // FIXME: This coin is common, but also predictable. It means that we can't guarentee
        // Liveness in the presence of a sophisticated adversary which controls the scheduler.
        // It is only a temporary measure until we implement an actual common coin.
        Ok(Some(temp_vote.round % 2 != 0))
    }

    // Returns all the meta votes from the event's voting ancestors except the event's creator.
    fn other_voting_ancestors_meta_votes(
        &self,
        voters: &PeerIndexSet,
        event: &Event<S::PublicId>,
    ) -> Vec<&PeerIndexMap<Vec<MetaVote>>> {
        voters
            .iter()
            .filter(|voter_index| *voter_index != event.creator())
            .filter_map(|creator| {
                event
                    .non_fork_last_ancestor_by(creator)
                    .and_then(|index_by_creator| {
                        let event_index = self
                            .peer_list
                            .events_by_index(creator, index_by_creator)
                            .next()?;
                        self.meta_election.populated_meta_votes(event_index)
                    })
            })
            .collect()
    }

    // Collect the vectors of meta votes for the peer
    fn peer_meta_votes<'a>(
        meta_votes_maps: &'a [&PeerIndexMap<Vec<MetaVote>>],
        peer_index: PeerIndex,
    ) -> Vec<&'a [MetaVote]> {
        meta_votes_maps
            .iter()
            .filter_map(|meta_votes| meta_votes.get(peer_index))
            .map(Vec::as_slice)
            .collect()
    }

    // List of voters for the given meta-election.
    fn voters(&self) -> &PeerIndexSet {
        self.meta_election.voters()
    }

    // Number of voters for the given meta-election.
    fn voter_count(&self) -> usize {
        self.meta_election.voters().len()
    }

    fn unconsensused_events(
        &self,
        filter_key: Option<&ObservationKey>,
    ) -> impl Iterator<Item = IndexedEventRef<S::PublicId>> {
        self.meta_election
            .unconsensused_events(filter_key)
            .filter_map(move |index| self.get_known_event(index).ok())
    }

    fn compute_consensus(&self, event_index: EventIndex) -> Vec<ObservationKey> {
        let event = if let Ok(event) = self.get_known_event(event_index) {
            event
        } else {
            return vec![];
        };

        // If the creator of the current event is the only known voter and the event carries
        // a payload, decide it immediately.
        if iter::once(event.creator()).eq(self.voters()) {
            return event.payload_key().into_iter().cloned().collect();
        }

        // Otherwise proceed normally with evaluating the meta-election.
        let last_meta_votes = match self.meta_election.populated_meta_votes(event_index) {
            Some(meta_votes) => meta_votes,
            None => return Vec::new(),
        };

        let decided_meta_votes = last_meta_votes
            .iter()
            .filter_map(|(peer_index, event_votes)| {
                event_votes
                    .last()
                    .and_then(MetaVote::decision)
                    .map(|v| (peer_index, v))
            });

        if decided_meta_votes.clone().count() < self.voter_count() {
            return Vec::new();
        }

        self.compute_payloads_for_consensus(decided_meta_votes)
    }

    // Produce the consensused `ObservationKey`in consensus order.
    fn compute_payloads_for_consensus<I>(&self, decided_meta_votes: I) -> Vec<ObservationKey>
    where
        I: IntoIterator<Item = (PeerIndex, bool)>,
    {
        let payloads = decided_meta_votes
            .into_iter()
            .flat_map(|(peer_index, decision)| {
                if decision {
                    match self.meta_election.interesting_content_by(peer_index) {
                        Some(content) => content.iter().enumerate().collect_vec(),
                        None => Vec::new(),
                    }
                } else {
                    Vec::new()
                }
            })
            .fold(BTreeMap::new(), |mut map, (idx, payload_key)| {
                let (count, min_index) = map.entry(payload_key.clone()).or_insert((0, idx));
                *count += 1;
                *min_index = std::cmp::min(*min_index, idx);
                map
            });

        payloads
            .into_iter()
            .sorted_by(
                |(lhs_key, (lhs_count, lhs_min_index)), (rhs_key, (rhs_count, rhs_min_index))| {
                    lhs_min_index
                        .cmp(rhs_min_index)
                        .then_with(|| lhs_count.cmp(rhs_count).reverse())
                        .then_with(|| lhs_key.consistent_cmp(rhs_key, &self.peer_list))
                },
            )
            .map(|(key, _)| key)
            .collect()
    }

    fn create_blocks(&self, payload_keys: &[ObservationKey]) -> Result<BlockGroup<T, S::PublicId>> {
        let voters = self.voters();
        let blocks: Result<VecDeque<_>> = payload_keys
            .iter()
            .map(|payload_key| {
                let votes = self
                    .unconsensused_events(Some(payload_key))
                    .map(|event| event.inner())
                    .filter(|event| voters.contains(event.creator()))
                    .filter_map(|event| {
                        let (vote, key) = event.vote_and_payload_key(&self.observations)?;
                        let creator_id = self.peer_list.get(event.creator()).map(Peer::id)?;
                        Some((key, vote, creator_id))
                    })
                    .map(|(_, vote, creator_id)| (creator_id.clone(), vote.clone()))
                    .collect();

                Block::new(&votes)
            })
            .filter(|block| match block {
                Err(Error::MissingVotes) => false,
                Err(_) => true,
                Ok(block) => {
                    // Do not leak internal blocks to Parsec consumer
                    !block.payload().is_internal()
                }
            })
            .collect();

        Ok(BlockGroup(blocks?))
    }

    // Returns the number of peers that created events which are seen by event X (descendant) and
    // see event Y (ancestor). This means number of peers through which there is a directed path
    // between x and y, excluding peers contains fork.
    fn num_peers_created_events_seen_by_x_that_can_see_y(
        &self,
        x: &Event<S::PublicId>,
        y: &Event<S::PublicId>,
    ) -> usize {
        x.last_ancestors()
            .filter(|(peer_index, event_index)| {
                for event_idx in self.peer_list.events_by_index(*peer_index, *event_index) {
                    if let Ok(event) = self.get_known_event(event_idx) {
                        if x.sees(event) && event.sees(y) {
                            return true;
                        }
                    }
                }
                false
            })
            .count()
    }

    // Returns whether event X can strongly see the event Y during the evaluation of the given
    // election.
    fn strongly_sees<A, B>(&self, x: A, y: B) -> bool
    where
        A: AsRef<Event<S::PublicId>>,
        B: AsRef<Event<S::PublicId>>,
    {
        is_more_than_two_thirds(
            self.num_peers_created_events_seen_by_x_that_can_see_y(x.as_ref(), y.as_ref()),
            self.voter_count(),
        )
    }

    // Constructs a sync event to prove receipt of a `Request` or `Response` (depending on the value
    // of `is_request`) from `src`, then add it to our graph.
    fn create_sync_event(&mut self, is_request: bool, other_parent: EventIndex) -> Result<()> {
        self.process_or_queue_pending_event(PendingEvent::Sync {
            is_request,
            other_parent,
            _phantom: PhantomData,
        })
    }

    fn add_sync_event(&mut self, is_request: bool, other_parent: EventIndex) -> Result<()> {
        let self_parent = self.our_last_event_index()?;
        let event = if is_request {
            Event::new_from_request(self_parent, other_parent, self.event_context())?
        } else {
            Event::new_from_response(self_parent, other_parent, self.event_context())?
        };

        #[cfg(feature = "malice-detection")]
        {
            if !self.graph.is_valid_sync_event(&event).unwrap_or(false) {
                // The message we're handling is invalid, since it doesn't allow us to create our
                // sync event so that it follows the `Requesting -> Request -> Response` pattern.
                return Err(Error::InvalidMessage);
            }
        }

        let _ = self.add_event(event)?;

        self.check_vote_status();

        Ok(())
    }

    fn create_dkg_events(&mut self) -> Result<()> {
        for msg in mem::replace(&mut self.pending_dkg_msgs, vec![]) {
            self.create_dkg_event(msg)?;
        }
        Ok(())
    }

    fn create_dkg_event(&mut self, msg: DkgMessage) -> Result<()> {
        self.process_or_queue_pending_event(PendingEvent::DkgMessage { msg })
    }

    fn add_dkg_event(&mut self, msg: DkgMessage) -> Result<()> {
        // TODO: Like for Accusation, handle DkgMessage that should not be published yet.
        // (Only for "malice-detection" enabled)
        let event = self.new_event_from_observation(
            self.our_last_event_index()?,
            Observation::DkgMessage(msg),
        )?;
        let _ = self.add_event(event)?;
        Ok(())
    }

    // Returns an iterator over `self.events` which will yield all the events we think `peer_id`
    // doesn't yet know about.  We should already have checked that we know `peer_id` and that we
    // have recorded at least one event from this peer before calling this function.
    fn events_to_gossip_to_peer(&self, peer_index: PeerIndex) -> Result<Vec<&Event<S::PublicId>>> {
        let last_event = if let Some(event_index) = self.peer_list.last_event(peer_index) {
            self.get_known_event(event_index)?
        } else {
            log_or_panic!("{:?} doesn't have peer {:?}", self.our_pub_id(), peer_index);
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

    fn flush_pending_events(&mut self) -> Result<()> {
        // Insert the pending events only if we already have the initial event, which means we are
        // voter.
        if self.peer_list.our_events().next().is_none() {
            return Ok(());
        }

        for event in mem::replace(&mut self.pending_events, vec![]) {
            self.process_pending_event(event)?;
        }

        Ok(())
    }

    fn process_or_queue_pending_event(
        &mut self,
        event: PendingEvent<T, S::PublicId>,
    ) -> Result<()> {
        // Store as pending events if we do not have the initial event, which means we are
        // not voter yet.
        if self.peer_list.last_event(PeerIndex::OUR).is_none() {
            self.pending_events.push(event);
            Ok(())
        } else {
            self.process_pending_event(event)
        }
    }

    fn process_pending_event(&mut self, event: PendingEvent<T, S::PublicId>) -> Result<()> {
        match event {
            PendingEvent::Sync {
                is_request,
                other_parent,
                ..
            } => self.add_sync_event(is_request, other_parent),
            PendingEvent::DkgMessage { msg } => self.add_dkg_event(msg),
            #[cfg(feature = "malice-detection")]
            PendingEvent::Accusation {
                offender,
                malice,
                other_parent,
            } => self.add_accusation_event(offender, malice, other_parent),
        }
    }

    fn event_context(&self) -> EventContextRef<T, S> {
        EventContextRef {
            graph: &self.graph,
            peer_list: &self.peer_list,
            observations: &self.observations,
            consensus_mode: self.consensus_mode,
        }
    }

    #[cfg(any(all(test, feature = "mock"), feature = "malice-detection"))]
    fn event_payload<'a>(
        &'a self,
        event: &Event<S::PublicId>,
    ) -> Option<&'a Observation<T, S::PublicId>> {
        event
            .payload_key()
            .and_then(|key| self.observations.get(key))
            .map(|info| &info.observation)
    }

    #[cfg(any(all(test, feature = "mock"), feature = "malice-detection"))]
    fn event_creator_id<'a>(&'a self, event: &Event<S::PublicId>) -> Result<&'a S::PublicId> {
        self.peer_list
            .get(event.creator())
            .map(Peer::id)
            .ok_or_else(|| {
                log_or_panic!(
                    "{:?} doesn't know the creator of {:?}",
                    self.our_pub_id(),
                    event
                );
                Error::Logic
            })
    }
}

#[cfg(feature = "malice-detection")]
impl<T: NetworkEvent, S: SecretId> Parsec<T, S> {
    fn create_accusation_events(&mut self, other_parent: EventIndex) -> Result<()> {
        let pending_accusations = mem::replace(&mut self.pending_accusations, vec![]);
        for (offender, malice) in pending_accusations {
            self.create_accusation_event(offender, malice, other_parent)?;
        }

        Ok(())
    }

    fn create_accusation_event(
        &mut self,
        offender: PeerIndex,
        malice: Malice<T, S::PublicId>,
        other_parent: EventIndex,
    ) -> Result<()> {
        self.process_or_queue_pending_event(PendingEvent::Accusation {
            offender,
            malice,
            other_parent,
        })
    }

    // If the accusation specifies a malicious event in our graph which won't be an ancestor of the
    // upcoming sync event we're about to create, (e.g. the accusation was enqueued during an
    // abortive handling of a previous message) don't add it, but return it to be re-enqueued.
    fn add_accusation_event(
        &mut self,
        offender: PeerIndex,
        malice: Malice<T, S::PublicId>,
        other_parent: EventIndex,
    ) -> Result<()> {
        if self
            .will_be_ancestor_of_our_next_sync(&malice, other_parent)
            .unwrap_or(false)
        {
            let offender = self.peer_list.get_known(offender)?.id().clone();
            let event = self.new_event_from_observation(
                self.our_last_event_index()?,
                Observation::Accusation { offender, malice },
            )?;

            let _ = self.add_event(event)?;
        } else {
            self.pending_accusations.push((offender, malice));
        }
        Ok(())
    }

    fn will_be_ancestor_of_our_next_sync(
        &self,
        malice: &Malice<T, S::PublicId>,
        other_parent: EventIndex,
    ) -> Result<bool> {
        let self_parent = self
            .our_last_event_index()
            .and_then(|index| self.get_known_event(index))?;
        let other_parent = self.get_known_event(other_parent)?;

        Ok(self.accused_events(&malice).iter().all(|accused_event| {
            self_parent.is_descendant_of(accused_event)
                || other_parent.is_descendant_of(accused_event)
        }))
    }

    fn detect_malice(&mut self, event: &Event<S::PublicId>) -> Result<()> {
        // NOTE: `detect_incorrect_genesis` must come first.
        self.detect_incorrect_genesis(event)?;

        self.detect_other_parent_by_same_creator(event)?;
        self.detect_self_parent_by_different_creator(event)?;
        self.detect_invalid_sync_event(event)?;

        self.detect_unexpected_genesis(event);
        self.detect_missing_genesis(event);
        self.detect_duplicate_vote(event);
        self.detect_fork(event);
        self.detect_invalid_accusations(event);

        Ok(())
    }

    // Detect if the event carries an `Observation::Genesis` that doesn't match what we'd expect.
    fn detect_incorrect_genesis(&mut self, event: &Event<S::PublicId>) -> Result<()> {
        if let Some(Observation::Genesis { ref group, .. }) = self.event_payload(event) {
            if self.genesis_group() == group.iter().collect() {
                return Ok(());
            }
        } else {
            return Ok(());
        }

        // Return an error to prevent accepting potentially large number of invalid / spam events
        // into our graph.
        let packed_event = Box::new(event.pack(self.event_context())?);
        self.accuse(event.creator(), Malice::IncorrectGenesis(packed_event));
        Err(Error::InvalidEvent)
    }

    // Detect if the event's other_parent has the same creator as this event.
    fn detect_other_parent_by_same_creator(&mut self, event: &Event<S::PublicId>) -> Result<()> {
        if let Some(other_parent) = self.graph.other_parent(event) {
            if other_parent.creator() != event.creator() {
                return Ok(());
            }
        } else {
            return Ok(());
        }

        let packed_event = event.pack(self.event_context())?;
        self.accuse(
            event.creator(),
            Malice::OtherParentBySameCreator(Box::new(packed_event)),
        );
        Err(Error::InvalidEvent)
    }

    // Detect if the event's self_parent has the different creator as this event.
    fn detect_self_parent_by_different_creator(
        &mut self,
        event: &Event<S::PublicId>,
    ) -> Result<()> {
        if let Some(self_parent) = self.graph.self_parent(event) {
            if self_parent.creator() == event.creator() {
                return Ok(());
            }
        } else {
            return Ok(());
        }

        let packed_event = event.pack(self.event_context())?;
        self.accuse(
            event.creator(),
            Malice::SelfParentByDifferentCreator(Box::new(packed_event)),
        );
        Err(Error::InvalidEvent)
    }

    fn detect_invalid_sync_event(&mut self, event: &Event<S::PublicId>) -> Result<()> {
        if self.graph.is_valid_sync_event(event).unwrap_or(true) {
            return Ok(());
        }

        let packed_event = Box::new(event.pack(self.event_context())?);
        let malice = if event.is_request() {
            Malice::InvalidRequest(packed_event)
        } else {
            Malice::InvalidResponse(packed_event)
        };
        self.accuse(event.creator(), malice);
        Err(Error::InvalidEvent)
    }

    // Detect whether the event carries unexpected `Observation::Genesis`.
    fn detect_unexpected_genesis(&mut self, event: &Event<S::PublicId>) {
        let accuse = {
            let payload = if let Some(payload) = self.event_payload(event) {
                payload
            } else {
                return;
            };

            let genesis_group = if let Observation::Genesis { ref group, .. } = *payload {
                group
            } else {
                return;
            };

            let creator_id = if let Ok(id) = self.event_creator_id(event) {
                id
            } else {
                return;
            };

            // - the creator is not member of the genesis group, or
            // - the self-parent of the event is not initial event
            !genesis_group.contains(creator_id)
                || self
                    .graph
                    .self_parent(event)
                    .map_or(true, |self_parent| !self_parent.is_initial())
        };

        if accuse {
            self.accuse(event.creator(), Malice::UnexpectedGenesis(*event.hash()));
        }
    }

    // Detect when the first event by a peer belonging to genesis doesn't carry genesis
    fn detect_missing_genesis(&mut self, event: &Event<S::PublicId>) {
        if event.index_by_creator() != 1 {
            return;
        }

        if let Some(&Observation::Genesis { .. }) = self.event_payload(event) {
            return;
        }

        let accuse = {
            let creator_id = if let Ok(id) = self.event_creator_id(event) {
                id
            } else {
                return;
            };

            self.genesis_group().contains(creator_id)
        };

        if accuse {
            self.accuse(event.creator(), Malice::MissingGenesis(*event.hash()));
        }
    }

    // Detect that if the event carries a vote, there is already one or more votes with the same
    // observation by the same creator.
    fn detect_duplicate_vote(&mut self, event: &Event<S::PublicId>) {
        let other_hash = {
            let payload_key = if let Some(key) = event.payload_key() {
                key
            } else {
                return;
            };

            let mut duplicates = self
                .peer_list
                .peer_events(event.creator())
                .rev()
                .filter_map(|index| self.get_known_event(index).ok())
                .filter(|event| {
                    event
                        .payload_key()
                        .map_or(false, |event_payload_key| event_payload_key == payload_key)
                })
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
            event.creator(),
            Malice::DuplicateVote(other_hash, *event.hash()),
        );
    }

    // Detect whether the event incurs a fork.
    fn detect_fork(&mut self, event: &Event<S::PublicId>) {
        if self.is_first_fork(event) {
            if let Some(self_parent_hash) = self.graph.self_parent(event).map(|event| *event.hash())
            {
                self.accuse(event.creator(), Malice::Fork(self_parent_hash));
            }
        }
    }

    fn is_first_fork(&self, event: &Event<S::PublicId>) -> bool {
        let same_index_events = self
            .peer_list
            .events_by_index(event.creator(), event.index_by_creator());
        // Having no event with the same index means no fork, meanwhile multiple and having the same
        // self_parent means already cast forking accusation.
        same_index_events
            .filter_map(|other_event| self.graph.get(other_event))
            .filter(|other_event| other_event.inner().self_parent() == event.self_parent())
            .count()
            == 1
    }

    // If `event` is a sync event, this checks all self-parents which form an unbroken sequence of
    // `Accusation`s.
    fn detect_invalid_accusations(&mut self, event: &Event<S::PublicId>) {
        if !event.is_sync_event() {
            return;
        }
        let mut invalid_accusations = vec![];
        let mut self_parent_index = event.self_parent();
        while let Some(self_parent) =
            self_parent_index.and_then(|event_index| self.get_known_event(event_index).ok())
        {
            match self.event_payload(&self_parent) {
                Some(&Observation::Accusation {
                    ref offender,
                    ref malice,
                }) => {
                    if malice.is_provable() && !self.we_have_accused(offender, malice) {
                        invalid_accusations.push(*self_parent.hash());
                    }
                    self_parent_index = self_parent.self_parent();
                }
                _ => {
                    // Stop checking further self-parents, since this isn't an `Accusation`.
                    self_parent_index = None;
                }
            }
        }
        for event_hash in invalid_accusations {
            self.accuse(event.creator(), Malice::InvalidAccusation(event_hash))
        }
    }

    fn we_have_accused(&self, offender: &S::PublicId, malice: &Malice<T, S::PublicId>) -> bool {
        let their_accusation = if let Some(offender_index) = self.peer_list.get_index(offender) {
            (offender_index, malice)
        } else {
            return false;
        };

        // First try to find the same accusation in our pending accusations...
        if self
            .pending_accusations
            .iter()
            .any(|&(our_offender, ref our_malice)| their_accusation == (our_offender, our_malice))
        {
            return true;
        }

        // ...then in our events...
        self.peer_list
            .our_events()
            .rev()
            .filter_map(|event_index| self.get_known_event(event_index).ok())
            .filter_map(|event| {
                if let Some(&Observation::Accusation {
                    ref offender,
                    ref malice,
                }) = self.event_payload(event.inner())
                {
                    Some((offender, malice))
                } else {
                    None
                }
            })
            .filter_map(|(offender_id, malice)| {
                self.peer_list
                    .get_index(offender_id)
                    .map(|index| (index, malice))
            })
            .any(|our_accusation| their_accusation == our_accusation)
    }

    fn detect_premature_gossip(&self) -> Result<()> {
        self.confirm_self_state(PeerState::DKG)
            .map_err(|_| Error::PrematureGossip)
    }

    fn accuse(&mut self, offender: PeerIndex, malice: Malice<T, S::PublicId>) {
        self.pending_accusations.push((offender, malice));
    }

    fn accusations_by_peer_since(
        &self,
        peer_index: PeerIndex,
        oldest_event: Option<EventIndex>,
    ) -> impl Iterator<Item = (PeerIndex, &Malice<T, S::PublicId>)> {
        self.graph
            .iter_from(oldest_event.map(EventIndex::topological_index).unwrap_or(0))
            .filter(move |event| event.creator() == peer_index)
            .filter_map(move |event| match self.event_payload(event.inner()) {
                Some(Observation::Accusation { offender, malice }) => Some((offender, malice)),
                _ => None,
            })
            .filter_map(move |(offender, malice)| {
                self.peer_list
                    .get_index(offender)
                    .map(|offender| (offender, malice))
            })
    }

    fn accused_events<'a>(
        &'a self,
        malice: &'a Malice<T, S::PublicId>,
    ) -> Vec<IndexedEventRef<'a, S::PublicId>> {
        malice
            .accused_events_in_graph()
            .iter()
            .filter_map(move |hash| self.graph.get_by_hash(hash))
            .collect()
    }

    fn accused_events_are_ancestors_of(
        &self,
        malice: &Malice<T, S::PublicId>,
        event_index: EventIndex,
    ) -> bool {
        let event = if let Some(event) = self.graph.get(event_index) {
            event
        } else {
            return false;
        };

        self.accused_events(malice)
            .iter()
            .all(|accused_event| event.is_descendant_of(accused_event))
    }

    fn events_with_self_parent(
        &self,
        parent: IndexedEventRef<S::PublicId>,
    ) -> impl Iterator<Item = IndexedEventRef<S::PublicId>> {
        let parent_index = parent.event_index();
        self.peer_list
            .events_by_index(parent.creator(), parent.index_by_creator() + 1)
            .filter_map(move |descendant_index| self.get_known_event(descendant_index).ok())
            .filter(move |descendant| descendant.self_parent() == Some(parent_index))
    }

    fn accused_event_is_fork_but_this_event_is_not_a_fork_descendant(
        &self,
        malice: &Malice<T, S::PublicId>,
        event_index: EventIndex,
    ) -> bool {
        if let Malice::Fork(accused_event_hash) = malice {
            self.graph
                .get_by_hash(accused_event_hash)
                .and_then(|accused_event| {
                    self.graph
                        .get(event_index)
                        .map(|event| (accused_event, event))
                })
                .map(|(accused_event, event)| {
                    // `event` must be a descendant of more than one fork branch to be in a position
                    // to know about the fork.
                    self.events_with_self_parent(accused_event)
                        .filter(|forked_event| event.is_descendant_of(forked_event))
                        .count()
                        < 2
                })
                .unwrap_or(true)
        } else {
            false
        }
    }

    fn detect_accomplice(&mut self, event_index: EventIndex) -> Result<()> {
        let (event_hash, creator) = {
            let event = self.get_known_event(event_index)?;

            // Peers will raise accusations just before creating `Request` and `Response` events, so
            // skip checking if this event is not one.
            if !event.is_request() && !event.is_response() {
                return Ok(());
            }

            (*event.hash(), event.creator())
        };

        let starting_index = self.peer_list.accomplice_event_checkpoint_by(creator);
        let accusations =
            self.detect_accomplice_for_our_accusations(event_index, starting_index)?;
        for (_, malice) in accusations {
            self.accuse(creator, Malice::Accomplice(event_hash, Box::new(malice)));
        }

        // Updating the event checkpoint for the next event when it will be used as starting index,
        // purely as an optimisation
        let last_malice_event_accused_by_peer = self
            .accusations_by_peer_since(creator, starting_index)
            .filter_map(|(_, malice)| malice.single_hash().and_then(|h| self.graph.get_index(&h)))
            .max_by_key(|event_index| event_index.topological_index());
        if let Some(index) = last_malice_event_accused_by_peer {
            self.peer_list
                .update_accomplice_event_checkpoint_by(creator, index);
        }

        Ok(())
    }

    fn detect_accomplice_for_our_accusations(
        &self,
        event_index: EventIndex,
        starting_event: Option<EventIndex>,
    ) -> Result<Accusations<T, S::PublicId>> {
        let creator = self.get_known_event(event_index)?.creator();
        let our_accusations = self.accusations_by_peer_since(PeerIndex::OUR, starting_event);
        let accusations_by_peer_since_starter_event = self
            .accusations_by_peer_since(creator, starting_event)
            .collect_vec();

        Ok(self
            .pending_accusations
            .iter()
            .map(|(offender, malice)| (*offender, malice))
            .chain(our_accusations)
            .filter(|(offender, _)| offender != &creator)
            .filter(|(_, malice)| self.accused_events_are_ancestors_of(&malice, event_index))
            .filter(|(_, malice)| {
                !self.accused_event_is_fork_but_this_event_is_not_a_fork_descendant(
                    &malice,
                    event_index,
                )
            })
            .filter(|accusation| !accusations_by_peer_since_starter_event.contains(accusation))
            .filter(|(_, malice)| {
                !self.pending_accusations.iter().any(|(off, mal)| match mal {
                    Malice::Accomplice(_, ori_mal) => off == &creator && **ori_mal == **malice,
                    _ => false,
                })
            })
            .map(|(offender, malice)| (offender, malice.clone()))
            .collect())
    }

    fn genesis_group(&self) -> BTreeSet<&S::PublicId> {
        self.graph
            .iter()
            .filter_map(|event| {
                let observation = self.event_payload(&*event)?;
                if let Observation::Genesis { ref group, .. } = *observation {
                    Some(group.iter().collect())
                } else {
                    None
                }
            })
            .next()
            .unwrap_or_else(|| self.peer_list.voters().map(|(_, peer)| peer.id()).collect())
    }
}

impl<T: NetworkEvent, S: SecretId> Drop for Parsec<T, S> {
    fn drop(&mut self) {
        dump_graph::to_file(dump_graph::ToFileInfo {
            owner_id: self.our_pub_id(),
            consensus_mode: self.consensus_mode,
            gossip_graph: &self.graph,
            meta_election: &self.meta_election,
            peer_list: &self.peer_list,
            observations: &self.observations,
            secure_rng: &self.secure_rng,
            key_gens_and_next_id: (&self.key_gen, &self.key_gen_next_id),
            info: &dump_graph::DumpGraphContext::DroppingParsec,
        });
    }
}

fn get_known_event<'a, P: PublicId>(
    our_pub_id: &P,
    graph: &'a Graph<P>,
    event_index: EventIndex,
) -> Result<IndexedEventRef<'a, P>> {
    graph.get(event_index).ok_or_else(|| {
        log_or_panic!("{:?} doesn't have event {:?}", our_pub_id, event_index);
        Error::Logic
    })
}

// What to do after processing the current event.
enum PostProcessAction {
    // Continue with the next event (if any)
    Continue,
    // Restart processing events from the given index.
    Restart(usize),
}

#[cfg(feature = "malice-detection")]
type Accusations<T, P> = Vec<(PeerIndex, Malice<T, P>)>;

enum PendingEvent<T: NetworkEvent, P: PublicId> {
    Sync {
        is_request: bool,
        other_parent: EventIndex,
        _phantom: PhantomData<(T, P)>,
    },
    DkgMessage {
        msg: DkgMessage,
    },
    #[cfg(feature = "malice-detection")]
    Accusation {
        offender: PeerIndex,
        malice: Malice<T, P>,
        // The other_parent of our sync event we'll create just after creating this Accusation event
        other_parent: EventIndex,
    },
}

#[cfg(any(test, feature = "testing"))]
impl<T: NetworkEvent, S: SecretId> Parsec<T, S> {
    // Disable processing consensus on this instance (speed up processing).
    pub(crate) fn set_ignore_process_events(&mut self) {
        self.ignore_process_events = true;
    }

    // Return true if processing consensus is disabled.
    pub(crate) fn ignore_process_events(&self) -> bool {
        self.ignore_process_events
    }
}

#[cfg(any(feature = "testing", all(test, feature = "mock")))]
impl Parsec<Transaction, PeerId> {
    #[cfg(all(test, feature = "mock"))]
    pub(crate) fn from_parsed_contents(
        mut parsed_contents: ParsedContents,
        secure_rng: Box<dyn rand::Rng>,
    ) -> Self {
        let peer_list = PeerList::new(parsed_contents.our_id);
        let mut parsec = Parsec::empty(
            peer_list,
            PeerIndexSet::default(),
            parsed_contents.consensus_mode,
            secure_rng,
        );

        for event in &parsed_contents.graph {
            if let Some(payload_key) = event.payload_key() {
                if let Some(info) = parsed_contents.observations.get_mut(payload_key) {
                    if event.creator() == PeerIndex::OUR {
                        info.created_by_us = true;
                    }
                }
            }
        }

        for consensused in parsed_contents.meta_election.consensus_history() {
            let _ = parsed_contents
                .observations
                .get_mut(consensused)
                .map(|info| info.consensused = true);
        }

        if let Some(serialized_key_gens_and_next_id) =
            &parsed_contents.serialized_key_gens_and_next_id
        {
            // `serialisation::deserialise` is over constrained and require `Serialize` which is
            // only available with `dump-graphs` enabled (as it is not safe to dump secrets).
            // Use Cursor to get an io::Read object so we can use the not over constrained
            // `deserialise_from`.
            let mut cursor = std::io::Cursor::new(serialized_key_gens_and_next_id);
            let (key_gen, key_gen_next_id) = unwrap!(
                maidsafe_utilities::serialisation::deserialise_from(&mut cursor)
            );

            parsec.key_gen = key_gen;
            parsec.key_gen_next_id = key_gen_next_id;
        }

        parsec.graph = parsed_contents.graph;
        parsec.meta_election = parsed_contents.meta_election;
        parsec.peer_list = parsed_contents.peer_list;
        parsec.observations = parsed_contents.observations;
        parsec
    }

    /// The consensus history hashes in order of consensus (for testing)
    pub fn meta_election_consensus_history_hash(&self) -> Vec<Hash> {
        self.meta_election
            .consensus_history
            .iter()
            .map(|observation| observation.hash().0)
            .collect()
    }
}

/// Wrapper around `Parsec` that exposes additional functionality useful for testing.
#[cfg(any(test, feature = "testing"))]
pub(crate) struct TestParsec<T: NetworkEvent, S: SecretId>(Parsec<T, S>);

#[cfg(any(test, feature = "testing"))]
impl<T: NetworkEvent, S: SecretId> TestParsec<T, S> {
    pub fn from_genesis(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        consensus_mode: ConsensusMode,
        secure_rng: Box<dyn rand::Rng>,
    ) -> Self {
        TestParsec(Parsec::from_genesis(
            our_id,
            genesis_group,
            vec![],
            consensus_mode,
            secure_rng,
        ))
    }

    pub fn from_existing(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        section: &BTreeSet<S::PublicId>,
        consensus_mode: ConsensusMode,
        secure_rng: Box<dyn rand::Rng>,
    ) -> Self {
        TestParsec(Parsec::from_existing(
            our_id,
            genesis_group,
            section,
            consensus_mode,
            secure_rng,
        ))
    }

    pub fn graph(&self) -> &Graph<S::PublicId> {
        &self.0.graph
    }

    pub fn peer_list(&self) -> &PeerList<S> {
        &self.0.peer_list
    }

    pub fn our_last_event_index(&self) -> EventIndex {
        unwrap!(self.0.our_last_event_index())
    }

    pub fn event_context(&self) -> EventContextRef<T, S> {
        self.0.event_context()
    }

    pub fn events_to_gossip_to_peer(
        &self,
        peer_index: PeerIndex,
    ) -> Result<Vec<&Event<S::PublicId>>> {
        self.0.events_to_gossip_to_peer(peer_index)
    }

    pub fn get_peer_index(&self, peer_id: &S::PublicId) -> Result<PeerIndex> {
        self.0.get_peer_index(peer_id)
    }

    pub fn confirm_allowed_to_gossip_to(&self, peer_index: PeerIndex) -> Result<()> {
        self.0.confirm_allowed_to_gossip_to(peer_index)
    }

    #[cfg(all(test, feature = "mock"))]
    pub fn event_payload(
        &self,
        event: &Event<S::PublicId>,
    ) -> Option<&Observation<T, S::PublicId>> {
        self.0.event_payload(event)
    }
}

#[cfg(all(test, feature = "mock"))]
impl TestParsec<Transaction, PeerId> {
    pub fn from_parsed_contents(
        parsed_contents: ParsedContents,
        secure_rng: Box<dyn rand::Rng>,
    ) -> Self {
        TestParsec(Parsec::from_parsed_contents(parsed_contents, secure_rng))
    }

    pub fn meta_election(&self) -> &MetaElection {
        &self.meta_election
    }

    pub fn consensused_blocks(&self) -> impl Iterator<Item = &Block<Transaction, PeerId>> {
        self.0.consensused_blocks.iter().flatten()
    }

    pub fn change_peer_state(&mut self, peer_id: &PeerId, state: PeerState) {
        let peer_index = unwrap!(self.0.peer_list.get_index(peer_id));
        self.0.peer_list.change_peer_state(peer_index, state)
    }

    pub fn pack_event(&self, event: &Event<PeerId>) -> PackedEvent<Transaction, PeerId> {
        unwrap!(event.pack(self.0.event_context()))
    }

    pub fn unpack_and_add_event(
        &mut self,
        packed_event: PackedEvent<Transaction, PeerId>,
    ) -> Result<EventIndex> {
        match self.0.unpack(packed_event)? {
            Some(event) => self.0.add_event(event),
            None => Err(Error::Logic),
        }
    }

    // Warning: only add events created using this instance of `Parsec`. Adding an event from other
    // instance is not detectable and might lead to incorrect test results. To add event from other
    // instance, first `pack_event` it using that other instance, then add it using
    // `unpack_and_add_event`.
    pub fn add_event(&mut self, event: Event<PeerId>) -> Result<EventIndex> {
        self.0.add_event(event)
    }

    pub fn event_creator_id(&self, event: &Event<PeerId>) -> &PeerId {
        unwrap!(self.0.event_creator_id(event))
    }

    pub fn new_event_from_observation(
        &mut self,
        self_parent: EventIndex,
        observation: Observation<Transaction, PeerId>,
    ) -> Result<Event<PeerId>> {
        self.0.new_event_from_observation(self_parent, observation)
    }
}

#[cfg(all(test, feature = "malice-detection", feature = "mock"))]
impl TestParsec<Transaction, PeerId> {
    pub fn remove_last_event(&mut self) -> Option<(EventIndex, Event<PeerId>)> {
        let (event_index, event) = self.graph.remove_last()?;
        assert_eq!(
            event_index,
            unwrap!(self.peer_list.remove_last_event(event.creator()))
        );

        if let Some(payload_key) = event.payload_key() {
            let _ = self
                .0
                .meta_election
                .unconsensused_events
                .ordered_indices
                .remove(&event_index);
            let _ = self
                .0
                .meta_election
                .unconsensused_events
                .indices_by_key
                .get_mut(payload_key)
                .map(|indices| indices.remove(&event_index));
        }

        Some((event_index, event))
    }

    // This is equivalent to handling a request normally, but falsely accusing the sender's last
    // event as being a fork.  Returns the hash of the invalid accusation.
    pub fn handle_request_make_false_accusation(
        &mut self,
        src: &PeerId,
        req: Request<Transaction, PeerId>,
    ) -> EventHash {
        let src_index = unwrap!(self.0.get_peer_index(src));
        let last_hash = unwrap!(req.packed_events.last()).compute_hash();
        let other_parent = unwrap!(self.0.unpack_and_add_events(src_index, req.packed_events));
        unwrap!(self.0.create_accusation_events(other_parent));

        let invalid_observation = Observation::<Transaction, _>::Accusation {
            offender: src.clone(),
            malice: Malice::Fork(last_hash),
        };
        unwrap!(self.0.vote_for(invalid_observation.clone()));
        let invalid_accusation_hash = {
            let invalid_accusation = unwrap!(self.0.graph.get(self.our_last_event_index()));
            assert_eq!(
                self.0.event_payload(&invalid_accusation),
                Some(&invalid_observation)
            );
            *invalid_accusation.hash()
        };

        unwrap!(self.0.create_sync_event(true, other_parent));
        invalid_accusation_hash
    }

    // This is equivalent to handling a request normally, but avoiding creating any accusations.
    // It can be used by an accomplice peer which wants to avoid accusing a malicious peer.
    pub fn handle_request_as_accomplice(
        &mut self,
        src: &PeerId,
        req: Request<Transaction, PeerId>,
    ) {
        let src_index = unwrap!(self.0.get_peer_index(src));
        let other_parent = unwrap!(self.0.unpack_and_add_events(src_index, req.packed_events));
        self.0.pending_accusations.clear();
        unwrap!(self.0.create_sync_event(true, other_parent));
    }

    pub fn pending_accusations(&self) -> &Accusations<Transaction, PeerId> {
        &self.0.pending_accusations
    }

    pub fn add_peer(&mut self, peer_id: PeerId, state: PeerState) {
        let _ = self.0.peer_list.add_peer(peer_id, state);
    }

    pub fn restart_consensus(&mut self) -> Result<()> {
        self.0.process_events(0)
    }
}

#[cfg(any(test, feature = "testing"))]
impl<T: NetworkEvent, S: SecretId> From<Parsec<T, S>> for TestParsec<T, S> {
    fn from(parsec: Parsec<T, S>) -> Self {
        TestParsec(parsec)
    }
}

#[cfg(any(test, feature = "testing"))]
impl<T: NetworkEvent, S: SecretId> Deref for TestParsec<T, S> {
    type Target = Parsec<T, S>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(any(test, feature = "testing"))]
impl<T: NetworkEvent, S: SecretId> DerefMut for TestParsec<T, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Get the parsec graph snapshot with inserted events out of order.
#[cfg(all(test, any(feature = "testing", feature = "mock")))]
pub(crate) fn get_graph_snapshot<T: NetworkEvent, S: SecretId>(
    parsec: &Parsec<T, S>,
    ignore_last_events: usize,
) -> GraphSnapshot {
    GraphSnapshot::new_with_ignore(&parsec.graph, ignore_last_events)
}

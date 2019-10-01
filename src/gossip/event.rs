// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    cause::{self, Cause},
    content::Content,
    event_context::EventContextRef,
    event_hash::EventHash,
    event_utils::{compute_ancestor_info, AncestorInfo, IndexSet},
    graph::{EventIndex, Graph},
    packed_event::PackedEvent,
};
#[cfg(any(test, feature = "testing"))]
use crate::observation::MaliceInput;
use crate::{
    error::Error,
    hash::Hash,
    id::{PublicId, SecretId},
    network_event::NetworkEvent,
    observation::{Observation, ObservationForStore, ObservationKey, ObservationStore},
    peer_list::{PeerIndex, PeerIndexMap, PeerList},
    serialise,
    vote::{Vote, VoteKey},
};
#[cfg(any(test, feature = "testing"))]
use crate::{
    mock::{PeerId, Transaction},
    observation::ConsensusMode,
};
use itertools::Itertools;
use std::fmt::{self, Debug, Display, Formatter};

pub(crate) struct Event<P: PublicId> {
    content: Content<VoteKey<P>, EventIndex, PeerIndex>,
    // Creator's signature of `content`.
    signature: P::Signature,
    cache: Cache,
}

impl<P: PublicId> Event<P> {
    // Creates a new event in preparation for sending a gossip request message.
    pub fn new_from_requesting<T: NetworkEvent, S: SecretId<PublicId = P>>(
        self_parent: EventIndex,
        recipient: &P,
        ctx: EventContextRef<T, S>,
    ) -> Result<Self, Error> {
        let content: Content<Vote<T, _>, _, _> = Content {
            creator: ctx.peer_list.our_pub_id().clone(),
            cause: Cause::Requesting {
                self_parent: cause::self_parent_hash(ctx.graph, self_parent)?,
                recipient: recipient.clone(),
            },
        };
        let (hash, signature) = compute_event_hash_and_signature(&content, ctx.peer_list.our_id());
        let content = Content {
            creator: PeerIndex::OUR,
            cause: Cause::Requesting {
                self_parent,
                recipient: cause::recipient_index(ctx.peer_list, recipient)?,
            },
        };

        Ok(Self::new(
            hash,
            signature,
            content,
            ctx.graph,
            ctx.peer_list,
        ))
    }

    // Creates a new event as the result of receiving a gossip request message.
    pub fn new_from_request<T: NetworkEvent, S: SecretId<PublicId = P>>(
        self_parent: EventIndex,
        other_parent: EventIndex,
        ctx: EventContextRef<T, S>,
    ) -> Result<Self, Error> {
        let content: Content<Vote<T, _>, _, _> = Content {
            creator: ctx.peer_list.our_pub_id().clone(),
            cause: Cause::Request {
                self_parent: cause::self_parent_hash(ctx.graph, self_parent)?,
                other_parent: cause::other_parent_hash(ctx.graph, other_parent)?,
            },
        };
        let (hash, signature) = compute_event_hash_and_signature(&content, ctx.peer_list.our_id());

        let content = Content {
            creator: PeerIndex::OUR,
            cause: Cause::Request {
                self_parent,
                other_parent,
            },
        };

        Ok(Self::new(
            hash,
            signature,
            content,
            ctx.graph,
            ctx.peer_list,
        ))
    }

    // Creates a new event as the result of receiving a gossip response message.
    pub fn new_from_response<T: NetworkEvent, S: SecretId<PublicId = P>>(
        self_parent: EventIndex,
        other_parent: EventIndex,
        ctx: EventContextRef<T, S>,
    ) -> Result<Self, Error> {
        let content: Content<Vote<T, _>, _, _> = Content {
            creator: ctx.peer_list.our_pub_id().clone(),
            cause: Cause::Response {
                self_parent: cause::self_parent_hash(ctx.graph, self_parent)?,
                other_parent: cause::other_parent_hash(ctx.graph, other_parent)?,
            },
        };
        let (hash, signature) = compute_event_hash_and_signature(&content, ctx.peer_list.our_id());

        let content = Content {
            creator: PeerIndex::OUR,
            cause: Cause::Response {
                self_parent,
                other_parent,
            },
        };

        Ok(Self::new(
            hash,
            signature,
            content,
            ctx.graph,
            ctx.peer_list,
        ))
    }

    // Creates a new event as the result of observing a network event.
    pub fn new_from_observation<T: NetworkEvent, S: SecretId<PublicId = P>>(
        self_parent: EventIndex,
        observation: Observation<T, P>,
        ctx: EventContextRef<T, S>,
    ) -> Result<(Self, ObservationForStore<T, P>), Error> {
        // Compute event hash + signature.
        let vote = Vote::new(ctx.peer_list.our_id(), observation);
        let content = Content {
            creator: ctx.peer_list.our_pub_id().clone(),
            cause: Cause::Observation {
                self_parent: cause::self_parent_hash(ctx.graph, self_parent)?,
                vote,
            },
        };
        let (hash, signature) = compute_event_hash_and_signature(&content, ctx.peer_list.our_id());
        let graph = ctx.graph;
        let peer_list = ctx.peer_list;
        let (content, observation_for_store) = Content::unpack(content, ctx)?;

        Ok((
            Self::new(hash, signature, content, graph, peer_list),
            observation_for_store,
        ))
    }

    // Creates an initial event.  This is the first event by its creator in the graph.
    pub fn new_initial<T: NetworkEvent, S: SecretId<PublicId = P>>(
        ctx: EventContextRef<T, S>,
    ) -> Self {
        let content: Content<Vote<T, _>, _, _> = Content {
            creator: ctx.peer_list.our_pub_id().clone(),
            cause: Cause::Initial,
        };
        let (hash, signature) = compute_event_hash_and_signature(&content, ctx.peer_list.our_id());

        let content = Content {
            creator: PeerIndex::OUR,
            cause: Cause::Initial,
        };

        Self::new(hash, signature, content, ctx.graph, ctx.peer_list)
    }

    fn new<S: SecretId<PublicId = P>>(
        hash: EventHash,
        signature: P::Signature,
        content: Content<VoteKey<P>, EventIndex, PeerIndex>,
        graph: &Graph<P>,
        peer_list: &PeerList<S>,
    ) -> Self {
        let cache = Cache::new(hash, &content, graph, peer_list);
        Self {
            content,
            signature,
            cache,
        }
    }

    // Creates an event from a `PackedEvent`.
    //
    // Returns:
    //   - `Ok(None)` if the event already exists
    //   - `Err(Error::SignatureFailure)` if signature validation fails
    //   - `Err(Error::UnknownParent)` if the event indicates it should have an ancestor, but the
    //     ancestor isn't in `events`.
    pub fn unpack<T: NetworkEvent, S: SecretId<PublicId = P>>(
        packed_event: PackedEvent<T, P>,
        ctx: EventContextRef<T, S>,
    ) -> Result<Option<UnpackedEvent<T, P>>, Error> {
        let hash = compute_event_hash_and_verify_signature(
            &packed_event.content,
            &packed_event.signature,
        )?;

        if ctx.graph.contains(&hash) {
            return Ok(None);
        }

        let graph = ctx.graph;
        let peer_list = ctx.peer_list;
        let (content, observation_for_store) = Content::unpack(packed_event.content, ctx)?;
        let cache = Cache::new(hash, &content, graph, peer_list);

        Ok(Some(UnpackedEvent {
            event: Self {
                content,
                signature: packed_event.signature,
                cache,
            },
            observation_for_store,
        }))
    }

    // Creates a `PackedEvent` from this `Event`.
    pub fn pack<T: NetworkEvent, S: SecretId<PublicId = P>>(
        &self,
        ctx: EventContextRef<T, S>,
    ) -> Result<PackedEvent<T, P>, Error> {
        Ok(PackedEvent {
            content: self.content.pack(ctx)?,
            signature: self.signature.clone(),
        })
    }

    // Returns whether this event is descendant of `other`.
    pub fn is_descendant_of<E: AsRef<Event<P>>>(&self, other: E) -> bool {
        let other = other.as_ref();

        let self_info = if let Some(info) = self.cache.ancestor_info.get(other.creator()) {
            info
        } else {
            return false;
        };

        if self_info.last < other.index_by_creator() {
            return false;
        }

        if let Some(self_forks) = self_info.forks.get(&other.index_by_creator()) {
            if let Some(other_forks) = other.fork_set() {
                !self_forks.is_disjoint(other_forks)
            } else {
                self_forks.contains(0)
            }
        } else {
            other
                .fork_set()
                .map(|other_forks| other_forks.contains(0))
                .unwrap_or(true)
        }
    }

    // Returns whether this event sees `other`, i.e. whether there's a directed path from `other`
    // to `self` in the graph, and there doesn't exist any pair of events by `other`'s creator
    // such that they are ancestors of this event but one is neither ancestor nor descendant of the
    // other.
    pub fn sees<E: AsRef<Event<P>>>(&self, other: E) -> bool {
        !self.descends_from_fork(other.as_ref().creator()) && self.is_descendant_of(other)
    }

    // Is this event aware of a fork by the given peer?
    // Note this method returns true only if the fork is provable by every node that has reached
    // this event. That means this event must have ancestors from at least two sides of the same
    // fork.
    pub fn descends_from_fork(&self, creator: PeerIndex) -> bool {
        self.cache
            .ancestor_info
            .get(creator)
            .map(|info| info.forks.values().any(|fork_set| fork_set.len() > 1))
            .unwrap_or(false)
    }

    // Fork set that this event is a member of.
    //
    // ("fork set" is a set of events from the same creator that have the same `index_by_creator`.
    // This can be events that have the same self-parent, or the same self-grand-parent, etc...)
    //
    // If this event is not member of a fork set (it's not forking) or is the first member of its
    // fork set (in the insertion order), this function returns `None`.
    pub fn fork_set(&self) -> Option<&IndexSet> {
        self.cache
            .ancestor_info
            .get(self.creator())
            .and_then(|info| info.forks.get(&self.index_by_creator()))
    }

    pub fn payload_key(&self) -> Option<&ObservationKey> {
        match self.content.cause {
            Cause::Observation { ref vote, .. } => Some(vote.payload_key()),
            _ => None,
        }
    }

    pub fn vote_and_payload_key<T: NetworkEvent>(
        &self,
        observations: &ObservationStore<T, P>,
    ) -> Option<(Vote<T, P>, ObservationKey)> {
        match self.content.cause {
            Cause::Observation { ref vote, .. } => {
                let key = *vote.payload_key();
                let vote = vote.resolve(observations).ok()?;

                Some((vote, key))
            }
            _ => None,
        }
    }

    pub fn creator(&self) -> PeerIndex {
        self.content.creator
    }

    pub fn self_parent(&self) -> Option<EventIndex> {
        self.content.self_parent().cloned()
    }

    pub fn other_parent(&self) -> Option<EventIndex> {
        self.content.other_parent().cloned()
    }

    pub fn hash(&self) -> &EventHash {
        &self.cache.hash
    }

    // Index of this event relative to other events by the same creator.
    pub fn index_by_creator(&self) -> usize {
        self.cache.index_by_creator
    }

    pub fn last_ancestors<'a>(&'a self) -> impl Iterator<Item = (PeerIndex, usize)> + 'a {
        self.cache
            .ancestor_info
            .iter()
            .map(|(peer_index, info)| (peer_index, info.last))
    }

    pub fn last_ancestor_by(&self, creator: PeerIndex) -> Option<usize> {
        self.cache.ancestor_info.get(creator).map(|info| info.last)
    }

    pub fn non_fork_last_ancestor_by(&self, creator: PeerIndex) -> Option<usize> {
        if self.descends_from_fork(creator) {
            None
        } else {
            self.last_ancestor_by(creator)
        }
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn ancestor_info(&self) -> &PeerIndexMap<AncestorInfo> {
        &self.cache.ancestor_info
    }

    pub fn is_sync_event(&self) -> bool {
        match self.content.cause {
            Cause::Requesting { .. } | Cause::Request { .. } | Cause::Response { .. } => true,
            Cause::Initial | Cause::Observation { .. } => false,
        }
    }

    pub fn is_observation(&self) -> bool {
        match self.content.cause {
            Cause::Observation { .. } => true,
            _ => false,
        }
    }

    pub fn is_requesting(&self) -> bool {
        if let Cause::Requesting { .. } = self.content.cause {
            true
        } else {
            false
        }
    }

    #[cfg(feature = "malice-detection")]
    pub fn requesting_recipient(&self) -> Option<PeerIndex> {
        if let Cause::Requesting { recipient, .. } = self.content.cause {
            Some(recipient)
        } else {
            None
        }
    }

    pub fn is_request(&self) -> bool {
        if let Cause::Request { .. } = self.content.cause {
            true
        } else {
            false
        }
    }

    pub fn is_response(&self) -> bool {
        if let Cause::Response { .. } = self.content.cause {
            true
        } else {
            false
        }
    }

    pub fn is_initial(&self) -> bool {
        if let Cause::Initial = self.content.cause {
            true
        } else {
            false
        }
    }

    /// Returns the first char of the creator's ID, followed by an underscore and the event's index.
    #[cfg(any(test, feature = "testing"))]
    pub fn short_name(&self) -> ShortName {
        ShortName {
            creator_initial: self.cache.creator_initial,
            index_by_creator: self.cache.index_by_creator,
        }
    }

    #[cfg(any(test, feature = "testing", feature = "dump-graphs"))]
    pub fn cause(&self) -> &Cause<VoteKey<P>, EventIndex, PeerIndex> {
        &self.content.cause
    }
}

impl<P: PublicId> PartialEq for Event<P> {
    fn eq(&self, other: &Self) -> bool {
        self.content == other.content && self.signature == other.signature
    }
}

impl<P: PublicId> Eq for Event<P> {}

impl<P: PublicId> Debug for Event<P> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Event{{")?;

        #[cfg(any(test, feature = "testing"))]
        write!(
            formatter,
            " {}{}",
            self.short_name(),
            self.fork_set()
                .map(|set| format!(",{:?}", set))
                .unwrap_or_default()
        )?;

        write!(formatter, " {:?}", self.hash())?;
        write!(formatter, ", {:?}", self.content.cause)?;
        write!(
            formatter,
            ", self_parent: {:?}, other_parent: {:?}",
            self.content.self_parent(),
            self.content.other_parent()
        )?;
        write!(
            formatter,
            ", last_ancestors: {:?}",
            self.cache
                .ancestor_info
                .iter()
                .map(|(peer_id, info)| EntryDebug(peer_id, info.last))
                .format(", ")
        )?;
        write!(formatter, " }}")
    }
}

struct EntryDebug<K: Debug, V: Debug>(K, V);

impl<K: Debug, V: Debug> Debug for EntryDebug<K, V> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:?}: {:?}", self.0, self.1)
    }
}

impl<P: PublicId> AsRef<Self> for Event<P> {
    fn as_ref(&self) -> &Self {
        self
    }
}

#[cfg(any(test, feature = "testing"))]
impl Event<PeerId> {
    // Creates a new event using the input parameters directly.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_from_dot_input(
        creator: &PeerId,
        cause: CauseInput,
        self_parent: Option<(EventIndex, EventHash, PeerIndexMap<AncestorInfo>)>,
        other_parent: Option<(EventIndex, EventHash, PeerIndexMap<AncestorInfo>)>,
        index_by_creator: usize,
        consensus_mode: ConsensusMode,
        peer_list: &mut PeerList<PeerId>,
        observations: &mut ObservationStore<Transaction, PeerId>,
    ) -> Self {
        let recipient = match cause {
            CauseInput::Requesting(ref recipient) => peer_list.get_index(recipient),
            _ => None,
        };
        let cause = Cause::new_from_dot_input(
            cause,
            creator,
            self_parent.as_ref().map(|(_, hash, _)| *hash),
            other_parent.as_ref().map(|(_, hash, _)| *hash),
        );
        let content = Content {
            creator: creator.clone(),
            cause,
        };
        let (hash, signature) = compute_event_hash_and_signature(&content, creator);

        let creator = unwrap!(peer_list.get_index(creator));
        let cause = Cause::unpack_from_dot_input(
            content.cause,
            creator,
            recipient,
            self_parent.as_ref().map(|(event_index, _, _)| *event_index),
            other_parent
                .as_ref()
                .map(|(event_index, _, _)| *event_index),
            consensus_mode,
            observations,
        );
        let content = Content { creator, cause };

        let self_parent_info = self_parent
            .as_ref()
            .map(|(_, _, ref ancestor_info)| ancestor_info);
        let other_parent_info = other_parent
            .as_ref()
            .map(|(_, _, ref ancestor_info)| ancestor_info);

        let ancestor_info = compute_ancestor_info(
            content.creator,
            index_by_creator,
            self_parent_info,
            other_parent_info,
            peer_list,
        );

        let cache = Cache {
            hash,
            index_by_creator,
            ancestor_info,
            creator_initial: get_creator_initial(peer_list, creator),
        };

        Self {
            content,
            signature,
            cache,
        }
    }
}

#[derive(Debug)]
pub(crate) struct UnpackedEvent<T: NetworkEvent, P: PublicId> {
    pub event: Event<P>,
    pub observation_for_store: ObservationForStore<T, P>,
}

#[cfg(any(test, feature = "testing"))]
#[derive(Debug)]
pub(crate) enum CauseInput {
    Initial,
    Requesting(PeerId),
    Request,
    Response,
    Observation(Observation<Transaction, PeerId>),
    Malice(PeerId, MaliceInput),
}

// Properties of `Event` that can be computed from its `Content`.
struct Cache {
    // Hash of `Event`s `Content`.
    hash: EventHash,
    // Index of this event relative to other events by the same creator.
    index_by_creator: usize,
    // Info about events that are ancestors of this event keyed by their creators.
    ancestor_info: PeerIndexMap<AncestorInfo>,
    // First letter of the creator name.
    #[cfg(any(test, feature = "testing"))]
    creator_initial: char,
}

impl Cache {
    fn new<S: SecretId>(
        hash: EventHash,
        content: &Content<VoteKey<S::PublicId>, EventIndex, PeerIndex>,
        graph: &Graph<S::PublicId>,
        peer_list: &PeerList<S>,
    ) -> Self {
        let self_parent = get_event(graph, content.self_parent());
        let other_parent = get_event(graph, content.other_parent());

        let index_by_creator = compute_index_by_creator(self_parent);
        let ancestor_info = compute_ancestor_info(
            content.creator,
            index_by_creator,
            self_parent.map(|event| &event.cache.ancestor_info),
            other_parent.map(|event| &event.cache.ancestor_info),
            peer_list,
        );

        Self {
            hash,
            index_by_creator,
            ancestor_info,
            #[cfg(any(test, feature = "testing"))]
            creator_initial: get_creator_initial(peer_list, content.creator),
        }
    }
}

fn get_event<'a, P: PublicId>(
    graph: &'a Graph<P>,
    event_index: Option<&EventIndex>,
) -> Option<&'a Event<P>> {
    event_index
        .and_then(|index| graph.get(*index))
        .map(|event| event.inner())
}

fn compute_index_by_creator<P: PublicId>(self_parent: Option<&Event<P>>) -> usize {
    if let Some(self_parent) = self_parent {
        self_parent.index_by_creator() + 1
    } else {
        // Initial event
        0
    }
}

fn compute_event_hash_and_signature<T: NetworkEvent, S: SecretId>(
    content: &Content<Vote<T, S::PublicId>, EventHash, S::PublicId>,
    our_id: &S,
) -> (EventHash, <S::PublicId as PublicId>::Signature) {
    let serialised_content = serialise(&content);
    let hash = EventHash(Hash::from(serialised_content.as_slice()));
    let signature = our_id.sign_detached(&serialised_content);

    (hash, signature)
}

fn compute_event_hash_and_verify_signature<T: NetworkEvent, P: PublicId>(
    content: &Content<Vote<T, P>, EventHash, P>,
    signature: &P::Signature,
) -> Result<EventHash, Error> {
    let serialised_content = serialise(content);
    if content
        .creator
        .verify_signature(signature, &serialised_content)
    {
        Ok(EventHash(Hash::from(serialised_content.as_slice())))
    } else {
        Err(Error::SignatureFailure)
    }
}

#[cfg(any(test, feature = "testing"))]
fn get_creator_initial<S: SecretId>(peer_list: &PeerList<S>, creator: PeerIndex) -> char {
    peer_list
        .get(creator)
        .and_then(|peer| {
            let name = format!("{:?}", peer.id());
            name.chars().next().map(|c| c.to_ascii_uppercase())
        })
        .unwrap_or('?')
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct ShortName {
    creator_initial: char,
    index_by_creator: usize,
}

impl Display for ShortName {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}_{}", self.creator_initial, self.index_by_creator)
    }
}

impl Debug for ShortName {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "\"{}\"", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::Error,
        gossip::{
            cause::Cause,
            event::Event,
            event_context::EventContext,
            event_hash::EventHash,
            graph::{EventIndex, Graph},
        },
        id::SecretId,
        mock::{PeerId, Transaction},
        observation::Observation,
        peer_list::PeerState,
    };

    fn create_event_with_single_peer(id: &str) -> (EventContext, Event<PeerId>) {
        let context = EventContext::new(PeerId::new(id));
        let event = Event::new_initial(context.as_ref());

        (context, event)
    }

    fn insert_into_gossip_graph(
        initial_event: Event<PeerId>,
        graph: &mut Graph<PeerId>,
    ) -> (EventIndex, EventHash) {
        let hash = *initial_event.hash();
        assert!(!graph.contains(&hash));
        (graph.insert(initial_event).event_index(), hash)
    }

    fn create_two_events(
        id0: &str,
        id1: &str,
    ) -> (EventContext, Event<PeerId>, EventContext, Event<PeerId>) {
        let mut context0 = EventContext::new(PeerId::new(id0));
        let mut context1 = EventContext::new(PeerId::new(id1));

        let _ = context0.peer_list.add_peer(
            context1.peer_list.our_pub_id().clone(),
            PeerState::VOTE | PeerState::SEND | PeerState::RECV,
        );
        let _ = context1.peer_list.add_peer(
            context0.peer_list.our_pub_id().clone(),
            PeerState::VOTE | PeerState::SEND | PeerState::RECV,
        );

        let event0 = Event::new_initial(context0.as_ref());
        let event1 = Event::new_initial(context1.as_ref());

        (context0, event0, context1, event1)
    }

    fn convert_event(
        event: &Event<PeerId>,
        src: EventContextRef<Transaction, PeerId>,
        dst: EventContextRef<Transaction, PeerId>,
    ) -> Event<PeerId> {
        let e = unwrap!(event.pack(src));
        unwrap!(unwrap!(Event::unpack(e, dst))).event
    }

    #[test]
    fn event_construction_initial() {
        let initial = create_event_with_single_peer("Alice").1;
        assert!(initial.is_initial());
        assert!(!initial.is_response());
        assert!(initial.self_parent().is_none());
        assert!(initial.other_parent().is_none());
        assert_eq!(initial.index_by_creator(), 0);
    }

    #[test]
    fn event_construction_from_observation() {
        let (mut alice, a_0) = create_event_with_single_peer("Alice");
        let (initial_event_index, initial_event_hash) =
            insert_into_gossip_graph(a_0, &mut alice.graph);

        // Our observation
        let net_event = Observation::OpaquePayload(Transaction::new("event_observed_by_alice"));

        let (event_from_observation, observation_for_store) = unwrap!(Event::new_from_observation(
            initial_event_index,
            net_event.clone(),
            alice.as_ref(),
        ));

        let (key, observation_info) = unwrap!(observation_for_store);
        let _ = alice.observations.insert(key, observation_info);

        let packed_event_from_observation = unwrap!(event_from_observation.pack(alice.as_ref()));

        assert_eq!(
            packed_event_from_observation.content.creator,
            *alice.peer_list.our_id().public_id()
        );
        match &packed_event_from_observation.content.cause {
            Cause::Observation { self_parent, vote } => {
                assert_eq!(self_parent, &initial_event_hash);
                assert_eq!(*vote.payload(), net_event);
            }
            _ => panic!(
                "Expected Observation, got {:?}",
                event_from_observation.content.cause
            ),
        }
        assert_eq!(event_from_observation.index_by_creator(), 1);
        assert!(!event_from_observation.is_initial());
        assert!(!event_from_observation.is_response());
        assert_eq!(
            event_from_observation.self_parent(),
            Some(initial_event_index)
        );
        assert!(event_from_observation.other_parent().is_none());
    }

    #[test]
    #[cfg(feature = "testing")]
    fn event_construction_from_observation_with_phony_self_parent() {
        let alice = EventContext::new(PeerId::new("Alice"));
        let self_parent_index = EventIndex::PHONY;
        let net_event = Observation::OpaquePayload(Transaction::new("event_observed_by_alice"));

        match Event::new_from_observation(self_parent_index, net_event.clone(), alice.as_ref()) {
            Err(Error::UnknownSelfParent) => (),
            x => panic!("Unexpected {:?}", x),
        }
    }

    #[test]
    fn event_construction_from_request() {
        let (mut alice, a_0, bob, b_0) = create_two_events("Alice", "Bob");
        let b_0 = convert_event(&b_0, bob.as_ref(), alice.as_ref());
        let a_0_index = alice.graph.insert(a_0).event_index();
        let b_0_index = alice.graph.insert(b_0).event_index();

        // Alice receives request from Bob
        let event_from_request = unwrap!(Event::new_from_request(
            a_0_index,
            b_0_index,
            alice.as_ref()
        ));

        let packed_event_from_request = unwrap!(event_from_request.pack(alice.as_ref()));

        assert_eq!(
            packed_event_from_request.content.creator,
            *alice.peer_list.our_id().public_id()
        );
        assert_eq!(event_from_request.index_by_creator(), 1);
        assert!(!event_from_request.is_initial());
        assert!(!event_from_request.is_response());
        assert_eq!(event_from_request.self_parent(), Some(a_0_index));
        assert_eq!(event_from_request.other_parent(), Some(b_0_index));
    }

    #[test]
    #[cfg(feature = "testing")]
    fn event_construction_from_request_without_self_parent_event_in_graph() {
        let (mut alice, _, bob, b_0) = create_two_events("Alice", "Bob");
        let b_0 = convert_event(&b_0, bob.as_ref(), alice.as_ref());
        let b_0_index = alice.graph.insert(b_0).event_index();

        match Event::new_from_request(EventIndex::PHONY, b_0_index, alice.as_ref()) {
            Err(Error::UnknownSelfParent) => (),
            x => panic!("Unexpected {:?}", x),
        }
    }

    #[test]
    #[cfg(feature = "testing")]
    fn event_construction_from_request_without_other_parent_event_in_graph() {
        let (mut alice, a_0, _, _) = create_two_events("Alice", "Bob");
        let a_0_index = alice.graph.insert(a_0).event_index();

        match Event::new_from_request(a_0_index, EventIndex::PHONY, alice.as_ref()) {
            Err(Error::UnknownOtherParent) => (),
            x => panic!("Unexpected {:?}", x),
        }
    }

    #[test]
    fn event_construction_from_response() {
        let (mut alice, a_0, bob, b_0) = create_two_events("Alice", "Bob");
        let b_0 = convert_event(&b_0, bob.as_ref(), alice.as_ref());
        let a_0_index = alice.graph.insert(a_0).event_index();
        let b_0_index = alice.graph.insert(b_0).event_index();

        let event_from_response = unwrap!(Event::new_from_response(
            a_0_index,
            b_0_index,
            alice.as_ref()
        ));
        let packed_event_from_response = unwrap!(event_from_response.pack(alice.as_ref()));

        assert_eq!(
            packed_event_from_response.content.creator,
            *alice.peer_list.our_id().public_id()
        );
        assert_eq!(event_from_response.index_by_creator(), 1);
        assert!(!event_from_response.is_initial());
        assert!(event_from_response.is_response());
        assert_eq!(event_from_response.self_parent(), Some(a_0_index));
        assert_eq!(event_from_response.other_parent(), Some(b_0_index));
    }

    #[test]
    fn event_construction_unpack() {
        let (mut alice, a_0) = create_event_with_single_peer("Alice");
        let a_0_index = alice.graph.insert(a_0).event_index();

        // Our observation
        let net_event = Observation::OpaquePayload(Transaction::new("event_observed_by_alice"));

        let (event_from_observation, observation_for_store) = unwrap!(Event::new_from_observation(
            a_0_index,
            net_event,
            alice.as_ref()
        ));

        let (key, observation_info) = unwrap!(observation_for_store);
        let _ = alice.observations.insert(key, observation_info);

        let packed_event = unwrap!(event_from_observation.pack(alice.as_ref()));
        let unpacked_event =
            unwrap!(unwrap!(Event::unpack(packed_event.clone(), alice.as_ref()))).event;

        assert_eq!(event_from_observation, unpacked_event);
        assert!(!alice.graph.contains(unpacked_event.hash()));

        let _ = alice.graph.insert(unpacked_event);

        assert!(unwrap!(Event::unpack(packed_event, alice.as_ref())).is_none());
    }

    #[test]
    fn event_construction_unpack_fail_with_wrong_signature() {
        let (mut alice, a_0) = create_event_with_single_peer("Alice");
        let a_0_index = alice.graph.insert(a_0).event_index();

        // Our observation
        let net_event = Observation::OpaquePayload(Transaction::new("event_observed_by_alice"));

        let (event_from_observation, observation_for_store) = unwrap!(Event::new_from_observation(
            a_0_index,
            net_event,
            alice.as_ref()
        ));

        let (key, observation_info) = unwrap!(observation_for_store);
        let _ = alice.observations.insert(key, observation_info);

        let mut packed_event = unwrap!(event_from_observation.pack(alice.as_ref()));
        packed_event.signature = alice.peer_list.our_id().sign_detached(&[123]);

        let error = unwrap_err!(Event::unpack(packed_event, alice.as_ref()));
        if let Error::SignatureFailure = error {
        } else {
            panic!("Expected SignatureFailure, but got {:?}", error);
        }
    }
}

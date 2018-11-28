// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    cause::Cause,
    content::Content,
    event_hash::EventHash,
    graph::{EventIndex, Graph, IndexedEventRef},
    packed_event::PackedEvent,
};
use error::Error;
use hash::Hash;
use id::{PublicId, SecretId};
#[cfg(any(test, feature = "testing"))]
use mock::{PeerId, Transaction};
use network_event::NetworkEvent;
use observation::Observation;
use observation::ObservationHash;
use peer_list::PeerList;
use serialise;
use std::cmp;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
#[cfg(feature = "dump-graphs")]
use std::io::{self, Write};
use vote::Vote;

pub(crate) struct Event<T: NetworkEvent, P: PublicId> {
    content: Content<T, P>,
    // Creator's signature of `content`.
    signature: P::Signature,
    cache: Cache<P>,
}

impl<T: NetworkEvent, P: PublicId> Event<T, P> {
    // Creates a new event as the result of receiving a gossip request message.
    pub fn new_from_request<S: SecretId<PublicId = P>>(
        self_parent: EventHash,
        other_parent: EventHash,
        graph: &Graph<T, P>,
        peer_list: &PeerList<S>,
        forking_peers: &BTreeSet<S::PublicId>,
    ) -> Self {
        Self::new(
            Cause::Request {
                self_parent,
                other_parent,
            },
            graph,
            peer_list,
            forking_peers,
        )
    }

    // Creates a new event as the result of receiving a gossip response message.
    pub fn new_from_response<S: SecretId<PublicId = P>>(
        self_parent: EventHash,
        other_parent: EventHash,
        graph: &Graph<T, P>,
        peer_list: &PeerList<S>,
        forking_peers: &BTreeSet<S::PublicId>,
    ) -> Self {
        Self::new(
            Cause::Response {
                self_parent,
                other_parent,
            },
            graph,
            peer_list,
            forking_peers,
        )
    }

    // Creates a new event as the result of observing a network event.
    pub fn new_from_observation<S: SecretId<PublicId = P>>(
        self_parent: EventHash,
        observation: Observation<T, P>,
        graph: &Graph<T, P>,
        peer_list: &PeerList<S>,
    ) -> Self {
        let vote = Vote::new(peer_list.our_id(), observation);
        Self::new(
            Cause::Observation { self_parent, vote },
            graph,
            peer_list,
            &BTreeSet::new(),
        )
    }

    // Creates an initial event.  This is the first event by its creator in the graph.
    pub fn new_initial<S: SecretId<PublicId = P>>(peer_list: &PeerList<S>) -> Self {
        Self::new(Cause::Initial, &Graph::new(), peer_list, &BTreeSet::new())
    }

    // Creates an event from a `PackedEvent`.
    //
    // Returns:
    //   - `Ok(None)` if the event already exists
    //   - `Err(Error::SignatureFailure)` if signature validation fails
    //   - `Err(Error::UnknownParent)` if the event indicates it should have an ancestor, but the
    //     ancestor isn't in `events`.
    pub(crate) fn unpack<S: SecretId<PublicId = P>>(
        packed_event: PackedEvent<T, P>,
        graph: &Graph<T, P>,
        peer_list: &PeerList<S>,
        forking_peers: &BTreeSet<P>,
    ) -> Result<UnpackedEvent<T, P>, Error> {
        let hash = compute_event_hash_and_verify_signature(
            &packed_event.content,
            &packed_event.signature,
        )?;

        if let Some(index) = graph.get_index(&hash) {
            return Ok(UnpackedEvent::Known(index));
        }

        let (self_parent, other_parent) =
            get_parents(&packed_event.content, graph, peer_list.our_pub_id())?;
        let cache = Cache::new(
            hash,
            &packed_event.content,
            self_parent,
            other_parent,
            forking_peers,
            peer_list,
        );

        Ok(UnpackedEvent::New(Self {
            content: packed_event.content,
            signature: packed_event.signature,
            cache,
        }))
    }

    // Creates a `PackedEvent` from this `Event`.
    pub(crate) fn pack(&self) -> PackedEvent<T, P> {
        PackedEvent {
            content: self.content.clone(),
            signature: self.signature.clone(),
        }
    }

    // Returns whether this event can see `other`, i.e. whether there's a directed path from `other`
    // to `self` in the graph, and no two events created by `other`'s creator are ancestors to
    // `self` (fork).
    pub fn sees<E: AsRef<Event<T, P>>>(&self, other: E) -> bool {
        self.is_descendant_of(other).unwrap_or(false)
    }

    // Returns whether this event is descendant of `other`. If there are forks between this event
    // and `other` the answer cannot be determined from the events themselves and graph traversal
    // is required. `None` is returned in that case. Otherwise returns `Some` with the correct
    // answer.
    pub fn is_descendant_of<E: AsRef<Event<T, P>>>(&self, other: E) -> Option<bool> {
        match self.last_ancestor_by(other.as_ref().creator()) {
            LastAncestor::Some(last_index) => Some(last_index >= other.as_ref().index_by_creator()),
            LastAncestor::None => Some(false),
            LastAncestor::Fork => None,
        }
    }

    // Returns the index-by-creator of the last ancestor of this event created by the given peer.
    pub fn last_ancestor_by(&self, peer: &P) -> LastAncestor {
        if self.is_forking_peer(peer) {
            LastAncestor::Fork
        } else {
            self.cache
                .last_ancestors
                .get(peer)
                .map(|last_index| LastAncestor::Some(*last_index))
                .unwrap_or(LastAncestor::None)
        }
    }

    pub(crate) fn is_forking_peer(&self, peer: &P) -> bool {
        self.cache.forking_peers.contains(peer)
    }

    /// Returns `Some(vote)` if the event is for a vote of network event, otherwise returns `None`.
    pub fn vote(&self) -> Option<&Vote<T, P>> {
        if let Cause::Observation { ref vote, .. } = self.content.cause {
            Some(vote)
        } else {
            None
        }
    }

    pub fn payload(&self) -> Option<&Observation<T, P>> {
        self.vote().map(Vote::payload)
    }

    pub fn payload_hash(&self) -> Option<&ObservationHash> {
        self.vote().and_then(|_| self.cache.payload_hash.as_ref())
    }

    pub fn payload_with_hash(&self) -> Option<(&Observation<T, P>, &ObservationHash)> {
        self.vote().and_then(|vote| match self.cache.payload_hash {
            Some(ref hash) => Some((vote.payload(), hash)),
            None => {
                log_or_panic!("Event has payload but no payload hash: {:?}", self);
                None
            }
        })
    }

    pub fn creator(&self) -> &P {
        &self.content.creator
    }

    pub fn self_parent(&self) -> Option<EventIndex> {
        self.cache.self_parent
    }

    pub fn other_parent(&self) -> Option<EventIndex> {
        self.cache.other_parent
    }

    #[cfg(test)]
    pub fn self_parent_hash(&self) -> Option<&EventHash> {
        self.content.self_parent()
    }

    #[cfg(test)]
    pub fn other_parent_hash(&self) -> Option<&EventHash> {
        self.content.other_parent()
    }

    pub fn hash(&self) -> &EventHash {
        &self.cache.hash
    }

    // Index of this event relative to other events by the same creator.
    pub fn index_by_creator(&self) -> usize {
        self.cache.index_by_creator
    }

    pub fn last_ancestors(&self) -> &BTreeMap<P, usize> {
        &self.cache.last_ancestors
    }

    #[cfg(feature = "testing")]
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

    pub fn sees_fork(&self) -> bool {
        !self.cache.forking_peers.is_empty()
    }

    /// Returns the first char of the creator's ID, followed by an underscore and the event's index.
    pub fn short_name(&self) -> String {
        format!(
            "{:.1}_{}",
            format!("{:?}", self.content.creator),
            self.cache.index_by_creator
        )
    }

    fn new<S: SecretId<PublicId = P>>(
        cause: Cause<T, P>,
        graph: &Graph<T, P>,
        peer_list: &PeerList<S>,
        forking_peers: &BTreeSet<S::PublicId>,
    ) -> Self {
        let content = Content {
            creator: peer_list.our_id().public_id().clone(),
            cause,
        };

        let (hash, signature) = compute_event_hash_and_signature(&content, peer_list.our_id());
        let (self_parent, other_parent) = get_parents(&content, graph, peer_list.our_pub_id())
            .unwrap_or_else(|error| {
                log_or_panic!(
                    "{:?} constructed an invalid event: {:?}.",
                    peer_list.our_pub_id(),
                    error
                );
                (None, None)
            });
        let cache = Cache::new(
            hash,
            &content,
            self_parent,
            other_parent,
            forking_peers,
            peer_list,
        );

        Self {
            content,
            signature,
            cache,
        }
    }

    #[cfg(feature = "dump-graphs")]
    pub fn write_to_dot_format(&self, writer: &mut Write) -> io::Result<()> {
        writeln!(writer, "/// cause: {}", self.content.cause)?;
        writeln!(writer, "/// last_ancestors: {:?}", self.last_ancestors())
    }
}

impl<T: NetworkEvent, P: PublicId> PartialEq for Event<T, P> {
    fn eq(&self, other: &Self) -> bool {
        self.content == other.content && self.signature == other.signature
    }
}

impl<T: NetworkEvent, P: PublicId> Eq for Event<T, P> {}

impl<T: NetworkEvent, P: PublicId> Debug for Event<T, P> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Event{{ {} {:?}", self.short_name(), self.hash(),)?;
        write!(
            formatter,
            ", {}",
            match &self.content.cause {
                Cause::Request { .. } => "Request".to_string(),
                Cause::Response { .. } => "Response".to_string(),
                Cause::Observation { vote, .. } => format!("Observation({:?})", vote.payload()),
                Cause::Initial => "Initial".to_string(),
            }
        )?;
        write!(
            formatter,
            ", self_parent: {:?}, other_parent: {:?}",
            self.content.self_parent(),
            self.content.other_parent()
        )?;
        write!(
            formatter,
            ", last_ancestors: {:?}",
            self.cache.last_ancestors
        )?;
        write!(formatter, " }}")
    }
}

impl<T: NetworkEvent, P: PublicId> AsRef<Self> for Event<T, P> {
    fn as_ref(&self) -> &Self {
        self
    }
}

#[cfg(any(test, feature = "testing"))]
impl Event<Transaction, PeerId> {
    // Creates a new event using the input parameters directly.
    pub(crate) fn new_from_dot_input(
        creator: &PeerId,
        cause: CauseInput,
        self_parent: Option<(EventIndex, EventHash)>,
        other_parent: Option<(EventIndex, EventHash)>,
        index_by_creator: usize,
        last_ancestors: BTreeMap<PeerId, usize>,
    ) -> Self {
        let cause = Cause::new_from_dot_input(
            cause,
            creator,
            self_parent.map(|p| p.1),
            other_parent.map(|p| p.1),
        );
        let payload_hash = compute_payload_hash(&cause);
        let content = Content {
            creator: creator.clone(),
            cause,
        };
        let (hash, signature) = compute_event_hash_and_signature(&content, creator);
        let cache = Cache {
            hash,
            self_parent: self_parent.map(|p| p.0),
            other_parent: other_parent.map(|p| p.0),
            index_by_creator,
            last_ancestors,
            forking_peers: BTreeSet::new(),
            payload_hash,
        };

        Self {
            content,
            signature,
            cache,
        }
    }
}

#[derive(Debug)]
pub(crate) enum UnpackedEvent<T: NetworkEvent, P: PublicId> {
    // Event is already in our gossip graph
    Known(EventIndex),
    // Event is not yet in our gossip graph
    New(Event<T, P>),
}

pub(crate) enum LastAncestor {
    // There are no forks and the ancestor exists.
    Some(usize),
    // Ancestor doesn't exist.
    None,
    // Fork detected. Ancestor cannot be determined from the events only. Graph traversal required.
    Fork,
}

#[cfg(any(test, feature = "testing"))]
#[derive(Debug)]
pub(crate) enum CauseInput {
    Initial,
    Request,
    Response,
    Observation(Observation<Transaction, PeerId>),
}

// Properties of `Event` that can be computed from its `Content`.
struct Cache<P: PublicId> {
    // Hash of `Event`s `Content`.
    hash: EventHash,
    // Index of self-parent
    self_parent: Option<EventIndex>,
    // Index of other-parent
    other_parent: Option<EventIndex>,
    // Index of this event relative to other events by the same creator.
    index_by_creator: usize,
    // Index of each peer's latest event that is an ancestor of this event.
    last_ancestors: BTreeMap<P, usize>,
    // Peers with a fork having both sides seen by this event.
    forking_peers: BTreeSet<P>,
    // Hash of the payload
    payload_hash: Option<ObservationHash>,
}

impl<P: PublicId> Cache<P> {
    fn new<T: NetworkEvent, S: SecretId<PublicId = P>>(
        hash: EventHash,
        content: &Content<T, P>,
        self_parent: Option<IndexedEventRef<T, P>>,
        other_parent: Option<IndexedEventRef<T, P>>,
        forking_peers: &BTreeSet<P>,
        peer_list: &PeerList<S>,
    ) -> Self {
        let (index_by_creator, last_ancestors) = index_by_creator_and_last_ancestors(
            &content.creator,
            self_parent.map(|e| e.inner()),
            other_parent.map(|e| e.inner()),
            peer_list,
        );
        let forking_peers = join_forking_peers(
            self_parent.map(|e| e.inner()),
            other_parent.map(|e| e.inner()),
            forking_peers,
        );
        let payload_hash = compute_payload_hash(&content.cause);

        Self {
            hash,
            self_parent: self_parent.map(|e| e.event_index()),
            other_parent: other_parent.map(|e| e.event_index()),
            index_by_creator,
            last_ancestors,
            forking_peers,
            payload_hash,
        }
    }
}

type OptionalParents<'a, T, P> = (
    Option<IndexedEventRef<'a, T, P>>,
    Option<IndexedEventRef<'a, T, P>>,
);

fn get_parents<'a, T: NetworkEvent, P: PublicId>(
    content: &Content<T, P>,
    graph: &'a Graph<T, P>,
    our_id: &P,
) -> Result<OptionalParents<'a, T, P>, Error> {
    let self_parent = get_parent(Parent::Self_, content, graph, our_id)?;
    let other_parent = get_parent(Parent::Other, content, graph, our_id)?;
    Ok((self_parent, other_parent))
}

fn get_parent<'a, T: NetworkEvent, P: PublicId>(
    parent: Parent,
    content: &Content<T, P>,
    graph: &'a Graph<T, P>,
    our_id: &P,
) -> Result<Option<IndexedEventRef<'a, T, P>>, Error> {
    if let Some(hash) = parent.hash(content) {
        Ok(Some(
            graph
                .get_index(hash)
                .and_then(|index| graph.get(index))
                .ok_or_else(|| {
                    debug!("{:?} missing {} parent for {:?}", our_id, parent, content);
                    Error::UnknownParent
                })?,
        ))
    } else {
        Ok(None)
    }
}

#[derive(Clone, Copy)]
enum Parent {
    Self_, // `Self` is reserved.
    Other,
}

impl Parent {
    fn hash<'a, T: NetworkEvent, P: PublicId>(
        self,
        content: &'a Content<T, P>,
    ) -> Option<&'a EventHash> {
        match self {
            Parent::Self_ => content.self_parent(),
            Parent::Other => content.other_parent(),
        }
    }
}

impl fmt::Display for Parent {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Parent::Self_ => write!(formatter, "self"),
            Parent::Other => write!(formatter, "other"),
        }
    }
}

fn index_by_creator_and_last_ancestors<T: NetworkEvent, S: SecretId>(
    creator: &S::PublicId,
    self_parent: Option<&Event<T, S::PublicId>>,
    other_parent: Option<&Event<T, S::PublicId>>,
    peer_list: &PeerList<S>,
) -> (usize, BTreeMap<S::PublicId, usize>) {
    let (index_by_creator, mut last_ancestors) = if let Some(self_parent) = self_parent {
        (
            self_parent.index_by_creator() + 1,
            self_parent.last_ancestors().clone(),
        )
    } else {
        // Initial event
        (0, BTreeMap::new())
    };

    if let Some(other_parent) = other_parent {
        for (peer_id, _) in peer_list.iter() {
            if let Some(other_index) = other_parent.last_ancestors().get(peer_id) {
                let existing_index = last_ancestors
                    .entry(peer_id.clone())
                    .or_insert(*other_index);
                *existing_index = cmp::max(*existing_index, *other_index);
            }
        }
    }

    let _ = last_ancestors.insert(creator.clone(), index_by_creator);

    (index_by_creator, last_ancestors)
}

// An event's forking_peers list is a union inherited from its self_parent and other_parent.
// The event shall only put forking peer into the list when have direct path to both sides of
// the fork.
fn join_forking_peers<T: NetworkEvent, P: PublicId>(
    self_parent: Option<&Event<T, P>>,
    other_parent: Option<&Event<T, P>>,
    prev_forking_peers: &BTreeSet<P>,
) -> BTreeSet<P> {
    let mut forking_peers = BTreeSet::new();
    forking_peers.extend(
        self_parent
            .into_iter()
            .flat_map(|parent| parent.cache.forking_peers.iter().cloned()),
    );
    forking_peers.extend(
        other_parent
            .into_iter()
            .flat_map(|parent| parent.cache.forking_peers.iter().cloned()),
    );
    forking_peers.extend(prev_forking_peers.iter().cloned());
    forking_peers
}

fn compute_payload_hash<T: NetworkEvent, P: PublicId>(
    cause: &Cause<T, P>,
) -> Option<ObservationHash> {
    if let Cause::Observation { ref vote, .. } = cause {
        Some(ObservationHash::from(vote.payload()))
    } else {
        None
    }
}

fn compute_event_hash_and_signature<T: NetworkEvent, S: SecretId>(
    content: &Content<T, S::PublicId>,
    our_id: &S,
) -> (EventHash, <S::PublicId as PublicId>::Signature) {
    let serialised_content = serialise(&content);
    let hash = EventHash(Hash::from(serialised_content.as_slice()));
    let signature = our_id.sign_detached(&serialised_content);

    (hash, signature)
}

fn compute_event_hash_and_verify_signature<T: NetworkEvent, P: PublicId>(
    content: &Content<T, P>,
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

/// Finds the first event which has the `short_name` provided.
#[cfg(test)]
pub(crate) fn find_event_by_short_name<'a, I, T, P>(
    events: I,
    short_name: &str,
) -> Option<IndexedEventRef<'a, T, P>>
where
    I: IntoIterator<Item = IndexedEventRef<'a, T, P>>,
    T: NetworkEvent,
    P: PublicId,
{
    let short_name = short_name.to_uppercase();
    events
        .into_iter()
        .find(|event| event.short_name().to_uppercase() == short_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use error::Error;
    use gossip::{
        cause::Cause,
        event::Event,
        event_hash::EventHash,
        graph::{EventIndex, Graph},
    };
    use id::SecretId;
    use mock::{PeerId, Transaction};
    use observation::Observation;
    use peer_list::{PeerList, PeerState};
    use std::collections::BTreeSet;

    struct PeerListAndEvent {
        peer_list: PeerList<PeerId>,
        event: Event<Transaction, PeerId>,
    }

    impl PeerListAndEvent {
        fn new(peer_list: PeerList<PeerId>) -> Self {
            Self {
                event: Event::<Transaction, PeerId>::new_initial(&peer_list),
                peer_list,
            }
        }
    }

    fn create_peer_list(id: &str) -> (PeerId, PeerList<PeerId>) {
        let peer_id = PeerId::new(id);
        let peer_list = PeerList::<PeerId>::new(peer_id.clone());
        (peer_id, peer_list)
    }

    fn create_event_with_single_peer(id: &str) -> PeerListAndEvent {
        let (_, peer_list) = create_peer_list(id);
        PeerListAndEvent::new(peer_list)
    }

    fn insert_into_gossip_graph(
        initial_event: Event<Transaction, PeerId>,
        graph: &mut Graph<Transaction, PeerId>,
    ) -> (EventIndex, EventHash) {
        let hash = *initial_event.hash();
        assert!(!graph.contains(&hash));
        (graph.insert(initial_event).event_index(), hash)
    }

    fn create_two_events(id0: &str, id1: &str) -> (PeerListAndEvent, PeerListAndEvent) {
        let (peer_id0, mut peer_id0_list) = create_peer_list(id0);
        let (peer_id1, mut peer_id1_list) = create_peer_list(id1);
        peer_id0_list.add_peer(
            peer_id1,
            PeerState::VOTE | PeerState::SEND | PeerState::RECV,
        );
        peer_id1_list.add_peer(
            peer_id0,
            PeerState::VOTE | PeerState::SEND | PeerState::RECV,
        );

        (
            PeerListAndEvent::new(peer_id0_list),
            PeerListAndEvent::new(peer_id1_list),
        )
    }

    fn create_gossip_graph_with_two_events(
        alice_initial: Event<Transaction, PeerId>,
        bob_initial: Event<Transaction, PeerId>,
    ) -> (
        EventIndex,
        EventHash,
        EventIndex,
        EventHash,
        Graph<Transaction, PeerId>,
    ) {
        let mut graph = Graph::new();
        let (alice_index, alice_hash) = insert_into_gossip_graph(alice_initial, &mut graph);
        let (bob_index, bob_hash) = insert_into_gossip_graph(bob_initial, &mut graph);
        (alice_index, alice_hash, bob_index, bob_hash, graph)
    }

    #[test]
    fn event_construction_initial() {
        let initial = create_event_with_single_peer("Alice").event;
        assert!(initial.is_initial());
        assert!(!initial.is_response());
        assert!(initial.self_parent().is_none());
        assert!(initial.other_parent().is_none());
        assert_eq!(initial.index_by_creator(), 0);
    }

    #[test]
    fn event_construction_from_observation() {
        let alice = create_event_with_single_peer("Alice");
        let mut graph = Graph::new();
        let (initial_event_index, initial_event_hash) =
            insert_into_gossip_graph(alice.event, &mut graph);

        // Our observation
        let net_event = Observation::OpaquePayload(Transaction::new("event_observed_by_alice"));

        let event_from_observation = Event::<Transaction, PeerId>::new_from_observation(
            initial_event_hash,
            net_event.clone(),
            &graph,
            &alice.peer_list,
        );

        assert_eq!(
            event_from_observation.content.creator,
            *alice.peer_list.our_id().public_id()
        );
        match &event_from_observation.content.cause {
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
    #[should_panic(expected = "Alice constructed an invalid event")]
    #[cfg(feature = "testing")]
    fn event_construction_from_observation_with_phony_self_parent() {
        let alice = create_event_with_single_peer("Alice");
        let self_parent_hash = EventHash::ZERO;
        let events = Graph::new();
        let net_event = Observation::OpaquePayload(Transaction::new("event_observed_by_alice"));
        let _ = Event::<Transaction, PeerId>::new_from_observation(
            self_parent_hash,
            net_event.clone(),
            &events,
            &alice.peer_list,
        );
    }

    #[test]
    fn event_construction_from_request() {
        let (alice, bob) = create_two_events("Alice", "Bob");
        let (alice_initial_index, alice_initial_hash, bob_initial_index, bob_initial_hash, events) =
            create_gossip_graph_with_two_events(alice.event, bob.event);

        // Alice receives request from Bob
        let event_from_request = Event::<Transaction, PeerId>::new_from_request(
            alice_initial_hash,
            bob_initial_hash,
            &events,
            &alice.peer_list,
            &BTreeSet::new(),
        );

        assert_eq!(
            event_from_request.content.creator,
            *alice.peer_list.our_id().public_id()
        );
        assert_eq!(event_from_request.index_by_creator(), 1);
        assert!(!event_from_request.is_initial());
        assert!(!event_from_request.is_response());
        assert_eq!(event_from_request.self_parent(), Some(alice_initial_index));
        assert_eq!(event_from_request.other_parent(), Some(bob_initial_index));
    }

    #[test]
    #[should_panic(expected = "Alice constructed an invalid event")]
    #[cfg(feature = "testing")]
    fn event_construction_from_request_without_self_parent_event_in_graph() {
        let (alice, bob) = create_two_events("Alice", "Bob");
        let mut events = Graph::new();
        let alice_initial_hash = *alice.event.hash();
        let (_, bob_initial_hash) = insert_into_gossip_graph(bob.event, &mut events);
        let _ = Event::<Transaction, PeerId>::new_from_request(
            alice_initial_hash,
            bob_initial_hash,
            &events,
            &alice.peer_list,
            &BTreeSet::new(),
        );
    }

    #[test]
    #[should_panic(expected = "Alice constructed an invalid event")]
    #[cfg(feature = "testing")]
    fn event_construction_from_request_without_other_parent_event_in_graph() {
        let (alice, bob) = create_two_events("Alice", "Bob");
        let mut events = Graph::new();
        let (_, alice_initial_hash) = insert_into_gossip_graph(alice.event, &mut events);
        let bob_initial_hash = *bob.event.hash();
        let _ = Event::<Transaction, PeerId>::new_from_request(
            alice_initial_hash,
            bob_initial_hash,
            &events,
            &alice.peer_list,
            &BTreeSet::new(),
        );
    }

    #[test]
    fn event_construction_from_response() {
        let (alice, bob) = create_two_events("Alice", "Bob");
        let (alice_initial_index, alice_initial_hash, bob_initial_index, bob_initial_hash, events) =
            create_gossip_graph_with_two_events(alice.event, bob.event);

        let event_from_response = Event::<Transaction, PeerId>::new_from_response(
            alice_initial_hash,
            bob_initial_hash,
            &events,
            &alice.peer_list,
            &BTreeSet::new(),
        );

        assert_eq!(
            event_from_response.content.creator,
            *alice.peer_list.our_id().public_id()
        );
        assert_eq!(event_from_response.index_by_creator(), 1);
        assert!(!event_from_response.is_initial());
        assert!(event_from_response.is_response());
        assert_eq!(event_from_response.self_parent(), Some(alice_initial_index));
        assert_eq!(event_from_response.other_parent(), Some(bob_initial_index));
    }

    #[test]
    fn event_construction_unpack() {
        let alice = create_event_with_single_peer("Alice");
        let mut graph = Graph::new();
        let (_, initial_event_hash) = insert_into_gossip_graph(alice.event, &mut graph);

        // Our observation
        let net_event = Observation::OpaquePayload(Transaction::new("event_observed_by_alice"));

        let event_from_observation = Event::<Transaction, PeerId>::new_from_observation(
            initial_event_hash,
            net_event,
            &graph,
            &alice.peer_list,
        );

        let packed_event = event_from_observation.pack();
        let unpacked_event = match unwrap!(Event::unpack(
            packed_event.clone(),
            &graph,
            &alice.peer_list,
            &BTreeSet::new(),
        )) {
            UnpackedEvent::New(event) => event,
            UnpackedEvent::Known(_) => panic!("Unexpected known event"),
        };

        assert_eq!(event_from_observation, unpacked_event);
        assert!(!graph.contains(unpacked_event.hash()));

        let _ = graph.insert(unpacked_event);

        match unwrap!(Event::unpack(
            packed_event,
            &graph,
            &alice.peer_list,
            &BTreeSet::new()
        )) {
            UnpackedEvent::New(_) => panic!("Unexpected new event"),
            UnpackedEvent::Known(_) => (),
        }
    }

    #[test]
    fn event_construction_unpack_fail_with_wrong_signature() {
        let alice = create_event_with_single_peer("Alice");
        let mut graph = Graph::new();
        let (_, initial_event_hash) = insert_into_gossip_graph(alice.event, &mut graph);

        // Our observation
        let net_event = Observation::OpaquePayload(Transaction::new("event_observed_by_alice"));

        let event_from_observation = Event::<Transaction, PeerId>::new_from_observation(
            initial_event_hash,
            net_event,
            &graph,
            &alice.peer_list,
        );

        let mut packed_event = event_from_observation.pack();
        packed_event.signature = alice.peer_list.our_id().sign_detached(&[123]);

        let error = unwrap_err!(Event::<Transaction, PeerId>::unpack(
            packed_event,
            &graph,
            &alice.peer_list,
            &BTreeSet::new()
        ));
        if let Error::SignatureFailure = error {
        } else {
            panic!("Expected SignatureFailure, but got {:?}", error);
        }
    }
}

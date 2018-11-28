// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use block::Block;
use dev_utils::parse_test_dot_file;
use error::Error;
use gossip::{Event, Graph, GraphSnapshot};
use id::PublicId;
use meta_voting::MetaElectionsSnapshot;
use mock::{self, PeerId, Transaction};
use network_event::NetworkEvent;
use observation::Observation;
use parsec::TestParsec;
use peer_list::{MembershipListChange, PeerListSnapshot, PeerState};
use std::collections::BTreeSet;

macro_rules! assert_err {
    ($expected_error:pat, $result:expr) => {
        match $result {
            Err($expected_error) => (),
            unexpected => panic!(
                "Expected {}, but got {:?}",
                stringify!($expected_error),
                unexpected
            ),
        }
    };
}

macro_rules! btree_set {
    ($($item:expr),*) => {{
        let mut set = BTreeSet::new();
        $(
            let _ = set.insert($item);
        )*
        set
    }}
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    peer_list: PeerListSnapshot<PeerId>,
    events: GraphSnapshot,
    meta_elections: MetaElectionsSnapshot<PeerId>,
    consensused_blocks: Vec<Block<Transaction, PeerId>>,
}

impl Snapshot {
    fn new(parsec: &TestParsec<Transaction, PeerId>) -> Self {
        Snapshot {
            peer_list: PeerListSnapshot::new(parsec.peer_list(), parsec.graph()),
            events: GraphSnapshot::new(parsec.graph()),
            meta_elections: MetaElectionsSnapshot::new(parsec.meta_elections(), parsec.graph()),
            consensused_blocks: parsec.consensused_blocks().cloned().collect(),
        }
    }
}

fn nth_event<T: NetworkEvent, P: PublicId>(graph: &Graph<T, P>, n: usize) -> &Event<T, P> {
    unwrap!(graph.iter_from(n).next()).inner()
}

#[test]
fn from_existing() {
    let mut peers = mock::create_ids(10);
    let our_id = unwrap!(peers.pop());
    let peers = peers.into_iter().collect();

    let parsec = TestParsec::<Transaction, _>::from_existing(our_id.clone(), &peers, &peers);

    // Existing section + us
    assert_eq!(parsec.peer_list().all_ids().count(), peers.len() + 1);

    // Only the initial event should be in the gossip graph.
    assert_eq!(parsec.graph().len(), 1);
    let event = nth_event(parsec.graph(), 0);
    assert_eq!(*event.creator(), our_id);
    assert!(event.is_initial());
}

// TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
#[cfg(feature = "testing")]
#[test]
#[should_panic(expected = "Genesis group can't be empty")]
fn from_existing_requires_non_empty_genesis_group() {
    let mut peers = mock::create_ids(10);
    let our_id = unwrap!(peers.pop());
    let peers = peers.into_iter().collect();

    let _ = TestParsec::<Transaction, _>::from_existing(our_id, &BTreeSet::new(), &peers);
}

// TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
#[cfg(feature = "testing")]
#[test]
#[should_panic(expected = "Genesis group can't already contain us")]
fn from_existing_requires_that_genesis_group_does_not_contain_us() {
    let peers = mock::create_ids(10);
    let our_id = unwrap!(peers.first()).clone();
    let genesis_group = peers.iter().cloned().collect();
    let section = peers.into_iter().skip(1).collect();

    let _ = TestParsec::<Transaction, _>::from_existing(our_id, &genesis_group, &section);
}

// TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
#[cfg(feature = "testing")]
#[test]
#[should_panic(expected = "Section can't be empty")]
fn from_existing_requires_non_empty_section() {
    let mut peers = mock::create_ids(10);
    let our_id = unwrap!(peers.pop());
    let genesis_group = peers.into_iter().collect();

    let _ = TestParsec::<Transaction, _>::from_existing(our_id, &genesis_group, &BTreeSet::new());
}

// TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
#[cfg(feature = "testing")]
#[test]
#[should_panic(expected = "Section can't already contain us")]
fn from_existing_requires_that_section_does_not_contain_us() {
    let peers = mock::create_ids(10);
    let our_id = unwrap!(peers.first()).clone();
    let genesis_group = peers.iter().skip(1).cloned().collect();
    let section = peers.into_iter().collect();

    let _ = TestParsec::<Transaction, _>::from_existing(our_id, &genesis_group, &section);
}

#[test]
fn from_genesis() {
    let peers = mock::create_ids(10);
    let our_id = unwrap!(peers.first()).clone();
    let peers = peers.into_iter().collect();

    let parsec = TestParsec::<Transaction, _>::from_genesis(our_id.clone(), &peers);
    // the peer_list should contain the entire genesis group
    assert_eq!(parsec.peer_list().all_ids().count(), peers.len());
    // initial event + genesis_observation
    assert_eq!(parsec.graph().len(), 2);
    let initial_event = nth_event(parsec.graph(), 0);
    assert_eq!(*initial_event.creator(), our_id);
    assert!(initial_event.is_initial());
    let genesis_observation = nth_event(parsec.graph(), 1);
    assert_eq!(*genesis_observation.creator(), our_id);
    match &genesis_observation.vote() {
        Some(vote) => {
            assert_eq!(*vote.payload(), Observation::Genesis(peers));
        }
        None => panic!("Expected observation, but event carried no vote"),
    }
}

// TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
#[cfg(feature = "testing")]
#[test]
#[should_panic(expected = "Genesis group must contain us")]
fn from_genesis_requires_the_genesis_group_contains_us() {
    let mut peers = mock::create_ids(10);
    let our_id = unwrap!(peers.pop());
    let peers = peers.into_iter().collect();

    let _ = TestParsec::<Transaction, _>::from_genesis(our_id.clone(), &peers);
}

#[test]
fn from_parsed_contents() {
    let input_file = "0.dot";
    let parsed_contents = parse_test_dot_file(input_file);
    let parsed_contents_comparison = parse_test_dot_file(input_file);
    let parsec = TestParsec::from_parsed_contents(parsed_contents);
    assert_eq!(parsed_contents_comparison.graph, *parsec.graph());
    assert_eq!(
        parsed_contents_comparison.meta_elections,
        *parsec.meta_elections()
    );

    let parsed_contents_other = parse_test_dot_file("1.dot");
    assert_ne!(parsed_contents_other.graph, *parsec.graph());
    assert_ne!(
        parsed_contents_other.meta_elections,
        *parsec.meta_elections()
    );
}

#[test]
fn add_peer() {
    // Generated with RNG seed: [411278735, 3293288956, 208850454, 2872654992].
    let mut parsed_contents = parse_test_dot_file("alice.dot");

    // The final decision to add Fred is reached in D_18, so pop this event for now.
    let d_18 = unwrap!(parsed_contents.remove_last_event());

    let mut alice = TestParsec::from_parsed_contents(parsed_contents);
    let genesis_group: BTreeSet<_> = alice.peer_list().all_ids().cloned().collect();

    let alice_id = PeerId::new("Alice");
    let bob_id = PeerId::new("Bob");
    let carol_id = PeerId::new("Carol");
    let dave_id = PeerId::new("Dave");
    let eric_id = PeerId::new("Eric");
    let fred_id = PeerId::new("Fred");
    let event_index = 18;
    let mut alice_membership_list_for_dave = vec![
        (event_index, MembershipListChange::Add(alice_id.clone())),
        (event_index, MembershipListChange::Add(bob_id)),
        (event_index, MembershipListChange::Add(carol_id)),
        (event_index, MembershipListChange::Add(dave_id.clone())),
        (event_index, MembershipListChange::Add(eric_id)),
    ];
    assert!(
        !alice
            .peer_list()
            .all_ids()
            .any(|peer_id| *peer_id == fred_id)
    );
    assert_eq!(
        alice
            .peer_list()
            .peer_membership_list_changes(&dave_id)
            .to_vec(),
        alice_membership_list_for_dave
    );

    let alice_snapshot = Snapshot::new(&alice);

    // Try calling `create_gossip()` for a peer which doesn't exist yet.
    assert_err!(Error::InvalidPeerState { .. }, alice.create_gossip(Some(&fred_id)));
    assert_eq!(alice_snapshot, Snapshot::new(&alice));

    // Now add D_18, which should result in Alice adding Fred.
    unwrap!(alice.add_event(d_18));
    unwrap!(alice.create_sync_event(&PeerId::new("Eric"), true, &BTreeSet::new()));
    assert!(
        alice
            .peer_list()
            .all_ids()
            .any(|peer_id| *peer_id == fred_id)
    );
    alice_membership_list_for_dave.push((18, MembershipListChange::Add(fred_id.clone())));
    assert_eq!(
        alice
            .peer_list()
            .peer_membership_list_changes(&dave_id)
            .to_vec(),
        alice_membership_list_for_dave
    );

    // Construct Fred's Parsec instance.
    let mut fred = TestParsec::from_existing(fred_id, &genesis_group, &genesis_group);

    // Create a "naughty Carol" instance where the graph only shows four peers existing before
    // adding Fred.
    #[cfg(feature = "malice-detection")]
    {
        parsed_contents = parse_test_dot_file("carol.dot");
        let naughty_carol = TestParsec::from_parsed_contents(parsed_contents);
        let malicious_message = unwrap!(naughty_carol.create_gossip(None));
        assert_err!(
            Error::InvalidEvent,
            fred.handle_request(&alice_id, malicious_message)
        );
    }

    // Now pass a valid initial request from Alice to Fred.  The generated response would
    // normally only contain Fred's initial event, and the one recording receipt of Alice's
    // request.  However this graph doesn't represent the state it would be in if Alice were
    // actually sending such a request - it should have an event by Alice as the latest.  We
    // really only need to check here though that Fred doesn't respond with the full graph.
    let message = unwrap!(alice.create_gossip(None));
    let response = unwrap!(fred.handle_request(&alice_id, message));
    assert!(response.packed_events.len() < fred.graph().len());
}

#[test]
fn remove_peer() {
    // Generated with RNG seed: [3580486268, 2993583568, 344059332, 3173905166].
    let mut parsed_contents = parse_test_dot_file("alice.dot");

    // The final decision to remove Eric is reached in the last event of Alice.
    let a_last = unwrap!(parsed_contents.remove_last_event());

    let mut alice = TestParsec::from_parsed_contents(parsed_contents);
    let alice_id = PeerId::new("Alice");
    let eric_id = PeerId::new("Eric");
    let event_index = 0;
    let mut alice_membership_list_for_alice =
        vec![(event_index, MembershipListChange::Add(alice_id.clone()))];

    assert!(
        alice
            .peer_list()
            .all_ids()
            .any(|peer_id| *peer_id == eric_id)
    );
    assert_ne!(
        alice.peer_list().peer_state(&eric_id),
        PeerState::inactive()
    );
    assert_eq!(
        alice
            .peer_list()
            .peer_membership_list_changes(&alice_id)
            .to_vec(),
        alice_membership_list_for_alice
    );

    // Add event now which shall result in Alice removing Eric.
    unwrap!(alice.add_event(a_last));
    assert_eq!(
        alice.peer_list().peer_state(&eric_id),
        PeerState::inactive()
    );
    alice_membership_list_for_alice
        .push((event_index, MembershipListChange::Remove(eric_id.clone())));
    assert_eq!(
        alice
            .peer_list()
            .peer_membership_list_changes(&alice_id)
            .to_vec(),
        alice_membership_list_for_alice
    );

    // Try calling `create_gossip()` for Eric shall result in error.
    assert_err!(Error::InvalidPeerState { .. }, alice.create_gossip(Some(&eric_id)));

    // Construct Eric's parsec instance.
    let mut section: BTreeSet<_> = alice.peer_list().all_ids().cloned().collect();
    let _ = section.remove(&eric_id);
    let mut eric = TestParsec::<Transaction, _>::from_existing(eric_id.clone(), &section, &section);

    // Peer state is (VOTE | SEND) when created from existing. Need to update the states to
    // (VOTE | SEND | RECV).
    for peer_id in &section {
        eric.change_peer_state(peer_id, PeerState::RECV);
    }

    // Eric can no longer gossip to anyone.
    assert_err!(
            Error::InvalidSelfState { .. },
            eric.create_gossip(Some(&PeerId::new("Alice")))
        );
}

#[test]
fn unpolled_and_unconsensused_observations() {
    // Generated with RNG seed: [3016139397, 1416620722, 2110786801, 3768414447], but using
    // Alice-002.dot to get the dot file where we get consensus on `Add(Eric)`.
    let mut alice_contents = parse_test_dot_file("alice.dot");
    let a_17 = unwrap!(alice_contents.remove_last_event());

    let mut alice = TestParsec::from_parsed_contents(alice_contents);

    // `Add(Eric)` should still be unconsensused since A_17 would be the first gossip event to
    // reach consensus on `Add(Eric)`, but it was removed from the graph.
    assert!(alice.has_unconsensused_observations());

    // Since we haven't called `poll()` yet, our vote for `Add(Eric)` should be returned by
    // `our_unpolled_observations()`.
    let add_eric = Observation::Add {
        peer_id: PeerId::new("Eric"),
        related_info: vec![],
    };
    assert_eq!(alice.our_unpolled_observations().count(), 1);
    assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), add_eric);

    // Call `poll()` and retry - should have no effect to unconsensused and unpolled
    // observations.
    assert!(alice.poll().is_none());
    assert!(alice.has_unconsensused_observations());
    assert_eq!(alice.our_unpolled_observations().count(), 1);
    assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), add_eric);

    // Have Alice process A_17 to get consensus on `Add(Eric)`.
    unwrap!(alice.add_event(a_17));

    // Since we haven't call `poll()` again yet, should still return our vote for `Add(Eric)`.
    // However, `has_unconsensused_observations()` should now return false.
    assert!(!alice.has_unconsensused_observations());
    assert_eq!(alice.our_unpolled_observations().count(), 1);
    assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), add_eric);

    // Call `poll()` and retry - should return none.
    unwrap!(alice.poll());
    assert!(alice.poll().is_none());
    assert!(alice.our_unpolled_observations().next().is_none());

    // Vote for a new observation and check it is returned as unpolled, and that
    // `has_unconsensused_observations()` returns false again.
    let vote = Observation::OpaquePayload(Transaction::new("ABCD"));
    unwrap!(alice.vote_for(vote.clone()));

    assert!(alice.has_unconsensused_observations());
    assert_eq!(alice.our_unpolled_observations().count(), 1);
    assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), vote);

    // Reset, and re-run, this time adding Alice's vote early to check that it is returned in
    // the correct order, i.e. after `Add(Eric)` at the point where `Add(Eric)` is consensused
    // but has not been returned by `poll()`.
    alice = TestParsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
    unwrap!(alice.vote_for(vote.clone()));
    let mut unpolled_observations = alice.our_unpolled_observations();
    assert_eq!(*unwrap!(unpolled_observations.next()), add_eric);
    assert_eq!(*unwrap!(unpolled_observations.next()), vote);
    assert!(unpolled_observations.next().is_none());
}

#[test]
fn gossip_after_fork() {
    let alice_id = PeerId::new("Alice");
    let bob_id = PeerId::new("Bob");

    let genesis_group = btree_set![
        alice_id.clone(),
        bob_id.clone(),
        PeerId::new("Carol"),
        PeerId::new("Dave")
    ];

    let mut alice = TestParsec::from_genesis(alice_id.clone(), &genesis_group);

    // Alice creates couple of valid events.
    let a_1_index = unwrap!(alice.peer_list().our_events().next());
    let a_1_hash = *unwrap!(alice.graph().get(a_1_index)).hash();

    let a_2 = Event::new_from_observation(
        a_1_hash,
        Observation::OpaquePayload(Transaction::new("one")),
        alice.graph(),
        alice.peer_list(),
    );
    let a_2_hash = *a_2.hash();
    unwrap!(alice.add_event(a_2));

    let a_3 = Event::new_from_observation(
        a_2_hash,
        Observation::OpaquePayload(Transaction::new("two")),
        alice.graph(),
        alice.peer_list(),
    );
    let a_3_hash = *a_3.hash();
    unwrap!(alice.add_event(a_3));

    let mut bob = TestParsec::from_genesis(bob_id.clone(), &genesis_group);

    // Alice sends a gossip request to Bob and receives a response back.
    let req = unwrap!(alice.create_gossip(Some(&bob_id)));
    let res = unwrap!(bob.handle_request(&alice_id, req));
    unwrap!(alice.handle_response(&bob_id, res));

    // Now Bob has a_0, a_1, a_2 and a_3 and Alice knows it.
    assert!(bob.graph().contains(&a_1_hash));
    assert!(bob.graph().contains(&a_2_hash));
    assert!(bob.graph().contains(&a_3_hash));

    // Alice creates a fork.
    let a_2_fork = Event::new_from_observation(
        a_1_hash,
        Observation::OpaquePayload(Transaction::new("two-fork")),
        alice.graph(),
        alice.peer_list(),
    );
    let a_2_fork_hash = *a_2_fork.hash();
    unwrap!(alice.add_event(a_2_fork));

    // Alice sends another gossip request to Bob.
    let req = unwrap!(alice.create_gossip(Some(&bob_id)));
    let _ = unwrap!(bob.handle_request(&alice_id, req));

    // Verify that Bob now has the forked event.
    assert!(bob.graph().contains(&a_2_fork_hash));
}

#[cfg(feature = "malice-detection")]
mod handle_malice {
    use super::*;
    use dev_utils::{parse_dot_file_with_test_name, parse_test_dot_file, ParsedContents};
    use gossip::{find_event_by_short_name, Event, EventHash};
    use id::SecretId;
    use mock::Transaction;
    use observation::Malice;
    use observation::UnprovableMalice;
    use peer_list::PeerList;
    use peer_list::PeerState;
    use std::collections::BTreeMap;

    // Returns iterator over all votes cast by the given node.
    fn our_votes<T: NetworkEvent, S: SecretId>(
        parsec: &TestParsec<T, S>,
    ) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        parsec
            .peer_list()
            .our_events()
            .filter_map(move |index| parsec.graph().get(index))
            .filter_map(|event| event.inner().vote())
            .map(|vote| vote.payload())
    }

    // Add the peers to the `PeerList` as the genesis group.
    fn add_genesis_group<S: SecretId>(
        peer_list: &mut PeerList<S>,
        genesis: &BTreeSet<S::PublicId>,
    ) {
        for peer_id in genesis {
            if peer_list.has_peer(peer_id) {
                continue;
            }

            peer_list.add_peer(peer_id.clone(), PeerState::active());
            peer_list.initialise_peer_membership_list(peer_id, genesis.iter().cloned());
        }
    }

    #[test]
    fn genesis_event_not_after_initial() {
        // Generated with RNG seed: [926181213, 2524489310, 392196615, 406869071].
        let alice_contents = parse_test_dot_file("alice.dot");
        let alice_id = alice_contents.peer_list.our_id().clone();
        let genesis: BTreeSet<_> = alice_contents.peer_list.all_ids().cloned().collect();
        let mut alice = TestParsec::from_parsed_contents(alice_contents);

        // Simulate Dave creating unexpected genesis.
        let dave_id = PeerId::new("Dave");
        let mut dave_contents = ParsedContents::new(dave_id.clone());

        dave_contents
            .peer_list
            .add_peer(dave_id.clone(), PeerState::active());
        add_genesis_group(&mut dave_contents.peer_list, &genesis);

        let d_0 = Event::<Transaction, _>::new_initial(&dave_contents.peer_list);
        let d_0_hash = *d_0.hash();
        dave_contents.add_event(d_0);

        let d_1 = Event::<Transaction, _>::new_from_observation(
            d_0_hash,
            Observation::OpaquePayload(Transaction::new("dave's malicious vote")),
            &dave_contents.graph,
            &dave_contents.peer_list,
        );
        let d_1_hash = *d_1.hash();
        dave_contents.add_event(d_1);

        let d_2 = Event::<Transaction, _>::new_from_observation(
            d_1_hash,
            Observation::Genesis(genesis),
            &dave_contents.graph,
            &dave_contents.peer_list,
        );
        let d_2_hash = *d_2.hash();
        dave_contents.add_event(d_2);

        let dave = TestParsec::from_parsed_contents(dave_contents);

        // Dave sends malicious gossip to Alice.
        let request = unwrap!(dave.create_gossip(Some(&alice_id)));
        unwrap!(alice.handle_request(&dave_id, request));

        // Verify that Alice detected the malice and accused Dave.
        let (offender, hash) = unwrap!(
            our_votes(&alice)
                .filter_map(|payload| match *payload {
                    Observation::Accusation {
                        ref offender,
                        malice: Malice::UnexpectedGenesis(hash),
                    } => Some((offender.clone(), hash)),
                    _ => None,
                }).next()
        );

        assert_eq!(offender, dave_id);
        assert_eq!(hash, d_2_hash);
    }

    #[test]
    fn genesis_event_creator_not_genesis_member() {
        // Generated with RNG seed: [848911612, 2362592349, 3178199135, 2458552022].
        let alice_contents = parse_test_dot_file("alice.dot");
        let alice_id = alice_contents.peer_list.our_id().clone();
        let genesis: BTreeSet<_> = alice_contents.peer_list.all_ids().cloned().collect();

        let mut alice = TestParsec::from_parsed_contents(alice_contents);

        // This is needed so the AddPeer(Eric) is consensused.
        unwrap!(alice.restart_consensus());

        // Simulate Eric creating unexpected genesis.
        let eric_id = PeerId::new("Eric");
        let mut eric_contents = ParsedContents::new(eric_id.clone());

        eric_contents
            .peer_list
            .add_peer(eric_id.clone(), PeerState::active());
        add_genesis_group(&mut eric_contents.peer_list, &genesis);

        let e_0 = Event::<Transaction, _>::new_initial(&eric_contents.peer_list);
        let e_0_hash = *e_0.hash();
        eric_contents.add_event(e_0);

        let e_1 = Event::<Transaction, _>::new_from_observation(
            e_0_hash,
            Observation::Genesis(genesis),
            &eric_contents.graph,
            &eric_contents.peer_list,
        );
        let e_1_hash = *e_1.hash();
        eric_contents.add_event(e_1);

        let eric = TestParsec::from_parsed_contents(eric_contents);

        // Eric sends malicious gossip to Alice.
        let request = unwrap!(eric.create_gossip(Some(&alice_id)));
        unwrap!(alice.handle_request(&eric_id, request));

        // Verify that Alice detected the malice and accused Eric.
        let (offender, hash) = unwrap!(
            our_votes(&alice)
                .filter_map(|payload| match *payload {
                    Observation::Accusation {
                        ref offender,
                        malice: Malice::UnexpectedGenesis(hash),
                    } => Some((offender.clone(), hash)),
                    _ => None,
                }).next()
        );

        assert_eq!(offender, eric_id);
        assert_eq!(hash, e_1_hash);
    }

    fn initialise_parsed_contents(
        id: PeerId,
        genesis: &BTreeSet<PeerId>,
        second_event: Option<Observation<Transaction, PeerId>>,
    ) -> ParsedContents {
        let mut result = ParsedContents::new(id);
        add_genesis_group(&mut result.peer_list, genesis);

        let ev_0 = Event::<Transaction, _>::new_initial(&result.peer_list);
        let ev_0_hash = *ev_0.hash();
        result.add_event(ev_0);
        let ev_1 = if let Some(obs_1) = second_event {
            Event::<Transaction, _>::new_from_observation(
                ev_0_hash,
                obs_1,
                &result.graph,
                &result.peer_list,
            )
        } else {
            Event::<Transaction, _>::new_from_observation(
                ev_0_hash,
                Observation::Genesis(genesis.clone()),
                &result.graph,
                &result.peer_list,
            )
        };

        result.add_event(ev_1);
        result
    }

    fn initialise_parsec(
        id: PeerId,
        genesis: &BTreeSet<PeerId>,
        second_event: Option<Observation<Transaction, PeerId>>,
    ) -> TestParsec<Transaction, PeerId> {
        let contents = initialise_parsed_contents(id, genesis, second_event);
        TestParsec::from_parsed_contents(contents)
    }

    #[test]
    fn missing_genesis_event() {
        let alice_id = PeerId::new("Alice");
        let dave_id = PeerId::new("Dave");

        let genesis = btree_set![alice_id.clone(), dave_id.clone()];

        // Create Alice where the first event is not a genesis event (malice)
        let alice = initialise_parsec(
            alice_id.clone(),
            &genesis,
            Some(Observation::OpaquePayload(Transaction::new("Foo"))),
        );
        let a_0_hash = *nth_event(alice.graph(), 0).hash();
        let a_1_hash = *nth_event(alice.graph(), 1).hash();

        // Create Dave where the first event is a genesis event containing both Alice and Dave.
        let mut dave = initialise_parsec(dave_id.clone(), &genesis, None);
        assert!(!dave.graph().contains(&a_0_hash));
        assert!(!dave.graph().contains(&a_1_hash));

        // Send gossip from Alice to Dave.
        let message = unwrap!(alice.create_gossip(Some(&dave_id)));
        unwrap!(dave.handle_request(&alice_id, message));
        assert!(dave.graph().contains(&a_0_hash));
        assert!(dave.graph().contains(&a_1_hash));

        // Verify that Dave detected and accused Alice for malice.
        let (offender, hash) = unwrap!(
            our_votes(&dave)
                .filter_map(|payload| match payload {
                    Observation::Accusation {
                        ref offender,
                        malice: Malice::MissingGenesis(hash),
                    } => Some((offender, hash)),
                    _ => None,
                }).next()
        );
        assert_eq!(*offender, alice_id);
        assert_eq!(*hash, a_1_hash);
    }

    #[test]
    fn incorrect_genesis_event() {
        let alice_id = PeerId::new("Alice");
        let dave_id = PeerId::new("Dave");

        let genesis = btree_set![alice_id.clone(), dave_id.clone()];
        let false_genesis = btree_set![alice_id.clone(), PeerId::new("Derp")];

        // Create Alice where the first event is an incorrect genesis event (malice)
        let alice = initialise_parsec(
            alice_id.clone(),
            &genesis,
            Some(Observation::Genesis(false_genesis)),
        );
        let a_0_hash = *nth_event(alice.graph(), 0).hash();
        let a_1_hash = *nth_event(alice.graph(), 1).hash();

        // Create Dave where the first event is a genesis event containing both Alice and Dave.
        let mut dave = initialise_parsec(dave_id.clone(), &genesis, None);
        assert!(!dave.graph().contains(&a_0_hash));
        assert!(!dave.graph().contains(&a_1_hash));

        // Send gossip from Alice to Dave.
        let message = unwrap!(alice.create_gossip(Some(&dave_id)));
        // Alice's genesis should be rejected as invalid
        assert_err!(Error::InvalidEvent, dave.handle_request(&alice_id, message));
        assert!(dave.graph().contains(&a_0_hash));
        // Dave's events shouldn't contain Alice's genesis because of the rejection
        assert!(!dave.graph().contains(&a_1_hash));

        // Verify that Dave detected and accused Alice for malice.
        let (offender, hash) = unwrap!(
            our_votes(&dave)
                .filter_map(|payload| match payload {
                    Observation::Accusation {
                        ref offender,
                        malice: Malice::IncorrectGenesis(hash),
                    } => Some((offender, hash)),
                    _ => None,
                }).next()
        );
        assert_eq!(*offender, alice_id);
        assert_eq!(*hash, a_1_hash);
    }

    #[test]
    fn duplicate_votes() {
        // Generated with RNG seed: [1353978636, 426502568, 2862743769, 1583787884].
        //
        // Carol has already voted for "ABCD".  Create two new duplicate votes by Carol for this
        // opaque payload.
        let mut carol = TestParsec::from_parsed_contents(parse_test_dot_file("carol.dot"));
        let first_duplicate = Event::new_from_observation(
            carol.our_last_event_hash(),
            Observation::OpaquePayload(Transaction::new("ABCD")),
            carol.graph(),
            carol.peer_list(),
        );
        let first_duplicate_clone = Event::new_from_observation(
            carol.our_last_event_hash(),
            Observation::OpaquePayload(Transaction::new("ABCD")),
            carol.graph(),
            carol.peer_list(),
        );
        let first_duplicate_hash = *first_duplicate.hash();
        unwrap!(carol.add_event(first_duplicate));
        let second_duplicate = Event::new_from_observation(
            first_duplicate_hash,
            Observation::OpaquePayload(Transaction::new("ABCD")),
            carol.graph(),
            carol.peer_list(),
        );

        // Check that the first duplicate triggers an accusation by Alice, but that the
        // duplicate is still added to the graph.
        let mut alice = TestParsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
        let carols_valid_vote_hash =
            *unwrap!(find_event_by_short_name(alice.graph(), "C_4")).hash();
        unwrap!(alice.add_event(first_duplicate_clone));
        let expected_accusations = vec![(
            carol.our_pub_id().clone(),
            Malice::DuplicateVote(carols_valid_vote_hash, first_duplicate_hash),
        )];
        assert_eq!(*alice.pending_accusations(), expected_accusations);
        assert!(alice.graph().contains(&first_duplicate_hash));

        // Check that the second one doesn't trigger any further accusation, but is also added
        // to the graph.
        let second_duplicate_hash = *second_duplicate.hash();
        unwrap!(alice.add_event(second_duplicate));
        assert_eq!(*alice.pending_accusations(), expected_accusations);
        assert!(alice.graph().contains(&second_duplicate_hash));
    }

    #[test]
    fn stale_other_parent() {
        // Generated with RNG seed: [856368386, 135728199, 764559083, 3829746197].
        //
        // Carol will create event C_4 with other-parent as B_1, despite having C_3 with other-
        // parent as B_2.
        let carol = TestParsec::from_parsed_contents(parse_test_dot_file("carol.dot"));
        let c_3_hash = *unwrap!(find_event_by_short_name(carol.graph(), "C_3")).hash();
        let b_1_hash = *unwrap!(find_event_by_short_name(carol.graph(), "B_1")).hash();

        let c_4 = Event::new_from_request(
            c_3_hash,
            b_1_hash,
            carol.graph(),
            carol.peer_list(),
            &BTreeSet::new(),
        );
        let c_4_hash = *c_4.hash();

        // Check that adding C_4 triggers an accusation by Alice, but that C_4 is still added
        // to the graph.
        let mut alice = TestParsec::from_parsed_contents(parse_test_dot_file("alice.dot"));

        let expected_accusations = vec![(
            carol.our_pub_id().clone(),
            Malice::StaleOtherParent(c_4_hash),
        )];
        unwrap!(alice.add_event(c_4));
        assert_eq!(*alice.pending_accusations(), expected_accusations);
        assert!(alice.graph().contains(&c_4_hash));
    }

    #[test]
    fn invalid_accusation() {
        // Generated with RNG seed: [935566334, 935694090, 88607029, 861330491].
        let mut alice_contents = parse_test_dot_file("alice.dot");

        let a_4_hash = *unwrap!(find_event_by_short_name(&alice_contents.graph, "A_4")).hash();
        let d_1_hash = *unwrap!(find_event_by_short_name(&alice_contents.graph, "D_1")).hash();

        // Create an invalid accusation from Alice
        let a_5 = Event::<Transaction, _>::new_from_observation(
            a_4_hash,
            Observation::Accusation {
                offender: PeerId::new("Dave"),
                malice: Malice::Fork(d_1_hash),
            },
            &alice_contents.graph,
            &alice_contents.peer_list,
        );
        let a_5_hash = *a_5.hash();
        alice_contents.add_event(a_5);
        let alice = TestParsec::from_parsed_contents(alice_contents);
        assert!(alice.graph().contains(&a_5_hash));

        let mut carol = TestParsec::from_parsed_contents(parse_test_dot_file("carol.dot"));
        assert!(!carol.graph().contains(&a_5_hash));

        // Send gossip from Alice to Carol
        let message = unwrap!(alice.create_gossip(Some(carol.our_pub_id())));

        unwrap!(carol.handle_request(alice.our_pub_id(), message));
        assert!(carol.graph().contains(&a_5_hash));

        // Verify that Carol detected malice and accused Alice of it.
        let (offender, hash) = unwrap!(
            our_votes(&carol)
                .filter_map(|payload| match payload {
                    Observation::Accusation {
                        ref offender,
                        malice: Malice::InvalidAccusation(hash),
                    } => Some((offender, hash)),
                    _ => None,
                }).next()
        );
        assert_eq!(offender, alice.our_pub_id());
        assert_eq!(*hash, a_5_hash);
    }

    #[test]
    fn invalid_gossip_creator() {
        // Generated with RNG seed: [753134140, 4096687351, 2912528994, 2847063513].
        //
        // Alice reports gossip to Bob from Carol that isn't in their section.
        let alice = TestParsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
        let mut bob = TestParsec::from_parsed_contents(parse_test_dot_file("bob.dot"));

        // Verify peer lists
        let alice_id = PeerId::new("Alice");
        let bob_id = PeerId::new("Bob");
        let mut alice_peer_list = PeerList::new(alice_id.clone());
        alice_peer_list.add_peer(alice_id.clone(), PeerState::active());
        alice_peer_list.add_peer(bob_id.clone(), PeerState::active());
        assert_eq!(
            alice.peer_list().peer_id_hashes().collect::<Vec<_>>(),
            alice_peer_list.peer_id_hashes().collect::<Vec<_>>()
        );
        let mut bob_peer_list = PeerList::new(bob_id.clone());
        bob_peer_list.add_peer(alice_id.clone(), PeerState::active());
        bob_peer_list.add_peer(bob_id.clone(), PeerState::active());
        assert_eq!(
            bob.peer_list().peer_id_hashes().collect::<Vec<_>>(),
            bob_peer_list.peer_id_hashes().collect::<Vec<_>>()
        );

        // Read the dot file again so we have a set of events we can manually add to Bob instead
        // of sending gossip.
        let alice_parsed_contents = parse_test_dot_file("alice.dot");

        let c_0_index = unwrap!(find_event_by_short_name(
            &alice_parsed_contents.graph,
            "C_0"
        )).event_index();

        let (a_2_index, a_2_hash) = {
            let ie = unwrap!(find_event_by_short_name(
                &alice_parsed_contents.graph,
                "A_2"
            ));
            (ie.event_index(), *ie.hash())
        };

        let b_2_index = unwrap!(find_event_by_short_name(
            &alice_parsed_contents.graph,
            "B_2"
        )).event_index();

        // Carol is marked as active peer so that Bob's peer_list will accept C_0, but Carol is
        // not part of the membership_list
        let carol_id = PeerId::new("Carol");
        bob.add_peer(carol_id, PeerState::active());

        let mut alice_events: BTreeMap<_, _> = alice_parsed_contents.graph.into_iter().collect();

        let c_0 = unwrap!(alice_events.remove(&c_0_index));
        unwrap!(bob.add_event(c_0));

        // This malice is setup in two events.
        // A_2 has C_0 from Carol as other parent as Carol has gossiped to Alice. Carol is
        // however not part of the section and Alice should not have accepted it.
        let a_2 = unwrap!(alice_events.remove(&a_2_index));
        unwrap!(bob.add_event(a_2));

        // B_2 is the sync event created by Bob when he receives A_2 from Alice.
        let b_2 = unwrap!(alice_events.remove(&b_2_index));
        unwrap!(bob.add_event(b_2));

        // Bob should now have seen that Alice in A_2 incorrectly reported gossip from Carol.
        // Check that this triggers an accusation
        let expected_accusations = (
            alice.our_pub_id().clone(),
            Malice::InvalidGossipCreator(a_2_hash),
        );

        assert!(bob.pending_accusations().contains(&expected_accusations));
        assert!(bob.graph().contains(&a_2_hash));
    }

    fn create_invalid_accusation() -> (EventHash, TestParsec<Transaction, PeerId>) {
        // Generated with RNG seed: [3932887254, 691979681, 2029125979, 3359276664]
        let mut alice_contents =
            parse_dot_file_with_test_name("alice.dot", "functional_tests_handle_malice_accomplice");

        let a_26_hash = *unwrap!(find_event_by_short_name(&alice_contents.graph, "A_26")).hash();
        let d_1_hash = *unwrap!(find_event_by_short_name(&alice_contents.graph, "D_1")).hash();

        // Create an invalid accusation from Alice
        let a_27 = Event::<Transaction, _>::new_from_observation(
            a_26_hash,
            Observation::Accusation {
                offender: PeerId::new("Dave"),
                malice: Malice::Fork(d_1_hash),
            },
            &alice_contents.graph,
            &alice_contents.peer_list,
        );
        let a_27_hash = *a_27.hash();
        alice_contents.add_event(a_27);
        let alice = TestParsec::from_parsed_contents(alice_contents);
        assert!(alice.graph().contains(&a_27_hash));
        (a_27_hash, alice)
    }

    fn verify_accused_accomplice(
        accuser: &TestParsec<Transaction, PeerId>,
        suspect: &PeerId,
        event_hash: &EventHash,
    ) {
        let (offender, hash) = unwrap!(
            our_votes(accuser)
                .filter_map(|payload| match payload {
                    Observation::Accusation {
                        ref offender,
                        malice: Malice::Unprovable(UnprovableMalice::Accomplice(hash)),
                    } => Some((offender, hash)),
                    _ => None,
                }).next()
        );
        assert_eq!(offender, suspect);
        assert_eq!(hash, event_hash);
    }

    #[test]
    // Carol received gossip from Bob, which should have raised an accomplice accusation against
    // Alice but didn't.
    fn accomplice() {
        let (invalid_accusation, alice) = create_invalid_accusation();

        let mut bob = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "bob.dot",
            "functional_tests_handle_malice_accomplice",
        ));
        assert!(!bob.graph().contains(&invalid_accusation));

        // Send gossip from Alice to Bob
        let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Bob"))));
        unwrap!(bob.handle_request(alice.our_pub_id(), message));
        assert!(bob.graph().contains(&invalid_accusation));

        let mut carol = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "carol.dot",
            "functional_tests_handle_malice_accomplice",
        ));
        assert!(!carol.graph().contains(&invalid_accusation));

        // Send gossip from Bob to Carol, remove the accusation event
        let mut message = unwrap!(bob.create_gossip(Some(&PeerId::new("Carol"))));
        let accusation_event = unwrap!(message.packed_events.pop());
        let bob_last_hash = unwrap!(accusation_event.self_parent());
        unwrap!(carol.handle_request(bob.our_pub_id(), message));
        assert!(carol.graph().contains(&invalid_accusation));

        // Verify that Carol detected malice and accused Alice of `InvalidAccusation` and Bob of
        // `Accomplice`.
        let (offender, hash) = unwrap!(
            our_votes(&carol)
                .filter_map(|payload| match payload {
                    Observation::Accusation {
                        ref offender,
                        malice: Malice::InvalidAccusation(hash),
                    } => Some((offender, hash)),
                    _ => None,
                }).next()
        );
        assert_eq!(offender, alice.our_pub_id());
        assert_eq!(*hash, invalid_accusation);

        verify_accused_accomplice(&carol, bob.our_pub_id(), bob_last_hash);
    }

    #[test]
    // Carol received `invalid_accusation` from Alice first, then received gossip from Bob,
    // which should have raised an accomplice accusation against Alice but didn't.
    fn accomplice_separate() {
        let (invalid_accusation, alice) = create_invalid_accusation();

        let mut carol = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "carol.dot",
            "functional_tests_handle_malice_accomplice",
        ));
        assert!(!carol.graph().contains(&invalid_accusation));

        // Send gossip from Alice to Carol
        let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Carol"))));
        unwrap!(carol.handle_request(alice.our_pub_id(), message));
        assert!(carol.graph().contains(&invalid_accusation));

        let mut bob = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "bob.dot",
            "functional_tests_handle_malice_accomplice",
        ));
        assert!(!bob.graph().contains(&invalid_accusation));

        // Send gossip from Alice to Bob
        let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Bob"))));
        unwrap!(bob.handle_request(alice.our_pub_id(), message));
        assert!(bob.graph().contains(&invalid_accusation));

        // Send gossip from Bob to Carol, remove the accusation event
        let mut message = unwrap!(bob.create_gossip(Some(&PeerId::new("Carol"))));
        let accusation_event = unwrap!(message.packed_events.pop());
        let bob_last_hash = unwrap!(accusation_event.self_parent());
        unwrap!(carol.handle_request(bob.our_pub_id(), message));
        assert!(carol.graph().contains(&invalid_accusation));

        // Verify that Carol detected malice and accused Bob of `Accomplice`.
        verify_accused_accomplice(&carol, bob.our_pub_id(), bob_last_hash);
    }

    #[test]
    // Carol received `invalid_accusation` from Alice first, then receive gossip from Bob, which
    // doesn't contain the malice of Alice. Carol shall not raise accusation against Bob.
    fn accomplice_negative() {
        let (invalid_accusation, alice) = create_invalid_accusation();

        let mut carol = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "carol.dot",
            "functional_tests_handle_malice_accomplice",
        ));
        assert!(!carol.graph().contains(&invalid_accusation));

        // Send gossip from Alice to Carol
        let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Carol"))));
        unwrap!(carol.handle_request(alice.our_pub_id(), message));
        assert!(carol.graph().contains(&invalid_accusation));

        let bob = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "bob.dot",
            "functional_tests_handle_malice_accomplice",
        ));
        assert!(!bob.graph().contains(&invalid_accusation));

        // Send gossip from Bob to Carol
        let message = unwrap!(bob.create_gossip(Some(&PeerId::new("Carol"))));
        unwrap!(carol.handle_request(bob.our_pub_id(), message));

        // Verify that Carol didn't accuse Bob of `Accomplice`.
        assert!(our_votes(&carol).all(|payload| match payload {
            Observation::Accusation {
                malice: Malice::Unprovable(UnprovableMalice::Accomplice(_)),
                ..
            } => false,
            _ => true,
        }));
    }

    #[test]
    fn handle_fork() {
        // In this scenario, Alice creates two descendants of A_3 and sends one of them to Bob,
        // and the other one to Dave. When Bob gossips to Dave afterwards, Dave is made aware of
        // both sides of the fork and should raise an accusation.
        let bob_contents = parse_test_dot_file("bob.dot");
        let dave_contents = parse_test_dot_file("dave.dot");
        let a_3_hash = *unwrap!(find_event_by_short_name(&bob_contents.graph, "A_3")).hash();
        // Bob and Dave have different notions of which event is the fourth one by Alice - here
        // we save the hashes of these two events that could be considered A_4.
        let a_4_bob_hash = *unwrap!(find_event_by_short_name(&bob_contents.graph, "A_4")).hash();
        let a_4_dave_hash = *unwrap!(find_event_by_short_name(&dave_contents.graph, "A_4")).hash();

        let bob = TestParsec::from_parsed_contents(bob_contents);
        let mut dave = TestParsec::from_parsed_contents(dave_contents);
        assert!(bob.graph().contains(&a_3_hash));
        assert!(dave.graph().contains(&a_3_hash));
        // Bob doesn't know Dave's A_4, and Dave doesn't know Bob's
        assert!(!bob.graph().contains(&a_4_dave_hash));
        assert!(!dave.graph().contains(&a_4_bob_hash));

        // Send gossip from Bob to Dave
        let message = unwrap!(bob.create_gossip(Some(dave.our_pub_id())));
        unwrap!(dave.handle_request(bob.our_pub_id(), message));
        // Dave should now become aware of the other branch of the fork
        assert!(dave.graph().contains(&a_4_bob_hash));

        // Verify that Dave detected malice and accused Alice of it.
        let (offender, hash) = unwrap!(
            our_votes(&dave)
                .filter_map(|payload| match payload {
                    Observation::Accusation {
                        ref offender,
                        malice: Malice::Fork(hash),
                    } => Some((offender, hash)),
                    _ => None,
                }).next()
        );
        assert_eq!(offender, &PeerId::new("Alice"));
        assert_eq!(*hash, a_3_hash);
    }

    #[test]
    fn self_parent_by_different_creator() {
        let test_folder = "functional_tests_handle_malice_stale_other_parent";
        let carol = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "carol.dot",
            test_folder,
        ));

        // Carol creates an event with one of Bob's as the self-parent.
        let b_2_hash = *unwrap!(find_event_by_short_name(carol.graph(), "B_2")).hash();
        let c_4 = Event::new_from_observation(
            b_2_hash,
            Observation::OpaquePayload(Transaction::new("ABCD")),
            carol.graph(),
            carol.peer_list(),
        );
        let c_4_hash = *c_4.hash();
        let packed_c_4 = c_4.pack();

        let mut alice = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "alice.dot",
            test_folder,
        ));

        // Try to add the event.
        assert_err!(Error::InvalidEvent, alice.add_event(c_4));

        // The invalid event should trigger an accusation vote to be raised immediately, and the
        // invalid event should not be added to the graph.
        let a_2 = unwrap!(find_event_by_short_name(alice.graph(), "A_2"));
        let expected_observation = Observation::Accusation {
            offender: carol.our_pub_id().clone(),
            malice: Malice::SelfParentByDifferentCreator(Box::new(packed_c_4)),
        };

        assert_eq!(*unwrap!(a_2.vote()).payload(), expected_observation);
        assert!(!alice.graph().contains(&c_4_hash));
    }

    #[test]
    fn other_parent_by_same_creator() {
        let alice_id = PeerId::new("Alice");
        let bob_id = PeerId::new("Bob");
        let genesis = btree_set![alice_id.clone(), bob_id.clone()];

        let mut alice = initialise_parsec(alice_id, &genesis, None);
        let mut bob_contents = initialise_parsed_contents(bob_id.clone(), &genesis, None);

        let b_0_hash = *unwrap!(find_event_by_short_name(&bob_contents.graph, "b_0")).hash();
        let b_1_hash = *unwrap!(find_event_by_short_name(&bob_contents.graph, "b_1")).hash();

        let b_2 = Event::new_from_request(
            b_1_hash,
            b_0_hash,
            &bob_contents.graph,
            &bob_contents.peer_list,
            &BTreeSet::new(),
        );
        let b_2_hash = *b_2.hash();

        let b_1 = unwrap!(bob_contents.remove_last_event());
        assert_eq!(*b_1.hash(), b_1_hash);

        let b_0 = unwrap!(bob_contents.remove_last_event());
        assert_eq!(*b_0.hash(), b_0_hash);

        unwrap!(alice.unpack_and_add_event(b_0.pack()));
        unwrap!(alice.unpack_and_add_event(b_1.pack()));

        // This should fail, as B_2 has other-parent by the same creator.
        assert_err!(Error::InvalidEvent, alice.unpack_and_add_event(b_2.pack()));

        // Alice should raise accusation against Bob
        let (offender, event) = unwrap!(
            our_votes(&alice)
                .filter_map(|payload| match payload {
                    Observation::Accusation {
                        ref offender,
                        malice: Malice::OtherParentBySameCreator(event),
                    } => Some((offender, event)),
                    _ => None,
                }).next()
        );

        assert_eq!(*offender, bob_id);
        assert_eq!(event.hash(), b_2_hash);

        // B_2 should not have been inserted into Alice's graph
        assert!(!alice.graph().contains(&b_2_hash));
    }

    #[test]
    fn premature_gossip() {
        // Generated with RNG seed: [411278735, 3293288956, 208850454, 2872654992].
        // Copied from add_peer
        let mut parsed_contents = parse_test_dot_file("alice.dot");

        // The final decision to add Frank is reached in D_18, so we remove this event.
        let _d_18 = unwrap!(parsed_contents.remove_last_event());

        let mut alice = TestParsec::from_parsed_contents(parsed_contents);
        let genesis_group: BTreeSet<_> = alice.peer_list().all_ids().cloned().collect();

        let alice_id = PeerId::new("Alice");
        let fred_id = PeerId::new("Fred");
        assert!(
            !alice
                .peer_list()
                .all_ids()
                .any(|peer_id| *peer_id == fred_id)
        );

        let alice_snapshot = Snapshot::new(&alice);

        // Try calling `create_gossip()` for a peer which doesn't exist yet.
        assert_err!(Error::InvalidPeerState { .. }, alice.create_gossip(Some(&fred_id)));
        assert_eq!(alice_snapshot, Snapshot::new(&alice));

        // We'll modify Alice's peer list to allow her to create gossip for Fred
        alice.add_peer(fred_id.clone(), PeerState::RECV | PeerState::VOTE);

        // Construct Fred's Parsec instance.
        let mut fred = TestParsec::from_existing(fred_id.clone(), &genesis_group, &genesis_group);

        // Check that Fred has no events that Alice has
        assert!(
            alice
                .graph()
                .iter()
                .all(|ev| !fred.graph().contains(ev.inner().hash()))
        );

        // Now Alice will prematurely gossip to Fred
        let request = unwrap!(alice.create_gossip(Some(&fred_id)));
        let result = fred.handle_request(&alice_id, request);

        // check that Fred detected premature gossip
        assert_err!(Error::PrematureGossip, result);

        // Check that Fred has all the events that Alice has
        assert!(
            alice
                .graph()
                .iter()
                .all(|ev| fred.graph().contains(ev.inner().hash()))
        );
    }
}

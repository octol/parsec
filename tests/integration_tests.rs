// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![cfg(feature = "testing")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    html_root_url = "https://docs.rs/parsec"
)]
#![forbid(
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    bad_style,
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences
)]

#[macro_use]
extern crate proptest;
#[macro_use]
extern crate unwrap;

use maidsafe_utilities::log;
use parsec::{
    dev_utils::{
        proptest::{arbitrary_delay, ScheduleOptionsStrategy, ScheduleStrategy},
        DelayDistribution, Environment, Genesis, ObservationEvent, ObservationSchedule, RngChoice,
        Sampling, Schedule, ScheduleOptions,
    },
    mock::{PeerId, Transaction, NAMES},
    ConsensusMode, Observation,
};
use proptest::{prelude::ProptestConfig, test_runner::FileFailurePersistence};
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet};

// Alter the seed here to reproduce failures
static SEED: RngChoice = RngChoice::SeededRandom;

#[test]
fn minimal_network() {
    // 4 is the minimal network size for which the super majority is less than it.
    let num_peers = 4;
    let mut env = Environment::new(SEED);
    let options = ScheduleOptions {
        genesis_size: num_peers,
        opaque_to_add: 1,
        votes_before_gossip: true,
        ..Default::default()
    };

    let schedule = Schedule::new(&mut env, &options);

    let result = env.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn multiple_votes_before_gossip() {
    let num_observations = 10;
    let mut env = Environment::new(SEED);
    let options = ScheduleOptions {
        opaque_to_add: num_observations,
        votes_before_gossip: true,
        ..Default::default()
    };

    let schedule = Schedule::new(&mut env, &options);

    let result = env.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn multiple_votes_during_gossip() {
    let num_observations = 10;
    let mut env = Environment::new(SEED);
    let options = ScheduleOptions {
        opaque_to_add: num_observations,
        ..Default::default()
    };

    let schedule = Schedule::new(&mut env, &options);

    let result = env.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn duplicate_vote_is_reduced_to_single() {
    let mut env = Environment::new(SEED);
    let options = ScheduleOptions {
        votes_before_gossip: true,
        prob_vote_duplication: 0.5,
        ..Default::default()
    };

    let schedule = Schedule::new(&mut env, &options);

    let result = env.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn faulty_third_never_gossip() {
    let num_peers = 10;
    let num_observations = 10;
    let num_faulty = (num_peers - 1) / 3;
    let mut env = Environment::new(SEED);

    let mut failures = BTreeMap::new();
    let _ = failures.insert(0, num_faulty);
    let options = ScheduleOptions {
        genesis_size: num_peers,
        opaque_to_add: num_observations,
        deterministic_failures: failures,
        ..Default::default()
    };
    let schedule = Schedule::new(&mut env, &options);

    let result = env.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn faulty_third_terminate_concurrently() {
    let num_peers = 10;
    let num_observations = 10;
    let num_faulty = (num_peers - 1) / 3;
    let mut env = Environment::new(SEED);

    let mut failures = BTreeMap::new();
    let _ = failures.insert(env.rng.gen_range(10, 50), num_faulty);
    let options = ScheduleOptions {
        genesis_size: num_peers,
        opaque_to_add: num_observations,
        deterministic_failures: failures,
        ..Default::default()
    };
    let schedule = Schedule::new(&mut env, &options);

    let result = env.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn faulty_nodes_terminate_at_random_points() {
    let num_peers = 10;
    let num_observations = 10;
    let prob_failure = 0.05;
    let mut env = Environment::new(SEED);
    let options = ScheduleOptions {
        genesis_size: num_peers,
        opaque_to_add: num_observations,
        prob_failure,
        ..Default::default()
    };
    let schedule = Schedule::new(&mut env, &options);

    let result = env.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn faulty_node_always_unresponsive_and_removed() {
    let num_peers = 10;
    let num_observations = 10;
    let num_faulty = 1;
    let mut env = Environment::new(SEED);

    let mut failures = BTreeMap::new();
    let _ = failures.insert(0, num_faulty);
    let options = ScheduleOptions {
        genesis_size: num_peers,
        opaque_to_add: num_observations,
        deterministic_failures: failures,
        ..Default::default()
    };
    let schedule = Schedule::new(&mut env, &options);

    let result = env.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);

    // Faulty nodes should have been detected as unresponsive and removed
    let responsive_nodes = num_peers - num_faulty;
    assert_eq!(env.network.peers.len(), responsive_nodes);
}

#[test]
fn faulty_node_unresponsive_at_random_point_and_removed() {
    let num_peers = 10;
    let num_observations = 10;
    let num_faulty = 1;
    let mut env = Environment::new(SEED);

    let mut failures = BTreeMap::new();
    let _ = failures.insert(env.rng.gen_range(10, 50), num_faulty);
    let options = ScheduleOptions {
        genesis_size: num_peers,
        opaque_to_add: num_observations,
        deterministic_failures: failures,
        ..Default::default()
    };
    let schedule = Schedule::new(&mut env, &options);

    let result = env.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);

    // Faulty nodes should have been detected as unresponsive and removed
    let responsive_nodes = num_peers - num_faulty;
    assert_eq!(env.network.peers.len(), responsive_nodes);
}

#[test]
fn faulty_third_unresponsive_concurrently_and_removed() {
    let num_peers = 10;
    let num_observations = 10;
    let num_faulty = (num_peers - 1) / 3;
    let mut env = Environment::new(SEED);

    let mut failures = BTreeMap::new();
    let _ = failures.insert(env.rng.gen_range(10, 50), num_faulty);
    let options = ScheduleOptions {
        genesis_size: num_peers,
        opaque_to_add: num_observations,
        deterministic_failures: failures,
        ..Default::default()
    };
    let schedule = Schedule::new(&mut env, &options);

    let result = env.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);

    // Faulty nodes should have been detected as unresponsive and removed
    let responsive_nodes = num_peers - num_faulty;
    assert_eq!(env.network.peers.len(), responsive_nodes);
}

#[test]
fn random_schedule_no_delays() {
    let num_observations = 10;
    let mut env = Environment::new(SEED);
    let options = ScheduleOptions {
        opaque_to_add: num_observations,
        delay_distr: DelayDistribution::Constant(0),
        ..Default::default()
    };
    let schedule = Schedule::new(&mut env, &options);

    let result = env.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn add_many_peers() {
    let mut env = Environment::new(SEED);
    let options = ScheduleOptions {
        genesis_size: 3,
        peers_to_add: 8,
        opaque_to_add: 0,
        ..Default::default()
    };

    let schedule = Schedule::new(&mut env, &options);

    unwrap!(env.execute_schedule(schedule));
}

#[test]
fn add_few_peers_and_vote() {
    use parsec::dev_utils::ObservationEvent::*;

    let mut names = NAMES.iter();
    let mut env = Environment::new(SEED);

    let obs_schedule = ObservationSchedule {
        genesis: Genesis::new(names.by_ref().take(4).cloned().map(PeerId::new).collect()),
        schedule: vec![
            // 1. Add a peer and then a transaction a bit later.
            (50, AddPeer(PeerId::new(unwrap!(names.next())))),
            (200, Opaque(Transaction::new("one"))),
            // 2. Add a peer and a transaction at the same time.
            (400, AddPeer(PeerId::new(unwrap!(names.next())))),
            (400, Opaque(Transaction::new("two"))),
        ],
    };

    let options = ScheduleOptions::default();
    let schedule = Schedule::from_observation_schedule(&mut env, &options, obs_schedule);

    unwrap!(env.execute_schedule(schedule));
}

// Run DKG with the 4 voters in genesis
#[test]
fn run_dkg() {
    let mut env = Environment::with_consensus_mode(SEED, ConsensusMode::Single);
    let named_peer_ids = PeerId::named_peer_ids();

    let genesis: BTreeSet<_> = named_peer_ids[0..4].iter().cloned().collect();

    let dkgs = vec![(genesis.clone(), "dkg".to_string())];

    run_dkgs(&mut env, &genesis, &genesis, dkgs, vec![]);
}

// Run 2 DKGs with disjoint sets of 4 peers from the 8 voters in genesis
#[test]
fn run_split_dkg() {
    let mut env = Environment::with_consensus_mode(SEED, ConsensusMode::Single);
    let named_peer_ids = PeerId::named_peer_ids();

    let genesis: BTreeSet<_> = named_peer_ids[0..8].iter().cloned().collect();
    let left: BTreeSet<_> = named_peer_ids[0..4].iter().cloned().collect();
    let right: BTreeSet<_> = named_peer_ids[4..8].iter().cloned().collect();

    let dkgs = vec![(left, "left".to_string()), (right, "right".to_string())];

    run_dkgs(&mut env, &genesis, &genesis, dkgs, vec![]);
}

// Run a DKG with 4 peers not in the 4 voters in genesis
#[test]
fn run_non_voters_dkg() {
    let mut env = Environment::with_consensus_mode(SEED, ConsensusMode::Single);
    let named_peer_ids = PeerId::named_peer_ids();

    let final_peer_ids: BTreeSet<_> = named_peer_ids[0..8].iter().cloned().collect();
    let genesis: BTreeSet<_> = named_peer_ids[0..4].iter().cloned().collect();
    let non_voters: BTreeSet<_> = named_peer_ids[4..8].iter().cloned().collect();

    let dkgs = vec![(non_voters, "non_voters".to_string())];

    run_dkgs(&mut env, &genesis, &final_peer_ids, dkgs, vec![]);
}

// Run a DKG with 4 peers with one of them not in the 4 voters in genesis
#[test]
fn run_non_member_single_add_remove_dkg() {
    let mut env = Environment::with_consensus_mode(SEED, ConsensusMode::Single);
    let named_peer_ids = PeerId::named_peer_ids();

    let final_peer_ids: BTreeSet<_> = named_peer_ids[0..5].iter().cloned().collect();
    let genesis: BTreeSet<_> = named_peer_ids[0..4].iter().cloned().collect();
    let single_add_remove: BTreeSet<_> = named_peer_ids[1..5].iter().cloned().collect();

    let dkgs = vec![(single_add_remove, "single_add_remove".to_string())];

    run_dkgs(&mut env, &genesis, &final_peer_ids, dkgs, vec![]);
}

// Run a DKG with 4 peers with one of them not in the 4 voters in genesis.
// After the DKG is initiated or complete, vote for the actual Add/Remove/Opaque events.
#[test]
fn run_non_member_single_add_remove_dkg_with_member_change() {
    let mut env = Environment::with_consensus_mode(SEED, ConsensusMode::Single);
    let named_peer_ids = PeerId::named_peer_ids();

    let final_peer_ids: BTreeSet<_> = named_peer_ids[1..5].iter().cloned().collect();
    let genesis: BTreeSet<_> = named_peer_ids[0..4].iter().cloned().collect();
    let single_add_remove: BTreeSet<_> = named_peer_ids[1..5].iter().cloned().collect();

    let dkgs = vec![(single_add_remove, "single_add_remove".to_string())];
    let additional_events = vec![
        (500, ObservationEvent::AddPeer(named_peer_ids[4].clone())),
        (500, ObservationEvent::RemovePeer(named_peer_ids[0].clone())),
        (500, ObservationEvent::Opaque(Transaction::new("info"))),
    ];

    run_dkgs(&mut env, &genesis, &final_peer_ids, dkgs, additional_events);
}

// Run 2 DKGs with disjoint sets of 4 peers, each with 2 of the 4 voters in genesis.
// After the DKG is initiated or complete, vote for an additional Opaque event.
#[test]
fn run_non_member_split_dkg() {
    let mut env = Environment::with_consensus_mode(SEED, ConsensusMode::Single);
    let named_peer_ids = PeerId::named_peer_ids();

    let final_peer_ids: BTreeSet<_> = named_peer_ids[0..8].iter().cloned().collect();
    let genesis: BTreeSet<_> = named_peer_ids[2..6].iter().cloned().collect();
    let left: BTreeSet<_> = named_peer_ids[0..4].iter().cloned().collect();
    let right: BTreeSet<_> = named_peer_ids[4..8].iter().cloned().collect();

    let dkgs = vec![(left, "left".to_string()), (right, "right".to_string())];
    let additional_events = vec![(500, ObservationEvent::Opaque(Transaction::new("info")))];

    run_dkgs(&mut env, &genesis, &final_peer_ids, dkgs, additional_events);
}

fn run_dkgs(
    env: &mut Environment,
    peer_ids: &BTreeSet<PeerId>,
    final_peer_ids: &BTreeSet<PeerId>,
    dkgs: Vec<(BTreeSet<PeerId>, String)>,
    additional_events: Vec<(usize, ObservationEvent)>,
) {
    //
    // Arrange
    //
    let dkgs: BTreeMap<_, _> = dkgs.into_iter().collect();
    let obs_schedule = ObservationSchedule {
        genesis: Genesis::new(peer_ids.iter().cloned().collect()),
        schedule: dkgs
            .keys()
            .map(|participants| (50, ObservationEvent::StartDkg(participants.clone())))
            .chain(additional_events.into_iter())
            .collect(),
    };

    let options = ScheduleOptions::default();
    let schedule = Schedule::from_observation_schedule(env, &options, obs_schedule);

    //
    // Act
    //
    unwrap!(env.execute_schedule(schedule));

    //
    // Assert
    // Each peer should have all the DkgResult from started DKGs with a secret key
    // if it was participating.
    //
    let dkg_name = |participants: &BTreeSet<_>| {
        dkgs.get(participants)
            .cloned()
            .unwrap_or_else(|| format!("{:?}", participants))
    };

    let actual: BTreeSet<_> = env
        .network
        .running_non_malicious_peers()
        .flat_map(|peer| {
            let id = peer.id().clone();
            peer.blocks().map(move |block| (id.clone(), block))
        })
        .filter_map(|(id, block)| match block.payload() {
            Observation::DkgResult {
                participants,
                dkg_result,
            } => Some((
                id.clone(),
                dkg_name(participants),
                dkg_result.0.secret_key_share.is_some(),
            )),
            _ => None,
        })
        .collect();

    let expected: BTreeSet<_> = dkgs
        .iter()
        .flat_map(|(participants, dkg_name)| {
            final_peer_ids
                .iter()
                .map(move |id| (id.clone(), dkg_name.clone(), participants.contains(&id)))
        })
        .collect();

    assert_eq!(
        actual, expected,
        "\n\nEach peer should have all the DkgResult from started DKGs with a secret \
         key if it was participating.\nStarted DKGs: {:?}",
        dkgs
    );
}

#[test]
fn add_many_peers_and_vote() {
    let mut env = Environment::new(SEED);
    let options = ScheduleOptions {
        genesis_size: 3,
        peers_to_add: 8,
        opaque_to_add: 10,
        ..Default::default()
    };

    let schedule = Schedule::new(&mut env, &options);

    unwrap!(env.execute_schedule(schedule));
}

#[test]
fn remove_one_peer() {
    let mut env = Environment::new(SEED);
    let options = ScheduleOptions {
        genesis_size: 6,
        peers_to_remove: 1,
        ..Default::default()
    };
    let schedule = Schedule::new(&mut env, &options);

    let result = env.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn remove_many_peers_at_once() {
    use parsec::dev_utils::ObservationEvent::*;

    let mut env = Environment::new(SEED);
    let obs_schedule = ObservationSchedule {
        genesis: Genesis::new(NAMES.iter().take(10).cloned().map(PeerId::new).collect()),
        schedule: vec![
            (50, RemovePeer(PeerId::new("Judy"))),
            (50, RemovePeer(PeerId::new("Iris"))),
            (50, RemovePeer(PeerId::new("Hank"))),
            (500, Opaque(Transaction::new("whatever"))),
        ],
    };
    let options = ScheduleOptions::default();
    let schedule = Schedule::from_observation_schedule(&mut env, &options, obs_schedule);

    let result = env.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn fail_add_remove() {
    use parsec::dev_utils::ObservationEvent::*;

    let mut env = Environment::new(SEED);
    let obs_schedule = ObservationSchedule {
        genesis: Genesis::new(NAMES.iter().take(7).cloned().map(PeerId::new).collect()),
        schedule: vec![
            // In this test we start with 7 peers.
            // One fails and one drops, which leaves us with 5 out of 7, and later out of 6,
            // active - just enough to be a supermajority.
            // Then, we add one peer, and drop one again. Then active peers try to reach
            // consensus on an opaque payload.
            // If this succeeds, this proves that the added peer became a full voter. Were this
            // not the case, we would be left with 4 out of 6 voters, which would stall the
            // section.
            (10, Fail(PeerId::new("Alice"))),
            (20, RemovePeer(PeerId::new("Bob"))),
            (200, AddPeer(PeerId::new("Hank"))),
            (1000, RemovePeer(PeerId::new("Carol"))),
            (1500, Opaque(Transaction::new("whatever"))),
        ],
    };
    let options = ScheduleOptions::default();
    let schedule = Schedule::from_observation_schedule(&mut env, &options, obs_schedule);

    let result = env.execute_schedule(schedule);
    assert!(result.is_ok(), "{:?}", result);
}

#[test]
fn consensus_mode_single() {
    let mut env = Environment::with_consensus_mode(SEED, ConsensusMode::Single);
    let options = ScheduleOptions {
        genesis_size: 4,
        peers_to_add: 4,
        peers_to_remove: 4,
        opaque_to_add: 10,
        opaque_voters: Sampling::Constant(1),
        ..Default::default()
    };
    let schedule = Schedule::new(&mut env, &options);

    unwrap!(env.execute_schedule(schedule));
}

#[test]
fn extensive_dynamic_membership() {
    use parsec::dev_utils::ObservationEvent::*;

    let max_num_nodes = 12;
    let min_num_nodes = 6;
    let genesis_size = 4;
    let initial_size = 9;
    // one in X chance to add a node
    let chance_to_add = 3;
    // max X nodes to be removed at once
    let remove_at_once = 2;

    let all_names: Vec<&str> = NAMES.iter().by_ref().take(max_num_nodes).cloned().collect();
    let mut names = all_names.iter();
    let mut env = Environment::new(SEED);

    let mut live_nodes: Vec<&str> = names.by_ref().take(genesis_size).cloned().collect();
    let genesis = Genesis::new(live_nodes.iter().map(|name| PeerId::new(name)).collect());

    let mut schedule = vec![];
    let mut step = 0;
    while live_nodes.len() < initial_size {
        step += 50;
        let name = unwrap!(names.next());
        schedule.push((step, AddPeer(PeerId::new(name))));
        live_nodes.push(name);
    }

    loop {
        if env.rng.gen_weighted_bool(chance_to_add) {
            if let Some(name) = names.next() {
                step += 200;
                schedule.push((step, AddPeer(PeerId::new(name))));
                live_nodes.push(name);
            }
        }

        if live_nodes.len() > min_num_nodes {
            step += 300;
            for _ in 0..env.rng.gen_range(1, remove_at_once + 1) {
                let num_of_nodes = live_nodes.len();
                let removed_peer = live_nodes.remove(env.rng.gen_range(0, num_of_nodes));
                schedule.push((step, RemovePeer(PeerId::new(removed_peer))));
            }
        } else {
            break;
        }
    }

    let obs_schedule = ObservationSchedule { genesis, schedule };
    let options = ScheduleOptions::default();
    let schedule = Schedule::from_observation_schedule(&mut env, &options, obs_schedule);

    unwrap!(env.execute_schedule(schedule));
}

#[test]
fn consensus_with_fork() {
    let mut env = Environment::new(SEED);
    let options = ScheduleOptions {
        genesis_size: 5,
        malicious_genesis_count: 1,
        opaque_to_add: 2,
        ..Default::default()
    };
    let schedule = Schedule::new(&mut env, &options);
    unwrap!(env.execute_schedule(schedule));
}

#[test]
fn grow_network_from_two_nodes() {
    let mut env = Environment::new(SEED);
    let options = ScheduleOptions {
        genesis_size: 2,
        peers_to_add: 2,
        ..Default::default()
    };
    let schedule = Schedule::new(&mut env, &options);
    unwrap!(env.execute_schedule(schedule));
}

#[test]
fn grow_network_from_one_node() {
    let mut env = Environment::new(SEED);
    let options = ScheduleOptions {
        genesis_size: 1,
        peers_to_add: 3,
        ..Default::default()
    };
    let schedule = Schedule::new(&mut env, &options);
    unwrap!(env.execute_schedule(schedule));
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("regressions"))),
        cases: 5,
        ..Default::default()
    })]

    #[test]
    fn agreement_under_various_conditions((mut env, sched) in ScheduleStrategy {
        opts: ScheduleOptionsStrategy {
            num_peers: (4..=10).into(),
            num_observations: (1..=10).into(),
            recv_trans: (0.001..0.5).into(),
            failure: (0.0..1.0).into(),
            vote_duplication: (0.0..0.5).into(),
            delay_distr: arbitrary_delay(0..10, 0.0..10.0),
        },
    }) {
        let _ = log::init(true);

        let result = env.execute_schedule(sched);
        assert!(result.is_ok(), "{:?}", result);
    }
}

#[test]
fn consensus_mode_single_all_vote_same() {
    let mut env = Environment::with_consensus_mode(SEED, ConsensusMode::Single);
    let options = ScheduleOptions {
        genesis_size: 8,
        opaque_to_add: 2,
        vote_for_same: true,
        ..Default::default()
    };
    let schedule = Schedule::new(&mut env, &options);

    unwrap!(env.execute_schedule(schedule));
}

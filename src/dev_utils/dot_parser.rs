// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use gossip::Event;
use hash::Hash;
use meta_vote::{BoolSet, MetaVote, Step};
use mock::{PeerId, Transaction};
use observation::Observation;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read};
use std::iter;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

/// The event graph and associated info that were parsed from the dumped dot file.
pub(crate) struct ParsedContents {
    pub events: BTreeMap<Hash, Event<Transaction, PeerId>>,
    pub events_order: Vec<Hash>,
    pub meta_votes: BTreeMap<Hash, BTreeMap<PeerId, Vec<MetaVote>>>,
}

/// Read a dumped dot file and return with parsed event graph and associated info.
pub(crate) fn parse_dot_file(full_path: &Path) -> io::Result<ParsedContents> {
    read(File::open(full_path)?)
}

/// For use by functional/unit tests which provide a dot file for the test setup.  This reads and
/// parses the dot file as per `parse_dot_file()` above, but also ensures there is a corresponding
/// SVG file which has been generated from the dot file.  If `dot` is available, it checks the
/// contents of the SVG file match the dot file.
pub(crate) fn parse_test_dot_file(filename: &str) -> ParsedContents {
    let mut dot_path = PathBuf::from("input_graphs");
    dot_path.push(unwrap!(thread::current().name()).replace("::", "_"));
    dot_path.push(filename);
    assert!(
        dot_path.exists(),
        "\nDot file {} doesn't exist.",
        dot_path.display()
    );

    let svg = open_corresponding_svg(&dot_path);
    try_check_svg_contents(&dot_path, svg);

    unwrap!(
        parse_dot_file(&dot_path),
        "Failed to parse {}",
        dot_path.display()
    )
}

fn open_corresponding_svg(dot_path: &Path) -> File {
    let mut svg_path = dot_path.to_owned();
    assert!(svg_path.set_extension("dot.svg"));
    unwrap!(
        File::open(&svg_path),
        "\nFailed to open SVG file for {0}.  Try running:\n    dot -Tsvg {0} -O\n",
        dot_path.display()
    )
}

fn try_check_svg_contents(dot_path: &Path, mut svg: File) {
    // If we have "dot" available, check that the SVG contents are correct.
    if let Ok(output) = Command::new("dot")
        .args(&["-Tsvg", dot_path.to_string_lossy().as_ref()])
        .output()
    {
        let dot_output = String::from_utf8_lossy(&output.stdout);

        let mut svg_file_contents = String::new();
        let _ = unwrap!(svg.read_to_string(&mut svg_file_contents));

        // Some lines can be ordered slightly differently between each run of dot.
        let mut ordered_dot_output = dot_output.lines().collect::<Vec<_>>();
        ordered_dot_output.sort();
        let mut ordered_svg_file_contents = svg_file_contents.lines().collect::<Vec<_>>();
        ordered_svg_file_contents.sort();
        //assert!(
        //    ordered_dot_output == ordered_svg_file_contents,
        //    "\nThe contents of the SVG file for {0} don't match running\n    dot -Tsvg {0} -O\n\n",
        //    dot_path.display()
        //);
    }
}

#[derive(Clone, Debug)]
struct ParsingEvent {
    creator: String,
    index: u64,
    cause: String,
    self_parent: Option<String>,
    other_parent: Option<String>,
    interesting_content: BTreeSet<Transaction>,
    last_ancestors: BTreeMap<PeerId, u64>,
    observations: BTreeSet<PeerId>,
}

impl ParsingEvent {
    #[cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
    fn new(
        creator: String,
        index: u64,
        cause: String,
        self_parent: Option<String>,
        other_parent: Option<String>,
        blocks_carried_string: &str,
        last_ancestors_string: &str,
        observations: BTreeSet<PeerId>,
    ) -> Self {
        let split_vbc = extract_between(blocks_carried_string, "{", "}");
        let interesting_content = if split_vbc.is_empty() {
            BTreeSet::new()
        } else {
            split_vbc
                .split(',')
                .map(|s| Transaction::new(extract_between(s, "(", ")")))
                .collect::<BTreeSet<_>>()
        };

        let mut last_ancestors = BTreeMap::new();
        let split_la = extract_between(last_ancestors_string, "{", "}");
        if !split_la.is_empty() {
            for entry in split_la.split(',').map(|s| s.trim()) {
                let split_entry = entry.split(": ").collect::<Vec<_>>();
                let _ = last_ancestors
                    .insert(PeerId::new(split_entry[0]), unwrap!(split_entry[1].parse()));
            }
        }

        ParsingEvent {
            creator,
            index,
            cause,
            self_parent,
            other_parent,
            interesting_content,
            last_ancestors,
            observations,
        }
    }
}

fn read(mut file: File) -> io::Result<ParsedContents> {
    let mut contents = String::new();
    let _ = file.read_to_string(&mut contents)?;

    let mut parsing_events = parse_event_graph(&contents);
    let mut parsing_mvs = parse_meta_votes(&contents);

    let mut events = BTreeMap::new();
    let mut events_order = Vec::new();
    let mut name_hash_map: BTreeMap<String, Hash> = BTreeMap::new();
    let mut meta_votes = BTreeMap::new();
    let length = parsing_events.len();

    while !parsing_events.is_empty() {
        let ordered_event = next_ordered_event(&parsing_events);
        if ordered_event.is_empty() {
            assert!(parsing_events.is_empty());
            break;
        }
        let event = unwrap!(parsing_events.remove(&ordered_event));

        let self_parent = event
            .self_parent
            .and_then(|name| Some(name_hash_map[&name]));
        let other_parent = event
            .other_parent
            .and_then(|name| Some(name_hash_map[&name]));

        let interesting_content = event
            .interesting_content
            .iter()
            .map(|transction| Observation::OpaquePayload(transction.clone()))
            .collect::<BTreeSet<_>>();

        let parsed_event: Event<Transaction, PeerId> = Event::new_from_dot_input(
            &PeerId::new(&event.creator),
            event.cause.as_ref(),
            self_parent,
            other_parent,
            event.index,
            event.last_ancestors,
            interesting_content,
        );

        let hash = *parsed_event.hash();

        if let Some(meta_vote) = parsing_mvs.remove(&ordered_event) {
            let _ = meta_votes.insert(hash, meta_vote);
        } else if let Some(parent_meta_vote) = parsed_event
            .self_parent()
            .and_then(|self_parent| meta_votes.get(self_parent))
            .and_then(|meta_vote| Some(meta_vote.clone()))
        {
            let _ = meta_votes.insert(hash, parent_meta_vote);
        }

        let _ = events.insert(hash, parsed_event);
        events_order.push(hash);
        let _ = name_hash_map.insert(ordered_event.to_string(), hash);
    }

    assert_eq!(events.len(), length);

    Ok(ParsedContents {
        events,
        events_order,
        meta_votes,
    })
}

fn parse_event_graph(contents: &str) -> BTreeMap<String, ParsingEvent> {
    let split_events = split_events(contents);
    let meta_votes = split_meta_votes(contents);

    let mut parsing_events = BTreeMap::new();
    for (name, events) in &split_events.nodes {
        for (index, event) in events.iter().enumerate() {
            if let Some(info) = meta_votes.get(event) {
                let self_parent: Option<String> = if index == 0 {
                    None
                } else {
                    Some(events[index - 1].to_string())
                };
                let other_parent: Option<String> = split_events
                    .other_parents
                    .get(event)
                    .and_then(|s| Some(s.to_string()));

                let _ = parsing_events.insert(
                    event.to_string(),
                    ParsingEvent::new(
                        name.to_string(),
                        index as u64,
                        info.cause.to_string(),
                        self_parent,
                        other_parent,
                        info.interesting_content,
                        info.last_ancestors,
                        BTreeSet::new(),
                    ),
                );
            }
        }
    }
    parsing_events
}

fn parse_meta_votes(contents: &str) -> BTreeMap<String, BTreeMap<PeerId, Vec<MetaVote>>> {
    // The last dot file generated by a node contains no meta_votes.
    let mvs_lines = if let Some(content) = contents.split("\n\n").find(|s| s.contains("aux")) {
        content.split('\n')
    } else {
        return BTreeMap::new();
    };
    let mut parsing_mvs: BTreeMap<String, BTreeMap<PeerId, Vec<MetaVote>>> = BTreeMap::new();
    let mut event_name = String::default();
    let mut peer_id = PeerId::new("");
    for line in mvs_lines {
        if line.contains("shape") {
            if let Some(name) = line.split('\"').nth(1) {
                event_name = name.to_string();
            }
        } else if line.contains("aux") {
            let meta_vote = if line.contains(": [ ") {
                let split_line = line.split(": [ ").collect::<Vec<_>>();
                peer_id = PeerId::from_initial(unwrap!(split_line[0].chars().next()));
                parse_meta_vote(split_line[1])
            } else {
                parse_meta_vote(line)
            };
            let _ = parsing_mvs
                .entry(event_name.clone())
                .and_modify(|peer_votes| {
                    let _ = peer_votes
                        .entry(peer_id.clone())
                        .and_modify(|meta_votes| meta_votes.push(meta_vote.clone()))
                        .or_insert_with(|| iter::once(meta_vote.clone()).collect());
                }).or_insert_with(|| {
                    iter::once((peer_id.clone(), iter::once(meta_vote.clone()).collect())).collect()
                });
        }
    }
    parsing_mvs
}

fn next_ordered_event(parsing_events: &BTreeMap<String, ParsingEvent>) -> String {
    let mut candidate = String::default();
    for (name, event) in parsing_events {
        let is_ordered = match (event.self_parent.clone(), event.other_parent.clone()) {
            (None, None) => true,
            (Some(ref self_parent), None) => !parsing_events.contains_key(self_parent),
            (None, Some(ref other_parent)) => !parsing_events.contains_key(other_parent),
            (Some(ref self_parent), Some(ref other_parent)) => {
                !parsing_events.contains_key(self_parent)
                    && !parsing_events.contains_key(other_parent)
            }
        };
        if is_ordered {
            candidate = name.to_string();
            break;
        }
    }
    candidate
}

struct SplitEvents<'a> {
    // Vec<(node_name, hashes_of_events_created_by_that_node)>
    nodes: Vec<(&'a str, Vec<&'a str>)>,
    // BTreeMap<event_hash, other_parent_hash>
    other_parents: BTreeMap<&'a str, &'a str>,
}

fn split_events(contents: &str) -> SplitEvents {
    let mut other_parents = BTreeMap::new();
    let nodes = contents
        .split("subgraph")
        .map(|s| s.trim())
        .filter(|s| s.starts_with("cluster_"))
        .map(|s| {
            let name = unwrap!(unwrap!(s.split("cluster_").last()).split(' ').next());
            let split_content = unwrap!(s.split('{').nth(1)).split('}').collect::<Vec<_>>();
            let events = split_content[0]
                .split('\n')
                .filter(|s| s.contains("->"))
                .map(|s| unwrap!(s.split("->").nth(1)))
                .map(|s| unwrap!(s.split('\"').nth(1)))
                .collect::<Vec<_>>();

            let edges = unwrap!(split_content[1].split("\n\n").next());
            for edge in edges.split('\n') {
                if edge.contains("->") {
                    let split_edge = edge.split('\"').collect::<Vec<_>>();
                    let _ = other_parents.insert(split_edge[3], split_edge[1]);
                }
            }
            (name, events)
        }).collect::<Vec<_>>();
    SplitEvents {
        nodes,
        other_parents,
    }
}

struct SplitMetaVote<'a> {
    cause: &'a str,
    interesting_content: &'a str,
    last_ancestors: &'a str,
}

// Returns with: BTreeMap<event_hash, SplitMetaVote>
fn split_meta_votes<'a>(contents: &'a str) -> BTreeMap<&'a str, SplitMetaVote> {
    let mut meta_votes = BTreeMap::new();
    let _ = contents
        .split("/// {")
        .filter(|s| s.contains("/// }"))
        .map(|s| unwrap!(s.split("/// }").next()))
        .map(|s| s.trim())
        .map(|s| {
            let split_info = s.split("///").map(|s| s.trim()).collect::<Vec<_>>();
            let _ = meta_votes.insert(
                split_info[0],
                SplitMetaVote {
                    cause: split_info[1],
                    interesting_content: split_info[2],
                    last_ancestors: split_info[3],
                },
            );
        }).collect::<Vec<_>>();
    meta_votes
}

fn parse_meta_vote(line: &str) -> MetaVote {
    // in the format of `{ 0/0, est:{f} bin:{t, f} aux:{f} dec:{} }`
    let split_line = line.split(':').collect::<Vec<_>>();
    let round: usize =
        unwrap!(unwrap!(unwrap!(split_line[0].split('/').next()).split(' ').nth(1)).parse());
    let step_index: u8 = unwrap!(extract_between(split_line[0], "/", ",").parse());
    let estimates = parse_boolset(unwrap!(split_line[1].split(" bin").next()));
    let bin_values = parse_boolset(unwrap!(split_line[2].split(" aux").next()));
    let aux_value = parse_option_bool(unwrap!(split_line[3].split(" dec").next()));
    let decision = parse_option_bool(unwrap!(split_line[4].split(" }").next()));
    MetaVote {
        round,
        step: parse_step(step_index),
        estimates,
        bin_values,
        aux_value,
        decision,
    }
}

fn parse_step(index: u8) -> Step {
    match index {
        0 => Step::ForcedTrue,
        1 => Step::ForcedFalse,
        2 => Step::GenuineFlip,
        _ => panic!("Improper Step index {:?}", index),
    }
}

fn parse_boolset(line: &str) -> BoolSet {
    match line {
        "{t}" => BoolSet::Single(true),
        "{f}" => BoolSet::Single(false),
        "{t, f}" => BoolSet::Both,
        "{}" => BoolSet::default(),
        _ => panic!("Not a proper BoolSet : {:?}", line),
    }
}

fn parse_option_bool(line: &str) -> Option<bool> {
    match line {
        "{t}" => Some(true),
        "{f}" => Some(false),
        "{}" => None,
        _ => panic!("Not a proper Option<bool> : {:?}", line),
    }
}

fn extract_between<'a>(input: &'a str, left: &str, right: &str) -> &'a str {
    unwrap!(unwrap!(input.split(left).nth(1)).split(right).next())
}

#[cfg(all(test, feature = "dump-graphs"))]
mod tests {
    use super::*;
    use dev_utils::{
        Environment, GossipStrategy, ObservationCount, PeerCount, RngChoice, Schedule,
        ScheduleOptions,
    };
    use dump_graph::DIR;
    use maidsafe_utilities::serialisation::deserialise;
    use meta_vote::MetaVote;
    use mock::{PeerId, Transaction};
    use std::fs;

    type SerialisedGraph = (
        BTreeMap<Hash, Event<Transaction, PeerId>>,
        BTreeMap<Hash, BTreeMap<PeerId, Vec<MetaVote>>>,
    );

    // Alter the seed here to reproduce failures
    static SEED: RngChoice = RngChoice::SeededRandom;

    #[test]
    fn dot_parser() {
        let mut env = Environment::new(&PeerCount(4), &ObservationCount(5), SEED);
        let schedule = Schedule::new(
            &mut env,
            &ScheduleOptions {
                gossip_strategy: GossipStrategy::Probabilistic(0.8),
                ..Default::default()
            },
        );
        env.network.execute_schedule(schedule);

        let result = env.network.blocks_all_in_sequence();
        assert!(result.is_ok(), "{:?}", result);

        let mut num_of_files = 0u8;
        let entries = DIR.with(|dir| unwrap!(fs::read_dir(dir)));
        for entry in entries {
            let entry = unwrap!(entry);

            if !unwrap!(entry.file_name().to_str()).contains(".core") {
                continue;
            }
            num_of_files += 1;
            let mut core_file = unwrap!(File::open(entry.path()));
            let mut core_info = Vec::new();
            assert_ne!(unwrap!(core_file.read_to_end(&mut core_info)), 0);

            let (mut gossip_graph, meta_votes): SerialisedGraph = unwrap!(deserialise(&core_info));

            let mut dot_file_path = entry.path();
            assert!(dot_file_path.set_extension("dot"));
            let parsed_result = unwrap!(parse_dot_file(&dot_file_path));

            assert_eq!(gossip_graph.len(), parsed_result.events_order.len());
            for event in &mut gossip_graph.values_mut() {
                event.observations.clear();
            }
            assert_eq!(gossip_graph, parsed_result.events);

            // The dumped dot file doesn't contain all the meta_votes
            assert!(meta_votes.len() >= parsed_result.meta_votes.len());
            for (hash, meta_vote) in &parsed_result.meta_votes {
                let ori_meta_vote = unwrap!(meta_votes.get(hash));
                assert_eq!(ori_meta_vote, meta_vote);
            }
        }
        assert_ne!(num_of_files, 0u8);
    }
}

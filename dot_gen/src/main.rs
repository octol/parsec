// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Tool to generate dot files for Parsec's functional tests.
//!
//! # Usage
//!
//! First, define your scenario below. Example:
//!
//! ```
//! scenarios
//!     .add("parsec::functional_tests::my_test_function", |env| {
//!         Schedule::new(
//!             env,
//!             &ScheduleOptions {
//!                 genesis_size: 6,
//!                 opaque_to_add: 1,
//!             }
//!         )
//!     })
//!     .seed([1, 2, 3, 4])
//!     .file("Alice", "alice.dot")
//!     .file("Dave", "dave.dot");
//! ```
//!
//! Notes:
//! - The name of the scenario is the fully-qualified name of the test function for which the dot
//!   files are to be generated.
//! - The body of the scenario is a lambda that returns `Schedule` according to which the scenario
//!   runs.
//! - Optionally, specify the seed to initialize the random number generator.
//!   If not specified, a randomly generated seed is used.
//! - Optionally specify the peers whose graphs should be outputted and the names of the files the
//!   graphs should be outputted to. If not specified, the default is to take Alice's graph and put
//!   it into a file named "alice.dot"
//!
//! When scenarios are defined, run the tool from within Parsec's root directory:
//!
//!     cargo run --manifest-path=dot_gen/Cargo.toml -- ARGS
//!
//! where ARGS are the arguments to the tool. Run with --help for more info.

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
    variant_size_differences,
    unused
)]

#[macro_use]
extern crate clap;
extern crate parsec;

use clap::{App, Arg};
use parsec::dev_utils::ObservationEvent::*;
use parsec::dev_utils::{Environment, ObservationSchedule, RngChoice, Schedule, ScheduleOptions};
use parsec::mock::{PeerId, Transaction};
use parsec::{Observation, DIR};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::slice;

const DST_ROOT: &str = "input_graphs";

/// Construct set of `PeerId`s with the given names.
macro_rules! peer_ids {
    ($($name:expr),*) => {{
        let mut result = BTreeSet::new();
        $(let _ = result.insert(PeerId::new($name));)*
        result
    }}
}

fn main() {
    let mut scenarios = Scenarios::new();

    // -------------------------------------------------------------------------
    // Define scenarios here:

    let _ = scenarios.add(
        "functional_tests::handle_malice_genesis_event_not_after_initial",
        |env| {
            let obs = ObservationSchedule {
                genesis: peer_ids!("Alice", "Bob", "Carol", "Dave"),
                schedule: vec![
                    (0, Fail(PeerId::new("Dave"))),
                    (50, Opaque(Transaction::new("ABCD"))),
                ],
            };

            Schedule::from_observation_schedule(env, &ScheduleOptions::default(), obs)
        },
    );

    let _ = scenarios.add(
        "functional_tests::handle_malice_genesis_event_creator_not_genesis_member",
        |env| {
            let obs = ObservationSchedule {
                genesis: peer_ids!("Alice", "Bob", "Carol", "Dave"),
                schedule: vec![(0, AddPeer(PeerId::new("Eric")))],
            };

            Schedule::from_observation_schedule(env, &ScheduleOptions::default(), obs)
        },
    );

    let _ = scenarios
        .add(
            "parsec::functional_tests::handle_malice_accomplice",
            |env| {
                Schedule::new(
                    env,
                    &ScheduleOptions {
                        genesis_size: 4,
                        opaque_to_add: 1,
                        ..Default::default()
                    },
                )
            },
        ).file("Alice", "alice.dot")
        .file("Bob", "bob.dot")
        .file("Carol", "carol.dot");

    let _ = scenarios
        .add("benches", |env| {
            Schedule::new(
                env,
                &ScheduleOptions {
                    genesis_size: 4,
                    opaque_to_add: 1,
                    ..Default::default()
                },
            )
        }).file("Alice", "minimal.dot");

    let _ = scenarios
        .add("benches", |env| {
            Schedule::new(
                env,
                &ScheduleOptions {
                    genesis_size: 5,
                    opaque_to_add: 5,
                    ..Default::default()
                },
            )
        }).file("Alice", "static.dot");

    let _ = scenarios
        .add("benches", |env| {
            Schedule::new(
                env,
                &ScheduleOptions {
                    genesis_size: 2,
                    peers_to_add: 3,
                    opaque_to_add: 5,
                    ..Default::default()
                },
            )
        }).file("Alice", "dynamic.dot");

    // Do not edit below this line.
    // -------------------------------------------------------------------------

    run(scenarios)
}

struct Scenario {
    name: String,
    seed: RngChoice,
    schedule_fn: Box<FnMut(&mut Environment) -> Schedule>,
    files: BTreeMap<String, String>,
}

impl Scenario {
    fn new<N, F>(name: N, schedule: F) -> Self
    where
        N: Into<String>,
        F: FnMut(&mut Environment) -> Schedule + 'static,
    {
        Scenario {
            name: name.into(),
            seed: RngChoice::SeededRandom,
            schedule_fn: Box::new(schedule),
            files: BTreeMap::new(),
        }
    }

    /// Use the given seed instead of randomly generated one.
    #[allow(unused)]
    pub fn seed(&mut self, seed: [u32; 4]) -> &mut Self {
        self.seed = RngChoice::Seeded(seed);
        self
    }

    /// Set the name of the output file for the graph of the given peer.
    #[allow(unused)]
    pub fn file(&mut self, peer_name: &str, dst_file: &str) -> &mut Self {
        let _ = self.files.insert(peer_name.into(), dst_file.into());
        self
    }

    fn matches(&self, pattern: &str) -> bool {
        self.files
            .values()
            .any(|file| format!("{}/{}", self.name, file).contains(pattern))
    }

    fn run(&mut self, mode: Mode) {
        println!("Running scenario {}", self.name);

        let mut env = Environment::new(self.seed);
        let schedule = (self.schedule_fn)(&mut env);
        println!("Using {:?}", env.rng);
        let result = env.network.execute_schedule(schedule);
        assert!(result.is_ok(), "{:?}", result);

        if self.files.is_empty() {
            self.collect_files(&default_file_map(), mode);
        } else {
            self.collect_files(&self.files, mode);
        }
    }

    fn collect_files(&self, files: &BTreeMap<String, String>, mode: Mode) {
        let src_dir = DIR.with(|dir| dir.clone());
        let dst_dir = self.dst_dir();

        if let Err(error) = fs::create_dir_all(&dst_dir) {
            panic!(
                "Failed to create destination dir {}: {}",
                dst_dir.display(),
                error
            );
        }

        for (peer_name, dst_file) in files {
            let src_path = match find_file_for_peer(&src_dir, peer_name) {
                Ok(path) => path,
                Err(error) => panic!("{}", error),
            };
            let dst_path = self.dst_dir().join(dst_file);

            println!("    o {}", dst_path.display());

            if dst_path.exists() {
                print!("      Already exists: ");

                match mode {
                    Mode::Overwrite => println!("overwriting."),
                    Mode::Skip => {
                        println!("skipping.");
                        continue;
                    }
                    Mode::Fail => {
                        println!("aborting.");
                        panic!(
                            "Destination file {} already exists. Re-run with --existing=overwrite (or -f) to overwrite",
                            dst_path.display()
                        );
                    }
                }
            }

            if let Err(error) = fs::copy(&src_path, &dst_path) {
                panic!(
                    "Failed to copy {} to {}: {}",
                    src_path.display(),
                    dst_path.display(),
                    error
                )
            }
        }
    }

    fn dst_dir(&self) -> PathBuf {
        PathBuf::from(DST_ROOT).join(self.name.replace("::", "_"))
    }
}

struct Scenarios(Vec<Scenario>);

impl Scenarios {
    pub fn new() -> Self {
        Scenarios(Vec::new())
    }

    /// Define new scenario for a test with the given fully qualified name
    /// using `Schedule` returned by the given lambda.
    pub fn add<N, F>(&mut self, name: N, schedule: F) -> &mut Scenario
    where
        N: Into<String>,
        F: FnMut(&mut Environment) -> Schedule + 'static,
    {
        self.0.push(Scenario::new(name, schedule));
        self.0.last_mut().unwrap()
    }

    fn iter(&self) -> slice::Iter<Scenario> {
        self.0.iter()
    }

    fn iter_mut(&mut self) -> slice::IterMut<Scenario> {
        self.0.iter_mut()
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Overwrite,
    Skip,
    Fail,
}

fn run(mut scenarios: Scenarios) {
    let matches = App::new("Parsec Dot Generator")
        .version(crate_version!())
        .arg(
            Arg::with_name("name")
                .index(1)
                .help("Run all scenarios matching this name")
                .required_unless("all")
                .required_unless("list"),
        ).arg(
            Arg::with_name("all")
                .short("a")
                .long("all")
                .help("Run all scenarios")
                .conflicts_with("name"),
        ).arg(
            Arg::with_name("list")
                .short("l")
                .long("list")
                .help("List all scenarios")
                .conflicts_with("name")
                .conflicts_with("all"),
        ).arg(
            Arg::with_name("existing")
                .short("e")
                .long("existing")
                .takes_value(true)
                .possible_values(&["overwrite", "skip", "fail"])
                .help("What to do with existing destination files")
                .conflicts_with("list"),
        ).arg(
            Arg::with_name("force")
                .short("f")
                .help("Same as --existing=overwrite")
                .conflicts_with("list"),
        ).get_matches();

    check_root_dir();

    if matches.is_present("list") {
        for scenario in scenarios.iter() {
            println!("- {}", scenario.name);

            for file in scenario.files.values() {
                println!("  - {}", file);
            }
        }

        return;
    }

    let mode = if matches.is_present("force") {
        Mode::Overwrite
    } else {
        match matches.value_of("existing") {
            Some("overwrite") => Mode::Overwrite,
            Some("skip") => Mode::Skip,
            _ => Mode::Fail,
        }
    };

    if matches.is_present("all") {
        for scenario in scenarios.iter_mut() {
            scenario.run(mode);
        }
    }

    if let Some(name) = matches.value_of("name") {
        for scenario in scenarios
            .iter_mut()
            .filter(|scenario| scenario.matches(name))
        {
            scenario.run(mode);
        }
    }
}

fn default_file_map() -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    let _ = result.insert("Alice".into(), "alice.dot".into());
    result
}

fn find_file_for_peer(dir: &Path, peer_name: &str) -> io::Result<PathBuf> {
    if let Some(name) = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with(peer_name) && name.ends_with(".dot"))
        .max()
    {
        Ok(dir.join(name))
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Dot file for {} not found", peer_name),
        ))
    }
}

// Check that the tool is run from the parsec crate root.
fn check_root_dir() {
    // TODO: maybe there is a better way to do this?

    if let Ok(mut file) = File::open("Cargo.toml") {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() && contents.contains("name = \"parsec\"") {
            return;
        }
    }

    panic!("This tool must be run from the Parsec crate root");
}

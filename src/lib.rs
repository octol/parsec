// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! This is an implementation of PARSEC (Protocol for Asynchronous, Reliable, Secure and Efficient
//! Consensus).  For details of the protocol, see
//! [the RFC](https://github.com/maidsafe/rfcs/tree/master/text/0049-parsec/0049-parsec.md) and
//! [the whitepaper](http://docs.maidsafe.net/Whitepapers/pdf/PARSEC.pdf).

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]
#![forbid(
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    //warnings
)]
#![deny(
    bad_style,
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    private_no_mangle_fns,
    private_no_mangle_statics,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    //unused,
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

#[cfg(feature = "dump-graphs")]
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate maidsafe_utilities;
#[cfg(any(test, feature = "testing"))]
#[macro_use]
extern crate proptest as proptest_crate;
#[macro_use]
extern crate quick_error;
extern crate rand;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate tiny_keccak;
#[cfg(any(test, feature = "testing", feature = "dump-graphs"))]
#[macro_use]
extern crate unwrap;
extern crate safe_crypto;

mod block;
mod dump_graph;
mod error;
mod gossip;
mod hash;
mod id;
mod meta_vote;
mod network_event;
mod observation;
mod parsec;
mod peer_list;
mod round_hash;
mod vote;

#[doc(hidden)]
#[cfg(any(test, feature = "testing"))]
pub mod dev_utils;

#[doc(hidden)]
/// **NOT FOR PRODUCTION USE**: Mock types which trivially implement the required Parsec traits.
///
/// This can be used to swap proper cryptographic functionality for inexpensive (in some cases
/// no-op) replacements.  This is useful to allow tests to run quickly, but should not be used
/// outside of testing code.
pub mod mock;

pub use block::Block;
#[cfg(feature = "dump-graphs")]
pub use dump_graph::DIR;
pub use error::Error;
pub use gossip::{Request, Response};
pub use id::{Proof, PublicId, SecretId};
pub use network_event::NetworkEvent;
pub use observation::Observation;
pub use parsec::{is_supermajority, Parsec};
pub use vote::Vote;

use maidsafe_utilities::serialisation;
use serde::ser::Serialize;
use std::fmt::Debug;

fn serialise<T: Serialize + Debug>(data: &T) -> Vec<u8> {
    if let Ok(serialised) = serialisation::serialise(data) {
        serialised
    } else {
        log_or_panic!("Failed to serialise {:?}", data);
        vec![]
    }
}

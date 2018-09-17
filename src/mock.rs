// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use id::{PublicId, SecretId};
use network_event::NetworkEvent;
use rand::{Rand, Rng};
use safe_crypto::{gen_sign_keypair, PublicSignKey, SecretSignKey};
use std::fmt::{self, Debug, Display, Formatter};

const NAMES: &[&str] = &[
    "Alice", "Bob", "Carol", "Dave", "Eric", "Fred", "Gina", "Hank", "Iris", "Judy", "Kent",
    "Lucy", "Mike", "Nina", "Oran", "Paul", "Quin", "Rose", "Stan", "Tina",
];

/// **NOT FOR PRODUCTION USE**: Mock signature type.
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub struct Signature(String);

/// **NOT FOR PRODUCTION USE**: Mock type implementing `PublicId` and `SecretId` traits.  For
/// non-mocks, these two traits must be implemented by two separate types; a public key and secret
/// key respectively.
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PeerId {
    id: String,
    pub_sign: PublicSignKey,
}

impl PeerId {
    pub fn new(id: &str) -> Self {
        let (pub_sign, _) = gen_sign_keypair();
        Self {
            id: id.to_string(),
            pub_sign,
        }

    }

    // Only being used by the dot_parser.
    #[cfg(test)]
    pub fn from_initial(initial: char) -> Self {
        for name in NAMES.iter() {
            if name.starts_with(initial) {
                return PeerId::new(name);
            }
        }
        panic!(
            "cannot find a name starts with {:?} within {:?}",
            initial, NAMES
        );
    }
}

impl Debug for PeerId {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id)
    }
}

impl PublicId for PeerId {
    type Signature = Signature;
    fn verify_signature(&self, _signature: &Self::Signature, _data: &[u8]) -> bool {
        true
    }
}

impl SecretId for PeerId {
    type PublicId = PeerId;
    fn public_id(&self) -> &Self::PublicId {
        &self
    }
    fn sign_detached(&self, _data: &[u8]) -> Signature {
        Signature(format!("of {:?}", self))
    }
}

/// **NOT FOR PRODUCTION USE**: Mock type implementing `NetworkEvent` trait.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Transaction(String);

impl Transaction {
    pub fn new(id: &str) -> Self {
        Transaction(id.to_string())
    }
}

impl NetworkEvent for Transaction {}

impl Display for Transaction {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Transaction({})", self.0)
    }
}

impl Debug for Transaction {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl Rand for Transaction {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        Transaction(rng.gen_ascii_chars().take(5).collect())
    }
}

/// **NOT FOR PRODUCTION USE**: Returns a collection of mock node IDs with human-readable names.
pub fn create_ids(count: usize) -> Vec<PeerId> {
    assert!(count <= names_len());
    NAMES.iter().take(count).cloned().map(PeerId::new).collect()
}

pub fn names_len() -> usize {
    NAMES.len()
}

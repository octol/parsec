// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::mem;

/// Split a slice into subslices, where the element matched by the predicate is the first in each
/// slice.
pub fn split_on_first<F, T>(items: Vec<T>, predicate: F) -> SplitOnFirst<T, F>
where
    F: FnMut(&T) -> bool,
{
    SplitOnFirst { items, predicate }
}

pub struct SplitOnFirst<T, P>
where
    P: FnMut(&T) -> bool,
{
    items: Vec<T>,
    predicate: P,
}

impl<T, P> Iterator for SplitOnFirst<T, P>
where
    P: FnMut(&T) -> bool,
{
    type Item = Vec<T>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.items.is_empty() {
            return None;
        }

        let mut index = 1;
        while index < self.items.len() {
            if (self.predicate)(&self.items[index]) {
                break;
            } else {
                index += 1;
            }
        }

        let new_items = self.items.split_off(index);
        Some(mem::replace(&mut self.items, new_items))
    }
}

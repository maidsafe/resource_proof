// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0 This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! # Resource proof
//!
//! An mechanism to prove resource avaliability of a machine prior to it joining a network. This
//! crate will provide the creation and confirmation algorithms. It is suggested that network
//! nodes will require minimum resources to confirm the proof, but joining nodes will have a
//! significantly higher resource requirementto attempt such a joining proof.
//!
//! [Github repository](https://github.com/dirvine/resource_proof)



#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://dirvine.github.io/resource_proof")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, improper_ctypes, missing_docs, non_shorthand_field_patterns,
        overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
        stable_features, unconditional_recursion, unknown_lints, unsafe_code, unused,
        unused_allocation, unused_attributes, unused_comparisons, unused_features, unused_parens,
        while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]


#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy))]
#![cfg_attr(feature="clippy", allow(use_debug))]

extern crate tiny_keccak;
use std::collections::VecDeque;
use tiny_keccak::Keccak;

/// Holds the prover requirements
pub struct ResourceProof {
    min_size: usize,
    /// minimum size of proof in bytes
    difficulty: u8,
}


impl ResourceProof {
    /// Rounds will factor how large the message to send is. It also has a slight impact on the
    /// hash power required, but this is minimal.
    pub fn new(min_size: usize, difficulty: u8) -> ResourceProof {
        ResourceProof {
            min_size: min_size,
            difficulty: difficulty,
        }
    }

    /// Use some data from them and some from you to create a proof.
    pub fn create_proof(&self, nonce: &[u8]) -> VecDeque<u8> {
        let mut data = self.create_proof_data(nonce);
        while ResourceProof::leading_zeros(&hash(&data.as_slices())) < self.difficulty as usize {
            data.push_front(0u8);
        }
        data
    }

    /// Use some data from them and some from you to confirm a proof.
    pub fn validate_proof(&self, nonce: &[u8], proof: &VecDeque<u8>) -> bool {
        let data = self.create_proof_data(nonce);
        self.check_hash(proof) && Self::check_proof_data(&data, proof) &&
        Self::check_leading_zeros(proof)
    }

    fn check_hash(&self, data: &VecDeque<u8>) -> bool {
        ResourceProof::leading_zeros(&hash(&data.as_slices())) >= self.difficulty as usize
    }

    fn check_proof_data(data: &VecDeque<u8>, proof: &VecDeque<u8>) -> bool {
        !proof.as_slices().1.is_empty() ||
        data.as_slices()
            .1
            .iter()
            .zip(proof.as_slices().1.iter().take(data.len()))
            .all(|(a, b)| a == b)
    }

    fn check_leading_zeros(proof: &VecDeque<u8>) -> bool {
        proof.as_slices().1.is_empty() || proof.as_slices().0.iter().all(|&x| x == 0u8)
    }

    #[allow(unused)]
    fn create_proof_data(&self, nonce: &[u8]) -> VecDeque<u8> {
        nonce.iter()
            .cloned()
            .cycle()
            .take(self.min_size)
            .collect()
    }

    fn leading_zeros(data: &[u8]) -> usize {
        let mut size = 0;
        for (count, i) in data.iter().enumerate() {
            size = count * 8;
            size += i.leading_zeros() as usize;
            if i.leading_zeros() == 8 {
                continue;
            } else {
                return size;
            }
        }
        size
    }
}

/// Simple wrapper around tiny-keccak for use with deques
fn hash(data: &(&[u8], &[u8])) -> [u8; 32] {
    let mut sha3 = Keccak::new_sha3_256();
    sha3.update(data.0);
    sha3.update(data.1);
    let mut res = [0u8; 32];
    sha3.finalize(&mut res);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_data_size() {
        let nonce = [1, 2, 3];
        let proof = ResourceProof::new(1024, 3);
        assert!(proof.create_proof_data(&nonce).len() == 1024);
    }

    #[test]
    fn min_proof_size() {
        let nonce = [1, 2, 3];
        let proof = ResourceProof::new(1024 * 1024, 3);
        assert!(proof.create_proof(&nonce).len() > 1024);

    }

    #[test]
    fn proof_no_work() {
        let nonce = [1, 2, 3];
        let proof = ResourceProof::new(1024, 0);
        assert!(proof.create_proof_data(&nonce).len() == 1024);
    }

    #[test]
    fn valid_proof() {
        let nonce = [1, 5, 3];
        let rp = ResourceProof::new(1024, 3);
        // nonce
        let mut proof = rp.create_proof(&nonce);

        assert!(rp.check_hash(&proof));
        assert!(ResourceProof::check_leading_zeros(&proof));
        assert!(ResourceProof::check_proof_data(&proof, &rp.create_proof_data(&nonce)));

        assert!(rp.validate_proof(&nonce, &proof));
        proof.push_front(0u8);
        assert!(!rp.validate_proof(&nonce, &proof));

    }

}

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
//! A mechanism to test resource avaliability (CPU and bandwidth) of a machine prior to it joining
//! a network. This crate provides the creation and validation algorithms.
//!
//! Validation has some CPU and memory requirements but far less than proof creation. Bandwidth
//! tests (data transfer) affect the machine being proved and the machine doing validation equally;
//! it is suggested that multiple machines test any new machine to apply an asymmetric load.
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

#[cfg(test)]
extern crate rand;
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
    /// Configure a new prover.
    ///
    /// `min_size` is target data size in bytes. It may be small or large to test bandwidth
    /// (although it may be compressible).
    ///
    /// `difficulty` is the number of leading binary zeros required in the hash. Each extra zero
    /// doubles the difficulty.
    pub fn new(min_size: usize, difficulty: u8) -> ResourceProof {
        ResourceProof {
            min_size: min_size,
            difficulty: difficulty,
        }
    }

    /// Create the proof data with a given nonce.
    pub fn create_proof_data(&self, nonce: &[u8]) -> VecDeque<u8> {
        nonce
            .iter()
            .cloned()
            .cycle()
            .take(self.min_size)
            .collect()
    }

    /// Create the proof key. Requires the data (from `create_proof_data`) to be passed in.
    pub fn create_proof(&self, data: &mut VecDeque<u8>) -> u64 {
        let mut count = 0u64;
        let ref mut tmp = data.clone();
        while self.check_hash(&tmp) < self.difficulty {
            tmp.push_front(0u8);
            count += 1;
        }
        count
    }

    /// Validate the proof data and key (this is the number of zeros to be pushed onto the data).
    pub fn validate_all(&self, nonce: &[u8], received_data: &VecDeque<u8>, key: u64) -> bool {
        let mut data = self.create_proof_data(nonce);
        if data != *received_data {
            return false;
        }
        for _ in 0..key {
            data.push_front(0u8);
        }
        self.check_hash(&data) >= self.difficulty
    }

    /// Validate the data for the given `nonce` and size data.
    pub fn validate_data(&self, nonce: &[u8], data: &VecDeque<u8>) -> bool {
        self.create_proof_data(nonce) == *data
    }

    /// Validate the proof key (this must recreate the data, hence `validate_all` is faster when
    /// both must be checked).
    pub fn validate_proof(&self, nonce: &[u8], key: u64) -> bool {
        let mut data = self.create_proof_data(nonce);
        for _ in 0..key {
            data.push_front(0u8);
        }
        self.check_hash(&data) >= self.difficulty
    }

    fn check_hash(&self, data: &VecDeque<u8>) -> u8 {
        ResourceProof::leading_zeros(&hash(&data.as_slices()))
    }

    fn leading_zeros(data: &[u8]) -> u8 {
        let mut zeros = 0u8;
        for (count, i) in data.iter().enumerate() {
            zeros = i.leading_zeros() as u8 + (count as u8 * 8);
            if i.leading_zeros() < 8 {
                break;
            }
        }
        zeros
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
    use rand;


    #[test]
    fn valid_proof() {
        for _ in 0..20 {
            let nonce = [rand::random::<u8>()];
            let rp = ResourceProof::new(1024, 3);
            let ref mut data = rp.create_proof_data(&nonce);
            let proof = rp.create_proof(data);
            assert!(rp.validate_proof(&nonce, proof));
            assert!(rp.validate_data(&nonce, data));
            assert!(rp.validate_all(&nonce, data, proof));
        }
    }
}

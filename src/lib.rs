// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! # Resource proof
//!
//! A mechanism to test resource availability (CPU and bandwidth) of a machine prior to it joining
//! a network. This crate provides the creation and validation algorithms.
//!
//! Validation has some CPU and memory requirements but far less than proof creation. Bandwidth
//! tests (data transfer) affect the machine being proved and the machine doing validation equally;
//! it is suggested that multiple machines test any new machine to apply an asymmetric load.
//!
//! [GitHub repository](https://github.com/maidsafe/resource_proof)

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]
// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(
    bad_style,
    arithmetic_overflow,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types
)]
#![deny(
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true,
    warnings
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

#[cfg(test)]
extern crate rand;
use std::collections::VecDeque;
use tiny_keccak::{Hasher, Sha3};

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
            min_size,
            difficulty,
        }
    }

    /// Create the proof data with a given nonce.
    pub fn create_proof_data(&self, nonce: &[u8]) -> VecDeque<u8> {
        nonce.iter().cloned().cycle().take(self.min_size).collect()
    }

    /// Create a prover object. Requires a copy of the data (from `create_proof_data`) to be
    /// passed in.
    pub fn create_prover(&self, data: VecDeque<u8>) -> ResourceProver {
        ResourceProver {
            difficulty: self.difficulty,
            count: 0,
            data,
        }
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

/// Object used to compute a result
pub struct ResourceProver {
    difficulty: u8,
    count: u64,
    data: VecDeque<u8>,
}

impl ResourceProver {
    /// The expected number of steps is `pow(2, difficulty)`.
    /// The process is probabilistic, so the actual number of steps required may be more or less.
    ///
    /// The length of each step depends on data size. Total expected time is proportional to
    /// `length * pow(2, difficulty)`.
    pub fn expected_steps(&self) -> u64 {
        2u64.pow(u32::from(self.difficulty))
    }

    /// Try one step; if successful return the proof result.
    ///
    /// (This does not invalidate the prover. Continuing might find another valid solution.)
    pub fn try_step(&mut self) -> Option<u64> {
        if self.check_hash() >= self.difficulty {
            return Some(self.count);
        }

        self.data.push_front(0u8);
        self.count += 1;
        None
    }

    /// Keep stepping until a solution is found. Expected time can be calculated roughly (see
    /// `expected_steps`) but there is no upper bound (besides `u64::MAX`).
    pub fn solve(&mut self) -> u64 {
        loop {
            if let Some(solution) = self.try_step() {
                return solution;
            }
        }
    }

    fn check_hash(&self) -> u8 {
        ResourceProof::leading_zeros(&hash(&self.data.as_slices()))
    }
}

/// Simple wrapper around tiny-keccak for use with deques
fn hash(data: &(&[u8], &[u8])) -> [u8; 32] {
    let mut hasher = Sha3::v256();
    let mut res = [0u8; 32];
    hasher.update(data.0);
    hasher.update(data.1);
    hasher.finalize(&mut res);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_proof() {
        for _ in 0..20 {
            let nonce = [rand::random::<u8>()];
            let rp = ResourceProof::new(1024, 3);
            let data = rp.create_proof_data(&nonce);
            let proof = rp.create_prover(data.clone()).solve();
            assert!(rp.validate_proof(&nonce, proof));
            assert!(rp.validate_data(&nonce, &data));
            assert!(rp.validate_all(&nonce, &data, proof));
        }
    }
}

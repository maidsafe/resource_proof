// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! Command line tool for generating and validating resource proofs.

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(
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

use clap::Parser;
use resource_proof::ResourceProof;
use std::time::Instant;
#[cfg(not(windows))]
use termion::color;

fn test_it(dif: u8, size: usize, nonce: [u8; 32]) {
    let create = Instant::now();
    let rp = ResourceProof::new(size, dif);
    let data = rp.create_proof_data(&nonce);
    let mut prover = rp.create_prover(data.clone());
    let expected_steps = prover.expected_steps();
    let proof = prover.solve();
    let create_time = create.elapsed().as_secs();
    let check = Instant::now();
    if !rp.validate_proof(&nonce, proof) {
        println!("FAILED TO CONFIRM PROOF - POSSIBLE VIOLATION");
    }

    if !rp.validate_data(&nonce, &data) {
        println!("FAILED TO CONFIRM PROOF DATA - POSSIBLE VIOLATION");
    }

    if !rp.validate_all(&nonce, &data, proof) {
        println!("FAILED TO CONFIRM PROOF & DATA - POSSIBLE VIOLATION");
    }

    println!(
        "Difficulty = {} expected_steps = {} size = {} create = {} seconds check = {} \
         seconds num of steps = {:?}",
        dif,
        expected_steps,
        size,
        create_time,
        check.elapsed().as_secs(),
        proof
    );
}

#[cfg(not(windows))]
fn print_red(message: &str) {
    println!();
    println!();
    println!(
        "{}{}{}",
        color::Fg(color::Red),
        message,
        color::Fg(color::Reset)
    );
}

#[cfg(windows)]
fn print_red(message: &str) {
    println!();
    println!();
    println!("{}", message);
}

#[derive(Parser, Debug)]
#[clap(author, version)]
#[clap(name = "Simple Resource Proof example")]
#[clap(about = "Please set the size and difficulty to test", long_about = None)]
#[clap(
    after_help = "Several proofs may be chained, i.e. a large difficulty and small size or vice versa to check CPU And BW seperately"
)]
struct Config {
    #[clap(short, long)]
    #[clap(help = "The number of leading zeros of the proof when hashed with SHA3")]
    difficulty: u8,

    #[clap(short, long)]
    #[clap(help = "The minimum size of the proof in bytes")]
    size: usize,

    #[clap(long, default_value = "A long long time ago..")]
    #[clap(help = "Initial nonce seed")]
    seed: String,

    #[clap(short, long, action)]
    #[clap(
        help = "Will run continuously, increasing difficulty with every invocation. Note this will likley not stop in your lifetime :-)"
    )]
    increase: bool,
}

fn main() {
    let config = Config::parse();

    print_red("Running analysis ....");

    let nonce = resource_proof::nonce_from_seed(config.seed.as_bytes());

    if config.increase {
        for i in config.difficulty.. {
            test_it(i, config.size, nonce);
        }
    } else {
        test_it(config.difficulty, config.size, nonce);
    }
}

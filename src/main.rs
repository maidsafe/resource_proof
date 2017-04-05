// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! Command line tool for generating and validating resource proofs.

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

extern crate resource_proof;
#[macro_use]
extern crate clap;
#[cfg(not(windows))]
extern crate termion;
extern crate rand;

use clap::{App, Arg};
use resource_proof::ResourceProof;
use std::time::Instant;
#[cfg(not(windows))]
use termion::color;

fn test_it(dif: u8, size: usize, nonce: [u8; 32]) {
    let create = Instant::now();
    let rp = ResourceProof::new(size, dif);
    let data = &mut rp.create_proof_data(&nonce);
    let proof = rp.create_proof(data);
    let create_time = create.elapsed().as_secs();
    let check = Instant::now();
    if !rp.validate_proof(&nonce, proof) {
        println!("FAILED TO CONFIRM PROOF - POSSIBLE VIOLATION");
    }

    if !rp.validate_data(&nonce, data) {
        println!("FAILED TO CONFIRM PROOF DATA - POSSIBLE VIOLATION");
    }

    if !rp.validate_all(&nonce, data, proof) {
        println!("FAILED TO CONFIRM PROOF & DATA - POSSIBLE VIOLATION");
    }

    println!("Difficulty = {} size = {} create = {} seconds check = {} seconds num of attempts = \
              {:?}",
             dif,
             size,
             create_time,
             check.elapsed().as_secs(),
             proof);
}

#[cfg(not(windows))]
fn print_red(message: &str) {
    println!("");
    println!("");
    println!("{}{}{}",
             color::Fg(color::Red),
             message,
             color::Fg(color::Reset));
}

#[cfg(windows)]
fn print_red(message: &str) {
    println!("");
    println!("");
    println!("{}", message);
}

fn main() {
    let matches = App::new("=============================\nSimple Resource Proof \
                            example\n=============================\n")
        .about("______________________________\nPlease set the size and difficulty to test")
        .author(crate_authors!())
        .version(crate_version!())
        .before_help("Resource proof testing framework")
        .after_help("_____________________________________________________________\nSeveral \
                     proofs may be chained, i.e. a large difficulty and small size or large size \
                     and small difficulty to check specifically CPU And BW seperately")
        .arg(Arg::with_name("Difficulty")
            .short("d")
            .required(true)
            .long("difficulty")
            .help("Set difficulty, i.e. the number of leading zeros of the proof when hashed \
                   with SHA3")
            .takes_value(true))
        .arg(Arg::with_name("Size")
            .required(true)
            .short("s")
            .long("size")
            .help("Set size, i.e. the minimum size of the proof in bytes")
            .takes_value(true))
        .arg(Arg::with_name("Increase")
            .short("i")
            .long("increase")
            .help("Will run continuously, increasing difficulty with every invocation. Note \
                   this will likley not stop in your lifetime :-)"))
        .get_matches();

    print_red("Running analysis ....");

    let repeat = matches.is_present("Increase");

    let dif = value_t!(matches, "Difficulty", u8).unwrap_or(1);

    let size = value_t!(matches, "Size", usize).unwrap_or(10);

    let nonce = [rand::random::<u8>(); 32];

    if repeat {
        for i in dif.. {

            test_it(i, size, nonce);
        }
    } else {
        test_it(dif, size, nonce);
    }

}

extern crate resource_proof;
#[macro_use]
extern crate clap;

use clap::{App, Arg};
use resource_proof::ResourceProof;
use std::time::Instant;


fn main() {
let matches = 				  App::new("=============================\nSimple Resource Proof example\n=============================\n")
                          .about("______________________________\nPlease set the size and difficulty to test")
													.author(crate_authors!())
													.version(crate_version!())
													.before_help("Resource proof testing framework")
													.after_help("_____________________________________________________________\nSeveral proofs may be chained, i.e. a large difficulty and \
													             small size or large size and small difficulty to check \
																			 specifically CPU And BW seperately")

                          .arg(Arg::with_name("Difficulty")
													.short("d")
													.required(true)
													.long("difficulty")
													.help("Set difficulty, i.e. the number of leading zeros of the proof when hashed with SHA3")
													.takes_value(true))
                          .arg(Arg::with_name("Size")
													.required(true)
													.short("s")
													.long("size")
													.help("Set size, i.e. the minimum size of the proof in bytes")
													.takes_value(true))
                          // .arg(Arg::with_name("Increase")
													// .short("i")
													// .long("increase")
													// .help("Will run continuously, increasing difficulty with every invocation. Note this will likley not stop in your lifetime :-)"))
                          .get_matches();

println!("Running analysis ....");

        let claiment = [4u8;32];
        let receiver = [1u8;32];
let create = Instant::now();
let dif = value_t!(matches, "Difficulty", u8).unwrap_or(1);
let size = value_t!(matches, "Size", usize).unwrap_or(10);

let rp = ResourceProof::new(size, dif);
let proof = rp.create_proof(&claiment, &receiver);
let create_time = create.elapsed().as_secs();
let check = Instant::now();
if !rp.validate_proof(&claiment, &receiver, &proof[..]) {
println!("FAILED TO CONFIRM PROOF - POSSIBLY VIOLATION");
}
println!("Difficulty = {} size = {} time to create = {} seconds time to check = {} seconds ", dif, size, create_time , check.elapsed().as_secs());




}

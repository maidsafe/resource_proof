# Resource Proof

[![Build
status](https://ci.appveyor.com/api/projects/status/fcpgnw8kya193w87?svg=true)](https://ci.appveyor.com/project/dirvine/resource-proof)
[![Build
Status](https://travis-ci.org/dirvine/resource_proof.svg?branch=master)](https://travis-ci.org/dirvine/resource_proof)

# Summary

This crate hopes to combine mechanisms that attempt to validate resources on remote machines. This
validation though, is a spot check and also best effort. It is not guaranteed to be accurate over
time and this consideration must be clear to users of the crate.

The purpose is to provide **some** indication that a machine has **some** capabilities.

# Motivation

In decentralised networks where trust is absent a node intending to join has to prove it can meet
the minimum requirements of the network. These resource requirements are  decided by either the
network itself (best) or set by the programmer.

In such networks, one must assume the node joining is not running the same software that existing
nodes are running.

# Current state

At version 0.1.1 this crate carries out soem rudimentary checks that requires a node has some
computing ability and also the ability to transfer a certain amount of data (bandwith check).

The current hashing mechanism used is sha3 (keccak), this provides some requirement on the machine
to "work" but is not ASIC resistant. This algorithm will likely be upgraded to something like
[Equihash](https://www.internetsociety.org/sites/default/files/blogs-media/equihash-asymmetric-proof-of-work-based-generalized-birthday-problem.pdf)
which will likely resist ASIC type workarounds, but importantly will allow better requirements on
the memory requirements of a node (this is not measured in this crate yet).

Disk space measurements may  also be added in future.

# Analysis

There is an example to test any values and allow measurements on different architectures. This can
be run as
```cargo run --release --example analyse -- -h```
Which will allow users to play with settings for difficulty and size. Difficulty is the setting that
asks the machine to continually push zeros to the beginning of any data until the number of leading
bits of the hash of the data are zero. Similar to a common proof of work algorithm.

The size parameter forces the nonce provided to be repeated until it reaches a certain size in
bytes. This is then transferred back to the network as a proof.

To find the proof the node must continaully push a zero to the beginning of the data (not at the end
as this is easily optimised). This forces the continuous reading of a large data segment in each
hash iteration.

Some figures on a desktop linux machine are below :

Small data element (36 bytes)
```
cargo run --release --example analyse -- -d 1 -s36   -i
            Running analysis ....
            Difficulty = 1 size = 36 time to create = 0 seconds time to check = 0  seconds
            Difficulty = 2 size = 36 time to create = 0 seconds time to check = 0  seconds
            Difficulty = 3 size = 36 time to create = 0 seconds time to check = 0  seconds
            Difficulty = 4 size = 36 time to create = 0 seconds time to check = 0  seconds
            Difficulty = 5 size = 36 time to create = 0 seconds time to check = 0  seconds
            Difficulty = 6 size = 36 time to create = 0 seconds time to check = 0  seconds
            Difficulty = 7 size = 36 time to create = 0 seconds time to check = 0  seconds
            Difficulty = 8 size = 36 time to create = 0 seconds time to check = 0  seconds
            Difficulty = 9 size = 36 time to create = 0 seconds time to check = 0  seconds
            Difficulty = 10 size = 36 time to create = 0 seconds time to check = 0  seconds
            Difficulty = 11 size = 36 time to create = 0 seconds time to check = 0  seconds
            Difficulty = 12 size = 36 time to create = 0 seconds time to check = 0  seconds
            Difficulty = 13 size = 36 time to create = 0 seconds time to check = 0  seconds
            Difficulty = 14 size = 36 time to create = 0 seconds time to check = 0  seconds
            Difficulty = 15 size = 36 time to create = 0 seconds time to check = 0  seconds
            Difficulty = 16 size = 36 time to create = 0 seconds time to check = 0  seconds
            Difficulty = 17 size = 36 time to create = 122 seconds time to check = 0  seconds
            Difficulty = 18 size = 36 time to create = 122 seconds time to check = 0  seconds
            Difficulty = 19 size = 36 time to create = 123 seconds time to check = 0  seconds
            Difficulty = 20 size = 36 time to create = 1890 seconds time to check = 0  seconds
```
Circa 10Mb data
```
cargo run --release --example analyse --  -d=1 -s=102400000 -i
         Running analysis ....
         Difficulty = 1 size = 102400000 time to create = 2 seconds time to check = 0  seconds
         Difficulty = 2 size = 102400000 time to create = 2 seconds time to check = 0  seconds
         Difficulty = 3 size = 102400000 time to create = 2 seconds time to check = 0  seconds
         Difficulty = 4 size = 102400000 time to create = 24 seconds time to check = 0  seconds
         Difficulty = 5 size = 102400000 time to create = 24 seconds time to check = 0  seconds
         Difficulty = 6 size = 102400000 time to create = 34 seconds time to check = 0  seconds
         Difficulty = 7 size = 102400000 time to create = 48 seconds time to check = 0  seconds
         Difficulty = 8 size = 102400000 time to create = 172 seconds time to check = 0  seconds
         Difficulty = 9 size = 102400000 time to create = 338 seconds time to check = 0  seconds
         Difficulty = 10 size = 102400000 time to create = 752 seconds time to check = 0  seconds
         Difficulty = 11 size = 102400000 time to create = 1144 seconds time to check = 0  seconds

```

The important point is that checking the proof is very fast and given enough difficulty, creating
the proof is work intensive. This is a critical consideration that will mitigate some attack vectors
on decentralised/p2p networks. It is by no means a security solution and should not be considered
withouth continaul ongoing checks on a nodes "behaviour".


## License

Licensed under either of

* the MaidSafe.net Commercial License, version 1.0 or later ([LICENSE](LICENSE))
* the General Public License (GPL), version 3 ([COPYING](COPYING) or http://www.gnu.org/licenses/gpl-3.0.en.html)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the MaidSafe Contributor Agreement, version 1.1 ([CONTRIBUTOR]
(CONTRIBUTOR)), shall be dual licensed as above, and you agree to be bound by the terms of the
MaidSafe Contributor Agreement, version 1.1.

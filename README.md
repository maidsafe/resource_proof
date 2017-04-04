# resource_proof

**Maintainer:** David Irvine (david.irvine@maidsafe.net)

|Crate|Documentation|Linux/OS X|Windows|Issues|
|:---:|:-----------:|:--------:|:-----:|:----:|
|[![](http://meritbadge.herokuapp.com/resource_proof)](https://crates.io/crates/resource_proof)|[![Documentation](https://docs.rs/resource_proof/badge.svg)](https://docs.rs/resource_proof)|[![Build Status](https://travis-ci.org/maidsafe/resource_proof.svg?branch=master)](https://travis-ci.org/maidsafe/resource_proof)|[![Build status](https://ci.appveyor.com/api/projects/status/yurq5amiwiunlv7w/branch/master?svg=true)](https://ci.appveyor.com/project/MaidSafe-QA/resource-proof/branch/master)|[![Stories in Ready](https://badge.waffle.io/maidsafe/resource_proof.png?label=ready&title=Ready)](https://waffle.io/maidsafe/resource_proof)|

| [MaidSafe website](https://maidsafe.net) | [SAFE Dev Forum](https://forum.safedev.org) | [SAFE Network Forum](https://safenetforum.org) |
|:----------------------------------------:|:-------------------------------------------:|:----------------------------------------------:|

## Summary

This crate hopes to combine mechanisms that attempt to validate resources on remote machines. This
validation though, is a spot check and also best effort. It is not guaranteed to be accurate over
time and this consideration must be clear to users of the crate.

The purpose is to provide **some** indication that a machine has **some** capabilities.

## Motivation

In decentralised networks where trust is absent a node intending to join has to prove it can meet
the minimum requirements of the network. These resource requirements are  decided by either the
network itself (best) or set by the programmer.

In such networks, one must assume the node joining is not running the same software that existing
nodes are running.

Even if nodes offset this proof by using another resource to aid the proof, it's unlikely to help as
the network should use continual monitoring of capability in parallel with these "spot checks".

## Current state

At version 0.2.x this crate carries out some rudimentary checks that requires a node has some
computing ability and also the ability to transfer a certain amount of data (bandwith check).

Based on a variant of [Hashcash](https://en.wikipedia.org/wiki/Hashcash) with the addition of the
requirement to transfer an amount of data, this library does provide a "proof of work" like
algorithm. This work requirement forces joining nodes to perform some calculation and data transfer.
The expected use case is to require the work is done and data transferred within a time duration. It
is possible to supply two proofs, one to focus on a large amount of work (difficulty) and another to
focus on a bandwidth requirement (size). These are combined in the API but do not necessarily need
to be used as a single proof, unless this requirement can be calculated.

The current hashing mechanism used is sha3 (keccak), this provides some requirement on the machine
to "work" but is not ASIC resistant. This algorithm will likely be upgraded to something like
[Equihash](https://www.internetsociety.org/sites/default/files/blogs-media/equihash-asymmetric-proof-of-work-based-generalized-birthday-problem.pdf)
which will likely resist ASIC type workarounds, but importantly will allow better requirements on
the memory requirements of a node (this is not measured in this crate yet).

Disk space measurements may  also be added in future.

## Analysis

There is an example to test any values and allow measurements on different architectures. This can
be run as
```cargo run --release --example analyse -- -h```
Which will allow users to play with settings for difficulty and size. Difficulty is the setting that
asks the machine to continually push zeros to the beginning of any data until the number of leading
bits of the hash of the data are zero. Similar to a common proof of work algorithm.

The size parameter forces the nonce provided to be repeated until it reaches a certain size in
bytes. This is then transferred back to the network as a proof.

To find the proof the node must continually push a zero to the beginning of the data (not at the end
as this is easily optimised). This forces the continuous reading of a large data segment in each
hash iteration.

Some figures on a desktop linux machine are below :

Small data element (36 bytes)

```
cargo run --release  -- -d 1 -s1024   -i
Running analysis ....
Difficulty = 1 size = 1024 create = 0 seconds check = 0 seconds num of attempts = 1
Difficulty = 2 size = 1024 create = 0 seconds check = 0 seconds num of attempts = 4
Difficulty = 3 size = 1024 create = 0 seconds check = 0 seconds num of attempts = 4
Difficulty = 4 size = 1024 create = 0 seconds check = 0 seconds num of attempts = 19
Difficulty = 5 size = 1024 create = 0 seconds check = 0 seconds num of attempts = 85
Difficulty = 6 size = 1024 create = 0 seconds check = 0 seconds num of attempts = 85
Difficulty = 7 size = 1024 create = 0 seconds check = 0 seconds num of attempts = 85
Difficulty = 8 size = 1024 create = 0 seconds check = 0 seconds num of attempts = 474
Difficulty = 9 size = 1024 create = 0 seconds check = 0 seconds num of attempts = 474
Difficulty = 10 size = 1024 create = 0 seconds check = 0 seconds num of attempts = 474
Difficulty = 11 size = 1024 create = 0 seconds check = 0 seconds num of attempts = 1017
Difficulty = 12 size = 1024 create = 0 seconds check = 0 seconds num of attempts = 1017
Difficulty = 13 size = 1024 create = 0 seconds check = 0 seconds num of attempts = 4367
Difficulty = 14 size = 1024 create = 0 seconds check = 0 seconds num of attempts = 4367
Difficulty = 15 size = 1024 create = 0 seconds check = 0 seconds num of attempts = 4367
Difficulty = 16 size = 1024 create = 0 seconds check = 0 seconds num of attempts = 4367
Difficulty = 17 size = 1024 create = 155 seconds check = 0 seconds num of attempts = 248184
Difficulty = 18 size = 1024 create = 154 seconds check = 0 seconds num of attempts = 248184
Difficulty = 19 size = 1024 create = 1508 seconds check = 0 seconds num of attempts = 787761
Difficulty = 20 size = 1024 create = 6087 seconds check = 0 seconds num of attempts = 1587092
```

Circa 100Mb data

```
cargo run --release  --  -d=1 -s=102400000 -i
Running analysis ....
Difficulty = 1 size = 10485760 create = 0 seconds check = 0 seconds num of attempts = 0
Difficulty = 2 size = 10485760 create = 0 seconds check = 0 seconds num of attempts = 0
Difficulty = 3 size = 10485760 create = 0 seconds check = 0 seconds num of attempts = 0
Difficulty = 4 size = 10485760 create = 0 seconds check = 0 seconds num of attempts = 0
Difficulty = 5 size = 10485760 create = 3 seconds check = 0 seconds num of attempts = 61
Difficulty = 6 size = 10485760 create = 3 seconds check = 0 seconds num of attempts = 61
Difficulty = 7 size = 10485760 create = 3 seconds check = 0 seconds num of attempts = 61
Difficulty = 8 size = 10485760 create = 3 seconds check = 0 seconds num of attempts = 61
Difficulty = 9 size = 10485760 create = 25 seconds check = 0 seconds num of attempts = 478
Difficulty = 10 size = 10485760 create = 25 seconds check = 0 seconds num of attempts = 478
Difficulty = 11 size = 10485760 create = 66 seconds check = 0 seconds num of attempts = 1268
Difficulty = 12 size = 10485760 create = 210 seconds check = 0 seconds num of attempts = 4032
Difficulty = 13 size = 10485760 create = 755 seconds check = 0 seconds num of attempts = 14860
Difficulty = 14 size = 10485760 create = 1039 seconds check = 0 seconds num of attempts = 20484
Difficulty = 15 size = 10485760 create = 1035 seconds check = 0 seconds num of attempts = 20484
Difficulty = 16 size = 10485760 create = 1849 seconds check = 0 seconds num of attempts = 36453
Difficulty = 17 size = 10485760 create = 2594 seconds check = 0 seconds num of attempts = 51130
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
work by you, as defined in the MaidSafe Contributor Agreement ([CONTRIBUTOR](CONTRIBUTOR)), shall be
dual licensed as above, and you agree to be bound by the terms of the MaidSafe Contributor Agreement.

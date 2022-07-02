# Repository layout

YASL is a fundamental library used in the secretflow stack. The major components are listed here:

- [base/](yasl/base/): Basic types and utils in yasl.
- [crypto/](yasl/crypto/): Crypto related utilities, say symmetric and asymmetric crypto, PRNG, hashing etc.
- [mpctools/](yasl/mpctools/): Common security building blocks in MPC world.
  - [dpf/](yasl/mpctools/dpf/): Distributed Point Function (DPF).
  - [ot/](yasl/mpctools/ot/): Various oblivious transfer primitives.
- [io/](yasl/io/): A simple streaming based io library.
- [link/](yasl/link/): A simple rpc based MPI framework. It provides the [SPMD](https://en.wikipedia.org/wiki/SPMD) parallel programming capability.

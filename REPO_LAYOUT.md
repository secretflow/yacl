# Repository layout

YACL is a fundamental library used in the SecretFlow stack. The major components are listed here:

- [base/](yacl/base/): Basic types and utils in yacl.
- [crypto/](yacl/crypto/): Crypto tools, primitives, utilities.
  - [core/](yacl/crypto/base): Standarized crypto functions, i.e. symmetric and asymmetric crypto, PRNG, hashing.
  - [primitives/](yacl/crypto/primitives/): Cryptographic Primitives used by protocols
    - [dpf/](yacl/crypto/primitives/dpf/): Distributed Point Function (DPF).
    - [ot/](yacl/crypto/primitives/ot/): Oblivious transfer and oblivious transfer extensions.
  - [tools/](yacl/crypto/tools/): Theoretical cryptographic tools such as Random Oracle (RO), Pseudorandom Generator (PRG).
  - [utils/](yacl/crypto/utils/): Easy-to-use cryptographic utilities, designed with succinctness in mind.
- [io/](yacl/io/): A simple streaming based io library.
- [link/](yacl/link/): A simple rpc based MPI framework. It provides the [SPMD](https://en.wikipedia.org/wiki/SPMD) parallel programming capability.

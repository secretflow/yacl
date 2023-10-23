# YACL (Yet Another Common crypto Library)

## MOOC Test Only

[![CircleCI](https://dl.circleci.com/status-badge/img/gh/secretflow/yacl/tree/main.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/gh/secretflow/yacl/tree/main)

A C++ library that contains common cryptgraphy, network and io modules which other SecretFlow code depends on.

Repo layout:

- [base](yacl/base/): some basic types and utils in yacl.
- [crypto](yacl/crypto/): a crypto library desigend for secure computation and so on.
  - [base](yacl/crypto/base): **basic/standarized crypto**, i.e. AES, DRBG, hashing.
  - [primitives](yacl/crypto/primitives/): **crypto primitives**, i.e. OT, DPF.
  - [tools](yacl/crypto/tools/): **theoretical crypto tools**, i.e. Random Oracle (RO), PRG.
  - [utils](yacl/crypto/utils/): easy-to-use **crypto utilities**.
- [io](yacl/io/): a simple streaming-based io library.
- [link](yacl/link/): a simple rpc-based MPI framework, providing the [SPMD](https://en.wikipedia.org/wiki/SPMD) parallel programming capability.

## Supported Crypto Primitives

Oblivious Transfer (and extensions)

- [Simplest OT](https://eprint.iacr.org/2015/267.pdf): 1-out-of-2 OT
- [IKNP OTe](https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf): 1-out-of-2 OT extension
- [Ferret OTe](https://eprint.iacr.org/2020/924): 1-out-of-2 OT extension
- [KKRT OTe](https://eprint.iacr.org/2016/799.pdf): 1-out-of-n OT (a.k.a OPRF)
- [SGRR OTe](https://eprint.iacr.org/2019/1084.pdf): (n-1)-out-of-n OTe
- [GYWZ+ OTe](https://eprint.iacr.org/2022/1431.pdf): (n-1)-out-of-n OTe with correlated GGM tree optimizations

Distributed Point Function

- [BGI16](https://eprint.iacr.org/2018/707.pdf)

Threshold Proxy-Re-encryption

- A substitute of [umbral](https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf). Our implementation supports SM2, SM3 and SM4.

## Build

### Prerequisite

#### Linux
```sh
Install gcc>=10.3, cmake, ninja, nasm
```

#### macOS
```sh
# Install Xcode
https://apps.apple.com/us/app/xcode/id497799835?mt=12

# Select Xcode toolchain version
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer

# Install homebrew
https://brew.sh/

# Install dependencies
brew install bazel cmake ninja nasm automake libtool
```

### Build & UnitTest
``` sh
# build as debug
bazel build //... -c dbg

# build as release
bazel build //... -c opt

# test
bazel test //...

# [optional] build & test with ASAN if you're not on MacOS
bazel build //... -c dbg --config=asan
bazel test //... --config=asan -c dbg

# [optional] build & test with ASAN on MacOS
bazel build //... -c dbg --config=macos-asan
bazel test //... --config=macos-asan -c dbg
```

# License

See [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md)

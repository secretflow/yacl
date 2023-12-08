# YACL (Yet Another Common crypto Library)

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

## Supported Crypto Algorithms

See **Full List** of supported algorithms: [ALGORITHMS.md](ALGORITHMS.md)

**Selected algorithms**:

- Oblivious Transfer (and extensions): [Simplest OT](https://eprint.iacr.org/2015/267.pdf), [IKNP OTe](https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf), [Ferret OTe](https://eprint.iacr.org/2020/924), [KKRT OTe](https://eprint.iacr.org/2016/799.pdf), [SGRR OTe](https://eprint.iacr.org/2019/1084.pdf).
- VOLE: [Silent VOLE](https://eprint.iacr.org/2019/1159.pdf), [Sparse VOLE (GF128)](https://eprint.iacr.org/2019/1084.pdf)
- Distributed Point Function: [BGI16](https://eprint.iacr.org/2018/707.pdf)
- Threshold Proxy-Re-encryption: [umbral with GM](https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf).

## Build

### Supported platforms

|     | Linux x86_64 | Linux aarch64 | macOS x86_64 | macOS Apple Silicon | Windows x86_64 | Windows WSL2 x86_64 |
|-----|--------------|---------------|--------------|---------------------|----------------|---------------------|
| CPU | yes          | yes           | yes          | yes                 | no             | yes                 |

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

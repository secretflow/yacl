# YACL (Yet Another Common crypto Library)

[![CircleCI](https://dl.circleci.com/status-badge/img/gh/secretflow/yacl/tree/main.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/gh/secretflow/yacl/tree/main)

Yacl is a C++ library that contains common cryptgraphy, network and io modules which other SecretFlow code depends on. The crypto modules in Yacl implement many state-of-art secure computation protocols, including primitives like OT, VOLE, TPRE, and tools like PRG, RO. Check the full list of Yacl's supported algorithms in [ALGORITHMS.md](ALGORITHMS.md).

Supported platforms:
- Linux x86_64
- Linux aarch64
- macOS x86_64
- macOS Apple Silicon
- Windows WSL2 x86_64

Note: Yacl has not been tested on Windows x86_64.


## Overview

Yacl includes the following folders:

- [base](yacl/base/): some basic types and utils in yacl.
- [crypto](yacl/crypto/): a crypto library desigend for secure computation and so on.
  - [base](yacl/crypto/base): **basic/standarized crypto**, i.e. AES, hashing.
  - [primitives](yacl/crypto/primitives/): **crypto primitives**, i.e. OT, DPF.
  - [tools](yacl/crypto/tools/): **theoretical crypto tools**, i.e. Random Oracle (RO), PRG.
  - [utils](yacl/crypto/utils/): easy-to-use **crypto utilities**.
- [io](yacl/io/): a simple streaming-based io library.
- [link](yacl/link/): a simple rpc-based MPI framework, providing the [SPMD](https://en.wikipedia.org/wiki/SPMD) parallel programming capability.


## Getting Started

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
brew install bazel cmake ninja nasm automake libtool libomp
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

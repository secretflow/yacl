# YACL (Yet Another Crypto Library) 

[![CircleCI](https://dl.circleci.com/status-badge/img/gh/secretflow/yacl/tree/main.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/gh/secretflow/yacl/tree/main)

A C++ library that contains cryptgraphy, network and io modules which other SecretFlow code depends on.

Repo layout:

- [base](yacl/base/): some basic types and utils in yacl.
- [crypto](yacl/crypto/): a crypto library desigend for secure computation and so on.
  - [base](yacl/crypto/base): **basic/standarized crypto**, i.e. AES, DRBG, hashing.
  - [primitives](yacl/crypto/primitives/): **crypto primitives**, i.e. OT, DPF.
  - [tools](yacl/crypto/tools/): **theoretical crypto tools**, i.e. Random Oracle (RO), PRG.
  - [utils](yacl/crypto/utils/): easy-to-use **crypto utilities**.
- [io](yacl/io/): a simple streaming-based io library.
- [link](yacl/link/): a simple rpc-based MPI framework, providing the [SPMD](https://en.wikipedia.org/wiki/SPMD) parallel programming capability.


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

# [optional] build & test with ASAN
bazel build //... -c dbg --config=asan
bazel test //... --config=asan -c dbg
```

### Bazel build options

- `--define gperf=on` enable gperf
- `--define tracelog=on` enable link trace log.


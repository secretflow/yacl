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

## Prerequisites

- **bazel**: the recommended verion is described in [.bazelversion](.bazelversion) file. We recommend to use the official [bazelisk](https://github.com/bazelbuild/bazelisk?tab=readme-ov-file#installation) to manage bazel version.
- **gcc >= 10.3**
- **[cmake](https://cmake.org/getting-started/)**
- **[ninja/ninja-build](https://ninja-build.org/)**
- **Perl 5 with core modules** (Required by [OpenSSL](https://github.com/openssl/openssl/blob/master/INSTALL.md#prerequisites))

## Build & UnitTest
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

# YACL (Yet Another Common crypto Library)

[![CircleCI](https://dl.circleci.com/status-badge/img/gh/secretflow/yacl/tree/main.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/gh/secretflow/yacl/tree/main)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/secretflow/yacl/badge)](https://securityscorecards.dev/viewer/?uri=github.com/secretflow/yacl)

Yacl is a C++ library that contains common cryptgraphy, network and io modules which other SecretFlow code depends on. The crypto modules in Yacl implement many state-of-art secure computation protocols, including primitives like OT, VOLE, TPRE, and tools like PRG, RO. Check the full list of Yacl's supported algorithms in [ALGORITHMS.md](ALGORITHMS.md).

Supported platforms:
| Linux x86_64 | Linux aarch64 | macOS x86_64   | macOS Apple Silicon | Windows x86_64 | Windows WSL2 x86_64 |
|--------------|---------------|----------------|---------------------|----------------|---------------------|
| yes          | yes           | yes<sup>1</sup>| yes                 | no             | yes<sup>1</sup>     |

1. Yacl has not been thoroughly tested on these platforms.

## Repo Layout

- [base](yacl/base/): some basic types and utils in yacl.
- [crypto](yacl/crypto/): **crypto algorithms** without [link](yacl/link/).
- [kernel](yacl/kernel/): **crypto kernel** that includes [link](yacl/link/) with multi-thread support, i.e. OT, DPF.
- [io](yacl/io/): a simple streaming-based io library.
- [link](yacl/link/): a simple rpc-based MPI framework, providing the [SPMD](https://en.wikipedia.org/wiki/SPMD) parallel programming capability.

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

## License

See [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md)

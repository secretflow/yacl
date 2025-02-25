# Getting Started

This document includes guidelines.

## Prerequisites

To build Yacl from source, you will need the following tools:

- [bazel](https://bazel.build/): We recommend to use the official [bazelisk](https://github.com/bazelbuild/bazelisk?tab=readme-ov-file#installation) to manage bazel version.
  - If not use bazelisk, please set the environment variable `USE_BAZEL_VERSION` to the specified version, which can be found in the `.bazeliskrc` file.
- [gcc >= 10.3](https://gcc.gnu.org/)
- [cmake](https://cmake.org/)
- [ninja/ninja-build](https://ninja-build.org/)
- **Perl 5 with core modules** (Required by [OpenSSL](https://github.com/openssl/openssl/blob/master/INSTALL.md#prerequisites))

## Download and build

Please make sure you already have `git` installed on your system, then clone Yacl via the github link,

```sh
$ git clone https://github.com/secretflow/yacl.git
```

The building process of YACL is as following.

### Ubuntu

Download the dependencies

```sh
$ sudo apt install gcc wget cmake ninja-build nasm automake libtool libomp-dev
```

We recommend to use `bazelisk` to manage different versions of `bazel`. On Linux, You can download Bazelisk binary on our Releases page and add it to your PATH manually, which also works on macOS and Windows. You can download the newest `bazelisk` binary from its official [github release page](https://github.com/bazelbuild/bazelisk/releases).

The following is an example of downloading and setting up bazelisk v1.20.0, you may change the tag `v1.20.0` to any latest version, or any version you prefer.

```sh
# If you use a x86 architecture cpu
$ wget https://github.com/bazelbuild/bazelisk/releases/download/v1.20.0/bazelisk-linux-amd64
$ mv bazelisk-linux-amd64 bazelisk && chmod +x bazelisk
$ sudo mv bazelisk /usr/local/bin # you need sudo to do this

# If you use an arm architecture cpu
$ wget https://github.com/bazelbuild/bazelisk/releases/download/v1.20.0/bazelisk-linux-arm64
$ mv bazelisk-linux-arm64 bazelisk && chmod +x bazelisk
$ sudo mv bazelisk /usr/local/bin # you need sudo to do this
```

To build Yacl, at yacl's root directory, run the following

```sh
$ bazelisk build //yacl/...
$ bazelisk build //yacl/... -c opt        # build as optimized mode
$ bazelisk build //yacl/... -c dbg        # build as debug mode
$ bazelisk build //yacl/... --config gm   # build with gm mode
```

To test Yacl

```sh
$ bazelisk test //yacl/...
```

### MacOS

First you need to download XCode and [homebrew](https://brew.sh/),

```sh
# Install Xcode
$ https://apps.apple.com/us/app/xcode/id497799835?mt=12

# Select Xcode toolchain version
$ sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
```

Then download the dependencies,

```sh
# Install dependencies
$ brew install bazelisk cmake ninja nasm automake libtool libomp
```

To build Yacl, at yacl's root directory, run the following

```sh
$ bazelisk build //yacl/...
$ bazelisk build //yacl/... -c opt        # build as optimized mode
$ bazelisk build //yacl/... -c dbg        # build as debug mode
$ bazelisk build //yacl/... --config gm   # build with gm mode
```

To test Yacl

```sh
$ bazelisk test //yacl/...
```

## Setup compilation database for your lsp

Language servers accept a `compile_commands.json` file input to help it with linting, jumping to definitions/references, and other functions. This file consists of an array of “command objects”, where each command object specifies one way a translation unit is compiled in the project. A lot of modern C/C++ build system can generate this file with simple steps, it's the same for bazel.

```sh
$ git clone https://github.com/secretflow/devtools.git ../devtools
$ python3 ../devtools/refresh-compile-command-bazel-module.py
```

## (Optional) Recommended vscode extensions

We recommend to use the following extensions for vscode users:
- [Bazel](https://marketplace.visualstudio.com/items?itemName=BazelBuild.vscode-bazel): Bazel BUILD integration
- [clangd](https://marketplace.visualstudio.com/items?itemName=llvm-vs-code-extensions.vscode-clangd): C/C++ completion, navigation, and insights
- [cpplint](https://marketplace.visualstudio.com/items?itemName=mine.cpplint): code style check tool extension for cpplint (requires `cpplint` binary)

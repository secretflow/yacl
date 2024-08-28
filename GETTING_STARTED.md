# Getting Started Guide

This document includes guidelines.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Download and Build](#download-and-build)
  - [Ubuntu](#ubuntu)
  - [MacOS](#macos)
- [Setup Compilation Database for your lsp](#setup-compilation-database-for-your-lsp)
- [(Optional) Setup Vscode](#optional-setup-vscode)

## Prerequisites

To build Yacl from source, you will need the following tools:

- **bazel**: We recommend to use the official [bazelisk](https://github.com/bazelbuild/bazelisk?tab=readme-ov-file#installation) to manage bazel version.
- **gcc >= 10.3**
- **[cmake](https://cmake.org/getting-started/)**
- **[ninja/ninja-build](https://ninja-build.org/)**
- **Perl 5 with core modules** (Required by [OpenSSL](https://github.com/openssl/openssl/blob/master/INSTALL.md#prerequisites))

## Download and Build

Please make sure you already have `git` installed on your system, then clone Yacl

```sh
git clone https://github.com/secretflow/yacl
```

### Ubuntu

Download the dependencies

```sh
sudo apt install gcc wget cmake ninja-build nasm automake libtool
```

We recommend to use `bazelisk` to manage different versions of `bazel`. On Linux, You can download Bazelisk binary on our Releases page and add it to your PATH manually, which also works on macOS and Windows. You can download the newest `bazelisk` binary from its official [github release page](https://github.com/bazelbuild/bazelisk/releases).

The following is an example of downloading and setting up bazelisk v1.20.0, you may change the tag `v1.20.0` to any latest version, or any version you prefer.

```sh
# If you use a x86 architecture cpu
wget https://github.com/bazelbuild/bazelisk/releases/download/v1.20.0/bazelisk-linux-amd64
mv bazelisk-linux-amd64 bazel && chmod +x bazel
sudo mv bazel /usr/local/bin # you need sudo to do this

# If you use an arm architecture cpu
wget https://github.com/bazelbuild/bazelisk/releases/download/v1.20.0/bazelisk-linux-arm64
mv bazelisk-linux-arm64 bazel && chmod +x bazel
sudo mv bazel /usr/local/bin # you need sudo to do this
```

To build Yacl, at yacl's root directory, run the following

```sh
bazel build //...
bazel build //... -c opt        # build as optimized mode
bazel build //... -c dbg        # build as debug mode
bazel build //... --config gm   # build with gm mode
```

To test Yacl

```sh
bazel test //...
```

### MacOS

First you need to download XCode and [homebrew](https://brew.sh/),

```sh
# Install Xcode
https://apps.apple.com/us/app/xcode/id497799835?mt=12

# Select Xcode toolchain version
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
```

Then download the dependencies,

```
# Install dependencies
brew install bazelisk cmake ninja nasm automake libtool
```

To build Yacl, at yacl's root directory, run the following

```sh
bazel build //...
bazel build //... -c opt        # build as optimized mode
bazel build //... -c dbg        # build as debug mode
```

To test Yacl

```sh
bazel test //...
```

## Setup Compilation Database for your lsp

Language servers accept a `compile_commands.json` file input to help it with linting, jumping to definitions/references, and other functions. This file consists of an array of “command objects”, where each command object specifies one way a translation unit is compiled in the project. A lot of modern C/C++ build system can generate this file with simple steps, it's the same for bazel.

```sh
sudo apt install curl
cd /path/to/yacl/                                # change to yacl path
bash <(curl -s https://raw.githubusercontent.com/secretflow/devtools/9efb0bc93068a122864fdb661946695badacbe24/refresh_compile_commands.sh)
```

## (Optional) Setup Vscode

We recommend to use the following extensions for vscode users:
- Clang-Format: Use Clang-Format in Visual Studio Code
- cpplint: code style check tool extension for cpplint
- Bazel: Bazel BUILD integration
- clangd: C/C++ completion, navigation, and insights

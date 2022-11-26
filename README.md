# YACL: Yet Another Crypto library

YACL (Yet Another Crypto library) is a C++ library that contains modules and utilities which other SecretFlow code depends on.

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
brew install bazel cmake ninja nasm automake lbtool
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

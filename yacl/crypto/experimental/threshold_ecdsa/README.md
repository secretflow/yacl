# threshold_ecdsa

Research artifact for a C++20 prototype implementation of the GG2019 threshold
ECDSA protocol.

## Paper Reference

- Rosario Gennaro, Steven Goldfeder.
  *Fast Multiparty Threshold ECDSA with Fast Trustless Setup* (CCS 2019).

This repository now exposes a round-driven prototype layer and emphasizes:

- protocol-correct message flow,
- strict input validation and abort behavior,
- reproducible tests.

It is not a production-ready wallet or signing service.

## Scope of This Artifact

### Implemented Components

- Elliptic-curve scalar and point operations (`yacl::crypto::EcGroup` with the
  OpenSSL backend).
- Native Paillier encryption implementation (MPInt-based, no GMP or GMPXX
  dependency).
- Hashing, commitments, transcript/challenge utilities, and wire encoding.
- Round-driven threshold key generation
  (`tecdsa::proto::KeygenParty`, 3 rounds).
- Round-driven threshold signing (`tecdsa::proto::SignParty`, `Phase1` through
  `Phase5E`).
- Fixed prototype proof validation for square-free and auxiliary-parameter
  artifacts.

### Current Engineering Goal

The repository targets protocol engineering reproducibility, not hardened
deployment.

## Repository Layout

```text
common/        # bytes/secure_zeroize/error helpers
crypto/        # Scalar/ECPoint/Paillier/hash/commitment/encoding/transcript/proofs
net/           # Envelope byte codec retained for low-level encoding tests
protocol/      # Round-driven keygen/sign prototype API
tests/
  crypto_primitives_test.cc
  keygen_flow_test.cc
  sign_flow_test.cc
  sign_flow_test_cases.cc
  sign_flow_test_shared.h
  sign_flow_test_support.cc
  proto_keygen_smoke_test.cc
  proto_sign_smoke_test.cc
```

## Reproducibility

### Requirements

- CMake >= 3.22
- C++20 compiler (`clang++` or `g++`)
- libtommath (backend dependency of `yacl/math/mpint` / `MPInt`)
- OpenSSL `libcrypto`

### Build

```bash
cmake -S . -B build
cmake --build build -j
```

### Bazel

```bash
bazelisk build //yacl/crypto/experimental/threshold_ecdsa:tecdsa_core
bazelisk build //yacl/crypto/experimental/threshold_ecdsa/...
```

If your environment resolves `rules_foreign_cc` to `built_make` and fails on
`BootstrapGNUMake`, run with one-off toolchain flags:

```bash
bazelisk build //yacl/crypto/experimental/threshold_ecdsa:tecdsa_core \
  --extra_toolchains=@rules_foreign_cc//toolchains:preinstalled_make_toolchain,@rules_foreign_cc//toolchains:preinstalled_pkgconfig_toolchain
```

### Test Suite

Run all CMake tests:

```bash
ctest --test-dir build --output-on-failure
```

Run individual CMake executables:

```bash
./build/crypto_primitives_tests
./build/keygen_flow_tests
./build/sign_flow_tests
./build/proto_keygen_smoke_tests
./build/proto_sign_smoke_tests
```

Run Bazel test binaries:

```bash
bazelisk run //yacl/crypto/experimental/threshold_ecdsa:crypto_primitives_tests
bazelisk run //yacl/crypto/experimental/threshold_ecdsa:keygen_flow_tests
bazelisk run //yacl/crypto/experimental/threshold_ecdsa:sign_flow_tests
bazelisk run //yacl/crypto/experimental/threshold_ecdsa:proto_keygen_smoke_tests
bazelisk run //yacl/crypto/experimental/threshold_ecdsa:proto_sign_smoke_tests
```

Migration sanity check (should be zero hits in code files):

```bash
rg -n "#include <gmpxx.h>|\bmpz_class\b|\bmpz_" yacl/crypto/experimental/threshold_ecdsa --glob '!**/0*.txt' --glob '!**/*.md'
```

### Test Coverage Summary

- `crypto_primitives_tests`: basic crypto primitives and wire format checks.
- `proto_keygen_smoke_tests`: direct round-driven keygen smoke coverage.
- `proto_sign_smoke_tests`: direct round-driven sign smoke coverage.
- `keygen_flow_tests`: end-to-end keygen, proof validation, and adversarial
  tampering.
- `sign_flow_tests`: end-to-end signing, proof checks, and adversarial failure
  paths.

## Error Handling Style

- Runtime argument, logic, and runtime failures in module code are normalized
  through `common/errors.h` (`TECDSA_THROW*`) and map to YACL exception macros.

## Protocol Flow (Primary API)

### Keygen (`tecdsa::proto::KeygenParty`)

1. Round1: broadcast commitment and Paillier public parameters.
2. Round2: broadcast openings and send secret shares point-to-point.
3. Round3: broadcast `X_i = g^{x_i}` with Schnorr proof.
4. Finalization: aggregate `x_i`, `y`, all `X_i`, and Paillier/public proof
   artifacts.

### Sign (`tecdsa::proto::SignParty`)

1. Phase1: commit to `Gamma_i`.
2. Phase2: MtA and MtAwc interaction with Appendix-A style proof checks.
3. Phase3: broadcast `delta_i` and aggregate inversion path.
4. Phase4: open `Gamma_i`, verify proof, derive `R` and `r`.
5. Phase5A to Phase5E: commit/open rounds with relation proofs, then finalize
   `(r, s)`.

## Limitations

- No real network or transport layer is implemented in the prototype API.
- No claim of production security hardening.
- Intended for protocol implementation study and testing.

# threshold_ecdsa

Research artifact for a C++20 implementation of the GG2019 threshold ECDSA protocol.

## Paper Reference

- Rosario Gennaro, Steven Goldfeder.  
  *Fast Multiparty Threshold ECDSA with Fast Trustless Setup* (CCS 2019).

This repository implements protocol components as executable state machines and emphasizes:

- protocol-correct message flow,
- strict input validation and abort behavior,
- reproducible tests.

It is not a production-ready wallet/signing service.

## Scope of This Artifact

### Implemented Components

- Elliptic-curve scalar/point operations (`yacl::crypto::EcGroup` with openssl backend).
- Native Paillier encryption implementation (`yacl-native`).
- Hashing, commitments, transcript/challenge utilities, wire encoding.
- Session model with lifecycle management (`running/completed/aborted/timed-out`).
- In-memory transport and session routing.
- Threshold key generation (`KeygenSession`, 3 phases).
- Threshold signing (`SignSession`, Phase1 to Phase5E).
- Strict/dev gating for square-free and auxiliary-parameter proof artifacts.

### Current Engineering Goal

The repository targets protocol engineering reproducibility, not hardened deployment.

## Repository Layout

```text
common/        # bytes/secure_zeroize/thread_pool
crypto/        # Scalar/ECPoint/Paillier/hash/commitment/encoding/transcript/proofs
net/           # Envelope, transport interfaces, in-memory network
protocol/      # Session base, router, keygen/sign state machines
tests/
  crypto_primitives_test.cc
  protocol_infrastructure_test.cc
  keygen_flow_test.cc
  sign_flow_test.cc
```

## Reproducibility

### Requirements

- CMake >= 3.22
- C++20 compiler (`clang++`/`g++`)
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
bazelisk build //yacl/crypto/experimental/threshold_ecdsa:all
```

If your environment resolves `rules_foreign_cc` to `built_make` and fails on
`BootstrapGNUMake`, run with one-off toolchain flags:

```bash
bazelisk build //yacl/crypto/experimental/threshold_ecdsa:tecdsa_core \
  --extra_toolchains=@rules_foreign_cc//toolchains:preinstalled_make_toolchain,@rules_foreign_cc//toolchains:preinstalled_pkgconfig_toolchain
```

### Test Suite

Run all tests:

```bash
ctest --test-dir build --output-on-failure
```

Run individual executables:

```bash
./build/crypto_primitives_tests
./build/protocol_infrastructure_tests
./build/keygen_flow_tests
./build/sign_flow_tests
```

### Test Coverage Summary

- `crypto_primitives_tests`: basic crypto primitives and wire format checks.
- `protocol_infrastructure_tests`: transport/router/session skeleton behavior.
- `keygen_flow_tests`: end-to-end keygen, strict gating, and adversarial tampering.
- `sign_flow_tests`: end-to-end signing, proof checks, and adversarial failure paths.

## Error Handling Style

- Runtime argument/logic/runtime failures in module code are normalized through
  `common/errors.h` (`TECDSA_THROW*`) and map to YACL exception macros.

## Protocol Flow (Implemented)

### Keygen (`KeygenSession`)

1. Phase1: broadcast commitment + Paillier public parameters.
2. Phase2: broadcast opens/commitments and send shares point-to-point.
3. Phase3: broadcast `X_i = g^{x_i}` with Schnorr proof.
4. Finalization: aggregate `x_i`, `y`, all `X_i`, and Paillier/public proof artifacts.

### Sign (`SignSession`)

1. Phase1: commit to `Gamma_i`.
2. Phase2: MtA/MtAwc interaction with Appendix-A style proof checks.
3. Phase3: broadcast `delta_i` and aggregate inversion path.
4. Phase4: open `Gamma_i`, verify proof, derive `R` and `r`.
5. Phase5A~5E: commit/open rounds with relation proofs, then finalize `(r, s)`.

## Limitations

- Network layer is in-memory only (no real transport security/retransmission/persistence).
- No claim of production security hardening.
- Intended for protocol implementation study and testing.

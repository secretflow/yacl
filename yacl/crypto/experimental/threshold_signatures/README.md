# Threshold Signatures

## Introduction

This directory contains experimental C++20 implementations of threshold ECDSA
and threshold SM2. The two schemes have independent protocol flows and share
common cryptographic building blocks through `core/`.

The code is intended for protocol review and integration experiments. It does
not include transport, persistent storage, wallet integration, or production
hardening.

## Implementation

### Code Structure

1. `common/` defines shared aliases, participant ids, peer maps, and error
   helpers.
2. `core/` contains the shared primitives used by both schemes:
   - `algebra/`: curve point and scalar wrappers over YACL ECC.
   - `bigint/`: protocol-facing `MPInt` encoding and validation helpers.
   - `commitment/`, `transcript/`, `proof/`, `vss/`: commitment,
     Fiat-Shamir transcript, Schnorr proof, and Feldman VSS helpers.
   - `mta/`: semantic MtA/MtAwc session API and the corresponding proof
     primitives.
   - `paillier/`: Paillier provider, auxiliary RSA setup, and paper proof
     helpers.
   - `protocol/`: peer-message checks and a simple linear round driver.
   - `random/`, `suite/`: threshold-signature random helpers, suite
     descriptors, group contexts, and hash dispatch.
3. `ecdsa/` implements threshold ECDSA key generation, signing, relation
   proofs, and signature verification.
4. `sm2/` implements threshold SM2 key generation, offline presigning, online
   signing, identifiable-abort data types, SM2-specific proofs, ZID binding,
   and signature verification.
5. `tests/` contains executable ECDSA and SM2 flow tests.

### Threshold ECDSA

1. Key generation uses dealerless Feldman VSS, Paillier parameters, auxiliary
   RSA parameters, square-free/auxiliary proofs, and public-share checks.
2. `VerifiedPublicKeygenData` validates and owns the public keygen data consumed
   by signing.
3. Signing is exposed as explicit round methods on `SignParty`. The large
   signing flow is split by round, and `SigningMtaExchange` hides pairwise
   MtA/MtAwc message and proof details from the scheme-level round code.
4. Finalization verifies the produced ECDSA signature before returning it.

### Threshold SM2

1. Key generation derives SM2 public-key material from distributed `z_i` shares,
   pairwise MtA sigma shares, group relation proofs, square-free proofs, and
   Paillier auxiliary proof artifacts.
2. Offline presigning computes nonce/product state with MtAwc and validates the
   aggregate product relation.
3. Online signing binds the SM2 ZID digest, computes partial signatures, and
   returns identifiable-abort evidence for invalid partials when possible.

## Build / Test

Build all threshold-signature targets:

```bash
bazel build //yacl/crypto/experimental/threshold_signatures:all
```

Build individual libraries:

```bash
bazel build //yacl/crypto/experimental/threshold_signatures:tsig_core
bazel build //yacl/crypto/experimental/threshold_signatures:tsig_ecdsa
bazel build //yacl/crypto/experimental/threshold_signatures:tsig_sm2
```

Run the executable flow tests:

```bash
bazel run //yacl/crypto/experimental/threshold_signatures:sign_flow_tests
bazel run //yacl/crypto/experimental/threshold_signatures:sm2_sign_flow_tests
```

## Dependencies

- Elliptic-curve operations use YACL ECC support.
- Big integer operations use YACL `MPInt`.
- Random bytes are sourced through `yacl::crypto::SecureRandBytes`.
- Hashing is routed through YACL hash abstractions such as `SslHash` and
  `HashAlgorithm`.

## Notes

- The module keeps ECDSA and SM2 protocol messages separate and shares only
  primitives that are common to both schemes.
- Scheme-level code calls semantic MtA APIs such as `InitiatorInit`,
  `ResponderMid`, and `InitiatorEnd`; low-level proof construction and
  verification remain inside `core/mta`.
- `core/bigint` is a protocol adapter for encoding and validation. It should
  not be expanded into a mirror of the full `MPInt` API.

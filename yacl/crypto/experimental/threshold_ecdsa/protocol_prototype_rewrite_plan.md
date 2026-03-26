# threshold_ecdsa protocol prototype rewrite plan

## Goal

Rewrite `protocol/` from an envelope-driven session framework into a round-driven
prototype layer that maps directly to the GG2019 paper flow.

The current implementation intentionally adds protocol engineering structure:

- state-machine sessions,
- transport and router abstractions,
- lifecycle and timeout handling,
- envelope byte-codecs and message type dispatch,
- proof profile and compatibility plumbing.

That structure is useful for a research artifact, but it is larger than what is
needed for a paper-faithful prototype.

## Rewrite target

Introduce a new `tecdsa::proto` layer with:

- typed round messages instead of `Envelope`,
- explicit round APIs instead of `HandleEnvelope` and `MaybeAdvance*`,
- direct peer maps instead of router and transport dispatch,
- a single proof path instead of strict/dev/legacy compatibility branches.

The protocol layer should keep the paper-facing cryptographic checks, while
removing general-purpose protocol framework code.

## Keep vs remove

### Keep

- keygen 3-round structure,
- signing `Phase1`, `Phase2 request/response`, `Phase3`, `Phase4`,
  `Phase5A` to `Phase5E`,
- Feldman share verification,
- Paillier `N > q^8` checks,
- MtA and MtAwc proofs,
- Schnorr proofs and V-relation proofs,
- final ECDSA verification.

### Remove or collapse

- `Session`, `SessionRouter`, `ITransport`, `InMemoryTransport`,
- timeout and terminal-state lifecycle logic,
- `Envelope`-driven message dispatch,
- duplicate keygen/sign byte helper code,
- proof metadata compatibility and legacy payload branches,
- phase-local ready flags and seen-peer bookkeeping that exist only to support
  the session framework,
- custom phase2 thread-pool plumbing.

## New file layout

The target layout is:

- `protocol/messages.h`
  - typed round messages and shared protocol data structures
- `protocol/proto_common.h/.cc`
  - participant validation, shared algebra helpers, Schnorr helpers
- `protocol/keygen.h/.cc`
  - round-driven key generation prototype
- `protocol/sign.h/.cc`
  - round-driven signing prototype

The old `*_session*` files stay temporarily during the transition, then get
deleted after tests are switched.

## Public API direction

### keygen

```cpp
class KeygenParty {
 public:
  explicit KeygenParty(KeygenConfig cfg);

  KeygenRound1Msg MakeRound1();
  KeygenRound2Out MakeRound2(const PeerMap<KeygenRound1Msg>& peer_round1);
  KeygenRound3Msg MakeRound3(
      const PeerMap<KeygenRound2Broadcast>& peer_round2,
      const PeerMap<Scalar>& shares_for_self);
  KeygenOutput Finalize(const PeerMap<KeygenRound3Msg>& peer_round3);
};
```

### sign

```cpp
class SignParty {
 public:
  explicit SignParty(SignConfig cfg);

  SignRound1Msg MakeRound1();
  std::vector<SignRound2Request> MakeRound2Requests(
      const PeerMap<SignRound1Msg>& peer_round1);
  std::vector<SignRound2Response> MakeRound2Responses(
      const PeerMap<SignRound2Request>& requests_for_self);
  SignRound3Msg MakeRound3(
      const PeerMap<SignRound2Response>& responses_for_self);
  SignRound4Msg MakeRound4(const PeerMap<SignRound3Msg>& peer_round3);
  SignRound5AMsg MakeRound5A(const PeerMap<SignRound4Msg>& peer_round4);
  SignRound5BMsg MakeRound5B(const PeerMap<SignRound5AMsg>& peer_round5a);
  SignRound5CMsg MakeRound5C(const PeerMap<SignRound5BMsg>& peer_round5b);
  SignRound5DMsg MakeRound5D(const PeerMap<SignRound5CMsg>& peer_round5c);
  Scalar RevealRound5E() const;
  Signature Finalize(const PeerMap<SignRound5DMsg>& peer_round5d,
                     const PeerMap<Scalar>& peer_round5e);
};
```

## Proof path simplification

The prototype layer uses one fixed path:

- `BuildSquareFreeProofGmr98`
- `VerifySquareFreeProofGmr98`
- `BuildAuxRsaParamProofStrict`
- `VerifyAuxRsaParamProofStrict`

The protocol layer does not negotiate proof scheme metadata or support legacy
payload shapes. The current flexible proof surface remains in `crypto/` during
the transition, but new protocol code should call the fixed-path functions
directly.

## Transition stages

### Stage 1

- add this design document,
- add `tecdsa::proto` messages and common helpers,
- land a new round-driven `KeygenParty`,
- add a smoke test for the new keygen API,
- keep all existing session-based code and tests building.

### Stage 2

- land round-driven sign constructor and round1,
- extend sign round by round until end-to-end signing is supported,
- add dedicated round-driven sign tests.

### Stage 3

- switch existing flow tests to the new API,
- delete `session/router/transport` and old protocol session files,
- remove `protocol_infrastructure_tests`.

### Stage 4

- narrow `strict_proofs` public surface.

## Current landing scope

The current tree implements Stage 1 through Stage 4:

- new design doc,
- new `tecdsa::proto` shared types,
- new round-driven `KeygenParty`,
- new round-driven `SignParty` through full signing completion,
- new keygen and sign smoke tests,
- `keygen_flow_tests` rewritten on top of `tecdsa::proto`,
- `sign_flow_tests` rewritten on top of `tecdsa::proto`,
- deleted `session/router/transport` and old protocol session files,
- removed `protocol_infrastructure_tests`,
- updated README and build targets so the round-driven prototype layer is the
  primary documented and tested path,
- narrowed `strict_proofs` public surface to the single prototype proof path.

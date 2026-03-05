#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <unordered_set>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/protocol/keygen_session.h"

namespace tecdsa::keygen_internal {

inline constexpr size_t kCommitmentLen = 32;
inline constexpr size_t kPointCompressedLen = 33;
inline constexpr size_t kScalarLen = 32;
inline constexpr size_t kMaxOpenRandomnessLen = 1024;
inline constexpr size_t kMaxPaillierModulusFieldLen = 8192;
inline constexpr size_t kMaxProofBlobLen = 16384;
inline constexpr size_t kMaxProofFieldLen = 16384;
inline constexpr uint32_t kMinPaillierKeygenBits = 2048;
inline constexpr uint32_t kMinAuxRsaKeygenBits = 2048;
inline constexpr size_t kMaxPaillierKeygenAttempts = 32;
inline constexpr char kPhase1CommitDomain[] = "GG2019/keygen/phase1";
inline constexpr char kSchnorrProofId[] = "GG2019/Schnorr/v1";

void ValidateParticipantsOrThrow(const std::vector<PartyIndex>& participants,
                                 PartyIndex self_id);

std::unordered_set<PartyIndex> BuildPeerSet(const std::vector<PartyIndex>& participants,
                                            PartyIndex self_id);

void AppendU32Be(uint32_t value, Bytes* out);
uint32_t ReadU32Be(std::span<const uint8_t> input, size_t* offset);

void AppendSizedField(std::span<const uint8_t> field, Bytes* out);
Bytes ReadSizedField(std::span<const uint8_t> input,
                     size_t* offset,
                     size_t max_len,
                     const char* field_name);

void AppendPoint(const ECPoint& point, Bytes* out);
ECPoint ReadPoint(std::span<const uint8_t> input, size_t* offset);

void AppendScalar(const Scalar& scalar, Bytes* out);
Scalar ReadScalar(std::span<const uint8_t> input, size_t* offset);

void AppendMpIntField(const BigInt& value, Bytes* out);
BigInt ReadMpIntField(std::span<const uint8_t> input,
                      size_t* offset,
                      size_t max_len,
                      const char* field_name);

Scalar RandomNonZeroScalar();
Scalar EvaluatePolynomialAt(const std::vector<Scalar>& coefficients, PartyIndex party_id);

Scalar BuildSchnorrChallenge(const Bytes& session_id,
                             PartyIndex party_id,
                             const ECPoint& statement,
                             const ECPoint& a);

const BigInt& MinPaillierModulusQ8();
void ValidatePaillierPublicKeyOrThrow(const PaillierPublicKey& pub);

StrictProofVerifierContext BuildStrictProofContext(const Bytes& session_id,
                                                   PartyIndex prover_id);

bool StrictMetadataCompatible(const ProofMetadata& expected,
                              const ProofMetadata& candidate);

}  // namespace tecdsa::keygen_internal

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/strict_proofs.h"

namespace tecdsa::strict_proofs_internal {

inline constexpr char kSquareFreeProofIdWeak[] = "GG2019/SquareFreeDevDigest/v2";
inline constexpr char kAuxParamProofIdWeak[] = "GG2019/AuxParamDevDigest/v2";
inline constexpr char kSquareFreeProofIdStrict[] = "GG2019/SquareFreeStrictAlgebraic/v1";
inline constexpr char kSquareFreeProofIdGmr98[] = "GG2019/SquareFreeGMR98/v1";
inline constexpr char kAuxParamProofIdStrict[] = "GG2019/AuxParamStrictAlgebraic/v1";
inline constexpr char kSquareFreeSchemeIdWeak[] = "GG2019/DevDigestBinding/SquareFree/v2";
inline constexpr char kAuxParamSchemeIdWeak[] = "GG2019/DevDigestBinding/AuxParam/v2";
inline constexpr char kSquareFreeSchemeIdStrict[] = "GG2019/StrictAlgebraic/SquareFree/v1";
inline constexpr char kSquareFreeSchemeIdGmr98[] = "GG2019/GMR98/SquareFree/v1";
inline constexpr char kAuxParamSchemeIdStrict[] = "GG2019/StrictAlgebraic/AuxParam/v1";

inline constexpr uint32_t kProofWireMagicV1 = 0x53505231;  // "SPR1"
inline constexpr uint32_t kProofWireMagicV2 = 0x53505232;  // "SPR2"
inline constexpr uint32_t kDevProofVersion = 1;
inline constexpr uint32_t kStrictAlgebraicVersion = 1;
inline constexpr uint32_t kSquareFreeGmr98Version = 1;
inline constexpr size_t kMaxSchemeIdLen = 256;
inline constexpr size_t kStrictNonceLen = 32;
inline constexpr size_t kMaxStrictNonceLen = 256;
inline constexpr size_t kMaxStrictFieldLen = 8192;
inline constexpr size_t kSquareFreeGmr98Rounds = 24;
inline constexpr size_t kMaxSquareFreeGmr98Rounds = 128;
inline constexpr size_t kMaxSquareFreeGmr98ChallengeAttempts = 64;
inline constexpr size_t kMaxAuxParamGenerationAttempts = 128;

struct SquareFreeStrictPayload {
  Bytes nonce;
  BigInt y;
  BigInt t1;
  BigInt t2;
  BigInt z1;
  BigInt z2;
};

struct SquareFreeGmr98Payload {
  Bytes nonce;
  uint32_t rounds = 0;
  std::vector<BigInt> roots;
};

struct AuxParamStrictPayload {
  Bytes nonce;
  BigInt c1;
  BigInt c2;
  BigInt t1;
  BigInt t2;
  BigInt z;
};

struct AuxRsaParamsBigInt {
  BigInt n_tilde;
  BigInt h1;
  BigInt h2;
};

bool HasContextBinding(const StrictProofVerifierContext& context);

ProofMetadata MakeWeakMetadata(const char* scheme_id);
ProofMetadata MakeStrictMetadata(const char* scheme_id,
                                 const StrictProofVerifierContext& context);
ProofMetadata MakeSquareFreeGmr98Metadata(const StrictProofVerifierContext& context);

Bytes EncodeProofWire(const ProofMetadata& metadata, std::span<const uint8_t> blob);
std::pair<ProofMetadata, Bytes> DecodeProofWire(std::span<const uint8_t> encoded,
                                                size_t max_len);

BigInt RandomBelow(const BigInt& upper_exclusive);
BigInt RandomZnStar(const BigInt& modulus_n);
bool IsZnStarResidue(const BigInt& value, const BigInt& modulus);
BigInt NormalizeMod(const BigInt& value, const BigInt& modulus);
BigInt MulMod(const BigInt& lhs, const BigInt& rhs, const BigInt& modulus);
BigInt PowMod(const BigInt& base, const BigInt& exp, const BigInt& modulus);
std::optional<BigInt> InvertMod(const BigInt& value, const BigInt& modulus);
bool IsPerfectSquare(const BigInt& value);

Bytes BuildWeakDigestFromFields(
    const char* proof_id,
    const StrictProofVerifierContext& context,
    const std::array<std::pair<const char*, Bytes>, 1>& fields);
Bytes BuildWeakDigestFromFields(
    const char* proof_id,
    const StrictProofVerifierContext& context,
    const std::array<std::pair<const char*, Bytes>, 3>& fields);

Scalar BuildSquareFreeStrictChallenge(const BigInt& modulus_n,
                                      const StrictProofVerifierContext& context,
                                      std::span<const uint8_t> nonce,
                                      const BigInt& y,
                                      const BigInt& t1,
                                      const BigInt& t2);

AuxRsaParamsBigInt ToBigIntParams(const AuxRsaParams& params);

Scalar BuildAuxParamStrictChallenge(const AuxRsaParamsBigInt& params,
                                    const StrictProofVerifierContext& context,
                                    std::span<const uint8_t> nonce,
                                    const BigInt& c1,
                                    const BigInt& c2,
                                    const BigInt& t1,
                                    const BigInt& t2);

BigInt DeriveSquareFreeGmr98Challenge(const BigInt& modulus_n,
                                      const StrictProofVerifierContext& context,
                                      std::span<const uint8_t> nonce,
                                      uint32_t round_idx);

Bytes EncodeSquareFreeStrictPayload(const SquareFreeStrictPayload& payload);
SquareFreeStrictPayload DecodeSquareFreeStrictPayload(std::span<const uint8_t> blob);

Bytes EncodeSquareFreeGmr98Payload(const SquareFreeGmr98Payload& payload);
SquareFreeGmr98Payload DecodeSquareFreeGmr98Payload(std::span<const uint8_t> blob);

Bytes EncodeAuxParamStrictPayload(const AuxParamStrictPayload& payload);
AuxParamStrictPayload DecodeAuxParamStrictPayload(std::span<const uint8_t> blob);

BigInt PickCoprimeDeterministic(const BigInt& modulus, const BigInt& seed);

}  // namespace tecdsa::strict_proofs_internal

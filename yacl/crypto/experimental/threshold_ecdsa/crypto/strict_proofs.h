#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/types.h"
#include "yacl/math/mpint/mp_int.h"

namespace tecdsa {

using BigInt = yacl::math::MPInt;

enum class StrictProofScheme : uint32_t {
  kUnknown = 0,
  // Development-only hash binding placeholder.
  kDevDigestBindingV1 = 1,
  // Transcript/algebraic strict proof path used by this implementation.
  kStrictAlgebraicV1 = 2,
  // Reserved for future strict external/cryptographic proofs.
  kStrictExternalV1 = 3,
  // Reserved for the future GG2019/[21] square-free proof track.
  kSquareFreeGmr98V1 = 4,
};

enum StrictProofCapability : uint32_t {
  kProofCapabilityNone = 0,
  kProofCapabilityAlgebraicChecks = 1u << 0,
  kProofCapabilityFreshRandomness = 1u << 1,
  kProofCapabilityContextBinding = 1u << 2,
  kProofCapabilityHeuristicChecks = 1u << 3,
  kProofCapabilityStrictReady = 1u << 31,
};

struct ProofMetadata {
  StrictProofScheme scheme = StrictProofScheme::kUnknown;
  uint32_t version = 0;
  uint32_t capability_flags = kProofCapabilityNone;
  std::string scheme_id;
};

struct StrictProofVerifierContext {
  Bytes session_id;
  std::optional<PartyIndex> prover_id;
  std::optional<PartyIndex> verifier_id;
};

struct AuxRsaParams {
  BigInt n_tilde = BigInt(0);
  BigInt h1 = BigInt(0);
  BigInt h2 = BigInt(0);
};

struct SquareFreeProof {
  ProofMetadata metadata;
  Bytes blob;
};

struct AuxRsaParamProof {
  ProofMetadata metadata;
  Bytes blob;
};

bool IsZnStarElement(const BigInt& value, const BigInt& modulus);
bool ValidateAuxRsaParams(const AuxRsaParams& params);
bool IsLikelySquareFreeModulus(const BigInt& modulus_n);
bool IsStrictProofScheme(StrictProofScheme scheme);
bool IsDevProofScheme(StrictProofScheme scheme);
bool HasProofCapability(const ProofMetadata& metadata, uint32_t capability_mask);
bool IsProofMetadataCompatible(const ProofMetadata& expected,
                               const ProofMetadata& candidate,
                               bool require_strict_scheme);

Bytes EncodeSquareFreeProof(const SquareFreeProof& proof);
SquareFreeProof DecodeSquareFreeProof(std::span<const uint8_t> encoded, size_t max_len = 4096);

Bytes EncodeAuxRsaParamProof(const AuxRsaParamProof& proof);
AuxRsaParamProof DecodeAuxRsaParamProof(std::span<const uint8_t> encoded, size_t max_len = 4096);

AuxRsaParams DeriveAuxRsaParamsFromModulus(const BigInt& modulus_n, PartyIndex party_id);
AuxRsaParams GenerateAuxRsaParams(uint32_t modulus_bits, PartyIndex party_id);

SquareFreeProof BuildSquareFreeProof(
    const BigInt& modulus_n,
    const StrictProofVerifierContext& context = {});
SquareFreeProof BuildSquareFreeProofGmr98(
    const BigInt& modulus_n,
    const StrictProofVerifierContext& context = {});
SquareFreeProof BuildSquareFreeProofGmr98(
    const BigInt& modulus_n,
    const BigInt& lambda_n,
    const StrictProofVerifierContext& context = {});
SquareFreeProof BuildSquareFreeProofWeak(
    const BigInt& modulus_n,
    const StrictProofVerifierContext& context = {});
SquareFreeProof BuildSquareFreeProofStrict(
    const BigInt& modulus_n,
    const StrictProofVerifierContext& context = {});
bool VerifySquareFreeProof(const BigInt& modulus_n,
                           const SquareFreeProof& proof,
                           const StrictProofVerifierContext& context = {});
bool VerifySquareFreeProofGmr98(const BigInt& modulus_n,
                                const SquareFreeProof& proof,
                                const StrictProofVerifierContext& context = {});
bool VerifySquareFreeProofWeak(const BigInt& modulus_n,
                               const SquareFreeProof& proof,
                               const StrictProofVerifierContext& context = {});
bool VerifySquareFreeProofStrict(const BigInt& modulus_n,
                                 const SquareFreeProof& proof,
                                 const StrictProofVerifierContext& context = {});

AuxRsaParamProof BuildAuxRsaParamProof(
    const AuxRsaParams& params,
    const StrictProofVerifierContext& context = {});
AuxRsaParamProof BuildAuxRsaParamProofWeak(
    const AuxRsaParams& params,
    const StrictProofVerifierContext& context = {});
AuxRsaParamProof BuildAuxRsaParamProofStrict(
    const AuxRsaParams& params,
    const StrictProofVerifierContext& context = {});
bool VerifyAuxRsaParamProof(const AuxRsaParams& params,
                            const AuxRsaParamProof& proof,
                            const StrictProofVerifierContext& context = {});
bool VerifyAuxRsaParamProofWeak(const AuxRsaParams& params,
                                const AuxRsaParamProof& proof,
                                const StrictProofVerifierContext& context = {});
bool VerifyAuxRsaParamProofStrict(const AuxRsaParams& params,
                                  const AuxRsaParamProof& proof,
                                  const StrictProofVerifierContext& context = {});

}  // namespace tecdsa

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/strict_proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/hash.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/random.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/transcript.h"

namespace tecdsa {
namespace {

constexpr char kSquareFreeProofIdWeak[] = "GG2019/SquareFreeDevDigest/v2";
constexpr char kAuxParamProofIdWeak[] = "GG2019/AuxParamDevDigest/v2";
constexpr char kSquareFreeProofIdStrict[] = "GG2019/SquareFreeStrictAlgebraic/v1";
constexpr char kSquareFreeProofIdGmr98[] = "GG2019/SquareFreeGMR98/v1";
constexpr char kAuxParamProofIdStrict[] = "GG2019/AuxParamStrictAlgebraic/v1";
constexpr char kSquareFreeSchemeIdWeak[] = "GG2019/DevDigestBinding/SquareFree/v2";
constexpr char kAuxParamSchemeIdWeak[] = "GG2019/DevDigestBinding/AuxParam/v2";
constexpr char kSquareFreeSchemeIdStrict[] = "GG2019/StrictAlgebraic/SquareFree/v1";
constexpr char kSquareFreeSchemeIdGmr98[] = "GG2019/GMR98/SquareFree/v1";
constexpr char kAuxParamSchemeIdStrict[] = "GG2019/StrictAlgebraic/AuxParam/v1";

constexpr uint32_t kProofWireMagicV1 = 0x53505231;  // "SPR1"
constexpr uint32_t kProofWireMagicV2 = 0x53505232;  // "SPR2"
constexpr uint32_t kDevProofVersion = 1;
constexpr uint32_t kStrictAlgebraicVersion = 1;
constexpr uint32_t kSquareFreeGmr98Version = 1;
constexpr size_t kMaxSchemeIdLen = 256;
constexpr size_t kStrictNonceLen = 32;
constexpr size_t kMaxStrictNonceLen = 256;
constexpr size_t kMaxStrictFieldLen = 8192;
constexpr size_t kSquareFreeGmr98Rounds = 24;
constexpr size_t kMaxSquareFreeGmr98Rounds = 128;
constexpr size_t kMaxSquareFreeGmr98ChallengeAttempts = 64;
constexpr size_t kMaxAuxParamGenerationAttempts = 128;

BigInt MpzToMpInt(const mpz_class& value) {
  return BigInt(value.get_str(10), 10);
}

mpz_class MpIntToMpz(const BigInt& value) {
  mpz_class out;
  const std::string decimal = value.ToString();
  if (mpz_set_str(out.get_mpz_t(), decimal.c_str(), 10) != 0) {
    TECDSA_THROW("failed to convert MPInt to mpz_class");
  }
  return out;
}

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

void AppendU32Be(uint32_t value, Bytes* out) {
  out->push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out->push_back(static_cast<uint8_t>(value & 0xFF));
}

uint32_t ReadU32Be(std::span<const uint8_t> input, size_t* offset) {
  if (*offset + 4 > input.size()) {
    TECDSA_THROW_ARGUMENT("Not enough bytes to read u32");
  }

  const size_t i = *offset;
  *offset += 4;
  return (static_cast<uint32_t>(input[i]) << 24) |
         (static_cast<uint32_t>(input[i + 1]) << 16) |
         (static_cast<uint32_t>(input[i + 2]) << 8) |
         static_cast<uint32_t>(input[i + 3]);
}

void AppendSizedField(std::span<const uint8_t> field, Bytes* out) {
  if (field.size() > UINT32_MAX) {
    TECDSA_THROW_ARGUMENT("sized field exceeds uint32 length");
  }
  AppendU32Be(static_cast<uint32_t>(field.size()), out);
  out->insert(out->end(), field.begin(), field.end());
}

Bytes ReadSizedField(std::span<const uint8_t> input,
                     size_t* offset,
                     size_t max_len,
                     const char* field_name) {
  const uint32_t len = ReadU32Be(input, offset);
  if (len > max_len) {
    TECDSA_THROW_ARGUMENT(std::string(field_name) + " exceeds maximum length");
  }
  if (*offset + len > input.size()) {
    TECDSA_THROW_ARGUMENT(std::string(field_name) + " has inconsistent length");
  }

  Bytes out(input.begin() + static_cast<std::ptrdiff_t>(*offset),
            input.begin() + static_cast<std::ptrdiff_t>(*offset + len));
  *offset += len;
  return out;
}

void AppendMpIntField(const BigInt& value, Bytes* out) {
  const Bytes encoded = EncodeMpInt(value);
  AppendSizedField(encoded, out);
}

BigInt ReadMpIntField(std::span<const uint8_t> input, size_t* offset, const char* field_name) {
  const Bytes encoded = ReadSizedField(input, offset, kMaxStrictFieldLen, field_name);
  return DecodeMpInt(encoded, kMaxStrictFieldLen);
}

uint32_t EncodeStrictProofScheme(StrictProofScheme scheme) {
  return static_cast<uint32_t>(scheme);
}

StrictProofScheme DecodeStrictProofScheme(uint32_t raw) {
  switch (raw) {
    case static_cast<uint32_t>(StrictProofScheme::kUnknown):
      return StrictProofScheme::kUnknown;
    case static_cast<uint32_t>(StrictProofScheme::kDevDigestBindingV1):
      return StrictProofScheme::kDevDigestBindingV1;
    case static_cast<uint32_t>(StrictProofScheme::kStrictAlgebraicV1):
      return StrictProofScheme::kStrictAlgebraicV1;
    case static_cast<uint32_t>(StrictProofScheme::kStrictExternalV1):
      return StrictProofScheme::kStrictExternalV1;
    case static_cast<uint32_t>(StrictProofScheme::kSquareFreeGmr98V1):
      return StrictProofScheme::kSquareFreeGmr98V1;
    default:
      return StrictProofScheme::kUnknown;
  }
}

ProofMetadata MakeWeakMetadata(const char* scheme_id) {
  return ProofMetadata{
      .scheme = StrictProofScheme::kDevDigestBindingV1,
      .version = kDevProofVersion,
      .capability_flags = kProofCapabilityNone,
      .scheme_id = scheme_id,
  };
}

bool HasContextBinding(const StrictProofVerifierContext& context) {
  return !context.session_id.empty() || context.prover_id.has_value() || context.verifier_id.has_value();
}

ProofMetadata MakeStrictMetadata(const char* scheme_id, const StrictProofVerifierContext& context) {
  uint32_t capability_flags =
      kProofCapabilityStrictReady |
      kProofCapabilityAlgebraicChecks |
      kProofCapabilityFreshRandomness;
  if (HasContextBinding(context)) {
    capability_flags |= kProofCapabilityContextBinding;
  }

  return ProofMetadata{
      .scheme = StrictProofScheme::kStrictAlgebraicV1,
      .version = kStrictAlgebraicVersion,
      .capability_flags = capability_flags,
      .scheme_id = scheme_id,
  };
}

ProofMetadata MakeSquareFreeGmr98Metadata(const StrictProofVerifierContext& context) {
  uint32_t capability_flags =
      kProofCapabilityStrictReady |
      kProofCapabilityAlgebraicChecks |
      kProofCapabilityFreshRandomness |
      kProofCapabilityHeuristicChecks;
  if (HasContextBinding(context)) {
    capability_flags |= kProofCapabilityContextBinding;
  }

  return ProofMetadata{
      .scheme = StrictProofScheme::kSquareFreeGmr98V1,
      .version = kSquareFreeGmr98Version,
      .capability_flags = capability_flags,
      .scheme_id = kSquareFreeSchemeIdGmr98,
  };
}

void AppendVerifierContext(Transcript* transcript, const StrictProofVerifierContext& context) {
  if (!context.session_id.empty()) {
    transcript->append_session_id(context.session_id);
  }
  if (context.prover_id.has_value()) {
    transcript->append_u32_be("prover_id", *context.prover_id);
  }
  if (context.verifier_id.has_value()) {
    transcript->append_u32_be("verifier_id", *context.verifier_id);
  }
}

Bytes EncodeProofWire(const ProofMetadata& metadata, std::span<const uint8_t> blob) {
  // Preserve legacy format for unknown metadata, where payload is raw blob only.
  if (metadata.scheme == StrictProofScheme::kUnknown &&
      metadata.version == 0 &&
      metadata.capability_flags == kProofCapabilityNone &&
      metadata.scheme_id.empty()) {
    return Bytes(blob.begin(), blob.end());
  }

  if (blob.size() > UINT32_MAX) {
    TECDSA_THROW_ARGUMENT("proof blob exceeds uint32 length");
  }
  if (metadata.scheme_id.size() > UINT32_MAX || metadata.scheme_id.size() > kMaxSchemeIdLen) {
    TECDSA_THROW_ARGUMENT("proof scheme id exceeds maximum length");
  }

  Bytes out;
  out.reserve(24 + metadata.scheme_id.size() + blob.size());
  AppendU32Be(kProofWireMagicV2, &out);
  AppendU32Be(EncodeStrictProofScheme(metadata.scheme), &out);
  AppendU32Be(metadata.version, &out);
  AppendU32Be(metadata.capability_flags, &out);
  AppendU32Be(static_cast<uint32_t>(metadata.scheme_id.size()), &out);
  AppendU32Be(static_cast<uint32_t>(blob.size()), &out);
  out.insert(out.end(), metadata.scheme_id.begin(), metadata.scheme_id.end());
  out.insert(out.end(), blob.begin(), blob.end());
  return out;
}

std::pair<ProofMetadata, Bytes> DecodeProofWire(std::span<const uint8_t> encoded, size_t max_len) {
  if (encoded.empty()) {
    return {ProofMetadata{}, Bytes{}};
  }

  if (encoded.size() >= 24) {
    size_t offset = 0;
    const uint32_t magic = ReadU32Be(encoded, &offset);
    if (magic == kProofWireMagicV2) {
      ProofMetadata metadata;
      metadata.scheme = DecodeStrictProofScheme(ReadU32Be(encoded, &offset));
      metadata.version = ReadU32Be(encoded, &offset);
      metadata.capability_flags = ReadU32Be(encoded, &offset);
      const uint32_t scheme_id_len = ReadU32Be(encoded, &offset);
      const uint32_t blob_len = ReadU32Be(encoded, &offset);
      if (blob_len > max_len) {
        TECDSA_THROW_ARGUMENT("proof blob exceeds maximum length");
      }
      if (scheme_id_len > kMaxSchemeIdLen) {
        TECDSA_THROW_ARGUMENT("proof scheme id exceeds maximum length");
      }
      if (offset + scheme_id_len + blob_len != encoded.size()) {
        TECDSA_THROW_ARGUMENT("proof wire payload has inconsistent length");
      }

      metadata.scheme_id.assign(
          reinterpret_cast<const char*>(encoded.data() + static_cast<std::ptrdiff_t>(offset)),
          scheme_id_len);
      offset += scheme_id_len;

      Bytes blob(
          encoded.begin() + static_cast<std::ptrdiff_t>(offset),
          encoded.begin() + static_cast<std::ptrdiff_t>(offset + blob_len));
      return {std::move(metadata), std::move(blob)};
    }
  }

  if (encoded.size() >= 16) {
    size_t offset = 0;
    const uint32_t magic = ReadU32Be(encoded, &offset);
    if (magic == kProofWireMagicV1) {
      ProofMetadata metadata;
      metadata.scheme = DecodeStrictProofScheme(ReadU32Be(encoded, &offset));
      metadata.version = ReadU32Be(encoded, &offset);
      metadata.capability_flags = kProofCapabilityNone;
      const uint32_t blob_len = ReadU32Be(encoded, &offset);
      if (blob_len > max_len) {
        TECDSA_THROW_ARGUMENT("proof blob exceeds maximum length");
      }
      if (offset + blob_len != encoded.size()) {
        TECDSA_THROW_ARGUMENT("proof wire payload has inconsistent length");
      }
      Bytes blob(
          encoded.begin() + static_cast<std::ptrdiff_t>(offset),
          encoded.begin() + static_cast<std::ptrdiff_t>(offset + blob_len));
      return {std::move(metadata), std::move(blob)};
    }
  }

  if (encoded.size() > max_len) {
    TECDSA_THROW_ARGUMENT("legacy proof blob exceeds maximum length");
  }
  return {ProofMetadata{}, Bytes(encoded.begin(), encoded.end())};
}

BigInt RandomBelow(const BigInt& upper_exclusive) {
  if (upper_exclusive <= 0) {
    TECDSA_THROW_ARGUMENT("random upper bound must be positive");
  }
  return bigint::RandomBelow(upper_exclusive);
}

BigInt RandomZnStar(const BigInt& modulus_n) {
  if (modulus_n <= 2) {
    TECDSA_THROW_ARGUMENT("modulus must be > 2");
  }
  return bigint::RandomZnStar(modulus_n);
}

bool IsInRange(const BigInt& value, const BigInt& modulus) {
  return value >= 0 && value < modulus;
}

bool IsZnStarResidue(const BigInt& value, const BigInt& modulus) {
  if (!IsInRange(value, modulus) || value == 0) {
    return false;
  }
  const BigInt gcd = BigInt::Gcd(value, modulus);
  return gcd == 1;
}

BigInt NormalizeMod(const BigInt& value, const BigInt& modulus) {
  return bigint::NormalizeMod(value, modulus);
}

BigInt MulMod(const BigInt& lhs, const BigInt& rhs, const BigInt& modulus) {
  return NormalizeMod(lhs * rhs, modulus);
}

BigInt PowMod(const BigInt& base, const BigInt& exp, const BigInt& modulus) {
  if (exp < 0) {
    TECDSA_THROW_ARGUMENT("modular exponent must be non-negative");
  }
  return bigint::PowMod(base, exp, modulus);
}

std::optional<BigInt> InvertMod(const BigInt& value, const BigInt& modulus) {
  return bigint::TryInvertMod(value, modulus);
}

bool IsPerfectSquare(const BigInt& value) {
  if (value < 0) {
    return false;
  }
  if (value <= 1) {
    return true;
  }

  BigInt low(1);
  BigInt high = BigInt(1) << (((value.BitCount() + 1) / 2) + 1);
  while (low <= high) {
    const BigInt mid = (low + high) >> 1;
    const BigInt sq = mid * mid;
    if (sq == value) {
      return true;
    }
    if (sq < value) {
      low = mid + BigInt(1);
    } else {
      high = mid - BigInt(1);
    }
  }
  return false;
}

Bytes BuildWeakDigestFromFields(const char* proof_id,
                      const StrictProofVerifierContext& context,
                      const std::array<std::pair<const char*, Bytes>, 1>& fields) {
  Transcript transcript;
  transcript.append_proof_id(proof_id);
  AppendVerifierContext(&transcript, context);
  for (const auto& [label, value] : fields) {
    transcript.append(label, value);
  }
  return Sha256(transcript.bytes());
}

Bytes BuildWeakDigestFromFields(const char* proof_id,
                      const StrictProofVerifierContext& context,
                      const std::array<std::pair<const char*, Bytes>, 3>& fields) {
  Transcript transcript;
  transcript.append_proof_id(proof_id);
  AppendVerifierContext(&transcript, context);
  for (const auto& [label, value] : fields) {
    transcript.append(label, value);
  }
  return Sha256(transcript.bytes());
}

Scalar BuildSquareFreeStrictChallenge(const BigInt& modulus_n,
                                      const StrictProofVerifierContext& context,
                                      std::span<const uint8_t> nonce,
                                      const BigInt& y,
                                      const BigInt& t1,
                                      const BigInt& t2) {
  Transcript transcript;
  transcript.append_proof_id(kSquareFreeProofIdStrict);
  AppendVerifierContext(&transcript, context);
  const Bytes n_bytes = EncodeMpInt(modulus_n);
  const Bytes y_bytes = EncodeMpInt(y);
  const Bytes t1_bytes = EncodeMpInt(t1);
  const Bytes t2_bytes = EncodeMpInt(t2);
  transcript.append_fields({
      TranscriptFieldRef{.label = "N", .data = n_bytes},
      TranscriptFieldRef{.label = "nonce", .data = nonce},
      TranscriptFieldRef{.label = "y", .data = y_bytes},
      TranscriptFieldRef{.label = "t1", .data = t1_bytes},
      TranscriptFieldRef{.label = "t2", .data = t2_bytes},
  });
  return transcript.challenge_scalar_mod_q();
}

struct AuxRsaParamsBigInt {
  BigInt n_tilde;
  BigInt h1;
  BigInt h2;
};

AuxRsaParamsBigInt ToBigIntParams(const AuxRsaParams& params) {
  return AuxRsaParamsBigInt{
      .n_tilde = MpzToMpInt(params.n_tilde),
      .h1 = MpzToMpInt(params.h1),
      .h2 = MpzToMpInt(params.h2),
  };
}

Scalar BuildAuxParamStrictChallenge(const AuxRsaParamsBigInt& params,
                                    const StrictProofVerifierContext& context,
                                    std::span<const uint8_t> nonce,
                                    const BigInt& c1,
                                    const BigInt& c2,
                                    const BigInt& t1,
                                    const BigInt& t2) {
  Transcript transcript;
  transcript.append_proof_id(kAuxParamProofIdStrict);
  AppendVerifierContext(&transcript, context);
  const Bytes n_tilde_bytes = EncodeMpInt(params.n_tilde);
  const Bytes h1_bytes = EncodeMpInt(params.h1);
  const Bytes h2_bytes = EncodeMpInt(params.h2);
  const Bytes c1_bytes = EncodeMpInt(c1);
  const Bytes c2_bytes = EncodeMpInt(c2);
  const Bytes t1_bytes = EncodeMpInt(t1);
  const Bytes t2_bytes = EncodeMpInt(t2);
  transcript.append_fields({
      TranscriptFieldRef{.label = "Ntilde", .data = n_tilde_bytes},
      TranscriptFieldRef{.label = "h1", .data = h1_bytes},
      TranscriptFieldRef{.label = "h2", .data = h2_bytes},
      TranscriptFieldRef{.label = "nonce", .data = nonce},
      TranscriptFieldRef{.label = "c1", .data = c1_bytes},
      TranscriptFieldRef{.label = "c2", .data = c2_bytes},
      TranscriptFieldRef{.label = "t1", .data = t1_bytes},
      TranscriptFieldRef{.label = "t2", .data = t2_bytes},
  });
  return transcript.challenge_scalar_mod_q();
}

Bytes ExpandHashStream(std::span<const uint8_t> seed, size_t out_len) {
  if (out_len == 0) {
    return {};
  }

  Bytes out;
  out.reserve(out_len);
  uint32_t block = 0;
  while (out.size() < out_len) {
    Bytes block_input(seed.begin(), seed.end());
    AppendU32Be(block, &block_input);
    const Bytes digest = Sha256(block_input);
    const size_t remaining = out_len - out.size();
    const size_t take = std::min(remaining, digest.size());
    out.insert(out.end(), digest.begin(), digest.begin() + static_cast<std::ptrdiff_t>(take));
    ++block;
  }
  return out;
}

BigInt DeriveSquareFreeGmr98Challenge(const BigInt& modulus_n,
                                         const StrictProofVerifierContext& context,
                                         std::span<const uint8_t> nonce,
                                         uint32_t round_idx) {
  if (modulus_n <= 3) {
    TECDSA_THROW_ARGUMENT("square-free GMR98 challenge requires modulus N > 3");
  }

  const Bytes n_bytes = EncodeMpInt(modulus_n);
  const size_t byte_len = std::max<size_t>(1, (modulus_n.BitCount() + 7) / 8);

  for (uint32_t attempt = 0; attempt < kMaxSquareFreeGmr98ChallengeAttempts; ++attempt) {
    Transcript transcript;
    transcript.append_proof_id(kSquareFreeProofIdGmr98);
    AppendVerifierContext(&transcript, context);
    transcript.append_fields({
        TranscriptFieldRef{.label = "N", .data = n_bytes},
        TranscriptFieldRef{.label = "nonce", .data = nonce},
    });
    transcript.append_u32_be("round", round_idx);
    transcript.append_u32_be("attempt", attempt);

    const Bytes seed = Sha256(transcript.bytes());
    const Bytes expanded = ExpandHashStream(seed, byte_len);
    BigInt candidate = bigint::FromBigEndian(expanded);
    candidate = NormalizeMod(candidate, modulus_n);
    if (IsZnStarResidue(candidate, modulus_n)) {
      return candidate;
    }
  }

  TECDSA_THROW("failed to derive square-free GMR98 challenge in Z*_N");
}

Bytes EncodeSquareFreeStrictPayload(const SquareFreeStrictPayload& payload) {
  Bytes out;
  AppendSizedField(payload.nonce, &out);
  AppendMpIntField(payload.y, &out);
  AppendMpIntField(payload.t1, &out);
  AppendMpIntField(payload.t2, &out);
  AppendMpIntField(payload.z1, &out);
  AppendMpIntField(payload.z2, &out);
  return out;
}

SquareFreeStrictPayload DecodeSquareFreeStrictPayload(std::span<const uint8_t> blob) {
  size_t offset = 0;
  SquareFreeStrictPayload payload;
  payload.nonce = ReadSizedField(blob, &offset, kMaxStrictNonceLen, "square-free nonce");
  payload.y = ReadMpIntField(blob, &offset, "square-free y");
  payload.t1 = ReadMpIntField(blob, &offset, "square-free t1");
  payload.t2 = ReadMpIntField(blob, &offset, "square-free t2");
  payload.z1 = ReadMpIntField(blob, &offset, "square-free z1");
  payload.z2 = ReadMpIntField(blob, &offset, "square-free z2");
  if (offset != blob.size()) {
    TECDSA_THROW_ARGUMENT("square-free proof payload has trailing bytes");
  }
  return payload;
}

Bytes EncodeSquareFreeGmr98Payload(const SquareFreeGmr98Payload& payload) {
  if (payload.rounds == 0 || payload.rounds > kMaxSquareFreeGmr98Rounds) {
    TECDSA_THROW_ARGUMENT("square-free GMR98 rounds out of range");
  }
  if (payload.roots.size() != payload.rounds) {
    TECDSA_THROW_ARGUMENT("square-free GMR98 roots count mismatch");
  }

  Bytes out;
  AppendSizedField(payload.nonce, &out);
  AppendU32Be(payload.rounds, &out);
  for (const BigInt& root : payload.roots) {
    AppendMpIntField(root, &out);
  }
  return out;
}

SquareFreeGmr98Payload DecodeSquareFreeGmr98Payload(std::span<const uint8_t> blob) {
  size_t offset = 0;
  SquareFreeGmr98Payload payload;
  payload.nonce = ReadSizedField(blob, &offset, kMaxStrictNonceLen, "square-free GMR98 nonce");
  payload.rounds = ReadU32Be(blob, &offset);
  if (payload.rounds == 0 || payload.rounds > kMaxSquareFreeGmr98Rounds) {
    TECDSA_THROW_ARGUMENT("square-free GMR98 rounds out of range");
  }
  payload.roots.reserve(payload.rounds);
  for (uint32_t i = 0; i < payload.rounds; ++i) {
    payload.roots.push_back(ReadMpIntField(blob, &offset, "square-free GMR98 root"));
  }
  if (offset != blob.size()) {
    TECDSA_THROW_ARGUMENT("square-free GMR98 payload has trailing bytes");
  }
  return payload;
}

Bytes EncodeAuxParamStrictPayload(const AuxParamStrictPayload& payload) {
  Bytes out;
  AppendSizedField(payload.nonce, &out);
  AppendMpIntField(payload.c1, &out);
  AppendMpIntField(payload.c2, &out);
  AppendMpIntField(payload.t1, &out);
  AppendMpIntField(payload.t2, &out);
  AppendMpIntField(payload.z, &out);
  return out;
}

AuxParamStrictPayload DecodeAuxParamStrictPayload(std::span<const uint8_t> blob) {
  size_t offset = 0;
  AuxParamStrictPayload payload;
  payload.nonce = ReadSizedField(blob, &offset, kMaxStrictNonceLen, "aux-param nonce");
  payload.c1 = ReadMpIntField(blob, &offset, "aux-param c1");
  payload.c2 = ReadMpIntField(blob, &offset, "aux-param c2");
  payload.t1 = ReadMpIntField(blob, &offset, "aux-param t1");
  payload.t2 = ReadMpIntField(blob, &offset, "aux-param t2");
  payload.z = ReadMpIntField(blob, &offset, "aux-param z");
  if (offset != blob.size()) {
    TECDSA_THROW_ARGUMENT("aux-param proof payload has trailing bytes");
  }
  return payload;
}

BigInt PickCoprimeDeterministic(const BigInt& modulus, const BigInt& seed) {
  BigInt value = NormalizeMod(seed, modulus);
  if (value < 2) {
    value = BigInt(2);
  }

  while (true) {
    if (value >= modulus) {
      value = BigInt(2);
    }
    const BigInt gcd = BigInt::Gcd(value, modulus);
    if (gcd == 1) {
      return value;
    }
    value += BigInt(1);
  }
}

mpz_class PickCoprimeDeterministic(const mpz_class& modulus, const mpz_class& seed) {
  return MpIntToMpz(PickCoprimeDeterministic(MpzToMpInt(modulus), MpzToMpInt(seed)));
}

}  // namespace

bool IsZnStarElement(const BigInt& value, const BigInt& modulus) {
  if (modulus <= 2 || value <= 0 || value >= modulus) {
    return false;
  }
  const BigInt gcd = BigInt::Gcd(value, modulus);
  return gcd == 1;
}

bool IsZnStarElement(const mpz_class& value, const mpz_class& modulus) {
  return IsZnStarElement(MpzToMpInt(value), MpzToMpInt(modulus));
}

bool ValidateAuxRsaParams(const AuxRsaParams& params) {
  if (params.n_tilde <= 2) {
    return false;
  }
  if (params.h1 == params.h2) {
    return false;
  }
  if (!IsZnStarElement(params.h1, params.n_tilde) ||
      !IsZnStarElement(params.h2, params.n_tilde)) {
    return false;
  }
  return true;
}

bool IsStrictProofScheme(StrictProofScheme scheme) {
  return scheme == StrictProofScheme::kStrictAlgebraicV1 ||
         scheme == StrictProofScheme::kStrictExternalV1 ||
         scheme == StrictProofScheme::kSquareFreeGmr98V1;
}

bool IsDevProofScheme(StrictProofScheme scheme) {
  return scheme == StrictProofScheme::kDevDigestBindingV1;
}

bool HasProofCapability(const ProofMetadata& metadata, uint32_t capability_mask) {
  return (metadata.capability_flags & capability_mask) == capability_mask;
}

bool IsProofMetadataCompatible(const ProofMetadata& expected,
                               const ProofMetadata& candidate,
                               bool require_strict_scheme) {
  if (require_strict_scheme && !IsStrictProofScheme(candidate.scheme)) {
    return false;
  }

  if (expected.scheme != StrictProofScheme::kUnknown &&
      candidate.scheme != expected.scheme) {
    return false;
  }
  if (expected.version != 0 && candidate.version < expected.version) {
    return false;
  }
  if (!expected.scheme_id.empty() && candidate.scheme_id != expected.scheme_id) {
    return false;
  }
  if (expected.capability_flags != kProofCapabilityNone &&
      !HasProofCapability(candidate, expected.capability_flags)) {
    return false;
  }
  return true;
}

Bytes EncodeSquareFreeProof(const SquareFreeProof& proof) {
  return EncodeProofWire(proof.metadata, proof.blob);
}

SquareFreeProof DecodeSquareFreeProof(std::span<const uint8_t> encoded, size_t max_len) {
  auto [metadata, blob] = DecodeProofWire(encoded, max_len);
  return SquareFreeProof{
      .metadata = std::move(metadata),
      .blob = std::move(blob),
  };
}

Bytes EncodeAuxRsaParamProof(const AuxRsaParamProof& proof) {
  return EncodeProofWire(proof.metadata, proof.blob);
}

AuxRsaParamProof DecodeAuxRsaParamProof(std::span<const uint8_t> encoded, size_t max_len) {
  auto [metadata, blob] = DecodeProofWire(encoded, max_len);
  return AuxRsaParamProof{
      .metadata = std::move(metadata),
      .blob = std::move(blob),
  };
}

bool IsLikelySquareFreeModulus(const BigInt& modulus_n) {
  if (modulus_n <= 2) {
    return false;
  }
  if (modulus_n.IsEven()) {
    return false;
  }
  if (IsPerfectSquare(modulus_n)) {
    return false;
  }

  static constexpr std::array<unsigned long, 168> kSmallPrimes = {
      2,   3,   5,   7,   11,  13,  17,  19,  23,  29,  31,  37,  41,  43,
      47,  53,  59,  61,  67,  71,  73,  79,  83,  89,  97,  101, 103, 107,
      109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
      191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263,
      269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
      353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433,
      439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521,
      523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613,
      617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
      709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
      811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887,
      907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997,
  };

  for (unsigned long prime : kSmallPrimes) {
    const unsigned long prime_square = prime * prime;
    if (modulus_n.Mod(BigInt(prime_square)) == 0) {
      return false;
    }
  }

  return true;
}

bool IsLikelySquareFreeModulus(const mpz_class& modulus_n) {
  return IsLikelySquareFreeModulus(MpzToMpInt(modulus_n));
}

AuxRsaParams GenerateAuxRsaParams(uint32_t modulus_bits, PartyIndex party_id) {
  if (modulus_bits < 32) {
    TECDSA_THROW_ARGUMENT("aux RSA modulus bits must be >= 32");
  }

  const size_t byte_len = (static_cast<size_t>(modulus_bits) + 7) / 8;
  for (size_t attempt = 0; attempt < kMaxAuxParamGenerationAttempts; ++attempt) {
    Bytes modulus_bytes = Csprng::RandomBytes(byte_len);
    if (modulus_bytes.empty()) {
      TECDSA_THROW("failed to sample auxiliary RSA modulus bytes");
    }

    const unsigned int top_bits = modulus_bits % 8;
    if (top_bits != 0) {
      const uint8_t mask = static_cast<uint8_t>((1u << top_bits) - 1u);
      modulus_bytes.front() &= mask;
    }
    const unsigned int msb_idx = (modulus_bits - 1) % 8;
    modulus_bytes.front() |= static_cast<uint8_t>(1u << msb_idx);
    modulus_bytes.back() |= 0x01;  // odd
    if (modulus_bytes.size() > 1 && modulus_bytes.front() == 0) {
      continue;
    }

    mpz_class modulus_n;
    mpz_import(modulus_n.get_mpz_t(),
               modulus_bytes.size(),
               1,
               sizeof(uint8_t),
               1,
               0,
               modulus_bytes.data());
    if (modulus_n <= 2 || !IsLikelySquareFreeModulus(modulus_n)) {
      continue;
    }

    const mpz_class h1 = PickCoprimeDeterministic(modulus_n, mpz_class(2 + 2 * party_id));
    mpz_class h2 = PickCoprimeDeterministic(modulus_n, mpz_class(3 + 2 * party_id));
    if (h1 == h2) {
      h2 = PickCoprimeDeterministic(modulus_n, h1 + 1);
    }

    AuxRsaParams params{
        .n_tilde = modulus_n,
        .h1 = h1,
        .h2 = h2,
    };
    if (ValidateAuxRsaParams(params)) {
      return params;
    }
  }

  TECDSA_THROW("failed to generate likely square-free auxiliary RSA params");
}

AuxRsaParams DeriveAuxRsaParamsFromModulus(const mpz_class& modulus_n, PartyIndex party_id) {
  if (modulus_n <= 2) {
    TECDSA_THROW_ARGUMENT("aux RSA modulus must be > 2");
  }

  const mpz_class h1 = PickCoprimeDeterministic(modulus_n, mpz_class(2 + 2 * party_id));
  mpz_class h2 = PickCoprimeDeterministic(modulus_n, mpz_class(3 + 2 * party_id));
  if (h1 == h2) {
    h2 = PickCoprimeDeterministic(modulus_n, h1 + 1);
  }

  AuxRsaParams params{
      .n_tilde = modulus_n,
      .h1 = h1,
      .h2 = h2,
  };
  if (!ValidateAuxRsaParams(params)) {
    TECDSA_THROW("failed to derive valid auxiliary RSA params");
  }
  return params;
}

SquareFreeProof BuildSquareFreeProofWeak(const mpz_class& modulus_n,
                                         const StrictProofVerifierContext& context) {
  const BigInt modulus_n_big = MpzToMpInt(modulus_n);
  SquareFreeProof proof;
  proof.metadata = MakeWeakMetadata(kSquareFreeSchemeIdWeak);
  proof.blob = BuildWeakDigestFromFields(
      kSquareFreeProofIdWeak,
      context,
      std::array<std::pair<const char*, Bytes>, 1>{{
          {"N", EncodeMpInt(modulus_n_big)},
      }});
  return proof;
}

SquareFreeProof BuildSquareFreeProofStrict(const mpz_class& modulus_n,
                                           const StrictProofVerifierContext& context) {
  const BigInt modulus_n_big = MpzToMpInt(modulus_n);
  if (modulus_n_big <= 2) {
    TECDSA_THROW_ARGUMENT("square-free proof requires modulus N > 2");
  }
  if (!IsLikelySquareFreeModulus(modulus_n_big)) {
    TECDSA_THROW_ARGUMENT("square-free strict proof requires likely square-free modulus");
  }

  const BigInt n2 = modulus_n_big * modulus_n_big;
  const BigInt witness = RandomZnStar(modulus_n_big);
  const BigInt r1 = RandomZnStar(modulus_n_big);
  const BigInt r2 = RandomZnStar(modulus_n_big);

  const BigInt y = PowMod(witness, modulus_n_big, n2);
  const BigInt t1 = PowMod(r1, modulus_n_big, n2);
  const BigInt t2 = PowMod(r2, modulus_n_big, n2);
  const Bytes nonce = Csprng::RandomBytes(kStrictNonceLen);
  const BigInt e =
      BuildSquareFreeStrictChallenge(modulus_n_big, context, nonce, y, t1, t2).mp_value();

  const BigInt z1 = MulMod(r1, PowMod(witness, e, modulus_n_big), modulus_n_big);
  const BigInt z2 = MulMod(r2, PowMod(witness, e + 1, modulus_n_big), modulus_n_big);

  SquareFreeProof proof;
  proof.metadata = MakeStrictMetadata(kSquareFreeSchemeIdStrict, context);
  proof.metadata.capability_flags |= kProofCapabilityHeuristicChecks;
  proof.blob = EncodeSquareFreeStrictPayload(SquareFreeStrictPayload{
      .nonce = nonce,
      .y = y,
      .t1 = t1,
      .t2 = t2,
      .z1 = z1,
      .z2 = z2,
  });
  return proof;
}

bool VerifySquareFreeProofWeak(const mpz_class& modulus_n,
                               const SquareFreeProof& proof,
                               const StrictProofVerifierContext& context) {
  if (proof.blob.empty()) {
    return false;
  }
  if (!IsLikelySquareFreeModulus(modulus_n)) {
    return false;
  }

  if (proof.metadata.scheme == StrictProofScheme::kUnknown && proof.metadata.version == 0) {
    const SquareFreeProof expected = BuildSquareFreeProofWeak(modulus_n, context);
    return proof.blob == expected.blob;
  }

  if (!IsDevProofScheme(proof.metadata.scheme) || proof.metadata.version != kDevProofVersion) {
    return false;
  }
  if (!proof.metadata.scheme_id.empty() && proof.metadata.scheme_id != kSquareFreeSchemeIdWeak) {
    return false;
  }
  const SquareFreeProof expected = BuildSquareFreeProofWeak(modulus_n, context);
  return proof.blob == expected.blob;
}

bool VerifySquareFreeProofStrict(const mpz_class& modulus_n,
                                 const SquareFreeProof& proof,
                                 const StrictProofVerifierContext& context) {
  const BigInt modulus_n_big = MpzToMpInt(modulus_n);
  if (!IsLikelySquareFreeModulus(modulus_n_big)) {
    return false;
  }
  if (proof.blob.empty()) {
    return false;
  }
  if (!IsStrictProofScheme(proof.metadata.scheme)) {
    return false;
  }
  if (proof.metadata.scheme != StrictProofScheme::kStrictAlgebraicV1) {
    // External strict schemes are reserved but not implemented in this module.
    return false;
  }
  if (proof.metadata.version != kStrictAlgebraicVersion) {
    return false;
  }
  if (!proof.metadata.scheme_id.empty() && proof.metadata.scheme_id != kSquareFreeSchemeIdStrict) {
    return false;
  }
  if (!HasProofCapability(
          proof.metadata,
          kProofCapabilityStrictReady |
              kProofCapabilityAlgebraicChecks |
              kProofCapabilityFreshRandomness |
              kProofCapabilityHeuristicChecks)) {
    return false;
  }
  if (HasContextBinding(context) &&
      !HasProofCapability(proof.metadata, kProofCapabilityContextBinding)) {
    return false;
  }

  const BigInt n2 = modulus_n_big * modulus_n_big;
  SquareFreeStrictPayload payload;
  try {
    payload = DecodeSquareFreeStrictPayload(proof.blob);
  } catch (const std::exception&) {
    return false;
  }
  if (payload.nonce.size() != kStrictNonceLen) {
    return false;
  }
  if (!IsZnStarResidue(payload.y, n2) ||
      !IsZnStarResidue(payload.t1, n2) ||
      !IsZnStarResidue(payload.t2, n2) ||
      !IsZnStarResidue(payload.z1, modulus_n_big) ||
      !IsZnStarResidue(payload.z2, modulus_n_big)) {
    return false;
  }

  const BigInt e =
      BuildSquareFreeStrictChallenge(modulus_n_big,
                                     context,
                                     payload.nonce,
                                     payload.y,
                                     payload.t1,
                                     payload.t2)
          .mp_value();

  const BigInt lhs1 = PowMod(payload.z1, modulus_n_big, n2);
  const BigInt rhs1 = MulMod(payload.t1, PowMod(payload.y, e, n2), n2);
  if (lhs1 != rhs1) {
    return false;
  }

  const BigInt lhs2 = PowMod(payload.z2, modulus_n_big, n2);
  const BigInt rhs2 = MulMod(payload.t2, PowMod(payload.y, e + 1, n2), n2);
  return lhs2 == rhs2;
}

SquareFreeProof BuildSquareFreeProofGmr98(const mpz_class& modulus_n,
                                          const mpz_class& lambda_n,
                                          const StrictProofVerifierContext& context) {
  const BigInt modulus_n_big = MpzToMpInt(modulus_n);
  const BigInt lambda_n_big = MpzToMpInt(lambda_n);
  if (modulus_n_big <= 3) {
    TECDSA_THROW_ARGUMENT("square-free GMR98 proof requires modulus N > 3");
  }
  if (lambda_n_big <= 1) {
    TECDSA_THROW_ARGUMENT("square-free GMR98 proof requires lambda(N) > 1");
  }
  if (!IsLikelySquareFreeModulus(modulus_n_big)) {
    TECDSA_THROW_ARGUMENT("square-free GMR98 proof requires likely square-free modulus");
  }

  const auto d_opt = InvertMod(NormalizeMod(modulus_n_big, lambda_n_big), lambda_n_big);
  if (!d_opt.has_value()) {
    TECDSA_THROW_ARGUMENT("square-free GMR98 proof requires gcd(N, lambda(N)) = 1");
  }
  const BigInt d = *d_opt;
  const Bytes nonce = Csprng::RandomBytes(kStrictNonceLen);

  SquareFreeGmr98Payload payload;
  payload.nonce = nonce;
  payload.rounds = static_cast<uint32_t>(kSquareFreeGmr98Rounds);
  payload.roots.reserve(payload.rounds);

  for (uint32_t round = 0; round < payload.rounds; ++round) {
    const BigInt challenge = DeriveSquareFreeGmr98Challenge(modulus_n_big, context, nonce, round);
    const BigInt root = PowMod(challenge, d, modulus_n_big);
    if (!IsZnStarResidue(root, modulus_n_big)) {
      TECDSA_THROW("square-free GMR98 proof generated invalid root");
    }
    const BigInt check = PowMod(root, modulus_n_big, modulus_n_big);
    if (check != challenge) {
      TECDSA_THROW("square-free GMR98 proof generated inconsistent root equation");
    }
    payload.roots.push_back(root);
  }

  SquareFreeProof proof;
  proof.metadata = MakeSquareFreeGmr98Metadata(context);
  proof.blob = EncodeSquareFreeGmr98Payload(payload);
  return proof;
}

SquareFreeProof BuildSquareFreeProofGmr98(const mpz_class& modulus_n,
                                          const StrictProofVerifierContext& context) {
  // Witness-less fallback retained for compatibility with callers that only have public N.
  return BuildSquareFreeProofStrict(modulus_n, context);
}

bool VerifySquareFreeProofGmr98(const mpz_class& modulus_n,
                                const SquareFreeProof& proof,
                                const StrictProofVerifierContext& context) {
  if (proof.metadata.scheme == StrictProofScheme::kStrictAlgebraicV1) {
    return VerifySquareFreeProofStrict(modulus_n, proof, context);
  }

  const BigInt modulus_n_big = MpzToMpInt(modulus_n);
  if (!IsLikelySquareFreeModulus(modulus_n_big)) {
    return false;
  }
  if (proof.blob.empty()) {
    return false;
  }
  if (proof.metadata.scheme != StrictProofScheme::kSquareFreeGmr98V1) {
    return false;
  }
  if (proof.metadata.version != kSquareFreeGmr98Version) {
    return false;
  }
  if (!proof.metadata.scheme_id.empty() && proof.metadata.scheme_id != kSquareFreeSchemeIdGmr98) {
    return false;
  }
  if (!HasProofCapability(
          proof.metadata,
          kProofCapabilityStrictReady |
              kProofCapabilityAlgebraicChecks |
              kProofCapabilityFreshRandomness |
              kProofCapabilityHeuristicChecks)) {
    return false;
  }
  if (HasContextBinding(context) &&
      !HasProofCapability(proof.metadata, kProofCapabilityContextBinding)) {
    return false;
  }

  SquareFreeGmr98Payload payload;
  try {
    payload = DecodeSquareFreeGmr98Payload(proof.blob);
  } catch (const std::exception&) {
    return false;
  }
  if (payload.nonce.size() != kStrictNonceLen) {
    return false;
  }
  if (payload.rounds != kSquareFreeGmr98Rounds) {
    return false;
  }
  if (payload.roots.size() != payload.rounds) {
    return false;
  }

  for (uint32_t round = 0; round < payload.rounds; ++round) {
    const BigInt& root = payload.roots[round];
    if (!IsZnStarResidue(root, modulus_n_big)) {
      return false;
    }
    const BigInt challenge =
        DeriveSquareFreeGmr98Challenge(modulus_n_big, context, payload.nonce, round);
    const BigInt lhs = PowMod(root, modulus_n_big, modulus_n_big);
    if (lhs != challenge) {
      return false;
    }
  }
  return true;
}

SquareFreeProof BuildSquareFreeProof(const mpz_class& modulus_n,
                                     const StrictProofVerifierContext& context) {
  return BuildSquareFreeProofGmr98(modulus_n, context);
}

bool VerifySquareFreeProof(const mpz_class& modulus_n,
                           const SquareFreeProof& proof,
                           const StrictProofVerifierContext& context) {
  if (IsStrictProofScheme(proof.metadata.scheme)) {
    return VerifySquareFreeProofGmr98(modulus_n, proof, context);
  }
  return VerifySquareFreeProofWeak(modulus_n, proof, context);
}

AuxRsaParamProof BuildAuxRsaParamProofWeak(const AuxRsaParams& params,
                                           const StrictProofVerifierContext& context) {
  if (!ValidateAuxRsaParams(params)) {
    TECDSA_THROW_ARGUMENT("cannot build aux param proof from invalid parameters");
  }

  const AuxRsaParamsBigInt params_big = ToBigIntParams(params);
  AuxRsaParamProof proof;
  proof.metadata = MakeWeakMetadata(kAuxParamSchemeIdWeak);
  proof.blob = BuildWeakDigestFromFields(
      kAuxParamProofIdWeak,
      context,
      std::array<std::pair<const char*, Bytes>, 3>{{
          {"Ntilde", EncodeMpInt(params_big.n_tilde)},
          {"h1", EncodeMpInt(params_big.h1)},
          {"h2", EncodeMpInt(params_big.h2)},
      }});
  return proof;
}

AuxRsaParamProof BuildAuxRsaParamProofStrict(const AuxRsaParams& params,
                                             const StrictProofVerifierContext& context) {
  if (!ValidateAuxRsaParams(params)) {
    TECDSA_THROW_ARGUMENT("cannot build aux param proof from invalid parameters");
  }
  const AuxRsaParamsBigInt params_big = ToBigIntParams(params);
  if (!IsLikelySquareFreeModulus(params_big.n_tilde)) {
    TECDSA_THROW_ARGUMENT("aux strict proof requires likely square-free Ntilde");
  }

  BigInt alpha;
  do {
    alpha = RandomBelow(Scalar::ModulusQMpInt());
  } while (alpha == 0);
  BigInt r;
  do {
    r = RandomBelow(Scalar::ModulusQMpInt());
  } while (r == 0);

  const BigInt c1 = PowMod(params_big.h1, alpha, params_big.n_tilde);
  const BigInt c2 = PowMod(params_big.h2, alpha, params_big.n_tilde);
  const BigInt t1 = PowMod(params_big.h1, r, params_big.n_tilde);
  const BigInt t2 = PowMod(params_big.h2, r, params_big.n_tilde);
  const Bytes nonce = Csprng::RandomBytes(kStrictNonceLen);
  const BigInt e = BuildAuxParamStrictChallenge(
                       params_big, context, nonce, c1, c2, t1, t2)
                       .mp_value();
  const BigInt z = r + (e * alpha);

  AuxRsaParamProof proof;
  proof.metadata = MakeStrictMetadata(kAuxParamSchemeIdStrict, context);
  proof.metadata.capability_flags |= kProofCapabilityHeuristicChecks;
  proof.blob = EncodeAuxParamStrictPayload(AuxParamStrictPayload{
      .nonce = nonce,
      .c1 = c1,
      .c2 = c2,
      .t1 = t1,
      .t2 = t2,
      .z = z,
  });
  return proof;
}

bool VerifyAuxRsaParamProofWeak(const AuxRsaParams& params,
                                const AuxRsaParamProof& proof,
                                const StrictProofVerifierContext& context) {
  if (proof.blob.empty()) {
    return false;
  }
  if (!ValidateAuxRsaParams(params)) {
    return false;
  }

  if (proof.metadata.scheme == StrictProofScheme::kUnknown && proof.metadata.version == 0) {
    const AuxRsaParamProof expected = BuildAuxRsaParamProofWeak(params, context);
    return proof.blob == expected.blob;
  }

  if (!IsDevProofScheme(proof.metadata.scheme) || proof.metadata.version != kDevProofVersion) {
    return false;
  }
  if (!proof.metadata.scheme_id.empty() && proof.metadata.scheme_id != kAuxParamSchemeIdWeak) {
    return false;
  }
  const AuxRsaParamProof expected = BuildAuxRsaParamProofWeak(params, context);
  return proof.blob == expected.blob;
}

bool VerifyAuxRsaParamProofStrict(const AuxRsaParams& params,
                                  const AuxRsaParamProof& proof,
                                  const StrictProofVerifierContext& context) {
  if (!ValidateAuxRsaParams(params)) {
    return false;
  }
  const AuxRsaParamsBigInt params_big = ToBigIntParams(params);
  if (!IsLikelySquareFreeModulus(params_big.n_tilde)) {
    return false;
  }
  if (proof.blob.empty()) {
    return false;
  }
  if (!IsStrictProofScheme(proof.metadata.scheme)) {
    return false;
  }
  if (proof.metadata.scheme != StrictProofScheme::kStrictAlgebraicV1) {
    // External strict schemes are reserved but not implemented in this module.
    return false;
  }
  if (proof.metadata.version != kStrictAlgebraicVersion) {
    return false;
  }
  if (!proof.metadata.scheme_id.empty() && proof.metadata.scheme_id != kAuxParamSchemeIdStrict) {
    return false;
  }
  if (!HasProofCapability(
          proof.metadata,
          kProofCapabilityStrictReady |
              kProofCapabilityAlgebraicChecks |
              kProofCapabilityFreshRandomness |
              kProofCapabilityHeuristicChecks)) {
    return false;
  }
  if (HasContextBinding(context) &&
      !HasProofCapability(proof.metadata, kProofCapabilityContextBinding)) {
    return false;
  }

  AuxParamStrictPayload payload;
  try {
    payload = DecodeAuxParamStrictPayload(proof.blob);
  } catch (const std::exception&) {
    return false;
  }
  if (payload.nonce.size() != kStrictNonceLen) {
    return false;
  }
  if (payload.z < 0) {
    return false;
  }
  if (!IsZnStarElement(payload.c1, params_big.n_tilde) ||
      !IsZnStarElement(payload.c2, params_big.n_tilde) ||
      !IsZnStarElement(payload.t1, params_big.n_tilde) ||
      !IsZnStarElement(payload.t2, params_big.n_tilde)) {
    return false;
  }

  const BigInt e = BuildAuxParamStrictChallenge(
                       params_big,
                       context,
                       payload.nonce,
                       payload.c1,
                       payload.c2,
                       payload.t1,
                       payload.t2)
                       .mp_value();

  const BigInt lhs1 = PowMod(params_big.h1, payload.z, params_big.n_tilde);
  const BigInt rhs1 =
      MulMod(payload.t1, PowMod(payload.c1, e, params_big.n_tilde), params_big.n_tilde);
  if (lhs1 != rhs1) {
    return false;
  }

  const BigInt lhs2 = PowMod(params_big.h2, payload.z, params_big.n_tilde);
  const BigInt rhs2 =
      MulMod(payload.t2, PowMod(payload.c2, e, params_big.n_tilde), params_big.n_tilde);
  return lhs2 == rhs2;
}

AuxRsaParamProof BuildAuxRsaParamProof(const AuxRsaParams& params,
                                       const StrictProofVerifierContext& context) {
  return BuildAuxRsaParamProofStrict(params, context);
}

bool VerifyAuxRsaParamProof(const AuxRsaParams& params,
                            const AuxRsaParamProof& proof,
                            const StrictProofVerifierContext& context) {
  if (IsStrictProofScheme(proof.metadata.scheme)) {
    return VerifyAuxRsaParamProofStrict(params, proof, context);
  }
  return VerifyAuxRsaParamProofWeak(params, proof, context);
}

}  // namespace tecdsa

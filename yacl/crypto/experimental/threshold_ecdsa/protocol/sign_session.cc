#include "yacl/crypto/experimental/threshold_ecdsa/protocol/sign_session.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <future>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/commitment.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ecdsa_verify.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/random.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/transcript.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/secure_zeroize.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/thread_pool.h"

namespace tecdsa {
namespace {

constexpr size_t kCommitmentLen = 32;
constexpr size_t kPointCompressedLen = 33;
constexpr size_t kScalarLen = 32;
constexpr size_t kMaxOpenRandomnessLen = 1024;
constexpr size_t kMtaInstanceIdLen = 16;
constexpr size_t kMaxMpIntEncodedLen = 8192;
constexpr char kPhase1CommitDomain[] = "GG2019/sign/phase1";
constexpr char kPhase5ACommitDomain[] = "GG2019/sign/phase5A";
constexpr char kPhase5CCommitDomain[] = "GG2019/sign/phase5C";
constexpr char kSchnorrProofId[] = "GG2019/Schnorr/v1";
constexpr char kVRelationProofId[] = "GG2019/VRel/v1";
constexpr char kA1RangeProofId[] = "GG2019/A1Range/v1";
constexpr char kA2MtAwcProofId[] = "GG2019/A2MtAwc/v1";
constexpr char kA3MtAProofId[] = "GG2019/A3MtA/v1";
constexpr char kCurveName[] = "secp256k1";

using AuxRsaParams = SignSessionConfig::AuxRsaParams;

struct MtaProofContext {
  Bytes session_id;
  PartyIndex initiator_id = 0;
  PartyIndex responder_id = 0;
  Bytes mta_instance_id;
};

struct A1RangeProof {
  BigInt z;
  BigInt u;
  BigInt w;
  BigInt s;
  BigInt s1;
  BigInt s2;
};

struct A2MtAwcProof {
  ECPoint u;
  BigInt z = BigInt(0);
  BigInt z2 = BigInt(0);
  BigInt t = BigInt(0);
  BigInt v = BigInt(0);
  BigInt w = BigInt(0);
  BigInt s = BigInt(0);
  BigInt s1 = BigInt(0);
  BigInt s2 = BigInt(0);
  BigInt t1 = BigInt(0);
  BigInt t2 = BigInt(0);
};

struct A3MtAProof {
  BigInt z = BigInt(0);
  BigInt z2 = BigInt(0);
  BigInt t = BigInt(0);
  BigInt v = BigInt(0);
  BigInt w = BigInt(0);
  BigInt s = BigInt(0);
  BigInt s1 = BigInt(0);
  BigInt s2 = BigInt(0);
  BigInt t1 = BigInt(0);
  BigInt t2 = BigInt(0);
};

void ValidateParticipantsOrThrow(const std::vector<PartyIndex>& participants, PartyIndex self_id) {
  if (participants.size() < 2) {
    TECDSA_THROW_ARGUMENT("SignSession requires at least 2 participants");
  }

  std::unordered_set<PartyIndex> dedup;
  bool self_present = false;
  for (PartyIndex id : participants) {
    if (id == 0) {
      TECDSA_THROW_ARGUMENT("participants must not contain 0");
    }
    if (!dedup.insert(id).second) {
      TECDSA_THROW_ARGUMENT("participants must be unique");
    }
    if (id == self_id) {
      self_present = true;
    }
  }

  if (!self_present) {
    TECDSA_THROW_ARGUMENT("self_id must be in participants");
  }
}

std::unordered_set<PartyIndex> BuildPeerSet(const std::vector<PartyIndex>& participants,
                                            PartyIndex self_id) {
  std::unordered_set<PartyIndex> peers;
  for (PartyIndex id : participants) {
    if (id != self_id) {
      peers.insert(id);
    }
  }
  return peers;
}

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

void AppendPoint(const ECPoint& point, Bytes* out) {
  const Bytes encoded = point.ToCompressedBytes();
  if (encoded.size() != kPointCompressedLen) {
    TECDSA_THROW("Encoded secp256k1 point must be 33 bytes");
  }
  out->insert(out->end(), encoded.begin(), encoded.end());
}

ECPoint ReadPoint(std::span<const uint8_t> input, size_t* offset) {
  if (*offset + kPointCompressedLen > input.size()) {
    TECDSA_THROW_ARGUMENT("Not enough bytes for compressed secp256k1 point");
  }

  const std::span<const uint8_t> view = input.subspan(*offset, kPointCompressedLen);
  *offset += kPointCompressedLen;
  return ECPoint::FromCompressed(view);
}

void AppendScalar(const Scalar& scalar, Bytes* out) {
  const std::array<uint8_t, kScalarLen> encoded = scalar.ToCanonicalBytes();
  out->insert(out->end(), encoded.begin(), encoded.end());
}

Scalar ReadScalar(std::span<const uint8_t> input, size_t* offset) {
  if (*offset + kScalarLen > input.size()) {
    TECDSA_THROW_ARGUMENT("Not enough bytes for scalar");
  }
  const std::span<const uint8_t> view = input.subspan(*offset, kScalarLen);
  *offset += kScalarLen;
  return Scalar::FromCanonicalBytes(view);
}

void AppendMpIntField(const BigInt& value, Bytes* out) {
  const Bytes encoded = EncodeMpInt(value);
  AppendSizedField(encoded, out);
}

BigInt ReadMpIntField(std::span<const uint8_t> input,
                      size_t* offset,
                      size_t max_len,
                      const char* field_name) {
  const Bytes encoded = ReadSizedField(input, offset, max_len, field_name);
  return DecodeMpInt(encoded, max_len);
}

std::string BytesToKey(const Bytes& bytes) {
  return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::string MakeResponderRequestKey(PartyIndex initiator, uint8_t type_code) {
  std::string out;
  out.reserve(8);
  out.push_back(static_cast<char>((initiator >> 24) & 0xFF));
  out.push_back(static_cast<char>((initiator >> 16) & 0xFF));
  out.push_back(static_cast<char>((initiator >> 8) & 0xFF));
  out.push_back(static_cast<char>(initiator & 0xFF));
  out.push_back(static_cast<char>(type_code));
  return out;
}

BigInt RandomBelow(const BigInt& upper_exclusive) {
  if (upper_exclusive <= 0) {
    TECDSA_THROW_ARGUMENT("random upper bound must be positive");
  }
  return bigint::RandomBelow(upper_exclusive);
}

BigInt SampleZnStar(const BigInt& modulus_n) {
  if (modulus_n <= 2) {
    TECDSA_THROW_ARGUMENT("Paillier modulus must be > 2");
  }
  return bigint::RandomZnStar(modulus_n);
}

bool IsZnStarElement(const BigInt& value, const BigInt& modulus) {
  if (value <= 0 || value >= modulus) {
    return false;
  }
  const BigInt gcd = BigInt::Gcd(value, modulus);
  return gcd == 1;
}

void ValidateAuxRsaParamsOrThrow(const AuxRsaParams& params) {
  if (!ValidateAuxRsaParams(params)) {
    TECDSA_THROW_ARGUMENT("invalid aux RSA parameters");
  }
}

const BigInt& QPow3() {
  static const BigInt q_pow_3 = []() {
    BigInt out(1);
    const BigInt& q = Scalar::ModulusQMpInt();
    for (size_t i = 0; i < 3; ++i) {
      out *= q;
    }
    return out;
  }();
  return q_pow_3;
}

const BigInt& QPow5() {
  static const BigInt q_pow_5 = []() {
    BigInt out(1);
    const BigInt& q = Scalar::ModulusQMpInt();
    for (size_t i = 0; i < 5; ++i) {
      out *= q;
    }
    return out;
  }();
  return q_pow_5;
}

const BigInt& QPow7() {
  static const BigInt q_pow_7 = []() {
    BigInt out(1);
    const BigInt& q = Scalar::ModulusQMpInt();
    for (size_t i = 0; i < 7; ++i) {
      out *= q;
    }
    return out;
  }();
  return q_pow_7;
}

const BigInt& MinPaillierModulusQ8() {
  static const BigInt q_pow_8 = []() {
    BigInt out(1);
    const BigInt& q = Scalar::ModulusQMpInt();
    for (size_t i = 0; i < 8; ++i) {
      out *= q;
    }
    return out;
  }();
  return q_pow_8;
}

StrictProofVerifierContext BuildKeygenProofContext(const Bytes& keygen_session_id,
                                                   PartyIndex prover_id) {
  StrictProofVerifierContext context;
  if (!keygen_session_id.empty()) {
    context.session_id = keygen_session_id;
    context.prover_id = prover_id;
  }
  return context;
}

bool StrictMetadataCompatible(const ProofMetadata& expected, const ProofMetadata& candidate) {
  return IsProofMetadataCompatible(expected, candidate, /*require_strict_scheme=*/true);
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

bool IsInRange(const BigInt& value, const BigInt& modulus) {
  return value >= 0 && value < modulus;
}

Bytes ExportFixedWidth(const BigInt& value, size_t width) {
  return bigint::ToFixedWidth(value, width);
}

const Bytes& CurveNameBytes() {
  static const Bytes kCurveBytes(
      reinterpret_cast<const uint8_t*>(kCurveName),
      reinterpret_cast<const uint8_t*>(kCurveName) + std::strlen(kCurveName));
  return kCurveBytes;
}

const Bytes& ModulusQBytes() {
  static const Bytes kQBytes = ExportFixedWidth(Scalar::ModulusQMpInt(), 32);
  return kQBytes;
}

size_t ResolvePhase2WorkerCount() {
  const char* env = std::getenv("TECDSA_PHASE2_THREADS");
  if (env != nullptr && env[0] != '\0') {
    char* end = nullptr;
    const unsigned long parsed = std::strtoul(env, &end, 10);
    if (end != env && end != nullptr && *end == '\0' && parsed > 0) {
      return static_cast<size_t>(parsed);
    }
  }

  const unsigned int hw = std::thread::hardware_concurrency();
  return std::max<size_t>(1, hw == 0 ? 1 : hw);
}

ThreadPool& Phase2ThreadPool() {
  static ThreadPool pool(ResolvePhase2WorkerCount());
  return pool;
}

void AppendCommonMtaTranscriptFields(Transcript* transcript,
                                     const char* proof_id,
                                     const MtaProofContext& ctx) {
  transcript->append_proof_id(proof_id);
  transcript->append_session_id(ctx.session_id);
  transcript->append_u32_be("initiator", ctx.initiator_id);
  transcript->append_u32_be("responder", ctx.responder_id);
  transcript->append_fields({
      TranscriptFieldRef{.label = "mta_id", .data = ctx.mta_instance_id},
      TranscriptFieldRef{.label = "curve", .data = CurveNameBytes()},
      TranscriptFieldRef{.label = "q", .data = ModulusQBytes()},
  });
}

Scalar BuildA1RangeChallenge(const MtaProofContext& ctx,
                             const BigInt& n,
                             const BigInt& gamma,
                             const AuxRsaParams& aux,
                             const BigInt& c,
                             const BigInt& z,
                             const BigInt& u,
                             const BigInt& w) {
  Transcript transcript;
  AppendCommonMtaTranscriptFields(&transcript, kA1RangeProofId, ctx);
  const Bytes n_bytes = EncodeMpInt(n);
  const Bytes gamma_bytes = EncodeMpInt(gamma);
  const Bytes n_tilde_bytes = EncodeMpInt(aux.n_tilde);
  const Bytes h1_bytes = EncodeMpInt(aux.h1);
  const Bytes h2_bytes = EncodeMpInt(aux.h2);
  const Bytes c_bytes = EncodeMpInt(c);
  const Bytes z_bytes = EncodeMpInt(z);
  const Bytes u_bytes = EncodeMpInt(u);
  const Bytes w_bytes = EncodeMpInt(w);
  transcript.append_fields({
      TranscriptFieldRef{.label = "N", .data = n_bytes},
      TranscriptFieldRef{.label = "Gamma", .data = gamma_bytes},
      TranscriptFieldRef{.label = "Ntilde", .data = n_tilde_bytes},
      TranscriptFieldRef{.label = "h1", .data = h1_bytes},
      TranscriptFieldRef{.label = "h2", .data = h2_bytes},
      TranscriptFieldRef{.label = "c", .data = c_bytes},
      TranscriptFieldRef{.label = "z", .data = z_bytes},
      TranscriptFieldRef{.label = "u", .data = u_bytes},
      TranscriptFieldRef{.label = "w", .data = w_bytes},
  });
  return transcript.challenge_scalar_mod_q();
}

Scalar BuildA2MtAwcChallenge(const MtaProofContext& ctx,
                             const BigInt& n,
                             const BigInt& gamma,
                             const AuxRsaParams& aux,
                             const BigInt& c1,
                             const BigInt& c2,
                             const ECPoint& statement_x,
                             const A2MtAwcProof& proof) {
  Transcript transcript;
  AppendCommonMtaTranscriptFields(&transcript, kA2MtAwcProofId, ctx);
  const Bytes n_bytes = EncodeMpInt(n);
  const Bytes gamma_bytes = EncodeMpInt(gamma);
  const Bytes n_tilde_bytes = EncodeMpInt(aux.n_tilde);
  const Bytes h1_bytes = EncodeMpInt(aux.h1);
  const Bytes h2_bytes = EncodeMpInt(aux.h2);
  const Bytes c1_bytes = EncodeMpInt(c1);
  const Bytes c2_bytes = EncodeMpInt(c2);
  const Bytes x_bytes = EncodePoint(statement_x);
  const Bytes u_bytes = EncodePoint(proof.u);
  const Bytes z_bytes = EncodeMpInt(proof.z);
  const Bytes z2_bytes = EncodeMpInt(proof.z2);
  const Bytes t_bytes = EncodeMpInt(proof.t);
  const Bytes v_bytes = EncodeMpInt(proof.v);
  const Bytes w_bytes = EncodeMpInt(proof.w);
  transcript.append_fields({
      TranscriptFieldRef{.label = "N", .data = n_bytes},
      TranscriptFieldRef{.label = "Gamma", .data = gamma_bytes},
      TranscriptFieldRef{.label = "Ntilde", .data = n_tilde_bytes},
      TranscriptFieldRef{.label = "h1", .data = h1_bytes},
      TranscriptFieldRef{.label = "h2", .data = h2_bytes},
      TranscriptFieldRef{.label = "c1", .data = c1_bytes},
      TranscriptFieldRef{.label = "c2", .data = c2_bytes},
      TranscriptFieldRef{.label = "X", .data = x_bytes},
      TranscriptFieldRef{.label = "u", .data = u_bytes},
      TranscriptFieldRef{.label = "z", .data = z_bytes},
      TranscriptFieldRef{.label = "z2", .data = z2_bytes},
      TranscriptFieldRef{.label = "t", .data = t_bytes},
      TranscriptFieldRef{.label = "v", .data = v_bytes},
      TranscriptFieldRef{.label = "w", .data = w_bytes},
  });
  return transcript.challenge_scalar_mod_q();
}

Scalar BuildA3MtAChallenge(const MtaProofContext& ctx,
                           const BigInt& n,
                           const BigInt& gamma,
                           const AuxRsaParams& aux,
                           const BigInt& c1,
                           const BigInt& c2,
                           const A3MtAProof& proof) {
  Transcript transcript;
  AppendCommonMtaTranscriptFields(&transcript, kA3MtAProofId, ctx);
  const Bytes n_bytes = EncodeMpInt(n);
  const Bytes gamma_bytes = EncodeMpInt(gamma);
  const Bytes n_tilde_bytes = EncodeMpInt(aux.n_tilde);
  const Bytes h1_bytes = EncodeMpInt(aux.h1);
  const Bytes h2_bytes = EncodeMpInt(aux.h2);
  const Bytes c1_bytes = EncodeMpInt(c1);
  const Bytes c2_bytes = EncodeMpInt(c2);
  const Bytes z_bytes = EncodeMpInt(proof.z);
  const Bytes z2_bytes = EncodeMpInt(proof.z2);
  const Bytes t_bytes = EncodeMpInt(proof.t);
  const Bytes v_bytes = EncodeMpInt(proof.v);
  const Bytes w_bytes = EncodeMpInt(proof.w);
  transcript.append_fields({
      TranscriptFieldRef{.label = "N", .data = n_bytes},
      TranscriptFieldRef{.label = "Gamma", .data = gamma_bytes},
      TranscriptFieldRef{.label = "Ntilde", .data = n_tilde_bytes},
      TranscriptFieldRef{.label = "h1", .data = h1_bytes},
      TranscriptFieldRef{.label = "h2", .data = h2_bytes},
      TranscriptFieldRef{.label = "c1", .data = c1_bytes},
      TranscriptFieldRef{.label = "c2", .data = c2_bytes},
      TranscriptFieldRef{.label = "z", .data = z_bytes},
      TranscriptFieldRef{.label = "z2", .data = z2_bytes},
      TranscriptFieldRef{.label = "t", .data = t_bytes},
      TranscriptFieldRef{.label = "v", .data = v_bytes},
      TranscriptFieldRef{.label = "w", .data = w_bytes},
  });
  return transcript.challenge_scalar_mod_q();
}

A1RangeProof ProveA1Range(const MtaProofContext& ctx,
                          const BigInt& n,
                          const AuxRsaParams& verifier_aux,
                          const BigInt& c,
                          const BigInt& witness_m,
                          const BigInt& witness_r) {
  const BigInt n2 = n * n;
  const BigInt gamma = n + BigInt(1);
  const BigInt n_tilde = verifier_aux.n_tilde;
  const BigInt h1 = verifier_aux.h1;
  const BigInt h2 = verifier_aux.h2;
  const BigInt q_mul_n_tilde = Scalar::ModulusQMpInt() * n_tilde;
  const BigInt q3_mul_n_tilde = QPow3() * n_tilde;

  while (true) {
    const BigInt alpha = RandomBelow(QPow3());
    const BigInt beta = SampleZnStar(n);
    const BigInt gamma_rand = RandomBelow(q3_mul_n_tilde);
    const BigInt rho = RandomBelow(q_mul_n_tilde);

    const BigInt z = MulMod(PowMod(h1, witness_m, n_tilde), PowMod(h2, rho, n_tilde), n_tilde);
    const BigInt u = MulMod(PowMod(gamma, alpha, n2), PowMod(beta, n, n2), n2);
    const BigInt w = MulMod(PowMod(h1, alpha, n_tilde), PowMod(h2, gamma_rand, n_tilde), n_tilde);

    const Scalar e_scalar = BuildA1RangeChallenge(ctx, n, gamma, verifier_aux, c, z, u, w);
    const BigInt e = e_scalar.mp_value();
    const BigInt s = MulMod(PowMod(witness_r, e, n), beta, n);
    const BigInt s1 = (e * witness_m) + alpha;
    const BigInt s2 = (e * rho) + gamma_rand;
    if (s1 > QPow3()) {
      continue;
    }

    return A1RangeProof{
        .z = z,
        .u = u,
        .w = w,
        .s = s,
        .s1 = s1,
        .s2 = s2,
    };
  }
}

bool VerifyA1Range(const MtaProofContext& ctx,
                   const BigInt& n,
                   const AuxRsaParams& verifier_aux,
                   const BigInt& c,
                   const A1RangeProof& proof) {
  const BigInt n2 = n * n;
  const BigInt gamma = n + BigInt(1);
  const BigInt n_tilde = verifier_aux.n_tilde;
  const BigInt h1 = verifier_aux.h1;
  const BigInt h2 = verifier_aux.h2;

  if (!IsInRange(c, n2) || !IsInRange(proof.u, n2) ||
      !IsInRange(proof.z, n_tilde) ||
      !IsInRange(proof.w, n_tilde) ||
      !IsZnStarElement(proof.s, n)) {
    return false;
  }
  if (proof.s1 < 0 || proof.s1 > QPow3()) {
    return false;
  }
  if (proof.s2 < 0) {
    return false;
  }

  const Scalar e_scalar = BuildA1RangeChallenge(ctx, n, gamma, verifier_aux, c, proof.z, proof.u, proof.w);
  const BigInt e = e_scalar.mp_value();

  const BigInt c_pow_e = PowMod(c, e, n2);
  const std::optional<BigInt> c_pow_e_inv = InvertMod(c_pow_e, n2);
  if (!c_pow_e_inv.has_value()) {
    return false;
  }

  BigInt rhs_u = MulMod(PowMod(gamma, proof.s1, n2), PowMod(proof.s, n, n2), n2);
  rhs_u = MulMod(rhs_u, *c_pow_e_inv, n2);
  if (NormalizeMod(proof.u, n2) != rhs_u) {
    return false;
  }

  const BigInt lhs_n_tilde = MulMod(PowMod(h1, proof.s1, n_tilde), PowMod(h2, proof.s2, n_tilde), n_tilde);
  const BigInt rhs_n_tilde = MulMod(proof.w, PowMod(proof.z, e, n_tilde), n_tilde);
  return lhs_n_tilde == rhs_n_tilde;
}

A2MtAwcProof ProveA2MtAwc(const MtaProofContext& ctx,
                          const BigInt& n,
                          const AuxRsaParams& verifier_aux,
                          const BigInt& c1,
                          const BigInt& c2,
                          const ECPoint& statement_x,
                          const BigInt& witness_x,
                          const BigInt& witness_y,
                          const BigInt& witness_r) {
  const BigInt n2 = n * n;
  const BigInt gamma = n + BigInt(1);
  const BigInt n_tilde = verifier_aux.n_tilde;
  const BigInt h1 = verifier_aux.h1;
  const BigInt h2 = verifier_aux.h2;
  const BigInt q_mul_n_tilde = Scalar::ModulusQMpInt() * n_tilde;
  const BigInt q3_mul_n_tilde = QPow3() * n_tilde;

  while (true) {
    const BigInt alpha = RandomBelow(QPow3());
    const Scalar alpha_scalar(alpha);
    if (alpha_scalar.value() == 0) {
      continue;
    }

    const BigInt rho = RandomBelow(q_mul_n_tilde);
    const BigInt rho2 = RandomBelow(q3_mul_n_tilde);
    const BigInt sigma = RandomBelow(q_mul_n_tilde);
    const BigInt beta = SampleZnStar(n);
    const BigInt gamma_rand = RandomBelow(QPow7());
    const BigInt tau = RandomBelow(q3_mul_n_tilde);

    const ECPoint u = ECPoint::GeneratorMultiply(alpha_scalar);
    const BigInt z = MulMod(PowMod(h1, witness_x, n_tilde), PowMod(h2, rho, n_tilde), n_tilde);
    const BigInt z2 = MulMod(PowMod(h1, alpha, n_tilde), PowMod(h2, rho2, n_tilde), n_tilde);
    const BigInt t = MulMod(PowMod(h1, witness_y, n_tilde), PowMod(h2, sigma, n_tilde), n_tilde);

    BigInt v = MulMod(PowMod(c1, alpha, n2), PowMod(gamma, gamma_rand, n2), n2);
    v = MulMod(v, PowMod(beta, n, n2), n2);
    const BigInt w = MulMod(PowMod(h1, gamma_rand, n_tilde), PowMod(h2, tau, n_tilde), n_tilde);

    A2MtAwcProof proof{
        .u = u,
        .z = z,
        .z2 = z2,
        .t = t,
        .v = v,
        .w = w,
    };
    const Scalar e_scalar =
        BuildA2MtAwcChallenge(ctx, n, gamma, verifier_aux, c1, c2, statement_x, proof);
    const BigInt e = e_scalar.mp_value();

    const BigInt s = MulMod(PowMod(witness_r, e, n), beta, n);
    const BigInt s1 = (e * witness_x) + alpha;
    const BigInt s2 = (e * rho) + rho2;
    const BigInt t1 = (e * witness_y) + gamma_rand;
    const BigInt t2 = (e * sigma) + tau;
    if (s1 > QPow3() || t1 > QPow7()) {
      continue;
    }
    proof.s = s;
    proof.s1 = s1;
    proof.s2 = s2;
    proof.t1 = t1;
    proof.t2 = t2;
    return proof;
  }
}

bool VerifyA2MtAwc(const MtaProofContext& ctx,
                   const BigInt& n,
                   const AuxRsaParams& verifier_aux,
                   const BigInt& c1,
                   const BigInt& c2,
                   const ECPoint& statement_x,
                   const A2MtAwcProof& proof) {
  const BigInt n2 = n * n;
  const BigInt gamma = n + BigInt(1);
  const BigInt n_tilde = verifier_aux.n_tilde;
  const BigInt h1 = verifier_aux.h1;
  const BigInt h2 = verifier_aux.h2;

  if (!IsInRange(c1, n2) || !IsInRange(c2, n2) ||
      !IsInRange(proof.v, n2) || !IsInRange(proof.z, n_tilde) ||
      !IsInRange(proof.z2, n_tilde) ||
      !IsInRange(proof.t, n_tilde) ||
      !IsInRange(proof.w, n_tilde) ||
      !IsZnStarElement(proof.s, n)) {
    return false;
  }
  if (proof.s1 < 0 || proof.s1 > QPow3() || proof.t1 < 0 || proof.t1 > QPow7() ||
      proof.s2 < 0 || proof.t2 < 0) {
    return false;
  }

  const Scalar e_scalar =
      BuildA2MtAwcChallenge(ctx, n, gamma, verifier_aux, c1, c2, statement_x, proof);

  try {
    const Scalar s1_mod_q(proof.s1);
    if (s1_mod_q.value() == 0) {
      return false;
    }
    const ECPoint lhs_curve = ECPoint::GeneratorMultiply(s1_mod_q);
    ECPoint rhs_curve = proof.u;
    if (e_scalar.value() != 0) {
      rhs_curve = rhs_curve.Add(statement_x.Mul(e_scalar));
    }
    if (lhs_curve != rhs_curve) {
      return false;
    }
  } catch (const std::exception&) {
    return false;
  }

  const BigInt e = e_scalar.mp_value();
  const BigInt lhs_nt_1 = MulMod(PowMod(h1, proof.s1, n_tilde), PowMod(h2, proof.s2, n_tilde), n_tilde);
  const BigInt rhs_nt_1 = MulMod(PowMod(proof.z, e, n_tilde), proof.z2, n_tilde);
  if (lhs_nt_1 != rhs_nt_1) {
    return false;
  }

  const BigInt lhs_nt_2 = MulMod(PowMod(h1, proof.t1, n_tilde), PowMod(h2, proof.t2, n_tilde), n_tilde);
  const BigInt rhs_nt_2 = MulMod(PowMod(proof.t, e, n_tilde), proof.w, n_tilde);
  if (lhs_nt_2 != rhs_nt_2) {
    return false;
  }

  BigInt lhs_paillier = MulMod(PowMod(c1, proof.s1, n2), PowMod(proof.s, n, n2), n2);
  lhs_paillier = MulMod(lhs_paillier, PowMod(gamma, proof.t1, n2), n2);
  const BigInt rhs_paillier = MulMod(PowMod(c2, e, n2), proof.v, n2);
  return lhs_paillier == rhs_paillier;
}

A3MtAProof ProveA3MtA(const MtaProofContext& ctx,
                      const BigInt& n,
                      const AuxRsaParams& verifier_aux,
                      const BigInt& c1,
                      const BigInt& c2,
                      const BigInt& witness_x,
                      const BigInt& witness_y,
                      const BigInt& witness_r) {
  const BigInt n2 = n * n;
  const BigInt gamma = n + BigInt(1);
  const BigInt n_tilde = verifier_aux.n_tilde;
  const BigInt h1 = verifier_aux.h1;
  const BigInt h2 = verifier_aux.h2;
  const BigInt q_mul_n_tilde = Scalar::ModulusQMpInt() * n_tilde;
  const BigInt q3_mul_n_tilde = QPow3() * n_tilde;

  while (true) {
    const BigInt alpha = RandomBelow(QPow3());
    const BigInt rho = RandomBelow(q_mul_n_tilde);
    const BigInt rho2 = RandomBelow(q3_mul_n_tilde);
    const BigInt sigma = RandomBelow(q_mul_n_tilde);
    const BigInt beta = SampleZnStar(n);
    const BigInt gamma_rand = RandomBelow(QPow7());
    const BigInt tau = RandomBelow(q3_mul_n_tilde);

    const BigInt z = MulMod(PowMod(h1, witness_x, n_tilde), PowMod(h2, rho, n_tilde), n_tilde);
    const BigInt z2 = MulMod(PowMod(h1, alpha, n_tilde), PowMod(h2, rho2, n_tilde), n_tilde);
    const BigInt t = MulMod(PowMod(h1, witness_y, n_tilde), PowMod(h2, sigma, n_tilde), n_tilde);
    BigInt v = MulMod(PowMod(c1, alpha, n2), PowMod(gamma, gamma_rand, n2), n2);
    v = MulMod(v, PowMod(beta, n, n2), n2);
    const BigInt w = MulMod(PowMod(h1, gamma_rand, n_tilde), PowMod(h2, tau, n_tilde), n_tilde);

    A3MtAProof proof{
        .z = z,
        .z2 = z2,
        .t = t,
        .v = v,
        .w = w,
    };
    const Scalar e_scalar = BuildA3MtAChallenge(ctx, n, gamma, verifier_aux, c1, c2, proof);
    const BigInt e = e_scalar.mp_value();

    const BigInt s = MulMod(PowMod(witness_r, e, n), beta, n);
    const BigInt s1 = (e * witness_x) + alpha;
    const BigInt s2 = (e * rho) + rho2;
    const BigInt t1 = (e * witness_y) + gamma_rand;
    const BigInt t2 = (e * sigma) + tau;
    if (s1 > QPow3() || t1 > QPow7()) {
      continue;
    }
    proof.s = s;
    proof.s1 = s1;
    proof.s2 = s2;
    proof.t1 = t1;
    proof.t2 = t2;
    return proof;
  }
}

bool VerifyA3MtA(const MtaProofContext& ctx,
                 const BigInt& n,
                 const AuxRsaParams& verifier_aux,
                 const BigInt& c1,
                 const BigInt& c2,
                 const A3MtAProof& proof) {
  const BigInt n2 = n * n;
  const BigInt gamma = n + BigInt(1);
  const BigInt n_tilde = verifier_aux.n_tilde;
  const BigInt h1 = verifier_aux.h1;
  const BigInt h2 = verifier_aux.h2;

  if (!IsInRange(c1, n2) || !IsInRange(c2, n2) ||
      !IsInRange(proof.v, n2) || !IsInRange(proof.z, n_tilde) ||
      !IsInRange(proof.z2, n_tilde) ||
      !IsInRange(proof.t, n_tilde) ||
      !IsInRange(proof.w, n_tilde) ||
      !IsZnStarElement(proof.s, n)) {
    return false;
  }
  if (proof.s1 < 0 || proof.s1 > QPow3() || proof.t1 < 0 || proof.t1 > QPow7() ||
      proof.s2 < 0 || proof.t2 < 0) {
    return false;
  }

  const Scalar e_scalar = BuildA3MtAChallenge(ctx, n, gamma, verifier_aux, c1, c2, proof);
  const BigInt e = e_scalar.mp_value();

  const BigInt lhs_nt_1 = MulMod(PowMod(h1, proof.s1, n_tilde), PowMod(h2, proof.s2, n_tilde), n_tilde);
  const BigInt rhs_nt_1 = MulMod(PowMod(proof.z, e, n_tilde), proof.z2, n_tilde);
  if (lhs_nt_1 != rhs_nt_1) {
    return false;
  }

  const BigInt lhs_nt_2 = MulMod(PowMod(h1, proof.t1, n_tilde), PowMod(h2, proof.t2, n_tilde), n_tilde);
  const BigInt rhs_nt_2 = MulMod(PowMod(proof.t, e, n_tilde), proof.w, n_tilde);
  if (lhs_nt_2 != rhs_nt_2) {
    return false;
  }

  BigInt lhs_paillier = MulMod(PowMod(c1, proof.s1, n2), PowMod(proof.s, n, n2), n2);
  lhs_paillier = MulMod(lhs_paillier, PowMod(gamma, proof.t1, n2), n2);
  const BigInt rhs_paillier = MulMod(PowMod(c2, e, n2), proof.v, n2);
  return lhs_paillier == rhs_paillier;
}

void AppendA1RangeProof(const A1RangeProof& proof, Bytes* out) {
  AppendMpIntField(proof.z, out);
  AppendMpIntField(proof.u, out);
  AppendMpIntField(proof.w, out);
  AppendMpIntField(proof.s, out);
  AppendMpIntField(proof.s1, out);
  AppendMpIntField(proof.s2, out);
}

A1RangeProof ReadA1RangeProof(std::span<const uint8_t> input, size_t* offset) {
  A1RangeProof proof;
  proof.z = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A1.z");
  proof.u = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A1.u");
  proof.w = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A1.w");
  proof.s = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A1.s");
  proof.s1 = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A1.s1");
  proof.s2 = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A1.s2");
  return proof;
}

void AppendA2MtAwcProof(const A2MtAwcProof& proof, Bytes* out) {
  AppendPoint(proof.u, out);
  AppendMpIntField(proof.z, out);
  AppendMpIntField(proof.z2, out);
  AppendMpIntField(proof.t, out);
  AppendMpIntField(proof.v, out);
  AppendMpIntField(proof.w, out);
  AppendMpIntField(proof.s, out);
  AppendMpIntField(proof.s1, out);
  AppendMpIntField(proof.s2, out);
  AppendMpIntField(proof.t1, out);
  AppendMpIntField(proof.t2, out);
}

A2MtAwcProof ReadA2MtAwcProof(std::span<const uint8_t> input, size_t* offset) {
  A2MtAwcProof proof{
      .u = ReadPoint(input, offset),
  };
  proof.z = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A2.z");
  proof.z2 = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A2.z2");
  proof.t = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A2.t");
  proof.v = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A2.v");
  proof.w = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A2.w");
  proof.s = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A2.s");
  proof.s1 = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A2.s1");
  proof.s2 = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A2.s2");
  proof.t1 = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A2.t1");
  proof.t2 = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A2.t2");
  return proof;
}

void AppendA3MtAProof(const A3MtAProof& proof, Bytes* out) {
  AppendMpIntField(proof.z, out);
  AppendMpIntField(proof.z2, out);
  AppendMpIntField(proof.t, out);
  AppendMpIntField(proof.v, out);
  AppendMpIntField(proof.w, out);
  AppendMpIntField(proof.s, out);
  AppendMpIntField(proof.s1, out);
  AppendMpIntField(proof.s2, out);
  AppendMpIntField(proof.t1, out);
  AppendMpIntField(proof.t2, out);
}

A3MtAProof ReadA3MtAProof(std::span<const uint8_t> input, size_t* offset) {
  A3MtAProof proof;
  proof.z = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A3.z");
  proof.z2 = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A3.z2");
  proof.t = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A3.t");
  proof.v = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A3.v");
  proof.w = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A3.w");
  proof.s = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A3.s");
  proof.s1 = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A3.s1");
  proof.s2 = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A3.s2");
  proof.t1 = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A3.t1");
  proof.t2 = ReadMpIntField(input, offset, kMaxMpIntEncodedLen, "A3.t2");
  return proof;
}

Bytes RandomMtaInstanceId() {
  return Csprng::RandomBytes(kMtaInstanceIdLen);
}

Scalar RandomNonZeroScalar() {
  while (true) {
    const Scalar candidate = Csprng::RandomScalar();
    if (candidate.value() != 0) {
      return candidate;
    }
  }
}

BigInt NormalizeModQ(const BigInt& value) {
  return bigint::NormalizeMod(value, Scalar::ModulusQMpInt());
}

std::optional<Scalar> InvertScalar(const Scalar& scalar) {
  if (scalar.value() == 0) {
    return std::nullopt;
  }
  try {
    return scalar.InverseModQ();
  } catch (const std::exception&) {
    return std::nullopt;
  }
}

bool IsHighScalar(const Scalar& scalar) {
  static const BigInt kHalfOrder = Scalar::ModulusQMpInt() >> 1;
  return scalar.value() > kHalfOrder;
}

std::unordered_map<PartyIndex, Scalar> ComputeLagrangeAtZero(
    const std::vector<PartyIndex>& participants) {
  std::unordered_map<PartyIndex, Scalar> out;
  out.reserve(participants.size());

  for (PartyIndex i : participants) {
    BigInt numerator(1);
    BigInt denominator(1);

    for (PartyIndex j : participants) {
      if (j == i) {
        continue;
      }

      const BigInt neg_j = NormalizeModQ(BigInt(0) - BigInt(j));
      numerator = NormalizeModQ(numerator * neg_j);

      const BigInt diff = NormalizeModQ(BigInt(i) - BigInt(j));
      if (diff == 0) {
        TECDSA_THROW_ARGUMENT("duplicate participant id in lagrange coefficient set");
      }
      denominator = NormalizeModQ(denominator * diff);
    }

    Scalar lambda = Scalar(numerator) * Scalar(denominator).InverseModQ();
    out.emplace(i, lambda);
  }

  return out;
}

ECPoint SumPointsOrThrow(const std::vector<ECPoint>& points) {
  if (points.empty()) {
    TECDSA_THROW_ARGUMENT("cannot sum empty point vector");
  }

  ECPoint sum = points.front();
  for (size_t i = 1; i < points.size(); ++i) {
    sum = sum.Add(points[i]);
  }
  return sum;
}

Bytes SerializePointPair(const ECPoint& first, const ECPoint& second) {
  Bytes out;
  out.reserve(kPointCompressedLen * 2);
  AppendPoint(first, &out);
  AppendPoint(second, &out);
  return out;
}

Scalar XCoordinateModQ(const ECPoint& point) {
  const Bytes compressed = point.ToCompressedBytes();
  if (compressed.size() != kPointCompressedLen) {
    TECDSA_THROW_ARGUMENT("invalid compressed point length");
  }

  const std::span<const uint8_t> x_bytes(compressed.data() + 1, 32);
  return Scalar::FromBigEndianModQ(x_bytes);
}

Scalar BuildSchnorrChallenge(const Bytes& session_id,
                             PartyIndex party_id,
                             const ECPoint& statement,
                             const ECPoint& a) {
  Transcript transcript;
  const Bytes statement_bytes = EncodePoint(statement);
  const Bytes a_bytes = EncodePoint(a);
  transcript.append_proof_id(kSchnorrProofId);
  transcript.append_session_id(session_id);
  transcript.append_u32_be("party_id", party_id);
  transcript.append_fields({
      TranscriptFieldRef{.label = "X", .data = statement_bytes},
      TranscriptFieldRef{.label = "A", .data = a_bytes},
  });
  return transcript.challenge_scalar_mod_q();
}

Scalar BuildVRelationChallenge(const Bytes& session_id,
                               PartyIndex party_id,
                               const ECPoint& r_statement,
                               const ECPoint& v_statement,
                               const ECPoint& alpha) {
  Transcript transcript;
  const Bytes r_bytes = EncodePoint(r_statement);
  const Bytes v_bytes = EncodePoint(v_statement);
  const Bytes alpha_bytes = EncodePoint(alpha);
  transcript.append_proof_id(kVRelationProofId);
  transcript.append_session_id(session_id);
  transcript.append_u32_be("party_id", party_id);
  transcript.append_fields({
      TranscriptFieldRef{.label = "R", .data = r_bytes},
      TranscriptFieldRef{.label = "V", .data = v_bytes},
      TranscriptFieldRef{.label = "alpha", .data = alpha_bytes},
  });
  return transcript.challenge_scalar_mod_q();
}

ECPoint BuildRGeneratorLinearCombination(const ECPoint& r_base,
                                         const Scalar& r_multiplier,
                                         const Scalar& g_multiplier) {
  std::optional<ECPoint> out;

  if (r_multiplier.value() != 0) {
    out = r_base.Mul(r_multiplier);
  }

  if (g_multiplier.value() != 0) {
    const ECPoint g_term = ECPoint::GeneratorMultiply(g_multiplier);
    if (out.has_value()) {
      out = out->Add(g_term);
    } else {
      out = g_term;
    }
  }

  if (!out.has_value()) {
    TECDSA_THROW_ARGUMENT("linear combination is point at infinity");
  }
  return *out;
}

}  // namespace

SignSession::SignSession(SignSessionConfig cfg)
    : Session(std::move(cfg.session_id), cfg.self_id, cfg.timeout),
      participants_(std::move(cfg.participants)),
      peers_(BuildPeerSet(participants_, cfg.self_id)),
      all_X_i_(std::move(cfg.all_X_i)),
      all_paillier_public_(std::move(cfg.all_paillier_public)),
      all_aux_rsa_params_(std::move(cfg.all_aux_rsa_params)),
      all_square_free_proofs_(std::move(cfg.all_square_free_proofs)),
      all_aux_param_proofs_(std::move(cfg.all_aux_param_proofs)),
      expected_square_free_proof_profile_(std::move(cfg.square_free_proof_profile)),
      expected_aux_param_proof_profile_(std::move(cfg.aux_param_proof_profile)),
      local_paillier_(std::move(cfg.local_paillier)),
      strict_mode_(cfg.strict_mode),
      require_aux_param_proof_(cfg.require_aux_param_proof),
      local_x_i_(cfg.x_i),
      public_key_y_(cfg.y),
      msg32_(std::move(cfg.msg32)),
      fixed_k_i_(cfg.fixed_k_i),
      fixed_gamma_i_(cfg.fixed_gamma_i) {
  ValidateParticipantsOrThrow(participants_, cfg.self_id);
  const Bytes keygen_session_id = std::move(cfg.keygen_session_id);

  if (msg32_.size() != 32) {
    TECDSA_THROW_ARGUMENT("msg32 must be exactly 32 bytes for SignSession");
  }
  if (local_x_i_.value() == 0) {
    TECDSA_THROW_ARGUMENT("local x_i share must be non-zero");
  }
  if (local_paillier_ == nullptr) {
    TECDSA_THROW_ARGUMENT("local Paillier provider must be present");
  }
  if (strict_mode_) {
    if (expected_square_free_proof_profile_.scheme != StrictProofScheme::kUnknown &&
        !IsStrictProofScheme(expected_square_free_proof_profile_.scheme)) {
      TECDSA_THROW_ARGUMENT("strict sign expected square-free profile must use strict scheme");
    }
    if (expected_aux_param_proof_profile_.scheme != StrictProofScheme::kUnknown &&
        !IsStrictProofScheme(expected_aux_param_proof_profile_.scheme)) {
      TECDSA_THROW_ARGUMENT("strict sign expected aux profile must use strict scheme");
    }
  }

  for (PartyIndex party : participants_) {
    if (!all_X_i_.contains(party)) {
      TECDSA_THROW_ARGUMENT("all_X_i is missing participant public share");
    }
    const auto paillier_it = all_paillier_public_.find(party);
    if (paillier_it == all_paillier_public_.end()) {
      TECDSA_THROW_ARGUMENT("all_paillier_public is missing participant key");
    }
    if (paillier_it->second.n <= MinPaillierModulusQ8()) {
      TECDSA_THROW_ARGUMENT("Paillier modulus must satisfy N > q^8");
    }

    const auto aux_it = all_aux_rsa_params_.find(party);
    if (aux_it == all_aux_rsa_params_.end()) {
      TECDSA_THROW_ARGUMENT("all_aux_rsa_params is missing participant params");
    }
    ValidateAuxRsaParamsOrThrow(aux_it->second);

    const auto square_it = all_square_free_proofs_.find(party);
    const bool has_square_proof =
        square_it != all_square_free_proofs_.end() && !square_it->second.blob.empty();
    if (strict_mode_ && !has_square_proof) {
      TECDSA_THROW_ARGUMENT("strict mode requires square-free proof for each participant");
    }
    if (has_square_proof) {
      const StrictProofVerifierContext context = BuildKeygenProofContext(keygen_session_id, party);
      if (strict_mode_) {
        if (expected_square_free_proof_profile_.scheme == StrictProofScheme::kUnknown) {
          expected_square_free_proof_profile_ = square_it->second.metadata;
        }
        if (!StrictMetadataCompatible(expected_square_free_proof_profile_, square_it->second.metadata)) {
          TECDSA_THROW_ARGUMENT("square-free proof metadata is not compatible with strict profile");
        }
        if (!VerifySquareFreeProofGmr98(paillier_it->second.n, square_it->second, context)) {
          TECDSA_THROW_ARGUMENT("square-free proof verification failed");
        }
      } else if (!VerifySquareFreeProof(paillier_it->second.n, square_it->second, context)) {
        TECDSA_THROW_ARGUMENT("square-free proof verification failed");
      }
    }

    const auto aux_pf_it = all_aux_param_proofs_.find(party);
    const bool has_aux_proof =
        aux_pf_it != all_aux_param_proofs_.end() && !aux_pf_it->second.blob.empty();
    if (strict_mode_ && require_aux_param_proof_ && !has_aux_proof) {
      TECDSA_THROW_ARGUMENT("strict mode requires aux parameter proof for each participant");
    }
    if (has_aux_proof) {
      const StrictProofVerifierContext context = BuildKeygenProofContext(keygen_session_id, party);
      if (strict_mode_) {
        if (expected_aux_param_proof_profile_.scheme == StrictProofScheme::kUnknown) {
          expected_aux_param_proof_profile_ = aux_pf_it->second.metadata;
        }
        if (!StrictMetadataCompatible(expected_aux_param_proof_profile_, aux_pf_it->second.metadata)) {
          TECDSA_THROW_ARGUMENT("aux proof metadata is not compatible with strict profile");
        }
        if (!VerifyAuxRsaParamProofStrict(aux_it->second, aux_pf_it->second, context)) {
          TECDSA_THROW_ARGUMENT("aux parameter proof verification failed");
        }
      } else if (!VerifyAuxRsaParamProof(aux_it->second, aux_pf_it->second, context)) {
        TECDSA_THROW_ARGUMENT("aux parameter proof verification failed");
      }
    }
  }
  const auto self_pk_it = all_paillier_public_.find(self_id());
  if (self_pk_it == all_paillier_public_.end()) {
    TECDSA_THROW_ARGUMENT("missing self Paillier public key");
  }
  if (self_pk_it->second.n != local_paillier_->modulus_n()) {
    TECDSA_THROW_ARGUMENT("self Paillier public key does not match local provider");
  }

  message_scalar_ = Scalar::FromBigEndianModQ(msg32_);
  PrepareResharedSigningShares();
}

SignPhase SignSession::phase() const {
  return phase_;
}

SignPhase5Stage SignSession::phase5_stage() const {
  return phase5_stage_;
}

size_t SignSession::received_peer_count_in_phase() const {
  switch (phase_) {
    case SignPhase::kPhase1:
      return seen_phase1_.size();
    case SignPhase::kPhase2:
      return std::min(phase2_initiator_instances_.size(), phase2_responder_requests_seen_.size()) / 2;
    case SignPhase::kPhase3:
      return seen_phase3_.size();
    case SignPhase::kPhase4:
      return seen_phase4_.size();
    case SignPhase::kPhase5:
      switch (phase5_stage_) {
        case SignPhase5Stage::kPhase5A:
          return seen_phase5a_.size();
        case SignPhase5Stage::kPhase5B:
          return seen_phase5b_.size();
        case SignPhase5Stage::kPhase5C:
          return seen_phase5c_.size();
        case SignPhase5Stage::kPhase5D:
          return seen_phase5d_.size();
        case SignPhase5Stage::kPhase5E:
          return seen_phase5e_.size();
        case SignPhase5Stage::kCompleted:
          return peers_.size();
      }
      TECDSA_THROW_ARGUMENT("invalid phase5 stage");
    case SignPhase::kCompleted:
      return peers_.size();
  }
  TECDSA_THROW_ARGUMENT("invalid sign phase");
}

Envelope SignSession::BuildPhase1CommitEnvelope() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase1 envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase1) {
    TECDSA_THROW_LOGIC("BuildPhase1CommitEnvelope must be called in sign phase1");
  }

  PreparePhase1SecretsIfNeeded();

  local_phase1_ready_ = true;
  phase1_commitments_[self_id()] = local_phase1_commitment_;

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase(SignPhase::kPhase1);
  out.payload = local_phase1_commitment_;

  MaybeAdvanceAfterPhase1();
  return out;
}

std::vector<Envelope> SignSession::BuildPhase2MtaEnvelopes() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase2 envelopes for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase2) {
    TECDSA_THROW_LOGIC("BuildPhase2MtaEnvelopes must be called in sign phase2");
  }

  InitializePhase2InstancesIfNeeded();

  std::vector<Envelope> out;
  out.swap(phase2_outbox_);

  MaybeAdvanceAfterPhase2();
  return out;
}

Envelope SignSession::BuildPhase3DeltaEnvelope() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase3 envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase3) {
    TECDSA_THROW_LOGIC("BuildPhase3DeltaEnvelope must be called in sign phase3");
  }

  local_phase3_ready_ = true;
  phase3_delta_shares_[self_id()] = local_delta_i_;

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase(SignPhase::kPhase3);
  AppendScalar(local_delta_i_, &out.payload);

  MaybeAdvanceAfterPhase3();
  return out;
}

Envelope SignSession::BuildPhase4OpenGammaEnvelope() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase4 envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase4) {
    TECDSA_THROW_LOGIC("BuildPhase4OpenGammaEnvelope must be called in sign phase4");
  }

  PreparePhase1SecretsIfNeeded();
  const SchnorrProof gamma_proof = BuildSchnorrProof(local_Gamma_i_, local_gamma_i_);

  local_phase4_ready_ = true;
  phase4_open_data_[self_id()] = Phase4OpenData{
      .gamma_i = local_Gamma_i_,
      .gamma_proof = gamma_proof,
      .randomness = local_phase1_randomness_,
  };

  Bytes payload;
  payload.reserve(kPointCompressedLen + 4 + local_phase1_randomness_.size() + kPointCompressedLen + kScalarLen);
  AppendPoint(local_Gamma_i_, &payload);
  AppendSizedField(local_phase1_randomness_, &payload);
  AppendPoint(gamma_proof.a, &payload);
  AppendScalar(gamma_proof.z, &payload);

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase(SignPhase::kPhase4);
  out.payload = std::move(payload);

  MaybeAdvanceAfterPhase4();
  return out;
}

Envelope SignSession::BuildPhase5ACommitEnvelope() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase5A envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5A) {
    TECDSA_THROW_LOGIC("BuildPhase5ACommitEnvelope must be called in sign phase5A");
  }

  local_s_i_ = (message_scalar_ * local_k_i_) + (r_ * local_sigma_i_);
  local_l_i_ = RandomNonZeroScalar();
  local_rho_i_ = RandomNonZeroScalar();

  ECPoint V_i = ECPoint::GeneratorMultiply(local_l_i_);
  if (local_s_i_.value() != 0) {
    V_i = V_i.Add(R_.Mul(local_s_i_));
  }
  local_V_i_ = V_i;
  local_A_i_ = ECPoint::GeneratorMultiply(local_rho_i_);

  const Bytes commit_message = SerializePointPair(local_V_i_, local_A_i_);
  const CommitmentResult commitment = CommitMessage(kPhase5ACommitDomain, commit_message);

  local_phase5a_randomness_ = commitment.randomness;
  local_phase5a_commitment_ = commitment.commitment;

  local_phase5a_ready_ = true;
  phase5a_commitments_[self_id()] = local_phase5a_commitment_;

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5A);
  out.payload = local_phase5a_commitment_;

  MaybeAdvanceAfterPhase5A();
  return out;
}

Envelope SignSession::BuildPhase5BOpenEnvelope() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase5B envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5B) {
    TECDSA_THROW_LOGIC("BuildPhase5BOpenEnvelope must be called in sign phase5B");
  }

  const SchnorrProof a_schnorr_proof = BuildSchnorrProof(local_A_i_, local_rho_i_);
  const VRelationProof v_relation_proof =
      BuildVRelationProof(R_, local_V_i_, local_s_i_, local_l_i_);

  local_phase5b_ready_ = true;
  phase5b_open_data_[self_id()] = Phase5BOpenData{
      .V_i = local_V_i_,
      .A_i = local_A_i_,
      .a_schnorr_proof = a_schnorr_proof,
      .v_relation_proof = v_relation_proof,
      .randomness = local_phase5a_randomness_,
  };

  Bytes payload;
  payload.reserve(kPointCompressedLen * 4 + kScalarLen * 3 + 4 + local_phase5a_randomness_.size());
  AppendPoint(local_V_i_, &payload);
  AppendPoint(local_A_i_, &payload);
  AppendSizedField(local_phase5a_randomness_, &payload);
  AppendPoint(a_schnorr_proof.a, &payload);
  AppendScalar(a_schnorr_proof.z, &payload);
  AppendPoint(v_relation_proof.alpha, &payload);
  AppendScalar(v_relation_proof.t, &payload);
  AppendScalar(v_relation_proof.u, &payload);

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5B);
  out.payload = std::move(payload);

  MaybeAdvanceAfterPhase5B();
  return out;
}

Envelope SignSession::BuildPhase5CCommitEnvelope() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase5C envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5C) {
    TECDSA_THROW_LOGIC("BuildPhase5CCommitEnvelope must be called in sign phase5C");
  }

  local_U_i_ = V_.Mul(local_rho_i_);
  local_T_i_ = A_.Mul(local_l_i_);

  const Bytes commit_message = SerializePointPair(local_U_i_, local_T_i_);
  const CommitmentResult commitment = CommitMessage(kPhase5CCommitDomain, commit_message);
  local_phase5c_randomness_ = commitment.randomness;
  local_phase5c_commitment_ = commitment.commitment;

  local_phase5c_ready_ = true;
  phase5c_commitments_[self_id()] = local_phase5c_commitment_;

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5C);
  out.payload = local_phase5c_commitment_;

  MaybeAdvanceAfterPhase5C();
  return out;
}

Envelope SignSession::BuildPhase5DOpenEnvelope() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase5D envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5D) {
    TECDSA_THROW_LOGIC("BuildPhase5DOpenEnvelope must be called in sign phase5D");
  }

  local_phase5d_ready_ = true;
  phase5d_open_data_[self_id()] =
      Phase5DOpenData{.U_i = local_U_i_, .T_i = local_T_i_, .randomness = local_phase5c_randomness_};

  Bytes payload;
  payload.reserve(kPointCompressedLen * 2 + 4 + local_phase5c_randomness_.size());
  AppendPoint(local_U_i_, &payload);
  AppendPoint(local_T_i_, &payload);
  AppendSizedField(local_phase5c_randomness_, &payload);

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5D);
  out.payload = std::move(payload);

  MaybeAdvanceAfterPhase5D();
  return out;
}

Envelope SignSession::BuildPhase5ERevealEnvelope() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase5E envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5E) {
    TECDSA_THROW_LOGIC("BuildPhase5ERevealEnvelope must be called in sign phase5E");
  }

  local_phase5e_ready_ = true;
  phase5e_revealed_s_[self_id()] = local_s_i_;

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5E);
  AppendScalar(local_s_i_, &out.payload);

  MaybeAdvanceAfterPhase5E();
  return out;
}

bool SignSession::HandleEnvelope(const Envelope& envelope) {
  if (PollTimeout()) {
    return false;
  }
  if (IsTerminal()) {
    return false;
  }

  std::string error;
  if (!ValidateSessionBinding(envelope.session_id, envelope.to, &error)) {
    return false;
  }

  if (!peers_.contains(envelope.from)) {
    return false;
  }

  switch (phase_) {
    case SignPhase::kPhase1:
      if (envelope.type != MessageTypeForPhase(SignPhase::kPhase1)) {
        Abort("unexpected envelope type for sign phase1");
        return false;
      }
      return HandlePhase1CommitEnvelope(envelope);
    case SignPhase::kPhase2:
      if (envelope.type == MessageTypeForPhase(SignPhase::kPhase2)) {
        return HandlePhase2InitEnvelope(envelope);
      }
      if (envelope.type == Phase2ResponseMessageType()) {
        return HandlePhase2ResponseEnvelope(envelope);
      }
      Abort("unexpected envelope type for sign phase2");
      return false;
    case SignPhase::kPhase3:
      if (envelope.type != MessageTypeForPhase(SignPhase::kPhase3)) {
        Abort("unexpected envelope type for sign phase3");
        return false;
      }
      return HandlePhase3DeltaEnvelope(envelope);
    case SignPhase::kPhase4:
      if (envelope.type != MessageTypeForPhase(SignPhase::kPhase4)) {
        Abort("unexpected envelope type for sign phase4");
        return false;
      }
      return HandlePhase4OpenEnvelope(envelope);
    case SignPhase::kPhase5:
      switch (phase5_stage_) {
        case SignPhase5Stage::kPhase5A:
          if (envelope.type != MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5A)) {
            Abort("unexpected envelope type for sign phase5A");
            return false;
          }
          return HandlePhase5ACommitEnvelope(envelope);
        case SignPhase5Stage::kPhase5B:
          if (envelope.type != MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5B)) {
            Abort("unexpected envelope type for sign phase5B");
            return false;
          }
          return HandlePhase5BOpenEnvelope(envelope);
        case SignPhase5Stage::kPhase5C:
          if (envelope.type != MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5C)) {
            Abort("unexpected envelope type for sign phase5C");
            return false;
          }
          return HandlePhase5CCommitEnvelope(envelope);
        case SignPhase5Stage::kPhase5D:
          if (envelope.type != MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5D)) {
            Abort("unexpected envelope type for sign phase5D");
            return false;
          }
          return HandlePhase5DOpenEnvelope(envelope);
        case SignPhase5Stage::kPhase5E:
          if (envelope.type != MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5E)) {
            Abort("unexpected envelope type for sign phase5E");
            return false;
          }
          return HandlePhase5ERevealEnvelope(envelope);
        case SignPhase5Stage::kCompleted:
          return false;
      }
      TECDSA_THROW_ARGUMENT("invalid sign phase5 stage");
    case SignPhase::kCompleted:
      return false;
  }
  TECDSA_THROW_ARGUMENT("invalid sign phase");
}

Envelope SignSession::MakePhaseBroadcastEnvelope(const Bytes& payload) const {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot create envelope for terminal session");
  }

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type =
      (phase_ == SignPhase::kPhase5) ? MessageTypeForPhase5Stage(phase5_stage_) : MessageTypeForPhase(phase_);
  out.payload = payload;
  return out;
}

bool SignSession::HasResult() const {
  return status() == SessionStatus::kCompleted && phase_ == SignPhase::kCompleted && has_result_;
}

const SignResult& SignSession::result() const {
  if (!HasResult()) {
    TECDSA_THROW_LOGIC("sign result is not ready");
  }
  return result_;
}

bool SignSession::PollTimeout(std::chrono::steady_clock::time_point now) {
  const bool timed_out = Session::PollTimeout(now);
  if (timed_out) {
    ClearSensitiveIntermediates();
  }
  return timed_out;
}

uint32_t SignSession::MessageTypeForPhase(SignPhase phase) {
  switch (phase) {
    case SignPhase::kPhase1:
      return static_cast<uint32_t>(SignMessageType::kPhase1);
    case SignPhase::kPhase2:
      return static_cast<uint32_t>(SignMessageType::kPhase2);
    case SignPhase::kPhase3:
      return static_cast<uint32_t>(SignMessageType::kPhase3);
    case SignPhase::kPhase4:
      return static_cast<uint32_t>(SignMessageType::kPhase4);
    case SignPhase::kPhase5:
      return static_cast<uint32_t>(SignMessageType::kPhase5A);
    case SignPhase::kCompleted:
      return static_cast<uint32_t>(SignMessageType::kAbort);
  }
  TECDSA_THROW_ARGUMENT("invalid sign phase");
}

uint32_t SignSession::Phase2ResponseMessageType() {
  return static_cast<uint32_t>(SignMessageType::kPhase2Response);
}

void SignSession::ClearSensitiveIntermediates() {
  SecureZeroize(&local_x_i_);
  SecureZeroize(&local_w_i_);
  SecureZeroize(&local_k_i_);
  SecureZeroize(&local_gamma_i_);
  SecureZeroize(&local_delta_i_);
  SecureZeroize(&local_sigma_i_);
  SecureZeroize(&delta_);
  SecureZeroize(&delta_inv_);
  SecureZeroize(&local_s_i_);
  SecureZeroize(&local_l_i_);
  SecureZeroize(&local_rho_i_);
  SecureZeroize(&s_);
  SecureZeroize(&phase2_mta_initiator_sum_);
  SecureZeroize(&phase2_mta_responder_sum_);
  SecureZeroize(&phase2_mtawc_initiator_sum_);
  SecureZeroize(&phase2_mtawc_responder_sum_);

  SecureZeroize(&fixed_k_i_);
  SecureZeroize(&fixed_gamma_i_);
  SecureZeroize(&local_phase1_randomness_);
  SecureZeroize(&local_phase1_commitment_);
  SecureZeroize(&local_phase5a_randomness_);
  SecureZeroize(&local_phase5a_commitment_);
  SecureZeroize(&local_phase5c_randomness_);
  SecureZeroize(&local_phase5c_commitment_);

  SecureZeroize(&lagrange_coefficients_);
  SecureZeroize(&w_shares_);
  SecureZeroize(&phase3_delta_shares_);
  SecureZeroize(&phase5e_revealed_s_);
  SecureZeroize(&phase1_commitments_);
  SecureZeroize(&phase5a_commitments_);
  SecureZeroize(&phase5c_commitments_);

  for (auto& [instance_key, instance] : phase2_initiator_instances_) {
    (void)instance_key;
    instance.c1 = BigInt(0);
    instance.c1_randomness = BigInt(0);
    SecureZeroize(&instance.instance_id);
  }
  phase2_initiator_instances_.clear();
  phase2_responder_requests_seen_.clear();

  for (Envelope& envelope : phase2_outbox_) {
    SecureZeroize(&envelope.payload);
  }
  phase2_outbox_.clear();

  for (auto& [party, open_data] : phase4_open_data_) {
    (void)party;
    SecureZeroize(&open_data.gamma_proof.z);
    SecureZeroize(&open_data.randomness);
  }
  phase4_open_data_.clear();

  for (auto& [party, open_data] : phase5b_open_data_) {
    (void)party;
    SecureZeroize(&open_data.a_schnorr_proof.z);
    SecureZeroize(&open_data.v_relation_proof.t);
    SecureZeroize(&open_data.v_relation_proof.u);
    SecureZeroize(&open_data.randomness);
  }
  phase5b_open_data_.clear();

  for (auto& [party, open_data] : phase5d_open_data_) {
    (void)party;
    SecureZeroize(&open_data.randomness);
  }
  phase5d_open_data_.clear();
}

void SignSession::Abort(const std::string& reason) {
  if (IsTerminal()) {
    return;
  }
  ClearSensitiveIntermediates();
  Session::Abort(reason);
}

void SignSession::Complete() {
  if (IsTerminal()) {
    return;
  }
  ClearSensitiveIntermediates();
  Session::Complete();
}

uint32_t SignSession::MessageTypeForPhase5Stage(SignPhase5Stage stage) {
  switch (stage) {
    case SignPhase5Stage::kPhase5A:
      return static_cast<uint32_t>(SignMessageType::kPhase5A);
    case SignPhase5Stage::kPhase5B:
      return static_cast<uint32_t>(SignMessageType::kPhase5B);
    case SignPhase5Stage::kPhase5C:
      return static_cast<uint32_t>(SignMessageType::kPhase5C);
    case SignPhase5Stage::kPhase5D:
      return static_cast<uint32_t>(SignMessageType::kPhase5D);
    case SignPhase5Stage::kPhase5E:
      return static_cast<uint32_t>(SignMessageType::kPhase5E);
    case SignPhase5Stage::kCompleted:
      return static_cast<uint32_t>(SignMessageType::kAbort);
  }
  TECDSA_THROW_ARGUMENT("invalid sign phase5 stage");
}

bool SignSession::HandlePhase1CommitEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase1 commitment message must be broadcast");
    return false;
  }
  if (envelope.payload.size() != kCommitmentLen) {
    Abort("invalid sign phase1 commitment payload length");
    return false;
  }

  const bool inserted = seen_phase1_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  phase1_commitments_[envelope.from] = envelope.payload;
  Touch();
  MaybeAdvanceAfterPhase1();
  return true;
}

bool SignSession::HandlePhase2InitEnvelope(const Envelope& envelope) {
  if (envelope.to != self_id()) {
    Abort("sign phase2 initiator message must target receiver directly");
    return false;
  }

  try {
    size_t offset = 0;
    const uint32_t raw_type = ReadU32Be(envelope.payload, &offset);
    if (raw_type != static_cast<uint32_t>(MtaType::kTimesGamma) &&
        raw_type != static_cast<uint32_t>(MtaType::kTimesW)) {
      TECDSA_THROW_ARGUMENT("unknown phase2 MtA type");
    }
    const MtaType mta_type = static_cast<MtaType>(raw_type);

    const Bytes instance_id =
        ReadSizedField(envelope.payload, &offset, kMtaInstanceIdLen, "phase2 mta instance id");
    if (instance_id.size() != kMtaInstanceIdLen) {
      TECDSA_THROW_ARGUMENT("phase2 mta instance id has invalid length");
    }
    const BigInt c1 =
        ReadMpIntField(envelope.payload, &offset, kMaxMpIntEncodedLen, "phase2 mta ciphertext c1");
    const A1RangeProof a1_proof = ReadA1RangeProof(envelope.payload, &offset);
    if (offset != envelope.payload.size()) {
      TECDSA_THROW_ARGUMENT("sign phase2 init payload has trailing bytes");
    }

    const auto sender_pk_it = all_paillier_public_.find(envelope.from);
    if (sender_pk_it == all_paillier_public_.end()) {
      TECDSA_THROW_ARGUMENT("missing Paillier public key for initiator");
    }
    const BigInt n = sender_pk_it->second.n;
    const BigInt n2 = n * n;
    if (c1 < 0 || c1 >= n2) {
      TECDSA_THROW_ARGUMENT("phase2 c1 is out of range");
    }
    const auto self_aux_it = all_aux_rsa_params_.find(self_id());
    if (self_aux_it == all_aux_rsa_params_.end()) {
      TECDSA_THROW_ARGUMENT("missing responder auxiliary parameters");
    }
    const MtaProofContext init_ctx{
        .session_id = session_id(),
        .initiator_id = envelope.from,
        .responder_id = self_id(),
        .mta_instance_id = instance_id,
    };
    if (!VerifyA1Range(init_ctx, n, self_aux_it->second, c1, a1_proof)) {
      TECDSA_THROW_ARGUMENT("phase2 A1 range proof verification failed");
    }

    const std::string request_key = MakeResponderRequestKey(envelope.from, static_cast<uint8_t>(raw_type));
    const std::string instance_key = BytesToKey(instance_id);
    const auto seen_request_it = phase2_responder_requests_seen_.find(request_key);
    if (seen_request_it != phase2_responder_requests_seen_.end()) {
      if (seen_request_it->second != instance_key) {
        TECDSA_THROW_ARGUMENT("phase2 request instance mismatch for sender/type");
      }
      return true;
    }

    const Scalar witness =
        (mta_type == MtaType::kTimesGamma) ? local_gamma_i_ : local_w_i_;
    const BigInt y = RandomBelow(QPow5());
    const BigInt r_b = SampleZnStar(n);
    const BigInt gamma = n + BigInt(1);
    const BigInt c1_pow_x = PowMod(c1, witness.mp_value(), n2);
    const BigInt gamma_pow_y = PowMod(gamma, y, n2);
    const BigInt r_pow_n = PowMod(r_b, n, n2);
    const BigInt c2 = MulMod(MulMod(c1_pow_x, gamma_pow_y, n2), r_pow_n, n2);

    const Scalar responder_share(-y);
    if (mta_type == MtaType::kTimesGamma) {
      phase2_mta_responder_sum_ = phase2_mta_responder_sum_ + responder_share;
    } else {
      phase2_mtawc_responder_sum_ = phase2_mtawc_responder_sum_ + responder_share;
    }
    phase2_responder_requests_seen_.emplace(request_key, instance_key);

    const auto initiator_aux_it = all_aux_rsa_params_.find(envelope.from);
    if (initiator_aux_it == all_aux_rsa_params_.end()) {
      TECDSA_THROW_ARGUMENT("missing initiator auxiliary parameters");
    }
    const MtaProofContext response_ctx{
        .session_id = session_id(),
        .initiator_id = envelope.from,
        .responder_id = self_id(),
        .mta_instance_id = instance_id,
    };

    Bytes payload;
    AppendU32Be(raw_type, &payload);
    AppendSizedField(instance_id, &payload);
    AppendMpIntField(c2, &payload);
    if (mta_type == MtaType::kTimesGamma) {
      const A3MtAProof a3_proof =
          ProveA3MtA(response_ctx,
                     n,
                     initiator_aux_it->second,
                     c1,
                     c2,
                     witness.mp_value(),
                     y,
                     r_b);
      AppendA3MtAProof(a3_proof, &payload);
    } else {
      const auto statement_x_it = W_points_.find(self_id());
      if (statement_x_it == W_points_.end()) {
        TECDSA_THROW_ARGUMENT("missing responder W_j point for MtAwc proof");
      }
      const A2MtAwcProof a2_proof =
          ProveA2MtAwc(response_ctx,
                       n,
                       initiator_aux_it->second,
                       c1,
                       c2,
                       statement_x_it->second,
                       witness.mp_value(),
                       y,
                       r_b);
      AppendA2MtAwcProof(a2_proof, &payload);
    }

    Envelope out;
    out.session_id = session_id();
    out.from = self_id();
    out.to = envelope.from;
    out.type = Phase2ResponseMessageType();
    out.payload = std::move(payload);
    phase2_outbox_.push_back(std::move(out));
  } catch (const std::exception& ex) {
    Abort(std::string("invalid sign phase2 initiator payload: ") + ex.what());
    return false;
  }

  seen_phase2_.insert(envelope.from);
  Touch();
  MaybeAdvanceAfterPhase2();
  return true;
}

bool SignSession::HandlePhase2ResponseEnvelope(const Envelope& envelope) {
  if (envelope.to != self_id()) {
    Abort("sign phase2 response message must target receiver directly");
    return false;
  }

  try {
    size_t offset = 0;
    const uint32_t raw_type = ReadU32Be(envelope.payload, &offset);
    if (raw_type != static_cast<uint32_t>(MtaType::kTimesGamma) &&
        raw_type != static_cast<uint32_t>(MtaType::kTimesW)) {
      TECDSA_THROW_ARGUMENT("unknown phase2 response MtA type");
    }
    const MtaType mta_type = static_cast<MtaType>(raw_type);

    const Bytes instance_id =
        ReadSizedField(envelope.payload, &offset, kMtaInstanceIdLen, "phase2 mta instance id");
    if (instance_id.size() != kMtaInstanceIdLen) {
      TECDSA_THROW_ARGUMENT("phase2 response instance id has invalid length");
    }
    const BigInt c2 =
        ReadMpIntField(envelope.payload, &offset, kMaxMpIntEncodedLen, "phase2 mta ciphertext c2");
    std::optional<A3MtAProof> a3_proof;
    std::optional<A2MtAwcProof> a2_proof;
    if (mta_type == MtaType::kTimesGamma) {
      a3_proof = ReadA3MtAProof(envelope.payload, &offset);
    } else {
      a2_proof = ReadA2MtAwcProof(envelope.payload, &offset);
    }
    if (offset != envelope.payload.size()) {
      TECDSA_THROW_ARGUMENT("sign phase2 response payload has trailing bytes");
    }

    const std::string instance_key = BytesToKey(instance_id);
    const auto instance_it = phase2_initiator_instances_.find(instance_key);
    if (instance_it == phase2_initiator_instances_.end()) {
      TECDSA_THROW_ARGUMENT("unknown phase2 response instance id");
    }
    Phase2InitiatorInstance& instance = instance_it->second;
    if (instance.responder != envelope.from) {
      TECDSA_THROW_ARGUMENT("phase2 response sender mismatch");
    }
    if (instance.type != mta_type) {
      TECDSA_THROW_ARGUMENT("phase2 response type mismatch");
    }
    if (instance.response_received) {
      return true;
    }

    const auto self_pk_it = all_paillier_public_.find(self_id());
    if (self_pk_it == all_paillier_public_.end()) {
      TECDSA_THROW_ARGUMENT("missing self Paillier public key");
    }
    const BigInt n = self_pk_it->second.n;
    const BigInt n2 = n * n;
    if (c2 < 0 || c2 >= n2) {
      TECDSA_THROW_ARGUMENT("phase2 c2 is out of range");
    }
    const auto self_aux_it = all_aux_rsa_params_.find(self_id());
    if (self_aux_it == all_aux_rsa_params_.end()) {
      TECDSA_THROW_ARGUMENT("missing initiator auxiliary parameters");
    }
    const MtaProofContext response_ctx{
        .session_id = session_id(),
        .initiator_id = self_id(),
        .responder_id = envelope.from,
        .mta_instance_id = instance_id,
    };
    if (mta_type == MtaType::kTimesGamma) {
      if (!a3_proof.has_value()) {
        TECDSA_THROW_ARGUMENT("missing A3 proof in MtA response");
      }
      if (!VerifyA3MtA(response_ctx, n, self_aux_it->second, instance.c1, c2, *a3_proof)) {
        TECDSA_THROW_ARGUMENT("phase2 A3 proof verification failed");
      }
    } else {
      if (!a2_proof.has_value()) {
        TECDSA_THROW_ARGUMENT("missing A2 proof in MtAwc response");
      }
      const auto statement_x_it = W_points_.find(envelope.from);
      if (statement_x_it == W_points_.end()) {
        TECDSA_THROW_ARGUMENT("missing W_j point for MtAwc response proof");
      }
      if (!VerifyA2MtAwc(response_ctx,
                         n,
                         self_aux_it->second,
                         instance.c1,
                         c2,
                         statement_x_it->second,
                         *a2_proof)) {
        TECDSA_THROW_ARGUMENT("phase2 A2 proof verification failed");
      }
    }

    const BigInt decrypted = local_paillier_->DecryptBigInt(c2);
    const Scalar initiator_share(decrypted);
    if (mta_type == MtaType::kTimesGamma) {
      phase2_mta_initiator_sum_ = phase2_mta_initiator_sum_ + initiator_share;
    } else {
      phase2_mtawc_initiator_sum_ = phase2_mtawc_initiator_sum_ + initiator_share;
    }
    instance.response_received = true;
  } catch (const std::exception& ex) {
    Abort(std::string("invalid sign phase2 response payload: ") + ex.what());
    return false;
  }

  seen_phase2_.insert(envelope.from);
  Touch();
  MaybeAdvanceAfterPhase2();
  return true;
}

bool SignSession::HandlePhase3DeltaEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase3 delta message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase3_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const Scalar delta_i = ReadScalar(envelope.payload, &offset);
    if (offset != envelope.payload.size()) {
      TECDSA_THROW_ARGUMENT("sign phase3 payload has trailing bytes");
    }

    phase3_delta_shares_[envelope.from] = delta_i;
  } catch (const std::exception& ex) {
    Abort(std::string("invalid sign phase3 payload: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase3();
  return true;
}

bool SignSession::HandlePhase4OpenEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase4 open message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase4_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const ECPoint gamma_i = ReadPoint(envelope.payload, &offset);
    const Bytes randomness =
        ReadSizedField(envelope.payload, &offset, kMaxOpenRandomnessLen, "sign phase4 open randomness");
    const ECPoint proof_a = ReadPoint(envelope.payload, &offset);
    const Scalar proof_z = ReadScalar(envelope.payload, &offset);
    if (offset != envelope.payload.size()) {
      TECDSA_THROW_ARGUMENT("sign phase4 payload has trailing bytes");
    }

    const auto commitment_it = phase1_commitments_.find(envelope.from);
    if (commitment_it == phase1_commitments_.end()) {
      TECDSA_THROW_ARGUMENT("missing phase1 commitment for sender");
    }

    const Bytes gamma_bytes = gamma_i.ToCompressedBytes();
    if (!VerifyCommitment(kPhase1CommitDomain, gamma_bytes, randomness, commitment_it->second)) {
      TECDSA_THROW_ARGUMENT("phase4 open does not match phase1 commitment");
    }

    const SchnorrProof gamma_proof{.a = proof_a, .z = proof_z};
    if (!VerifySchnorrProof(envelope.from, gamma_i, gamma_proof)) {
      TECDSA_THROW_ARGUMENT("phase4 gamma Schnorr proof verification failed");
    }

    phase4_open_data_[envelope.from] = Phase4OpenData{
        .gamma_i = gamma_i,
        .gamma_proof = gamma_proof,
        .randomness = randomness,
    };
  } catch (const std::exception& ex) {
    Abort(std::string("invalid sign phase4 payload: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase4();
  return true;
}

bool SignSession::HandlePhase5ACommitEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase5A commitment message must be broadcast");
    return false;
  }
  if (envelope.payload.size() != kCommitmentLen) {
    Abort("invalid sign phase5A commitment payload length");
    return false;
  }

  const bool inserted = seen_phase5a_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  phase5a_commitments_[envelope.from] = envelope.payload;
  Touch();
  MaybeAdvanceAfterPhase5A();
  return true;
}

bool SignSession::HandlePhase5BOpenEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase5B open message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase5b_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const ECPoint V_i = ReadPoint(envelope.payload, &offset);
    const ECPoint A_i = ReadPoint(envelope.payload, &offset);
    const Bytes randomness =
        ReadSizedField(envelope.payload, &offset, kMaxOpenRandomnessLen, "sign phase5B open randomness");
    const ECPoint schnorr_a = ReadPoint(envelope.payload, &offset);
    const Scalar schnorr_z = ReadScalar(envelope.payload, &offset);
    const ECPoint relation_alpha = ReadPoint(envelope.payload, &offset);
    const Scalar relation_t = ReadScalar(envelope.payload, &offset);
    const Scalar relation_u = ReadScalar(envelope.payload, &offset);
    if (offset != envelope.payload.size()) {
      TECDSA_THROW_ARGUMENT("sign phase5B payload has trailing bytes");
    }

    const auto commitment_it = phase5a_commitments_.find(envelope.from);
    if (commitment_it == phase5a_commitments_.end()) {
      TECDSA_THROW_ARGUMENT("missing phase5A commitment for sender");
    }

    const Bytes commit_message = SerializePointPair(V_i, A_i);
    if (!VerifyCommitment(kPhase5ACommitDomain, commit_message, randomness, commitment_it->second)) {
      TECDSA_THROW_ARGUMENT("phase5B open does not match phase5A commitment");
    }

    const SchnorrProof a_schnorr_proof{.a = schnorr_a, .z = schnorr_z};
    if (!VerifySchnorrProof(envelope.from, A_i, a_schnorr_proof)) {
      TECDSA_THROW_ARGUMENT("phase5B A_i Schnorr proof verification failed");
    }

    const VRelationProof v_relation_proof{.alpha = relation_alpha, .t = relation_t, .u = relation_u};
    if (!VerifyVRelationProof(envelope.from, R_, V_i, v_relation_proof)) {
      TECDSA_THROW_ARGUMENT("phase5B V relation proof verification failed");
    }

    phase5b_open_data_[envelope.from] = Phase5BOpenData{
        .V_i = V_i,
        .A_i = A_i,
        .a_schnorr_proof = a_schnorr_proof,
        .v_relation_proof = v_relation_proof,
        .randomness = randomness,
    };
  } catch (const std::exception& ex) {
    Abort(std::string("invalid sign phase5B payload: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase5B();
  return true;
}

bool SignSession::HandlePhase5CCommitEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase5C commitment message must be broadcast");
    return false;
  }
  if (envelope.payload.size() != kCommitmentLen) {
    Abort("invalid sign phase5C commitment payload length");
    return false;
  }

  const bool inserted = seen_phase5c_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  phase5c_commitments_[envelope.from] = envelope.payload;
  Touch();
  MaybeAdvanceAfterPhase5C();
  return true;
}

bool SignSession::HandlePhase5DOpenEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase5D open message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase5d_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const ECPoint U_i = ReadPoint(envelope.payload, &offset);
    const ECPoint T_i = ReadPoint(envelope.payload, &offset);
    const Bytes randomness =
        ReadSizedField(envelope.payload, &offset, kMaxOpenRandomnessLen, "sign phase5D open randomness");
    if (offset != envelope.payload.size()) {
      TECDSA_THROW_ARGUMENT("sign phase5D payload has trailing bytes");
    }

    const auto commitment_it = phase5c_commitments_.find(envelope.from);
    if (commitment_it == phase5c_commitments_.end()) {
      TECDSA_THROW_ARGUMENT("missing phase5C commitment for sender");
    }

    const Bytes commit_message = SerializePointPair(U_i, T_i);
    if (!VerifyCommitment(kPhase5CCommitDomain, commit_message, randomness, commitment_it->second)) {
      TECDSA_THROW_ARGUMENT("phase5D open does not match phase5C commitment");
    }

    phase5d_open_data_[envelope.from] = Phase5DOpenData{.U_i = U_i, .T_i = T_i, .randomness = randomness};
  } catch (const std::exception& ex) {
    Abort(std::string("invalid sign phase5D payload: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase5D();
  return true;
}

bool SignSession::HandlePhase5ERevealEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase5E reveal message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase5e_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const Scalar s_i = ReadScalar(envelope.payload, &offset);
    if (offset != envelope.payload.size()) {
      TECDSA_THROW_ARGUMENT("sign phase5E payload has trailing bytes");
    }

    phase5e_revealed_s_[envelope.from] = s_i;
  } catch (const std::exception& ex) {
    Abort(std::string("invalid sign phase5E payload: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase5E();
  return true;
}

void SignSession::PrepareResharedSigningShares() {
  lagrange_coefficients_ = ComputeLagrangeAtZero(participants_);

  const auto lambda_self_it = lagrange_coefficients_.find(self_id());
  if (lambda_self_it == lagrange_coefficients_.end()) {
    TECDSA_THROW_ARGUMENT("missing lagrange coefficient for self");
  }

  local_w_i_ = lambda_self_it->second * local_x_i_;
  w_shares_[self_id()] = local_w_i_;

  std::vector<ECPoint> w_points;
  w_points.reserve(participants_.size());
  for (PartyIndex party : participants_) {
    const auto lambda_it = lagrange_coefficients_.find(party);
    const auto x_pub_it = all_X_i_.find(party);
    if (lambda_it == lagrange_coefficients_.end() || x_pub_it == all_X_i_.end()) {
      TECDSA_THROW_ARGUMENT("missing lagrange coefficient or X_i for participant");
    }

    try {
      W_points_[party] = x_pub_it->second.Mul(lambda_it->second);
    } catch (const std::exception& ex) {
      TECDSA_THROW_ARGUMENT(std::string("failed to compute W_i: ") + ex.what());
    }
    w_points.push_back(W_points_.at(party));
  }

  try {
    const ECPoint reconstructed_y = SumPointsOrThrow(w_points);
    if (reconstructed_y != public_key_y_) {
      TECDSA_THROW_ARGUMENT("W_i aggregation does not reconstruct y");
    }
  } catch (const std::exception& ex) {
    TECDSA_THROW_ARGUMENT(std::string("failed to validate W_i aggregation: ") + ex.what());
  }
}

void SignSession::PreparePhase1SecretsIfNeeded() {
  if (!local_phase1_commitment_.empty()) {
    return;
  }

  local_k_i_ = fixed_k_i_.value_or(RandomNonZeroScalar());
  local_gamma_i_ = fixed_gamma_i_.value_or(RandomNonZeroScalar());
  if (local_k_i_.value() == 0 || local_gamma_i_.value() == 0) {
    TECDSA_THROW_ARGUMENT("fixed k_i and gamma_i must be non-zero");
  }

  local_Gamma_i_ = ECPoint::GeneratorMultiply(local_gamma_i_);
  const Bytes gamma_bytes = local_Gamma_i_.ToCompressedBytes();
  const CommitmentResult commitment = CommitMessage(kPhase1CommitDomain, gamma_bytes);
  local_phase1_randomness_ = commitment.randomness;
  local_phase1_commitment_ = commitment.commitment;
}

void SignSession::InitializePhase2InstancesIfNeeded() {
  if (phase2_instances_initialized_) {
    return;
  }
  if (phase_ != SignPhase::kPhase2) {
    TECDSA_THROW_LOGIC("phase2 instances can only be initialized in sign phase2");
  }

  PreparePhase1SecretsIfNeeded();

  const auto self_pk_it = all_paillier_public_.find(self_id());
  if (self_pk_it == all_paillier_public_.end()) {
    TECDSA_THROW_LOGIC("missing local Paillier or peer auxiliary parameters for phase2 init");
  }
  const BigInt local_n = self_pk_it->second.n;
  const BigInt local_k_value = local_k_i_.mp_value();
  const Bytes session_id_bytes = session_id();
  const PartyIndex initiator_id = self_id();

  struct PendingInit {
    PartyIndex peer = 0;
    MtaType type = MtaType::kTimesGamma;
    Bytes instance_id;
    BigInt c1;
    BigInt c1_randomness;
    AuxRsaParams peer_aux;
  };

  std::vector<PendingInit> pending;
  pending.reserve(peers_.size() * 2);
  std::unordered_set<std::string> reserved_instance_keys;
  reserved_instance_keys.reserve(peers_.size() * 2);

  for (PartyIndex peer : participants_) {
    if (peer == self_id()) {
      continue;
    }

    const auto peer_aux_it = all_aux_rsa_params_.find(peer);
    if (peer_aux_it == all_aux_rsa_params_.end()) {
      TECDSA_THROW_LOGIC("missing local Paillier or peer auxiliary parameters for phase2 init");
    }

    for (MtaType type : {MtaType::kTimesGamma, MtaType::kTimesW}) {
      Bytes instance_id = RandomMtaInstanceId();
      std::string instance_key = BytesToKey(instance_id);
      while (phase2_initiator_instances_.contains(instance_key) ||
             reserved_instance_keys.contains(instance_key)) {
        instance_id = RandomMtaInstanceId();
        instance_key = BytesToKey(instance_id);
      }
      reserved_instance_keys.insert(instance_key);

      const PaillierCiphertextWithRandomBigInt encrypted =
          local_paillier_->EncryptWithRandomBigInt(local_k_value);
      pending.push_back(PendingInit{
          .peer = peer,
          .type = type,
          .instance_id = instance_id,
          .c1 = encrypted.ciphertext,
          .c1_randomness = encrypted.randomness,
          .peer_aux = peer_aux_it->second,
      });
    }
  }

  ThreadPool& pool = Phase2ThreadPool();
  std::vector<std::future<Bytes>> payload_futures;
  payload_futures.reserve(pending.size());
  for (const PendingInit& init : pending) {
    payload_futures.push_back(pool.Submit([init, local_n, local_k_value, session_id_bytes, initiator_id]() {
      const MtaProofContext proof_ctx{
          .session_id = session_id_bytes,
          .initiator_id = initiator_id,
          .responder_id = init.peer,
          .mta_instance_id = init.instance_id,
      };
      const A1RangeProof a1_proof = ProveA1Range(
          proof_ctx, local_n, init.peer_aux, init.c1, local_k_value, init.c1_randomness);

      Bytes payload;
      AppendU32Be(static_cast<uint32_t>(init.type), &payload);
      AppendSizedField(init.instance_id, &payload);
      AppendMpIntField(init.c1, &payload);
      AppendA1RangeProof(a1_proof, &payload);
      return payload;
    }));
  }

  std::vector<Bytes> payloads;
  payloads.reserve(payload_futures.size());
  for (std::future<Bytes>& future : payload_futures) {
    payloads.push_back(future.get());
  }

  for (size_t i = 0; i < pending.size(); ++i) {
    const PendingInit& init = pending[i];
    const std::string instance_key = BytesToKey(init.instance_id);
    phase2_initiator_instances_.emplace(
        instance_key,
        Phase2InitiatorInstance{
            .responder = init.peer,
            .type = init.type,
            .instance_id = init.instance_id,
            .c1 = init.c1,
            .c1_randomness = init.c1_randomness,
            .response_received = false,
        });

    Envelope out;
    out.session_id = session_id();
    out.from = self_id();
    out.to = init.peer;
    out.type = MessageTypeForPhase(SignPhase::kPhase2);
    out.payload = std::move(payloads[i]);
    phase2_outbox_.push_back(std::move(out));
  }

  phase2_instances_initialized_ = true;
}

void SignSession::MaybeFinalizePhase2AndAdvance() {
  if (phase_ != SignPhase::kPhase2 || local_phase2_ready_) {
    return;
  }
  if (!phase2_instances_initialized_) {
    return;
  }
  if (!phase2_outbox_.empty()) {
    return;
  }

  const size_t expected_instance_count = peers_.size() * 2;
  if (phase2_initiator_instances_.size() != expected_instance_count) {
    return;
  }
  if (phase2_responder_requests_seen_.size() != expected_instance_count) {
    return;
  }

  for (const auto& [instance_key, instance] : phase2_initiator_instances_) {
    (void)instance_key;
    if (!instance.response_received) {
      return;
    }
  }

  local_delta_i_ =
      (local_k_i_ * local_gamma_i_) + phase2_mta_initiator_sum_ + phase2_mta_responder_sum_;
  local_sigma_i_ =
      (local_k_i_ * local_w_i_) + phase2_mtawc_initiator_sum_ + phase2_mtawc_responder_sum_;

  local_phase2_ready_ = true;
}

void SignSession::ComputeDeltaInverseAndAdvanceToPhase4() {
  Scalar delta;
  for (PartyIndex party : participants_) {
    const auto delta_it = phase3_delta_shares_.find(party);
    if (delta_it == phase3_delta_shares_.end()) {
      Abort("missing phase3 delta share");
      return;
    }
    delta = delta + delta_it->second;
  }

  if (delta.value() == 0) {
    Abort("aggregated delta is zero");
    return;
  }

  const std::optional<Scalar> delta_inv = InvertScalar(delta);
  if (!delta_inv.has_value()) {
    Abort("failed to invert aggregated delta");
    return;
  }

  delta_ = delta;
  delta_inv_ = *delta_inv;
  phase_ = SignPhase::kPhase4;
}

void SignSession::ComputeRAndAdvanceToPhase5() {
  std::vector<ECPoint> gammas;
  gammas.reserve(participants_.size());
  for (PartyIndex party : participants_) {
    const auto gamma_it = phase4_open_data_.find(party);
    if (gamma_it == phase4_open_data_.end()) {
      Abort("missing phase4 opened gamma point");
      return;
    }
    gammas.push_back(gamma_it->second.gamma_i);
  }

  try {
    Gamma_ = SumPointsOrThrow(gammas);
    R_ = Gamma_.Mul(delta_inv_);
  } catch (const std::exception& ex) {
    Abort(std::string("failed to compute R in phase4: ") + ex.what());
    return;
  }

  r_ = XCoordinateModQ(R_);
  if (r_.value() == 0) {
    Abort("computed r is zero");
    return;
  }

  phase_ = SignPhase::kPhase5;
  phase5_stage_ = SignPhase5Stage::kPhase5A;
}

void SignSession::ComputePhase5VAAndAdvanceToStage5C() {
  std::vector<ECPoint> v_points;
  std::vector<ECPoint> a_points;
  v_points.reserve(participants_.size());
  a_points.reserve(participants_.size());

  for (PartyIndex party : participants_) {
    const auto open_it = phase5b_open_data_.find(party);
    if (open_it == phase5b_open_data_.end()) {
      Abort("missing phase5B open data");
      return;
    }
    v_points.push_back(open_it->second.V_i);
    a_points.push_back(open_it->second.A_i);
  }

  try {
    V_ = SumPointsOrThrow(v_points);
    A_ = SumPointsOrThrow(a_points);

    if (message_scalar_.value() != 0) {
      const Scalar neg_m = Scalar() - message_scalar_;
      V_ = V_.Add(ECPoint::GeneratorMultiply(neg_m));
    }

    const Scalar neg_r = Scalar() - r_;
    V_ = V_.Add(public_key_y_.Mul(neg_r));
  } catch (const std::exception& ex) {
    Abort(std::string("failed to compute phase5 V/A aggregates: ") + ex.what());
    return;
  }

  phase5_stage_ = SignPhase5Stage::kPhase5C;
}

void SignSession::VerifyPhase5DAndAdvanceToStage5E() {
  std::vector<ECPoint> u_points;
  std::vector<ECPoint> t_points;
  u_points.reserve(participants_.size());
  t_points.reserve(participants_.size());

  for (PartyIndex party : participants_) {
    const auto open_it = phase5d_open_data_.find(party);
    if (open_it == phase5d_open_data_.end()) {
      Abort("missing phase5D open data");
      return;
    }
    u_points.push_back(open_it->second.U_i);
    t_points.push_back(open_it->second.T_i);
  }

  try {
    const ECPoint sum_u = SumPointsOrThrow(u_points);
    const ECPoint sum_t = SumPointsOrThrow(t_points);
    if (sum_u != sum_t) {
      Abort("phase5D consistency check failed");
      return;
    }
  } catch (const std::exception& ex) {
    Abort(std::string("failed to validate phase5D consistency: ") + ex.what());
    return;
  }

  phase5_stage_ = SignPhase5Stage::kPhase5E;
}

void SignSession::FinalizeSignatureAndComplete() {
  Scalar s;
  for (PartyIndex party : participants_) {
    const auto s_it = phase5e_revealed_s_.find(party);
    if (s_it == phase5e_revealed_s_.end()) {
      Abort("missing phase5E revealed share");
      return;
    }
    s = s + s_it->second;
  }

  if (s.value() == 0) {
    Abort("aggregated signature scalar s is zero");
    return;
  }

  Scalar canonical_s = s;
  if (IsHighScalar(canonical_s)) {
    canonical_s = Scalar() - canonical_s;
  }

  if (!VerifyEcdsaSignatureMath(public_key_y_, msg32_, r_, canonical_s)) {
    Abort("final ECDSA signature verification failed");
    return;
  }

  s_ = canonical_s;
  result_.r = r_;
  result_.s = s_;
  result_.R = R_;
  result_.local_w_i = local_w_i_;
  result_.lagrange_coefficients = lagrange_coefficients_;
  result_.w_shares = w_shares_;
  result_.W_points = W_points_;
  has_result_ = true;

  phase5_stage_ = SignPhase5Stage::kCompleted;
  phase_ = SignPhase::kCompleted;
  Complete();
}

void SignSession::MaybeAdvanceAfterPhase1() {
  if (phase_ != SignPhase::kPhase1) {
    return;
  }
  if (!local_phase1_ready_) {
    return;
  }
  if (seen_phase1_.size() != peers_.size()) {
    return;
  }
  if (phase1_commitments_.size() != participants_.size()) {
    return;
  }
  phase_ = SignPhase::kPhase2;
}

void SignSession::MaybeAdvanceAfterPhase2() {
  if (phase_ != SignPhase::kPhase2) {
    return;
  }
  MaybeFinalizePhase2AndAdvance();
  if (!local_phase2_ready_) {
    return;
  }
  phase_ = SignPhase::kPhase3;
}

void SignSession::MaybeAdvanceAfterPhase3() {
  if (phase_ != SignPhase::kPhase3) {
    return;
  }
  if (!local_phase3_ready_) {
    return;
  }
  if (seen_phase3_.size() != peers_.size()) {
    return;
  }
  if (phase3_delta_shares_.size() != participants_.size()) {
    return;
  }
  ComputeDeltaInverseAndAdvanceToPhase4();
}

void SignSession::MaybeAdvanceAfterPhase4() {
  if (phase_ != SignPhase::kPhase4) {
    return;
  }
  if (!local_phase4_ready_) {
    return;
  }
  if (seen_phase4_.size() != peers_.size()) {
    return;
  }
  if (phase4_open_data_.size() != participants_.size()) {
    return;
  }
  ComputeRAndAdvanceToPhase5();
}

void SignSession::MaybeAdvanceAfterPhase5A() {
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5A) {
    return;
  }
  if (!local_phase5a_ready_) {
    return;
  }
  if (seen_phase5a_.size() != peers_.size()) {
    return;
  }
  if (phase5a_commitments_.size() != participants_.size()) {
    return;
  }
  phase5_stage_ = SignPhase5Stage::kPhase5B;
}

void SignSession::MaybeAdvanceAfterPhase5B() {
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5B) {
    return;
  }
  if (!local_phase5b_ready_) {
    return;
  }
  if (seen_phase5b_.size() != peers_.size()) {
    return;
  }
  if (phase5b_open_data_.size() != participants_.size()) {
    return;
  }
  ComputePhase5VAAndAdvanceToStage5C();
}

void SignSession::MaybeAdvanceAfterPhase5C() {
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5C) {
    return;
  }
  if (!local_phase5c_ready_) {
    return;
  }
  if (seen_phase5c_.size() != peers_.size()) {
    return;
  }
  if (phase5c_commitments_.size() != participants_.size()) {
    return;
  }
  phase5_stage_ = SignPhase5Stage::kPhase5D;
}

void SignSession::MaybeAdvanceAfterPhase5D() {
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5D) {
    return;
  }
  if (!local_phase5d_ready_) {
    return;
  }
  if (seen_phase5d_.size() != peers_.size()) {
    return;
  }
  if (phase5d_open_data_.size() != participants_.size()) {
    return;
  }
  VerifyPhase5DAndAdvanceToStage5E();
}

void SignSession::MaybeAdvanceAfterPhase5E() {
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5E) {
    return;
  }
  if (!local_phase5e_ready_) {
    return;
  }
  if (seen_phase5e_.size() != peers_.size()) {
    return;
  }
  if (phase5e_revealed_s_.size() != participants_.size()) {
    return;
  }
  FinalizeSignatureAndComplete();
}

SignSession::SchnorrProof SignSession::BuildSchnorrProof(const ECPoint& statement,
                                                         const Scalar& witness) const {
  if (witness.value() == 0) {
    TECDSA_THROW_ARGUMENT("schnorr witness must be non-zero");
  }

  while (true) {
    const Scalar r = RandomNonZeroScalar();
    const ECPoint a = ECPoint::GeneratorMultiply(r);
    const Scalar e = BuildSchnorrChallenge(session_id(), self_id(), statement, a);
    const Scalar z = r + (e * witness);
    if (z.value() == 0) {
      continue;
    }
    return SchnorrProof{.a = a, .z = z};
  }
}

bool SignSession::VerifySchnorrProof(PartyIndex prover_id,
                                     const ECPoint& statement,
                                     const SchnorrProof& proof) const {
  if (proof.z.value() == 0) {
    return false;
  }

  try {
    const Scalar e = BuildSchnorrChallenge(session_id(), prover_id, statement, proof.a);
    const ECPoint lhs = ECPoint::GeneratorMultiply(proof.z);

    ECPoint rhs = proof.a;
    if (e.value() != 0) {
      rhs = rhs.Add(statement.Mul(e));
    }
    return lhs == rhs;
  } catch (const std::exception&) {
    return false;
  }
}

SignSession::VRelationProof SignSession::BuildVRelationProof(const ECPoint& r_statement,
                                                             const ECPoint& v_statement,
                                                             const Scalar& s_witness,
                                                             const Scalar& l_witness) const {
  while (true) {
    const Scalar a = Csprng::RandomScalar();
    const Scalar b = Csprng::RandomScalar();
    if (a.value() == 0 && b.value() == 0) {
      continue;
    }

    ECPoint alpha;
    try {
      alpha = BuildRGeneratorLinearCombination(r_statement, a, b);
    } catch (const std::exception&) {
      continue;
    }

    const Scalar c = BuildVRelationChallenge(session_id(), self_id(), r_statement, v_statement, alpha);
    const Scalar t = a + (c * s_witness);
    const Scalar u = b + (c * l_witness);
    if (t.value() == 0 && u.value() == 0) {
      continue;
    }

    return VRelationProof{
        .alpha = alpha,
        .t = t,
        .u = u,
    };
  }
}

bool SignSession::VerifyVRelationProof(PartyIndex prover_id,
                                       const ECPoint& r_statement,
                                       const ECPoint& v_statement,
                                       const VRelationProof& proof) const {
  if (proof.t.value() == 0 && proof.u.value() == 0) {
    return false;
  }

  try {
    const Scalar c = BuildVRelationChallenge(
        session_id(), prover_id, r_statement, v_statement, proof.alpha);
    const ECPoint lhs = BuildRGeneratorLinearCombination(r_statement, proof.t, proof.u);

    ECPoint rhs = proof.alpha;
    if (c.value() != 0) {
      rhs = rhs.Add(v_statement.Mul(c));
    }
    return lhs == rhs;
  } catch (const std::exception&) {
    return false;
  }
}

}  // namespace tecdsa

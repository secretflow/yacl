// Copyright 2026 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "yacl/crypto/experimental/threshold_ecdsa/protocol/proto_sign_internal.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <optional>
#include <stdexcept>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/random.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/transcript.h"

namespace tecdsa::sign_internal {
namespace {

constexpr char kVRelationProofId[] = "GG2019/VRel/v1";
constexpr char kA1RangeProofId[] = "GG2019/A1Range/v1";
constexpr char kA2MtAwcProofId[] = "GG2019/A2MtAwc/v1";
constexpr char kA3MtAProofId[] = "GG2019/A3MtA/v1";
constexpr char kCurveName[] = "secp256k1";

BigInt NormalizeMod(const BigInt& value, const BigInt& modulus) {
  return bigint::NormalizeMod(value, modulus);
}

bool IsZnStarElement(const BigInt& value, const BigInt& modulus) {
  if (value <= 0 || value >= modulus) {
    return false;
  }
  return BigInt::Gcd(value, modulus) == 1;
}

bool IsInRange(const BigInt& value, const BigInt& modulus) {
  return value >= 0 && value < modulus;
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

const Bytes& CurveNameBytes() {
  static const Bytes curve_bytes(
      reinterpret_cast<const uint8_t*>(kCurveName),
      reinterpret_cast<const uint8_t*>(kCurveName) + std::strlen(kCurveName));
  return curve_bytes;
}

const Bytes& ModulusQBytes() {
  static const Bytes q_bytes = bigint::ToFixedWidth(Scalar::ModulusQMpInt(), 32);
  return q_bytes;
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

Scalar BuildA1RangeChallenge(const MtaProofContext& ctx, const BigInt& n,
                             const BigInt& gamma, const AuxRsaParams& aux,
                             const BigInt& c, const BigInt& z, const BigInt& u,
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

Scalar BuildA2MtAwcChallenge(const MtaProofContext& ctx, const BigInt& n,
                             const BigInt& gamma, const AuxRsaParams& aux,
                             const BigInt& c1, const BigInt& c2,
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

Scalar BuildA3MtAChallenge(const MtaProofContext& ctx, const BigInt& n,
                           const BigInt& gamma, const AuxRsaParams& aux,
                           const BigInt& c1, const BigInt& c2,
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

}  // namespace

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

Bytes RandomMtaInstanceId() { return Csprng::RandomBytes(kMtaInstanceIdLen); }

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

BigInt MulMod(const BigInt& lhs, const BigInt& rhs, const BigInt& modulus) {
  return NormalizeMod(lhs * rhs, modulus);
}

BigInt PowMod(const BigInt& base, const BigInt& exp, const BigInt& modulus) {
  if (exp < 0) {
    TECDSA_THROW_ARGUMENT("modular exponent must be non-negative");
  }
  return bigint::PowMod(base, exp, modulus);
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

A1RangeProof ProveA1Range(const MtaProofContext& ctx, const BigInt& n,
                          const AuxRsaParams& verifier_aux, const BigInt& c,
                          const BigInt& witness_m, const BigInt& witness_r) {
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

    const BigInt z = MulMod(PowMod(h1, witness_m, n_tilde),
                            PowMod(h2, rho, n_tilde), n_tilde);
    const BigInt u = MulMod(PowMod(gamma, alpha, n2), PowMod(beta, n, n2), n2);
    const BigInt w = MulMod(PowMod(h1, alpha, n_tilde),
                            PowMod(h2, gamma_rand, n_tilde), n_tilde);

    const Scalar e_scalar =
        BuildA1RangeChallenge(ctx, n, gamma, verifier_aux, c, z, u, w);
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

bool VerifyA1Range(const MtaProofContext& ctx, const BigInt& n,
                   const AuxRsaParams& verifier_aux, const BigInt& c,
                   const A1RangeProof& proof) {
  const BigInt n2 = n * n;
  const BigInt gamma = n + BigInt(1);
  const BigInt n_tilde = verifier_aux.n_tilde;
  const BigInt h1 = verifier_aux.h1;
  const BigInt h2 = verifier_aux.h2;

  if (!IsInRange(c, n2) || !IsInRange(proof.u, n2) ||
      !IsInRange(proof.z, n_tilde) || !IsInRange(proof.w, n_tilde) ||
      !IsZnStarElement(proof.s, n)) {
    return false;
  }
  if (proof.s1 < 0 || proof.s1 > QPow3() || proof.s2 < 0) {
    return false;
  }

  const Scalar e_scalar = BuildA1RangeChallenge(ctx, n, gamma, verifier_aux, c,
                                                proof.z, proof.u, proof.w);
  const BigInt e = e_scalar.mp_value();

  const BigInt c_pow_e = PowMod(c, e, n2);
  const std::optional<BigInt> c_pow_e_inv = bigint::TryInvertMod(c_pow_e, n2);
  if (!c_pow_e_inv.has_value()) {
    return false;
  }

  BigInt rhs_u =
      MulMod(PowMod(gamma, proof.s1, n2), PowMod(proof.s, n, n2), n2);
  rhs_u = MulMod(rhs_u, *c_pow_e_inv, n2);
  if (NormalizeMod(proof.u, n2) != rhs_u) {
    return false;
  }

  const BigInt lhs_nt = MulMod(PowMod(h1, proof.s1, n_tilde),
                               PowMod(h2, proof.s2, n_tilde), n_tilde);
  const BigInt rhs_nt = MulMod(proof.w, PowMod(proof.z, e, n_tilde), n_tilde);
  return lhs_nt == rhs_nt;
}

A2MtAwcProof ProveA2MtAwc(const MtaProofContext& ctx, const BigInt& n,
                          const AuxRsaParams& verifier_aux, const BigInt& c1,
                          const BigInt& c2, const ECPoint& statement_x,
                          const BigInt& witness_x, const BigInt& witness_y,
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
    const BigInt z = MulMod(PowMod(h1, witness_x, n_tilde),
                            PowMod(h2, rho, n_tilde), n_tilde);
    const BigInt z2 =
        MulMod(PowMod(h1, alpha, n_tilde), PowMod(h2, rho2, n_tilde), n_tilde);
    const BigInt t = MulMod(PowMod(h1, witness_y, n_tilde),
                            PowMod(h2, sigma, n_tilde), n_tilde);

    BigInt v = MulMod(PowMod(c1, alpha, n2), PowMod(gamma, gamma_rand, n2), n2);
    v = MulMod(v, PowMod(beta, n, n2), n2);
    const BigInt w = MulMod(PowMod(h1, gamma_rand, n_tilde),
                            PowMod(h2, tau, n_tilde), n_tilde);

    A2MtAwcProof proof{
        .u = u,
        .z = z,
        .z2 = z2,
        .t = t,
        .v = v,
        .w = w,
    };
    const Scalar e_scalar = BuildA2MtAwcChallenge(ctx, n, gamma, verifier_aux,
                                                  c1, c2, statement_x, proof);
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

bool VerifyA2MtAwc(const MtaProofContext& ctx, const BigInt& n,
                   const AuxRsaParams& verifier_aux, const BigInt& c1,
                   const BigInt& c2, const ECPoint& statement_x,
                   const A2MtAwcProof& proof) {
  const BigInt n2 = n * n;
  const BigInt gamma = n + BigInt(1);
  const BigInt n_tilde = verifier_aux.n_tilde;
  const BigInt h1 = verifier_aux.h1;
  const BigInt h2 = verifier_aux.h2;

  if (!IsInRange(c1, n2) || !IsInRange(c2, n2) || !IsInRange(proof.v, n2) ||
      !IsInRange(proof.z, n_tilde) || !IsInRange(proof.z2, n_tilde) ||
      !IsInRange(proof.t, n_tilde) || !IsInRange(proof.w, n_tilde) ||
      !IsZnStarElement(proof.s, n)) {
    return false;
  }
  if (proof.s1 < 0 || proof.s1 > QPow3() || proof.t1 < 0 ||
      proof.t1 > QPow7() || proof.s2 < 0 || proof.t2 < 0) {
    return false;
  }

  const Scalar e_scalar = BuildA2MtAwcChallenge(ctx, n, gamma, verifier_aux, c1,
                                                c2, statement_x, proof);

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
  const BigInt lhs_nt_1 = MulMod(PowMod(h1, proof.s1, n_tilde),
                                 PowMod(h2, proof.s2, n_tilde), n_tilde);
  const BigInt rhs_nt_1 =
      MulMod(PowMod(proof.z, e, n_tilde), proof.z2, n_tilde);
  if (lhs_nt_1 != rhs_nt_1) {
    return false;
  }

  const BigInt lhs_nt_2 = MulMod(PowMod(h1, proof.t1, n_tilde),
                                 PowMod(h2, proof.t2, n_tilde), n_tilde);
  const BigInt rhs_nt_2 = MulMod(PowMod(proof.t, e, n_tilde), proof.w, n_tilde);
  if (lhs_nt_2 != rhs_nt_2) {
    return false;
  }

  BigInt lhs_paillier =
      MulMod(PowMod(c1, proof.s1, n2), PowMod(proof.s, n, n2), n2);
  lhs_paillier = MulMod(lhs_paillier, PowMod(gamma, proof.t1, n2), n2);
  const BigInt rhs_paillier = MulMod(PowMod(c2, e, n2), proof.v, n2);
  return lhs_paillier == rhs_paillier;
}

A3MtAProof ProveA3MtA(const MtaProofContext& ctx, const BigInt& n,
                      const AuxRsaParams& verifier_aux, const BigInt& c1,
                      const BigInt& c2, const BigInt& witness_x,
                      const BigInt& witness_y, const BigInt& witness_r) {
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

    const BigInt z = MulMod(PowMod(h1, witness_x, n_tilde),
                            PowMod(h2, rho, n_tilde), n_tilde);
    const BigInt z2 =
        MulMod(PowMod(h1, alpha, n_tilde), PowMod(h2, rho2, n_tilde), n_tilde);
    const BigInt t = MulMod(PowMod(h1, witness_y, n_tilde),
                            PowMod(h2, sigma, n_tilde), n_tilde);
    BigInt v = MulMod(PowMod(c1, alpha, n2), PowMod(gamma, gamma_rand, n2), n2);
    v = MulMod(v, PowMod(beta, n, n2), n2);
    const BigInt w = MulMod(PowMod(h1, gamma_rand, n_tilde),
                            PowMod(h2, tau, n_tilde), n_tilde);

    A3MtAProof proof{
        .z = z,
        .z2 = z2,
        .t = t,
        .v = v,
        .w = w,
    };
    const Scalar e_scalar =
        BuildA3MtAChallenge(ctx, n, gamma, verifier_aux, c1, c2, proof);
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

bool VerifyA3MtA(const MtaProofContext& ctx, const BigInt& n,
                 const AuxRsaParams& verifier_aux, const BigInt& c1,
                 const BigInt& c2, const A3MtAProof& proof) {
  const BigInt n2 = n * n;
  const BigInt gamma = n + BigInt(1);
  const BigInt n_tilde = verifier_aux.n_tilde;
  const BigInt h1 = verifier_aux.h1;
  const BigInt h2 = verifier_aux.h2;

  if (!IsInRange(c1, n2) || !IsInRange(c2, n2) || !IsInRange(proof.v, n2) ||
      !IsInRange(proof.z, n_tilde) || !IsInRange(proof.z2, n_tilde) ||
      !IsInRange(proof.t, n_tilde) || !IsInRange(proof.w, n_tilde) ||
      !IsZnStarElement(proof.s, n)) {
    return false;
  }
  if (proof.s1 < 0 || proof.s1 > QPow3() || proof.t1 < 0 ||
      proof.t1 > QPow7() || proof.s2 < 0 || proof.t2 < 0) {
    return false;
  }

  const Scalar e_scalar =
      BuildA3MtAChallenge(ctx, n, gamma, verifier_aux, c1, c2, proof);
  const BigInt e = e_scalar.mp_value();

  const BigInt lhs_nt_1 = MulMod(PowMod(h1, proof.s1, n_tilde),
                                 PowMod(h2, proof.s2, n_tilde), n_tilde);
  const BigInt rhs_nt_1 =
      MulMod(PowMod(proof.z, e, n_tilde), proof.z2, n_tilde);
  if (lhs_nt_1 != rhs_nt_1) {
    return false;
  }

  const BigInt lhs_nt_2 = MulMod(PowMod(h1, proof.t1, n_tilde),
                                 PowMod(h2, proof.t2, n_tilde), n_tilde);
  const BigInt rhs_nt_2 = MulMod(PowMod(proof.t, e, n_tilde), proof.w, n_tilde);
  if (lhs_nt_2 != rhs_nt_2) {
    return false;
  }

  BigInt lhs_paillier =
      MulMod(PowMod(c1, proof.s1, n2), PowMod(proof.s, n, n2), n2);
  lhs_paillier = MulMod(lhs_paillier, PowMod(gamma, proof.t1, n2), n2);
  const BigInt rhs_paillier = MulMod(PowMod(c2, e, n2), proof.v, n2);
  return lhs_paillier == rhs_paillier;
}

Bytes SerializePointPair(const ECPoint& first, const ECPoint& second) {
  Bytes out;
  const Bytes first_bytes = first.ToCompressedBytes();
  const Bytes second_bytes = second.ToCompressedBytes();
  out.reserve(first_bytes.size() + second_bytes.size());
  out.insert(out.end(), first_bytes.begin(), first_bytes.end());
  out.insert(out.end(), second_bytes.begin(), second_bytes.end());
  return out;
}

Scalar BuildVRelationChallenge(const Bytes& session_id, PartyIndex party_id,
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
    out = out.has_value() ? out->Add(g_term) : g_term;
  }
  if (!out.has_value()) {
    TECDSA_THROW_ARGUMENT("linear combination is point at infinity");
  }
  return *out;
}

}  // namespace tecdsa::sign_internal

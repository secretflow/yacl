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

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <thread>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/transcript.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/sign_session_internal.h"

namespace tecdsa::sign_internal {
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
Scalar BuildSchnorrChallenge(const Bytes& session_id, PartyIndex party_id,
                             const ECPoint& statement, const ECPoint& a) {
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

}  // namespace tecdsa::sign_internal

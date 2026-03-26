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
#include <cstddef>
#include <cstdint>
#include <span>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/hash.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/random.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/strict_proofs_internal.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/transcript.h"

namespace tecdsa::strict_proofs_internal {
namespace {

void AppendVerifierContext(Transcript* transcript,
                           const StrictProofVerifierContext& context) {
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

void AppendU32Be(uint32_t value, Bytes* out) {
  out->push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out->push_back(static_cast<uint8_t>(value & 0xFF));
}

bool IsInRange(const BigInt& value, const BigInt& modulus) {
  return value >= 0 && value < modulus;
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
    out.insert(out.end(), digest.begin(),
               digest.begin() + static_cast<std::ptrdiff_t>(take));
    ++block;
  }
  return out;
}

}  // namespace

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

AuxRsaParamsBigInt ToBigIntParams(const AuxRsaParams& params) {
  return AuxRsaParamsBigInt{
      .n_tilde = params.n_tilde,
      .h1 = params.h1,
      .h2 = params.h2,
  };
}

Scalar BuildAuxParamStrictChallenge(const AuxRsaParamsBigInt& params,
                                    const StrictProofVerifierContext& context,
                                    std::span<const uint8_t> nonce,
                                    const BigInt& c1, const BigInt& c2,
                                    const BigInt& t1, const BigInt& t2) {
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

BigInt DeriveSquareFreeGmr98Challenge(const BigInt& modulus_n,
                                      const StrictProofVerifierContext& context,
                                      std::span<const uint8_t> nonce,
                                      uint32_t round_idx) {
  if (modulus_n <= 3) {
    TECDSA_THROW_ARGUMENT("square-free GMR98 challenge requires modulus N > 3");
  }

  const Bytes n_bytes = EncodeMpInt(modulus_n);
  const size_t byte_len = std::max<size_t>(1, (modulus_n.BitCount() + 7) / 8);

  for (uint32_t attempt = 0; attempt < kMaxSquareFreeGmr98ChallengeAttempts;
       ++attempt) {
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

}  // namespace tecdsa::strict_proofs_internal

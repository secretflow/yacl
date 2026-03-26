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

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/strict_proofs.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/random.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/strict_proofs_internal.h"

namespace tecdsa {
namespace spi = strict_proofs_internal;

bool IsZnStarElement(const BigInt& value, const BigInt& modulus) {
  if (modulus <= 2 || value <= 0 || value >= modulus) {
    return false;
  }
  return BigInt::Gcd(value, modulus) == 1;
}

bool ValidateAuxRsaParams(const AuxRsaParams& params) {
  if (params.n_tilde <= 2 || params.h1 == params.h2) {
    return false;
  }
  return IsZnStarElement(params.h1, params.n_tilde) &&
         IsZnStarElement(params.h2, params.n_tilde);
}

Bytes EncodeSquareFreeProof(const SquareFreeProof& proof) { return proof.blob; }

SquareFreeProof DecodeSquareFreeProof(std::span<const uint8_t> encoded,
                                      size_t max_len) {
  if (encoded.size() > max_len) {
    TECDSA_THROW_ARGUMENT("square-free proof blob exceeds maximum length");
  }
  return SquareFreeProof{.blob = Bytes(encoded.begin(), encoded.end())};
}

Bytes EncodeAuxRsaParamProof(const AuxRsaParamProof& proof) {
  return proof.blob;
}

AuxRsaParamProof DecodeAuxRsaParamProof(std::span<const uint8_t> encoded,
                                        size_t max_len) {
  if (encoded.size() > max_len) {
    TECDSA_THROW_ARGUMENT("aux-param proof blob exceeds maximum length");
  }
  return AuxRsaParamProof{.blob = Bytes(encoded.begin(), encoded.end())};
}

bool IsLikelySquareFreeModulus(const BigInt& modulus_n) {
  if (modulus_n <= 2 || modulus_n.IsEven() || spi::IsPerfectSquare(modulus_n)) {
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

AuxRsaParams GenerateAuxRsaParams(uint32_t modulus_bits, PartyIndex party_id) {
  if (modulus_bits < 32) {
    TECDSA_THROW_ARGUMENT("aux RSA modulus bits must be >= 32");
  }

  const size_t byte_len = (static_cast<size_t>(modulus_bits) + 7) / 8;
  for (size_t attempt = 0; attempt < spi::kMaxAuxParamGenerationAttempts;
       ++attempt) {
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
    modulus_bytes.back() |= 0x01;
    if (modulus_bytes.size() > 1 && modulus_bytes.front() == 0) {
      continue;
    }

    const BigInt modulus_n = bigint::FromBigEndian(modulus_bytes);
    if (modulus_n <= 2 || !IsLikelySquareFreeModulus(modulus_n)) {
      continue;
    }

    const BigInt h1 =
        spi::PickCoprimeDeterministic(modulus_n, BigInt(2 + 2 * party_id));
    BigInt h2 =
        spi::PickCoprimeDeterministic(modulus_n, BigInt(3 + 2 * party_id));
    if (h1 == h2) {
      h2 = spi::PickCoprimeDeterministic(modulus_n, h1 + 1);
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

SquareFreeProof BuildSquareFreeProofGmr98(
    const BigInt& modulus_n, const BigInt& lambda_n,
    const StrictProofVerifierContext& context) {
  if (modulus_n <= 3) {
    TECDSA_THROW_ARGUMENT("square-free GMR98 proof requires modulus N > 3");
  }
  if (lambda_n <= 1) {
    TECDSA_THROW_ARGUMENT("square-free GMR98 proof requires lambda(N) > 1");
  }
  if (!IsLikelySquareFreeModulus(modulus_n)) {
    TECDSA_THROW_ARGUMENT(
        "square-free GMR98 proof requires likely square-free modulus");
  }

  const auto d_opt =
      spi::InvertMod(spi::NormalizeMod(modulus_n, lambda_n), lambda_n);
  if (!d_opt.has_value()) {
    TECDSA_THROW_ARGUMENT(
        "square-free GMR98 proof requires gcd(N, lambda(N)) = 1");
  }
  const BigInt d = *d_opt;
  const Bytes nonce = Csprng::RandomBytes(spi::kStrictNonceLen);

  spi::SquareFreeGmr98Payload payload;
  payload.nonce = nonce;
  payload.rounds = static_cast<uint32_t>(spi::kSquareFreeGmr98Rounds);
  payload.roots.reserve(payload.rounds);

  for (uint32_t round = 0; round < payload.rounds; ++round) {
    const BigInt challenge =
        spi::DeriveSquareFreeGmr98Challenge(modulus_n, context, nonce, round);
    const BigInt root = spi::PowMod(challenge, d, modulus_n);
    if (!spi::IsZnStarResidue(root, modulus_n)) {
      TECDSA_THROW("square-free GMR98 proof generated invalid root");
    }
    if (spi::PowMod(root, modulus_n, modulus_n) != challenge) {
      TECDSA_THROW(
          "square-free GMR98 proof generated inconsistent root equation");
    }
    payload.roots.push_back(root);
  }

  return SquareFreeProof{.blob = spi::EncodeSquareFreeGmr98Payload(payload)};
}

bool VerifySquareFreeProofGmr98(const BigInt& modulus_n,
                                const SquareFreeProof& proof,
                                const StrictProofVerifierContext& context) {
  if (!IsLikelySquareFreeModulus(modulus_n) || proof.blob.empty()) {
    return false;
  }

  spi::SquareFreeGmr98Payload payload;
  try {
    payload = spi::DecodeSquareFreeGmr98Payload(proof.blob);
  } catch (const std::exception&) {
    return false;
  }
  if (payload.nonce.size() != spi::kStrictNonceLen ||
      payload.rounds != spi::kSquareFreeGmr98Rounds ||
      payload.roots.size() != payload.rounds) {
    return false;
  }

  for (uint32_t round = 0; round < payload.rounds; ++round) {
    const BigInt& root = payload.roots[round];
    if (!spi::IsZnStarResidue(root, modulus_n)) {
      return false;
    }
    const BigInt challenge = spi::DeriveSquareFreeGmr98Challenge(
        modulus_n, context, payload.nonce, round);
    if (spi::PowMod(root, modulus_n, modulus_n) != challenge) {
      return false;
    }
  }
  return true;
}

AuxRsaParamProof BuildAuxRsaParamProofStrict(
    const AuxRsaParams& params, const StrictProofVerifierContext& context) {
  if (!ValidateAuxRsaParams(params)) {
    TECDSA_THROW_ARGUMENT(
        "cannot build aux param proof from invalid parameters");
  }
  const spi::AuxRsaParamsBigInt params_big = spi::ToBigIntParams(params);
  if (!IsLikelySquareFreeModulus(params_big.n_tilde)) {
    TECDSA_THROW_ARGUMENT(
        "aux strict proof requires likely square-free Ntilde");
  }

  BigInt alpha;
  do {
    alpha = spi::RandomBelow(Scalar::ModulusQMpInt());
  } while (alpha == 0);
  BigInt r;
  do {
    r = spi::RandomBelow(Scalar::ModulusQMpInt());
  } while (r == 0);

  const BigInt c1 = spi::PowMod(params_big.h1, alpha, params_big.n_tilde);
  const BigInt c2 = spi::PowMod(params_big.h2, alpha, params_big.n_tilde);
  const BigInt t1 = spi::PowMod(params_big.h1, r, params_big.n_tilde);
  const BigInt t2 = spi::PowMod(params_big.h2, r, params_big.n_tilde);
  const Bytes nonce = Csprng::RandomBytes(spi::kStrictNonceLen);
  const BigInt e = spi::BuildAuxParamStrictChallenge(params_big, context, nonce,
                                                     c1, c2, t1, t2)
                       .mp_value();
  const BigInt z = r + (e * alpha);

  return AuxRsaParamProof{
      .blob = spi::EncodeAuxParamStrictPayload(spi::AuxParamStrictPayload{
          .nonce = nonce,
          .c1 = c1,
          .c2 = c2,
          .t1 = t1,
          .t2 = t2,
          .z = z,
      }),
  };
}

bool VerifyAuxRsaParamProofStrict(const AuxRsaParams& params,
                                  const AuxRsaParamProof& proof,
                                  const StrictProofVerifierContext& context) {
  if (!ValidateAuxRsaParams(params)) {
    return false;
  }
  const spi::AuxRsaParamsBigInt params_big = spi::ToBigIntParams(params);
  if (!IsLikelySquareFreeModulus(params_big.n_tilde) || proof.blob.empty()) {
    return false;
  }

  spi::AuxParamStrictPayload payload;
  try {
    payload = spi::DecodeAuxParamStrictPayload(proof.blob);
  } catch (const std::exception&) {
    return false;
  }
  if (payload.nonce.size() != spi::kStrictNonceLen || payload.z < 0) {
    return false;
  }
  if (!IsZnStarElement(payload.c1, params_big.n_tilde) ||
      !IsZnStarElement(payload.c2, params_big.n_tilde) ||
      !IsZnStarElement(payload.t1, params_big.n_tilde) ||
      !IsZnStarElement(payload.t2, params_big.n_tilde)) {
    return false;
  }

  const BigInt e = spi::BuildAuxParamStrictChallenge(
                       params_big, context, payload.nonce, payload.c1,
                       payload.c2, payload.t1, payload.t2)
                       .mp_value();

  const BigInt lhs1 = spi::PowMod(params_big.h1, payload.z, params_big.n_tilde);
  const BigInt rhs1 =
      spi::MulMod(payload.t1, spi::PowMod(payload.c1, e, params_big.n_tilde),
                  params_big.n_tilde);
  if (lhs1 != rhs1) {
    return false;
  }

  const BigInt lhs2 = spi::PowMod(params_big.h2, payload.z, params_big.n_tilde);
  const BigInt rhs2 =
      spi::MulMod(payload.t2, spi::PowMod(payload.c2, e, params_big.n_tilde),
                  params_big.n_tilde);
  return lhs2 == rhs2;
}

}  // namespace tecdsa

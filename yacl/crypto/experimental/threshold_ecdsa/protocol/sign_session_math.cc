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

#include <cstddef>
#include <optional>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/random.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/sign_session_internal.h"

namespace tecdsa::sign_internal {
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

StrictProofVerifierContext BuildKeygenProofContext(
    const Bytes& keygen_session_id, PartyIndex prover_id) {
  StrictProofVerifierContext context;
  if (!keygen_session_id.empty()) {
    context.session_id = keygen_session_id;
    context.prover_id = prover_id;
  }
  return context;
}

bool StrictMetadataCompatible(const ProofMetadata& expected,
                              const ProofMetadata& candidate) {
  return IsProofMetadataCompatible(expected, candidate,
                                   /*require_strict_scheme=*/true);
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
        TECDSA_THROW_ARGUMENT(
            "duplicate participant id in lagrange coefficient set");
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

}  // namespace tecdsa::sign_internal

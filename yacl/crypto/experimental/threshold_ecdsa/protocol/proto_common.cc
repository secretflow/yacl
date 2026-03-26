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

#include "yacl/crypto/experimental/threshold_ecdsa/protocol/proto_common.h"

#include <cstddef>
#include <stdexcept>
#include <unordered_set>

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/random.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/transcript.h"

namespace tecdsa::proto {
namespace {

constexpr char kSchnorrProofId[] = "GG2019/Schnorr/v1";

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

BigInt NormalizeModQ(const BigInt& value) {
  return bigint::NormalizeMod(value, Scalar::ModulusQMpInt());
}

}  // namespace

void ValidateParticipantsOrThrow(const std::vector<PartyIndex>& participants,
                                 PartyIndex self_id,
                                 const char* context_name) {
  if (participants.size() < 2) {
    TECDSA_THROW_ARGUMENT(std::string(context_name) +
                          " requires at least 2 participants");
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

std::vector<PartyIndex> BuildPeers(const std::vector<PartyIndex>& participants,
                                   PartyIndex self_id) {
  std::vector<PartyIndex> peers;
  peers.reserve(participants.size());
  for (PartyIndex party : participants) {
    if (party != self_id) {
      peers.push_back(party);
    }
  }
  return peers;
}

Scalar RandomNonZeroScalar() {
  while (true) {
    const Scalar candidate = Csprng::RandomScalar();
    if (candidate.value() != 0) {
      return candidate;
    }
  }
}

Scalar EvaluatePolynomialAt(const std::vector<Scalar>& coefficients,
                            PartyIndex party_id) {
  if (coefficients.empty()) {
    TECDSA_THROW_ARGUMENT("polynomial coefficients must not be empty");
  }

  const BigInt& q = Scalar::ModulusQMpInt();
  const BigInt x = BigInt(party_id).Mod(q);

  BigInt acc(0);
  BigInt power(1);
  for (const Scalar& coefficient : coefficients) {
    acc = bigint::NormalizeMod(acc + coefficient.mp_value() * power, q);
    power = bigint::NormalizeMod(power * x, q);
  }
  return Scalar(acc);
}

StrictProofVerifierContext BuildProofContext(const Bytes& session_id,
                                             PartyIndex prover_id) {
  StrictProofVerifierContext context;
  context.session_id = session_id;
  context.prover_id = prover_id;
  return context;
}

SchnorrProof BuildSchnorrProof(const Bytes& session_id, PartyIndex prover_id,
                               const ECPoint& statement,
                               const Scalar& witness) {
  if (witness.value() == 0) {
    TECDSA_THROW_ARGUMENT("schnorr witness must be non-zero");
  }

  while (true) {
    const Scalar r = RandomNonZeroScalar();
    const ECPoint a = ECPoint::GeneratorMultiply(r);
    const Scalar e = BuildSchnorrChallenge(session_id, prover_id, statement, a);
    const Scalar z = r + (e * witness);
    if (z.value() == 0) {
      continue;
    }
    return SchnorrProof{.a = a, .z = z};
  }
}

bool VerifySchnorrProof(const Bytes& session_id, PartyIndex prover_id,
                        const ECPoint& statement, const SchnorrProof& proof) {
  if (proof.z.value() == 0) {
    return false;
  }

  try {
    const Scalar e =
        BuildSchnorrChallenge(session_id, prover_id, statement, proof.a);
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

void ValidatePaillierPublicKeyOrThrow(const PaillierPublicKey& pub) {
  if (pub.n <= MinPaillierModulusQ8()) {
    TECDSA_THROW_ARGUMENT("Paillier modulus must satisfy N > q^8");
  }
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
        TECDSA_THROW_ARGUMENT("duplicate participant id in lagrange set");
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
    TECDSA_THROW_ARGUMENT("cannot sum an empty point vector");
  }
  ECPoint sum = points.front();
  for (size_t i = 1; i < points.size(); ++i) {
    sum = sum.Add(points[i]);
  }
  return sum;
}

Scalar XCoordinateModQ(const ECPoint& point) {
  const Bytes compressed = point.ToCompressedBytes();
  if (compressed.size() != 33) {
    TECDSA_THROW_ARGUMENT("invalid compressed point length");
  }

  const std::span<const uint8_t> x_bytes(compressed.data() + 1, 32);
  return Scalar::FromBigEndianModQ(x_bytes);
}

bool IsHighScalar(const Scalar& scalar) {
  static const BigInt kHalfOrder = Scalar::ModulusQMpInt() >> 1;
  return scalar.value() > kHalfOrder;
}

}  // namespace tecdsa::proto

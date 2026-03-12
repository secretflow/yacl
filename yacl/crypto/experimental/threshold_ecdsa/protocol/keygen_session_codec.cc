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
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/random.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/transcript.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/keygen_session_internal.h"

namespace tecdsa::keygen_internal {

void ValidateParticipantsOrThrow(const std::vector<PartyIndex>& participants,
                                 PartyIndex self_id) {
  if (participants.size() < 2) {
    TECDSA_THROW_ARGUMENT("KeygenSession requires at least 2 participants");
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

std::unordered_set<PartyIndex> BuildPeerSet(
    const std::vector<PartyIndex>& participants, PartyIndex self_id) {
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
    TECDSA_THROW_ARGUMENT("Sized field exceeds uint32 length");
  }
  AppendU32Be(static_cast<uint32_t>(field.size()), out);
  out->insert(out->end(), field.begin(), field.end());
}

Bytes ReadSizedField(std::span<const uint8_t> input, size_t* offset,
                     size_t max_len, const char* field_name) {
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
  const Bytes encoded = EncodePoint(point);
  if (encoded.size() != kPointCompressedLen) {
    TECDSA_THROW("Encoded secp256k1 point must be 33 bytes");
  }
  out->insert(out->end(), encoded.begin(), encoded.end());
}

ECPoint ReadPoint(std::span<const uint8_t> input, size_t* offset) {
  if (*offset + kPointCompressedLen > input.size()) {
    TECDSA_THROW_ARGUMENT("Not enough bytes for compressed secp256k1 point");
  }

  const std::span<const uint8_t> view =
      input.subspan(*offset, kPointCompressedLen);
  *offset += kPointCompressedLen;
  return DecodePoint(view);
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

BigInt ReadMpIntField(std::span<const uint8_t> input, size_t* offset,
                      size_t max_len, const char* field_name) {
  const Bytes encoded = ReadSizedField(input, offset, max_len, field_name);
  return DecodeMpInt(encoded, max_len);
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
    TECDSA_THROW_ARGUMENT("Polynomial coefficients must not be empty");
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

const BigInt& MinPaillierModulusQ8() {
  static const BigInt q_to_8 = []() {
    BigInt out(1);
    const BigInt& q = Scalar::ModulusQMpInt();
    for (size_t i = 0; i < 8; ++i) {
      out *= q;
    }
    return out;
  }();
  return q_to_8;
}

void ValidatePaillierPublicKeyOrThrow(const PaillierPublicKey& pub) {
  if (pub.n <= MinPaillierModulusQ8()) {
    TECDSA_THROW_ARGUMENT("Paillier modulus must satisfy N > q^8");
  }
}

StrictProofVerifierContext BuildStrictProofContext(const Bytes& session_id,
                                                   PartyIndex prover_id) {
  StrictProofVerifierContext context;
  context.session_id = session_id;
  context.prover_id = prover_id;
  return context;
}

bool StrictMetadataCompatible(const ProofMetadata& expected,
                              const ProofMetadata& candidate) {
  return IsProofMetadataCompatible(expected, candidate,
                                   /*require_strict_scheme=*/true);
}

}  // namespace tecdsa::keygen_internal

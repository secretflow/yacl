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

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <unordered_set>
#include <utility>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/random.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/sign_session_internal.h"

namespace tecdsa::sign_internal {
void ValidateParticipantsOrThrow(const std::vector<PartyIndex>& participants,
                                 PartyIndex self_id) {
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
    TECDSA_THROW_ARGUMENT("sized field exceeds uint32 length");
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

  const std::span<const uint8_t> view =
      input.subspan(*offset, kPointCompressedLen);
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

BigInt ReadMpIntField(std::span<const uint8_t> input, size_t* offset,
                      size_t max_len, const char* field_name) {
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

Bytes RandomMtaInstanceId() { return Csprng::RandomBytes(kMtaInstanceIdLen); }

}  // namespace tecdsa::sign_internal

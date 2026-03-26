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
#include <cstdint>
#include <span>
#include <string>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/strict_proofs_internal.h"

namespace tecdsa::strict_proofs_internal {
namespace {

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

void AppendMpIntField(const BigInt& value, Bytes* out) {
  const Bytes encoded = EncodeMpInt(value);
  AppendSizedField(encoded, out);
}

BigInt ReadMpIntField(std::span<const uint8_t> input, size_t* offset,
                      const char* field_name) {
  const Bytes encoded =
      ReadSizedField(input, offset, kMaxStrictFieldLen, field_name);
  return DecodeMpInt(encoded, kMaxStrictFieldLen);
}

}  // namespace

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

SquareFreeStrictPayload DecodeSquareFreeStrictPayload(
    std::span<const uint8_t> blob) {
  size_t offset = 0;
  SquareFreeStrictPayload payload;
  payload.nonce =
      ReadSizedField(blob, &offset, kMaxStrictNonceLen, "square-free nonce");
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

SquareFreeGmr98Payload DecodeSquareFreeGmr98Payload(
    std::span<const uint8_t> blob) {
  size_t offset = 0;
  SquareFreeGmr98Payload payload;
  payload.nonce = ReadSizedField(blob, &offset, kMaxStrictNonceLen,
                                 "square-free GMR98 nonce");
  payload.rounds = ReadU32Be(blob, &offset);
  if (payload.rounds == 0 || payload.rounds > kMaxSquareFreeGmr98Rounds) {
    TECDSA_THROW_ARGUMENT("square-free GMR98 rounds out of range");
  }
  payload.roots.reserve(payload.rounds);
  for (uint32_t i = 0; i < payload.rounds; ++i) {
    payload.roots.push_back(
        ReadMpIntField(blob, &offset, "square-free GMR98 root"));
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

AuxParamStrictPayload DecodeAuxParamStrictPayload(
    std::span<const uint8_t> blob) {
  size_t offset = 0;
  AuxParamStrictPayload payload;
  payload.nonce =
      ReadSizedField(blob, &offset, kMaxStrictNonceLen, "aux-param nonce");
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

}  // namespace tecdsa::strict_proofs_internal

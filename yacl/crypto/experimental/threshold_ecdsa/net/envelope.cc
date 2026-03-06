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

#include "yacl/crypto/experimental/threshold_ecdsa/net/envelope.h"

#include <stdexcept>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"

namespace tecdsa {
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

Bytes ReadSizedField(std::span<const uint8_t> input, size_t* offset,
                     size_t max_len, const char* field_name) {
  const uint32_t len = ReadU32Be(input, offset);
  if (len > max_len) {
    TECDSA_THROW_ARGUMENT(std::string(field_name) + " exceeds max length");
  }
  if (*offset + len > input.size()) {
    TECDSA_THROW_ARGUMENT(std::string(field_name) + " has inconsistent length");
  }

  Bytes out(input.begin() + static_cast<std::ptrdiff_t>(*offset),
            input.begin() + static_cast<std::ptrdiff_t>(*offset + len));
  *offset += len;
  return out;
}

}  // namespace

Bytes EncodeEnvelope(const Envelope& envelope) {
  if (envelope.session_id.size() > UINT32_MAX ||
      envelope.payload.size() > UINT32_MAX) {
    TECDSA_THROW_ARGUMENT("Envelope field exceeds uint32 length");
  }

  Bytes out;
  out.reserve(4 + envelope.session_id.size() + 4 + 4 + 4 + 4 +
              envelope.payload.size());

  AppendU32Be(static_cast<uint32_t>(envelope.session_id.size()), &out);
  out.insert(out.end(), envelope.session_id.begin(), envelope.session_id.end());

  AppendU32Be(envelope.from, &out);
  AppendU32Be(envelope.to, &out);
  AppendU32Be(envelope.type, &out);

  AppendU32Be(static_cast<uint32_t>(envelope.payload.size()), &out);
  out.insert(out.end(), envelope.payload.begin(), envelope.payload.end());

  return out;
}

Envelope DecodeEnvelope(std::span<const uint8_t> encoded,
                        size_t max_session_id_len, size_t max_payload_len) {
  size_t offset = 0;

  Envelope out;
  out.session_id =
      ReadSizedField(encoded, &offset, max_session_id_len, "session_id");
  out.from = ReadU32Be(encoded, &offset);
  out.to = ReadU32Be(encoded, &offset);
  out.type = ReadU32Be(encoded, &offset);
  out.payload = ReadSizedField(encoded, &offset, max_payload_len, "payload");

  if (offset != encoded.size()) {
    TECDSA_THROW_ARGUMENT("Envelope has trailing bytes");
  }
  return out;
}

}  // namespace tecdsa

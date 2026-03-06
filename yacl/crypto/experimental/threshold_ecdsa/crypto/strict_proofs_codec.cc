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
#include <utility>

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

uint32_t EncodeStrictProofScheme(StrictProofScheme scheme) {
  return static_cast<uint32_t>(scheme);
}

StrictProofScheme DecodeStrictProofScheme(uint32_t raw) {
  switch (raw) {
    case static_cast<uint32_t>(StrictProofScheme::kUnknown):
      return StrictProofScheme::kUnknown;
    case static_cast<uint32_t>(StrictProofScheme::kDevDigestBindingV1):
      return StrictProofScheme::kDevDigestBindingV1;
    case static_cast<uint32_t>(StrictProofScheme::kStrictAlgebraicV1):
      return StrictProofScheme::kStrictAlgebraicV1;
    case static_cast<uint32_t>(StrictProofScheme::kStrictExternalV1):
      return StrictProofScheme::kStrictExternalV1;
    case static_cast<uint32_t>(StrictProofScheme::kSquareFreeGmr98V1):
      return StrictProofScheme::kSquareFreeGmr98V1;
    default:
      return StrictProofScheme::kUnknown;
  }
}

}  // namespace

bool HasContextBinding(const StrictProofVerifierContext& context) {
  return !context.session_id.empty() || context.prover_id.has_value() ||
         context.verifier_id.has_value();
}

ProofMetadata MakeWeakMetadata(const char* scheme_id) {
  return ProofMetadata{
      .scheme = StrictProofScheme::kDevDigestBindingV1,
      .version = kDevProofVersion,
      .capability_flags = kProofCapabilityNone,
      .scheme_id = scheme_id,
  };
}

ProofMetadata MakeStrictMetadata(const char* scheme_id,
                                 const StrictProofVerifierContext& context) {
  uint32_t capability_flags = kProofCapabilityStrictReady |
                              kProofCapabilityAlgebraicChecks |
                              kProofCapabilityFreshRandomness;
  if (HasContextBinding(context)) {
    capability_flags |= kProofCapabilityContextBinding;
  }

  return ProofMetadata{
      .scheme = StrictProofScheme::kStrictAlgebraicV1,
      .version = kStrictAlgebraicVersion,
      .capability_flags = capability_flags,
      .scheme_id = scheme_id,
  };
}

ProofMetadata MakeSquareFreeGmr98Metadata(
    const StrictProofVerifierContext& context) {
  uint32_t capability_flags =
      kProofCapabilityStrictReady | kProofCapabilityAlgebraicChecks |
      kProofCapabilityFreshRandomness | kProofCapabilityHeuristicChecks;
  if (HasContextBinding(context)) {
    capability_flags |= kProofCapabilityContextBinding;
  }

  return ProofMetadata{
      .scheme = StrictProofScheme::kSquareFreeGmr98V1,
      .version = kSquareFreeGmr98Version,
      .capability_flags = capability_flags,
      .scheme_id = kSquareFreeSchemeIdGmr98,
  };
}

Bytes EncodeProofWire(const ProofMetadata& metadata,
                      std::span<const uint8_t> blob) {
  if (metadata.scheme == StrictProofScheme::kUnknown && metadata.version == 0 &&
      metadata.capability_flags == kProofCapabilityNone &&
      metadata.scheme_id.empty()) {
    return Bytes(blob.begin(), blob.end());
  }

  if (blob.size() > UINT32_MAX) {
    TECDSA_THROW_ARGUMENT("proof blob exceeds uint32 length");
  }
  if (metadata.scheme_id.size() > UINT32_MAX ||
      metadata.scheme_id.size() > kMaxSchemeIdLen) {
    TECDSA_THROW_ARGUMENT("proof scheme id exceeds maximum length");
  }

  Bytes out;
  out.reserve(24 + metadata.scheme_id.size() + blob.size());
  AppendU32Be(kProofWireMagicV2, &out);
  AppendU32Be(EncodeStrictProofScheme(metadata.scheme), &out);
  AppendU32Be(metadata.version, &out);
  AppendU32Be(metadata.capability_flags, &out);
  AppendU32Be(static_cast<uint32_t>(metadata.scheme_id.size()), &out);
  AppendU32Be(static_cast<uint32_t>(blob.size()), &out);
  out.insert(out.end(), metadata.scheme_id.begin(), metadata.scheme_id.end());
  out.insert(out.end(), blob.begin(), blob.end());
  return out;
}

std::pair<ProofMetadata, Bytes> DecodeProofWire(
    std::span<const uint8_t> encoded, size_t max_len) {
  if (encoded.empty()) {
    return {ProofMetadata{}, Bytes{}};
  }

  if (encoded.size() >= 24) {
    size_t offset = 0;
    const uint32_t magic = ReadU32Be(encoded, &offset);
    if (magic == kProofWireMagicV2) {
      ProofMetadata metadata;
      metadata.scheme = DecodeStrictProofScheme(ReadU32Be(encoded, &offset));
      metadata.version = ReadU32Be(encoded, &offset);
      metadata.capability_flags = ReadU32Be(encoded, &offset);
      const uint32_t scheme_id_len = ReadU32Be(encoded, &offset);
      const uint32_t blob_len = ReadU32Be(encoded, &offset);
      if (blob_len > max_len) {
        TECDSA_THROW_ARGUMENT("proof blob exceeds maximum length");
      }
      if (scheme_id_len > kMaxSchemeIdLen) {
        TECDSA_THROW_ARGUMENT("proof scheme id exceeds maximum length");
      }
      if (offset + scheme_id_len + blob_len != encoded.size()) {
        TECDSA_THROW_ARGUMENT("proof wire payload has inconsistent length");
      }

      metadata.scheme_id.assign(
          reinterpret_cast<const char*>(encoded.data() +
                                        static_cast<std::ptrdiff_t>(offset)),
          scheme_id_len);
      offset += scheme_id_len;

      Bytes blob(
          encoded.begin() + static_cast<std::ptrdiff_t>(offset),
          encoded.begin() + static_cast<std::ptrdiff_t>(offset + blob_len));
      return {std::move(metadata), std::move(blob)};
    }
  }

  if (encoded.size() >= 16) {
    size_t offset = 0;
    const uint32_t magic = ReadU32Be(encoded, &offset);
    if (magic == kProofWireMagicV1) {
      ProofMetadata metadata;
      metadata.scheme = DecodeStrictProofScheme(ReadU32Be(encoded, &offset));
      metadata.version = ReadU32Be(encoded, &offset);
      metadata.capability_flags = kProofCapabilityNone;
      const uint32_t blob_len = ReadU32Be(encoded, &offset);
      if (blob_len > max_len) {
        TECDSA_THROW_ARGUMENT("proof blob exceeds maximum length");
      }
      if (offset + blob_len != encoded.size()) {
        TECDSA_THROW_ARGUMENT("proof wire payload has inconsistent length");
      }
      Bytes blob(
          encoded.begin() + static_cast<std::ptrdiff_t>(offset),
          encoded.begin() + static_cast<std::ptrdiff_t>(offset + blob_len));
      return {std::move(metadata), std::move(blob)};
    }
  }

  if (encoded.size() > max_len) {
    TECDSA_THROW_ARGUMENT("legacy proof blob exceeds maximum length");
  }
  return {ProofMetadata{}, Bytes(encoded.begin(), encoded.end())};
}

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

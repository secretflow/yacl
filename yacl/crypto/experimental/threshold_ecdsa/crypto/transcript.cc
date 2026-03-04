#include "yacl/crypto/experimental/threshold_ecdsa/crypto/transcript.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"

#include <array>
#include <stdexcept>

#include <openssl/sha.h>

namespace tecdsa {
namespace {

void AppendU32Be(uint32_t value, Bytes* out) {
  out->push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out->push_back(static_cast<uint8_t>(value & 0xFF));
}

std::array<uint8_t, SHA256_DIGEST_LENGTH> Sha256(std::span<const uint8_t> input) {
  std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{};
  if (SHA256(input.data(), input.size(), digest.data()) == nullptr) {
    TECDSA_THROW("SHA256 failed");
  }
  return digest;
}

std::span<const uint8_t> AsByteSpan(std::string_view value) {
  return std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(value.data()), value.size());
}

}  // namespace

void Transcript::append(std::string_view label, std::span<const uint8_t> data) {
  if (label.size() > UINT32_MAX || data.size() > UINT32_MAX) {
    TECDSA_THROW_ARGUMENT("Transcript field exceeds uint32 length");
  }

  AppendU32Be(static_cast<uint32_t>(label.size()), &transcript_);
  transcript_.insert(transcript_.end(), label.begin(), label.end());

  AppendU32Be(static_cast<uint32_t>(data.size()), &transcript_);
  transcript_.insert(transcript_.end(), data.begin(), data.end());
}

void Transcript::append_ascii(std::string_view label, std::string_view ascii) {
  append(label, AsByteSpan(ascii));
}

void Transcript::append_proof_id(std::string_view proof_id) {
  append_ascii("proof_id", proof_id);
}

void Transcript::append_session_id(std::span<const uint8_t> session_id) {
  append("session_id", session_id);
}

void Transcript::append_u32_be(std::string_view label, uint32_t value) {
  std::array<uint8_t, 4> encoded = {
      static_cast<uint8_t>((value >> 24) & 0xFF),
      static_cast<uint8_t>((value >> 16) & 0xFF),
      static_cast<uint8_t>((value >> 8) & 0xFF),
      static_cast<uint8_t>(value & 0xFF),
  };
  append(label, encoded);
}

void Transcript::append_fields(std::initializer_list<TranscriptFieldRef> fields) {
  for (const TranscriptFieldRef& field : fields) {
    append(field.label, field.data);
  }
}

Scalar Transcript::challenge_scalar_mod_q() const {
  const auto digest = Sha256(transcript_);
  return Scalar::FromBigEndianModQ(digest);
}

const Bytes& Transcript::bytes() const {
  return transcript_;
}

}  // namespace tecdsa

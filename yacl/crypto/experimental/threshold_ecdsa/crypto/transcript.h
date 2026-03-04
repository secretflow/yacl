#pragma once

#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"

namespace tecdsa {

struct TranscriptFieldRef {
  std::string_view label;
  std::span<const uint8_t> data;
};

class Transcript {
 public:
  void append(std::string_view label, std::span<const uint8_t> data);
  void append_ascii(std::string_view label, std::string_view ascii);
  void append_proof_id(std::string_view proof_id);
  void append_session_id(std::span<const uint8_t> session_id);
  void append_u32_be(std::string_view label, uint32_t value);
  void append_fields(std::initializer_list<TranscriptFieldRef> fields);
  Scalar challenge_scalar_mod_q() const;

  const Bytes& bytes() const;

 private:
  Bytes transcript_;
};

}  // namespace tecdsa

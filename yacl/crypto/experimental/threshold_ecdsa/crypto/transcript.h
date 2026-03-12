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

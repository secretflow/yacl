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
#include <string>
#include <string_view>
#include <type_traits>

#include "yacl/crypto/experimental/threshold_signatures/common/errors.h"

namespace tecdsa::core::protocol {

template <typename Step>
class LinearRoundDriver {
 public:
  static_assert(std::is_enum_v<Step>,
                "LinearRoundDriver requires an enum step type");

  constexpr explicit LinearRoundDriver(Step initial) : current_(initial) {}

  constexpr Step current() const { return current_; }

  constexpr bool CanProceed(Step required_current) const {
    return Value(current_) == Value(required_current);
  }

  constexpr bool HasReached(Step step) const {
    return Value(current_) >= Value(step);
  }

  std::string ExpectedMessages(std::string_view message_name) const {
    return "expected " + std::string(message_name);
  }

  void RequireReached(Step required, std::string_view error_message) const {
    if (!HasReached(required)) {
      TECDSA_THROW_LOGIC(std::string(error_message));
    }
  }

  void Advance(Step required_current, Step next,
               std::string_view error_message) {
    if (!CanProceed(required_current)) {
      TECDSA_THROW_LOGIC(std::string(error_message));
    }
    current_ = next;
  }

 private:
  static constexpr auto Value(Step step) {
    return static_cast<std::underlying_type_t<Step>>(step);
  }

  Step current_;
};

}  // namespace tecdsa::core::protocol

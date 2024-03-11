// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "yacl/utils/spi/argument/arg_kv.h"

#include "yacl/math/mpint/mp_int.h"

namespace yacl {

const std::string& SpiArg::Key() const { return key_; }

bool SpiArg::HasValue() const { return value_.has_value(); }

SpiArg& SpiArg::operator=(const char* value) {
  value_ = absl::AsciiStrToLower(std::string(value));
  return *this;
}

SpiArg& SpiArg::operator=(const std::string& value) {
  value_ = absl::AsciiStrToLower(value);
  return *this;
}

#define TRY_TYPE(type)                                              \
  if (t == typeid(type)) {                                          \
    return fmt::format("{}={}", key_, std::any_cast<type>(value_)); \
  }

std::string SpiArg::ToString() const {
  const auto& t = value_.type();
  // Place the types with a high probability of being hit at the front.
  TRY_TYPE(std::string);
  TRY_TYPE(int64_t);  // mac-m1 doesn't support int128
  TRY_TYPE(uint64_t);
  TRY_TYPE(bool);
  TRY_TYPE(double);

  TRY_TYPE(int8_t);
  TRY_TYPE(int16_t);
  TRY_TYPE(int32_t);
  TRY_TYPE(uint8_t);
  TRY_TYPE(uint16_t);
  TRY_TYPE(uint32_t);
  TRY_TYPE(float);
  TRY_TYPE(char);
  TRY_TYPE(unsigned char);
  TRY_TYPE(yacl::math::MPInt);  // MPInt is a first-class citizen in SPI
  return fmt::format("{}=Object<{}>", key_, t.name());
}

}  // namespace yacl

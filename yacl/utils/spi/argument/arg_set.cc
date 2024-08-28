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

#include "yacl/utils/spi/argument/arg_set.h"

// formatter to format SpiArgs values
template <>
struct fmt::formatter<std::map<std::string, yacl::SpiArg>::value_type> {
  template <typename ParseContext>
  constexpr auto parse(ParseContext &ctx) {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const std::map<std::string, yacl::SpiArg>::value_type &fp,
              FormatContext &ctx) const {
    return fmt::format_to(ctx.out(), "{}", fp.second);
  }
};

namespace yacl {

SpiArgs::SpiArgs(std::initializer_list<SpiArg> args) {
  for (const auto &item : args) {
    insert({item.Key(), item});
  }
}

void SpiArgs::Insert(const SpiArg &arg) { insert({arg.Key(), arg}); }

std::string SpiArgs::ToString() const {
  return fmt::format("{{{}}}", fmt::join(*this, ", "));
}

}  // namespace yacl

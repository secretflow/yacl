// Copyright 2024 Ant Group Co., Ltd.
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

#include "yacl/utils/spi/argument/util.h"

#include <regex>

#include "absl/strings/ascii.h"
#include "absl/strings/str_join.h"
#include "fmt/core.h"

namespace yacl::util {

std::string ToSnakeCase(const std::string& str) {
  std::regex reg("[A-Z]?[a-z0-9]*");
  std::string log = str;
  std::vector<std::string> words;
  for (std::smatch sm;
       std::regex_search(log, sm, reg, std::regex_constants::match_not_null);
       log = sm.suffix()) {
    words.push_back(absl::AsciiStrToLower(sm.str()));
  }
  return absl::StrJoin(words, "_");
}

}  // namespace yacl::util

// Copyright 2019 Ant Group Co., Ltd.
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

#include "absl/types/span.h"

namespace yacl::crypto {

// Drbg abstract class

class IDrbg {
 public:
  IDrbg() = default;
  virtual ~IDrbg() = default;

  virtual void FillPRandBytes(absl::Span<uint8_t> out) = 0;

  template <typename T,
            std::enable_if_t<std::is_trivially_copyable_v<T>, int> = 0>
  void FillPRand(absl::Span<T> out) {
    FillPRandBytes(absl::MakeSpan(reinterpret_cast<uint8_t*>(out.data()),
                                  out.size() * sizeof(T)));
  }
};

}  // namespace yacl::crypto

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

#include "yasl/crypto/drbg/std_entropy_source.h"

#include <algorithm>
#include <iostream>
#include <random>
#include <string>

namespace yasl::crypto {


std::string StdEntropySource::GetEntropy(size_t entropy_bytes) {
  std::string entropy_buf;

  if (entropy_bytes == 0) {
    return entropy_buf;
  }

  entropy_buf.resize(entropy_bytes);

  uint64_t temp_rand;

  size_t batch_bytes = sizeof(uint64_t);
  size_t batch_size = (entropy_bytes + batch_bytes - 1) / batch_bytes;

  for (size_t idx = 0; idx < batch_size; idx++) {
    size_t current_pos = idx * batch_bytes;
    size_t current_batch_bytes =
        std::min(entropy_bytes - current_pos, batch_bytes);

    temp_rand = GetEntropy();
    std::memcpy(&entropy_buf[current_pos], &temp_rand, current_batch_bytes);
  }

  return entropy_buf;
}

uint64_t StdEntropySource::GetEntropy() {
  std::random_device rd("/dev/urandom");

  return static_cast<uint64_t>(rd()) << 32 | rd();
}

}  // namespace yasl::crypto

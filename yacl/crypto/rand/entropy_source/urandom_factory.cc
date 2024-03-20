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

#include "yacl/crypto/rand/entropy_source/urandom_factory.h"

#include <algorithm>
#include <iostream>
#include <random>
#include <string>

namespace yacl::crypto {

Buffer UrandomEntropySource::GetEntropy(uint32_t num_bytes) {
  YACL_ENFORCE(num_bytes != 0);

  Buffer out(num_bytes);
  std::random_device rd("/dev/urandom");

  // Batched Random Entropy Generation
  size_t batch_size = sizeof(uint32_t);
  size_t batch_num = (num_bytes + batch_size - 1) / batch_size;
  for (size_t idx = 0; idx < batch_num; idx++) {
    uint64_t temp_rand = 0;
    size_t current_pos = idx * batch_size;
    size_t current_batch_size = std::min(num_bytes - current_pos, batch_size);

    temp_rand = static_cast<uint32_t>(rd());

    std::memcpy(static_cast<char *>(out.data()) + current_pos, &temp_rand,
                current_batch_size);
  }

  return out;
}

REGISTER_ENTROPY_SOURCE_LIBRARY("urandom", 100, UrandomEntropySource::Check,
                                UrandomEntropySource::Create);

}  // namespace yacl::crypto

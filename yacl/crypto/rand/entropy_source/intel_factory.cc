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

#include "yacl/crypto/rand/entropy_source/intel_factory.h"

#include <iostream>

#ifdef __x86_64

namespace yacl::crypto {

namespace {

// Example from Code Example 9,
// https://www.intel.com/content/www/us/en/developer/articles/guide/
// intel-digital-random-number-generator-drng-software-implementation-guide.html
int rdseed64_step(uint64_t *out) {
  unsigned char ok = 0;
  asm volatile("rdseed %0; setc %1" : "=r"(*out), "=qm"(ok));
  return static_cast<int>(ok);
}

// Or maybe just use the buit-in function:
// ----------------------------------------
// #include <immintrin.h>
// int _rdseed64_step(uint64_t*);
// ----------------------------------------

}  // namespace

Buffer IntelEntropySource::GetEntropy(uint32_t num_bytes) {
  YACL_ENFORCE(num_bytes != 0);

  Buffer out(num_bytes);

  // Batched Random Entropy Generation
  size_t batch_size = sizeof(uint64_t);
  size_t batch_num = (num_bytes + batch_size - 1) / batch_size;
  for (size_t idx = 0; idx < batch_num; idx++) {
    uint64_t temp_rand = 0;
    size_t current_pos = idx * batch_size;
    size_t current_batch_size = std::min(num_bytes - current_pos, batch_size);

    // if failed, retry geneartion, we adopt strategy in section 5.3.1.1
    while (rdseed64_step(&temp_rand) == 0) {
      // [retry forever ... ] Maybe add loops / pauses in the future
    }

    std::memcpy(static_cast<char *>(out.data()) + current_pos, &temp_rand,
                current_batch_size);
  }

  return out;
}

REGISTER_ENTROPY_SOURCE_LIBRARY("Intel", 100, IntelEntropySource::Check,
                                IntelEntropySource::Create);

}  // namespace yacl::crypto

#endif

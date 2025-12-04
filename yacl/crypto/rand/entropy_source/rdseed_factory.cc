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

#include "yacl/crypto/rand/entropy_source/rdseed_factory.h"

#ifdef __x86_64

namespace yacl::crypto {

namespace {

// Example from Code Example 9,
// https://www.intel.com/content/www/us/en/developer/articles/guide/intel-digital-random-number-generator-drng-software-implementation-guide.html
//
int rdseed64_step(uint64_t *out) {
  unsigned char ok = 0;
  asm volatile("rdseed %0; setc %1" : "=r"(*out), "=qm"(ok));
  return static_cast<int>(ok);
}

// Or the built-in function (may not implemented by all c++ compilers):
// ----------------------------------------
// #include <immintrin.h>
// int _rdseed64_step(uint64_t*);
// ----------------------------------------

}  // namespace

Buffer RdSeedEntropySource::GetEntropy(uint32_t bits_of_entropy) {
  // required bits_of_entropy should > 0
  if (bits_of_entropy == 0) {
    return {};
  }

  if (std::strcmp(cpu_features::GetX86Info().vendor,
                  CPU_FEATURES_VENDOR_GENUINE_INTEL) == 0) {
    // from intel's report, section 7
    // https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/entropy/
    // E65_PublicUse.pdf
    //
    // The assessed entropy from the noise source is min(Hr, Hc, HI) = 0.6 bits
    // of entropy per bit of data. Therefore, to acquire n bits of entropy, the
    // output bitstring length (in bytes) would be (ceil(n/0.6) + 7 / 8)

    uint32_t num_bytes = ((bits_of_entropy * 5 + 2) / 3 + 7) / 8;
    std::vector<uint8_t> out(num_bytes);

    // Batched Random Entropy Generation
    size_t batch_size = sizeof(uint64_t);
    size_t batch_num = (num_bytes + batch_size - 1) / batch_size;
    for (size_t idx = 0; idx < batch_num; idx++) {
      uint64_t temp_rand = 0;
      size_t current_pos = idx * batch_size;
      size_t current_batch_size = std::min(num_bytes - current_pos, batch_size);

      // if failed, retry generation, we adopt strategy in section 5.3.1.1
      //
      // If the application is not latency-sensitive, then it can simply retry
      // the RDSEED instruction indefinitely, though it is recommended that a
      // PAUSE instruction be placed in the retry loop. In the worst-case
      // scenario, where multiple threads are invoking RDSEED continually, the
      // delays can be long, but the longer the delay, the more likely (with an
      // exponentially increasing probability) that the instruction will return
      // a result.
      while (rdseed64_step(&temp_rand) == 0) {
        // [retry forever ... ] Maybe add loops / pauses in the future
      }

      std::memcpy(out.data() + current_pos, &temp_rand, current_batch_size);
    }

    return {out.data(), out.size()};
  } else if (std::strcmp(cpu_features::GetX86Info().vendor,
                         CPU_FEATURES_VENDOR_AUTHENTIC_AMD) == 0) {
    // from amd's report, section 7
    // https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/entropy/
    // E27_PublicUse.pdf
    //
    // The assessed entropy from the noise source is approx. min(Hr, Hc, HI) =
    // 0.3 bits per 128-bit rdseed output.
    uint32_t num_bytes = ((bits_of_entropy * 10 + 2) / 3 + 7) / 8;
    std::vector<uint8_t> out(num_bytes);

    // Batched Random Entropy Generation
    size_t batch_size = sizeof(uint64_t);
    size_t batch_num = (num_bytes + batch_size - 1) / batch_size;
    for (size_t idx = 0; idx < batch_num; idx++) {
      uint64_t temp_rand = 0;
      size_t current_pos = idx * batch_size;
      size_t current_batch_size = std::min(num_bytes - current_pos, batch_size);

      // if failed, retry generation, we adopt strategy in section 5.3.1.1
      //
      // If the application is not latency-sensitive, then it can simply retry
      // the RDSEED instruction indefinitely, though it is recommended that a
      // PAUSE instruction be placed in the retry loop. In the worst-case
      // scenario, where multiple threads are invoking RDSEED continually, the
      // delays can be long, but the longer the delay, the more likely (with an
      // exponentially increasing probability) that the instruction will return
      // a result.
      while (rdseed64_step(&temp_rand) == 0) {
        // [retry forever ... ] Maybe add loops / pauses in the future
      }

      std::memcpy(out.data() + current_pos, &temp_rand, current_batch_size);
    }

    return {out.data(), out.size()};
  } else {
    SPDLOG_WARN(
        "Unconfigured CPU vendors, continue gracefully without generating "
        "entropy");
    return {};
  }
}

REGISTER_ENTROPY_SOURCE_LIBRARY("RdSeed", 100, RdSeedEntropySource::Check,
                                RdSeedEntropySource::Create);

}  // namespace yacl::crypto

#endif

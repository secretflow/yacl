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

#include "yasl/crypto/drbg/intel_entropy_source.h"

#include <algorithm>
#include <iostream>
#include <random>
#include <string>

#include "ippcp.h"

#ifdef __x86_64
#include "cpu_features/cpuinfo_x86.h"
#endif

#include "yasl/base/exception.h"

namespace yasl::crypto {

IntelEntropySource::IntelEntropySource() {
#ifdef __x86_64
  // check RDSEED support
  has_rdseed_ = cpu_features::GetX86Info().features.rdseed;
#else
  has_rdseed_ = false;
#endif
}

std::string IntelEntropySource::GetEntropy(size_t entropy_bytes) {
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

uint64_t IntelEntropySource::GetEntropy() {
  uint64_t temp_rand;

  if (has_rdseed_) {
    IppStatus status = ippsTRNGenRDSEED(reinterpret_cast<Ipp32u *>(&temp_rand),
                                        sizeof(temp_rand) * 8, NULL);
    YASL_ENFORCE(status == ippStsNoErr);

  } else {
    std::random_device rd("/dev/urandom");
    temp_rand = static_cast<uint64_t>(rd()) << 32 | rd();
  }
  return temp_rand;
}

}  // namespace yasl::crypto

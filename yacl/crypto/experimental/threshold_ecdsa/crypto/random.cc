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

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/random.h"

#include <openssl/rand.h>

#include <limits>
#include <stdexcept>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"

namespace tecdsa {

Bytes Csprng::RandomBytes(size_t size) {
  Bytes out(size);
  if (size == 0) {
    return out;
  }

  if (size > static_cast<size_t>(std::numeric_limits<int>::max())) {
    TECDSA_THROW("RAND_bytes size exceeds INT_MAX");
  }

  if (RAND_bytes(out.data(), static_cast<int>(size)) != 1) {
    TECDSA_THROW("RAND_bytes failed");
  }
  return out;
}

Scalar Csprng::RandomScalar() {
  while (true) {
    const Bytes bytes = RandomBytes(32);
    try {
      return Scalar::FromCanonicalBytes(bytes);
    } catch (const std::invalid_argument&) {
      continue;
    }
  }
}

}  // namespace tecdsa

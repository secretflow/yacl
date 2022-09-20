// Copyright 2022 Ant Group Co., Ltd.
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

#include "yasl/crypto/drbg/entropy_source_selector.h"

#include <memory>

#ifdef __x86_64
#include "yasl/crypto/drbg/intel_entropy_source.h"
#else
#include "yasl/crypto/drbg/std_entropy_source.h"
#endif

namespace yasl::crypto {

std::shared_ptr<IEntropySource> makeEntropySource() {
#ifdef __x86_64
  return std::make_shared<IntelEntropySource>();
#else
  return std::make_shared<StdEntropySource>();
#endif
}

}  // namespace yasl::crypto

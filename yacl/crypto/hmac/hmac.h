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

#pragma once

#include <vector>

#include "yacl/base/byte_container_view.h"
#include "yacl/crypto/openssl_wrappers.h"

/* submodules */
#include "yacl/crypto/hash/hash_interface.h"

namespace yacl::crypto {

// Hmac defines an base for hmac functions.
//
// Data may be added to an instance of Hmac via the Update() method at
// any point during the object's lifetime. A user may call the CumulativeMac()
// method to get a mac of all data added to the object since its creation or
// last call to its Init() method.
//
// This is not thread-safe.
class Hmac {
 public:
  // Hmac(const Hmac &) = delete;
  // Hmac &operator=(const Hmac &) = delete;

  Hmac(HashAlgorithm hash_algo, ByteContainerView key);
  // virtual ~Hmac();

  // Returns the hash algorithm implemented by this object.
  HashAlgorithm GetHashAlgorithm() const;

  // Reset this hmac object to a clean state. Calling this method clears
  // the effects of all previous Update() operations. Note that a newly
  // constructed hash object is always expected to be in a clean state and users
  // are not required to call Reset() on such objects.
  Hmac &Reset();

  // Updates this hash object by adding the contents of |data|.
  Hmac &Update(ByteContainerView data);

  // Computes the hmac of the data added so far and writes it to |digest|.
  // Returns a non-OK status on error.
  //
  // Note that the internal state of the object remains unchanged, and the
  // object can continue to accumulate additional data via Update() operations.
  std::vector<uint8_t> CumulativeMac() const;

 private:
  const HashAlgorithm hash_algo_;
  const std::vector<uint8_t> key_;
  openssl::UniqueMac mac_;
  openssl::UniqueMacCtx ctx_;
};

}  // namespace yacl::crypto

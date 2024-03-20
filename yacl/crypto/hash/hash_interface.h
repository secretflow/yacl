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

#include "openssl/evp.h" /* for evp type conversions */

#include "yacl/base/byte_container_view.h"
#include "yacl/secparam.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("hash_all", SecParam::C::k128, SecParam::S::INF);

namespace yacl::crypto {

enum class HashAlgorithm : int {
  UNKNOWN,
  // SHA-2 family of algorithms
  SHA224 = 1,
  SHA256 = 2,
  SHA384 = 3,
  SHA512 = 4,

  // SHA_1 = 5, // not recommended to use

  SM3 = 6,

  BLAKE2B = 7,
  BLAKE3 = 8
};

// HashInterface defines an interface for hash functions.
//
// Data may be added to an instance of HashInterface via the Update() method at
// any point during the object's lifetime. A user may call the CumulativeHash()
// method to get a hash of all data added to the object since its creation or
// last call to its Init() method.
//
// Implementations of this interface need not be thread-safe.
class HashInterface {
 public:
  HashInterface(const HashInterface &) = delete;
  HashInterface &operator=(const HashInterface &) = delete;
  HashInterface() = default;
  virtual ~HashInterface() = default;

  // Returns the hash algorithm implemented by this object.
  virtual HashAlgorithm GetHashAlgorithm() const = 0;

  // Returns the size of the message-digest of this hash algorithm. A return
  // value of zero indicates that the object does not implement a fixed-size
  // hash function.
  virtual size_t DigestSize() const = 0;

  // Reset this hash object to a clean state. Calling this method clears
  // the effects of all previous Update() operations. Note that a newly
  // constructed hash object is always expected to be in a clean state and users
  // are not required to call Reset() on such objects.
  virtual HashInterface &Reset() = 0;

  // Updates this hash object by adding the contents of |data|.
  virtual HashInterface &Update(ByteContainerView data) = 0;

  // Computes the hash of the data added so far and writes it to |digest|.
  // Returns a non-OK status on error.
  //
  // Note that the internal state of the object remains unchanged, and the
  // object can continue to accumulate additional data via Update() operations.
  virtual std::vector<uint8_t> CumulativeHash() const = 0;
};

/* to a string which openssl recognizes */
inline const char *ToString(HashAlgorithm hash_algo) {
  switch (hash_algo) {
    // see: https://www.openssl.org/docs/man3.0/man7/EVP_MD-SHA3.html
    // see: https://www.openssl.org/docs/man3.0/man7/EVP_MD-SHA2.html
    case HashAlgorithm::SHA224:
      return "sha2-224";
    case HashAlgorithm::SHA256:
      return "sha2-256";
    case HashAlgorithm::SHA384:
      return "sha2-384";
    case HashAlgorithm::SHA512:
      return "sha2-512";
    // case HashAlgorithm::SHA_1:
    //   return "sha1";
    case HashAlgorithm::SM3:
      return "sm3";
    case HashAlgorithm::BLAKE2B:
      return "blake2b-512";
    default:
      YACL_THROW("Unsupported hash algo: {}", static_cast<int>(hash_algo));
  }
}

}  // namespace yacl::crypto

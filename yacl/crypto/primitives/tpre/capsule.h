// Copyright 2023 Chengfang Financial Technology Co., Ltd.
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

#ifndef YACL_CRYPTO_PRIMITIVES_TPRE_CAPSULE_H_
#define YACL_CRYPTO_PRIMITIVES_TPRE_CAPSULE_H_
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "yacl/crypto/base/ecc/ec_point.h"
#include "yacl/crypto/base/mpint/mp_int.h"
#include "yacl/crypto/primitives/tpre/keys.h"

namespace yacl::crypto {

/**
 * This class encapsulates the Encapsule, Decapsule and CheckCapsule methods:
 * 1. Encapsule is used to generate the data key K and capsule, where K is
 *    encapsulated in the capsule.
 * 2. Decapsule is used to unpack the capsule to obtain K.
 * 3. CheckCapsule is used to verify the correctness of the capsule before
 *    it is encapsulated.
 */
class Capsule {
 public:
  Capsule() {}
  ~Capsule() {}

  /// @brief Capsule for encapsulating data keys, Capsule struct includes 2
  ///        elliptic curve point and a big number
  struct CapsuleStruct {
    EcPoint E;  // E = g^r, g is the generator of elliptic group
    EcPoint V;  // V = g^u, g is the generator of elliptic group
    MPInt s;    // s = u + r · H(E, V)
  };

  /// @brief CFrag is the fragment of Capsule after re-encapsulating
  struct CFrag {
    EcPoint E_1;  // E_1 = E^rk
    EcPoint V_1;  // V_1 = V^rk
    MPInt id;     // identity number of each proxy
    EcPoint X_A;  // X_A = g^x_A
  };

  /// @brief EnCapsulate algorithm, generate and capsulate the random data
  ///        encryption key
  /// @param ecc_group
  /// @param delegating_public_key
  /// @return capsule and data ecnryption key

  std::pair<CapsuleStruct, std::vector<uint8_t>> EnCapsulate(
      const std::unique_ptr<EcGroup>& ecc_group,
      const Keys::PublicKey& delegating_public_key) const;

  /// @brief DeCapsulate algorithm, to obtain the data encryption key
  /// @param private_key
  /// @param capsule_struct
  /// @return data encryption key
  std::vector<uint8_t> DeCapsulate(const std::unique_ptr<EcGroup>& ecc_group,
                                   const Keys::PrivateKey& private_key,
                                   const CapsuleStruct& capsule_struct) const;

  /// @brief Capsule check algorithm
  /// @param ecc_group
  /// @param capsule_struct
  /// @return 0 (check fail) or 1 (check success)
  std::pair<CapsuleStruct, int> CheckCapsule(
      const std::unique_ptr<EcGroup>& ecc_group,
      const CapsuleStruct& capsule_struct) const;

  /// @brief Re-encapsulate capsule
  /// @param ecc_group
  /// @param kfrag, re-encryption key fragment
  /// @param capsule
  /// @return Re-encapsulated capsule
  CFrag ReEncapsulate(const std::unique_ptr<EcGroup>& ecc_group,
                      const Keys::KFrag& kfrag,
                      const CapsuleStruct& capsule) const;

  /// @brief Restore the re-encapsulated capsule set to data encryption key
  /// @param ecc_group
  /// @param sk_B, secret key of Bob
  /// @param pk_A, public key of Alice
  /// @param pk_B, public key of Bob
  /// @param cfrags, re-encapsulated capsule set
  /// @return Data encryption key
  std::vector<uint8_t> DeCapsulateFrags(
      const std::unique_ptr<EcGroup>& ecc_group, const Keys::PrivateKey& sk_B,
      const Keys::PublicKey& pk_A, const Keys::PublicKey& pk_B,
      const std::vector<CFrag>& cfrags) const;
};
}  // namespace yacl::crypto
#endif  // YACL_CRYPTO_PRIMITIVES_TPRE_CAPSULE_H_

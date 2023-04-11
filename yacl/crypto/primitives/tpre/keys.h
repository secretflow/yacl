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

#ifndef YACL_CRYPTO_PRIMITIVES_TPRE_KEYS_H_
#define YACL_CRYPTO_PRIMITIVES_TPRE_KEYS_H_

#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "yacl/crypto/base/ecc/ec_point.h"
#include "yacl/crypto/base/mpint/mp_int.h"
#include "yacl/crypto/primitives/tpre/hash.h"

namespace yacl::crypto {
/**
 * This class encapsulates the definition of the keys and their generation
 * algorithm in the TPRE cryptosystem
 *
 * There are 3 types of keys included here:
 * 1. public key, used for encrypting plaintext
 * 2. secret key, used for decrypting ciphertext
 * 3. re-encryption key, used for re-encrypting ciphertext, Each proxy has a
 *    re-encryption key fragment.
 *
 * class Keys include 2 mesthods:
 * 1. GenerateKeyPair is the key pair generation algorithm, it outputs the key
 *    pair \langle public key, secret key \rangle for user.
 * 2. GenerateReKey is the re-encryption key fragments generation algorithm, it
 *    outputs the specific key fragment for each  proxy.
 */
class Keys {
 public:
  Keys() {}
  ~Keys() {}

  /// @brief public key struct
  struct PublicKey {
    EcPoint g;  // generator of group
    EcPoint y;  // y= g^x, where x is the secret key.
  };

  /// @brief secret key struct
  struct PrivateKey {
    MPInt x;  // a random value in the group
  };

  /// @brief re-encryption key fragment struct
  struct KFrag {
    MPInt id;     // the identity number assigned to each proxy
    MPInt rk;     // the key fragment of proxy
    EcPoint X_A;  // X_A = g^{x_A}
    EcPoint U;    // Another generator other than g
    EcPoint U_1;  // U_1 = U^rk
    MPInt z_1;    // z_1 = H(Y,id,pkA,pkB,U_1,X_A)
    MPInt z_2;    // z_2 = y-a*z_1；
  };

  /// @brief Generate the key pair
  /// @param ecc_group
  /// @return key pair, which includes public key and secret key
  std::pair<PublicKey, PrivateKey> GenerateKeyPair(
      const std::unique_ptr<EcGroup>& ecc_group) const;

  /// @brief Generates re-ecnryption key
  /// @param ecc_group
  /// @param sk_A, Secret key of the user who owns the authority
  /// @param pk_A, Public key for authorized user
  /// @param pk_B, Public key for authorized user
  /// @param N, Total number of proxys
  /// @param t, Capsule fragment threshold required for decryption
  /// @return re-encryption key fragment
  std::vector<KFrag> GenerateReKey(const std::unique_ptr<EcGroup>& ecc_group,
                                   const PrivateKey& sk_A,
                                   const PublicKey& pk_A, const PublicKey& pk_B,
                                   int N, int t) const;
};
}  // namespace yacl::crypto

#endif  // YACL_CRYPTO_PRIMITIVES_TPRE_KEYS_H_

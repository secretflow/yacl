#ifndef TPRE_CAPSULE_H_
#define TPRE_CAPSULE_H_
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "keys.h"

#include "yacl/crypto/base/ecc/ec_point.h"  //yacl ec_point
#include "yacl/crypto/base/mpint/mp_int.h"  //yacl big number

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
  Capsule(){};
  ~Capsule(){};

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
  std::pair<std::unique_ptr<CapsuleStruct>, std::vector<uint8_t>> EnCapsulate(
      std::unique_ptr<EcGroup> ecc_group,
      std::unique_ptr<Keys::PublicKey> delegating_public_key);

  /// @brief DeCapsulate algorithm, to obtain the data encryption key
  /// @param private_key
  /// @param capsule_struct
  /// @return data encryption key
  std::vector<uint8_t> DeCapsulate(
      std::unique_ptr<EcGroup> ecc_group,
      std::unique_ptr<Keys::PrivateKey> private_key,
      std::unique_ptr<CapsuleStruct> capsule_struct);

  /// @brief Capsule check algorithm
  /// @param ecc_group
  /// @param capsule_struct
  /// @return 0 (check fail) or 1 (check success)
  std::pair<std::unique_ptr<CapsuleStruct>, int> CheckCapsule(
      std::unique_ptr<EcGroup> ecc_group,
      std::unique_ptr<CapsuleStruct> capsule_struct);

  /// @brief Re-encapsulate capsule
  /// @param ecc_group
  /// @param kfrag, re-encryption key fragment
  /// @param capsule
  /// @return Re-encapsulated capsule
  std::unique_ptr<CFrag> ReEncapsulate(std::unique_ptr<EcGroup> ecc_group,
                                       std::unique_ptr<Keys::KFrag> kfrag,
                                       std::unique_ptr<CapsuleStruct> capsule);

  /// @brief Restore the re-encapsulated capsule set to data encryption key
  /// @param ecc_group
  /// @param sk_B, secret key of Bob
  /// @param pk_A, public key of Alice
  /// @param pk_B, public key of Bob
  /// @param cfrags, re-encapsulated capsule set
  /// @return Data encryption key
  std::vector<uint8_t> DeCapsulateFrags(
      std::unique_ptr<EcGroup> ecc_group,
      std::unique_ptr<Keys::PrivateKey> sk_B,
      std::unique_ptr<Keys::PublicKey> pk_A,
      std::unique_ptr<Keys::PublicKey> pk_B,
      std::vector<std::unique_ptr<CFrag>> cfrags);

 private:
  std::unique_ptr<CapsuleStruct> capsule_struct_;  // capsule struct
};
}  // namespace yacl::crypto
#endif  // TPRE_CAPSULE_H_

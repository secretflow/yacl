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

#include "yacl/crypto/primitives/tpre/capsule.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/base/hash/hash_utils.h"
#include "yacl/crypto/primitives/tpre/hash.h"
#include "yacl/crypto/primitives/tpre/kdf.h"
#include "yacl/utils/scope_guard.h"

namespace yacl::crypto {

// Encapsulate(pkA)->(K,capsule)
std::pair<Capsule::CapsuleStruct, std::vector<uint8_t>> Capsule::EnCapsulate(
    const std::unique_ptr<EcGroup>& ecc_group,
    const Keys::PublicKey& delegating_public_key) const {
  MPInt zero_bn(0);
  MPInt order = ecc_group->GetOrder();
  MPInt r;
  MPInt::RandomLtN(order, &r);
  MPInt u;
  MPInt::RandomLtN(order, &u);

  EcPoint E = ecc_group->MulBase(r);
  EcPoint V = ecc_group->MulBase(u);
  std::string E_string_join_V_sting =
      std::string(ecc_group->SerializePoint(E)) +
      std::string(ecc_group->SerializePoint(V));

  MPInt s = u.AddMod(
      r.MulMod(CipherHash(E_string_join_V_sting, ecc_group), order), order);

  EcPoint K_point = ecc_group->Mul(delegating_public_key.y, u.AddMod(r, order));

  std::string K_string = std::string(ecc_group->SerializePoint(K_point));

  Capsule::CapsuleStruct capsule_struct = {E, V, s};
  std::vector<uint8_t> K = KDF(K_string, 16);

  std::pair<Capsule::CapsuleStruct, std::vector<uint8_t>> capsule_pair;
  capsule_pair.first = capsule_struct;
  capsule_pair.second = K;

  return capsule_pair;
}

// Decapsulate(skA,capsule)->(K)
std::vector<uint8_t> Capsule::DeCapsulate(
    const std::unique_ptr<EcGroup>& ecc_group,
    const Keys::PrivateKey& private_key,
    const CapsuleStruct& capsule_struct) const {
  EcPoint K_point = ecc_group->Mul(
      ecc_group->Add(capsule_struct.E, capsule_struct.V), private_key.x);
  std::string K_string = std::string(ecc_group->SerializePoint(K_point));

  std::vector<uint8_t> K = KDF(K_string, 16);

  return K;
}

std::pair<Capsule::CapsuleStruct, int> Capsule::CheckCapsule(
    const std::unique_ptr<EcGroup>& ecc_group,
    const CapsuleStruct& capsule_struct) const {
  EcPoint tmp0 = ecc_group->MulBase(capsule_struct.s);

  // compute H_2(E,V)
  std::string E_string_join_V_sting =
      std::string(ecc_group->SerializePoint(capsule_struct.E)) +
      std::string(ecc_group->SerializePoint(capsule_struct.V));
  MPInt hev = CipherHash(E_string_join_V_sting, ecc_group);

  EcPoint e_exp_hev = ecc_group->Mul(capsule_struct.E, hev);
  EcPoint tmp1 = ecc_group->Add(capsule_struct.V, e_exp_hev);

  std::string tmp0_string = std::string(ecc_group->SerializePoint(tmp0));
  std::string tmp1_string = std::string(ecc_group->SerializePoint(tmp1));

  int signal;
  if (tmp0_string == tmp1_string) {
    signal = 1;
  } else {
    signal = 0;
  }

  std::pair<Capsule::CapsuleStruct, int> capsule_check_result = {capsule_struct,
                                                                 signal};

  return capsule_check_result;
}

// /**
//  * Each Re-encryptor generates the ciphertext fragment, i.e., cfrag
//  * */
Capsule::CFrag Capsule::ReEncapsulate(const std::unique_ptr<EcGroup>& ecc_group,
                                      const Keys::KFrag& kfrag,
                                      const CapsuleStruct& capsule) const {
  //  First checks the validity of the capsule with CheckCapsule and outputs ⊥
  //  if the check fails.

  auto capsule_check_result = CheckCapsule(ecc_group, capsule);

  YACL_ENFORCE(capsule_check_result.second == 1,
               "check_result: The capsule is damaged or has problems ");

  // Compute E_1 = E^rk
  EcPoint E_1 = ecc_group->Mul(capsule_check_result.first.E, kfrag.rk);

  // Compute V_1 = V^rk
  EcPoint V_1 = ecc_group->Mul(capsule_check_result.first.V, kfrag.rk);

  // Construct the re-encryption ciphertext fragment, i.e., cfrag
  CFrag cfrag = {E_1, V_1, kfrag.id, kfrag.X_A};

  return cfrag;
}

std::vector<uint8_t> Capsule::DeCapsulateFrags(
    const std::unique_ptr<EcGroup>& ecc_group, const Keys::PrivateKey& sk_B,
    const Keys::PublicKey& pk_A, const Keys::PublicKey& pk_B,
    const std::vector<CFrag>& cfrags) const {
  MPInt one_bn(1);

  // Compute (pk_B)^a
  EcPoint pk_A_mul_b = ecc_group->Mul(pk_A.y, sk_B.x);
  std::string pk_A_mul_b_str =
      std::string(ecc_group->SerializePoint(pk_A_mul_b));
  std::string pk_A_str = std::string(ecc_group->SerializePoint(pk_A.y));
  std::string pk_B_str = std::string(ecc_group->SerializePoint(pk_B.y));

  // 1. Compute D = H_6(pk_A, pk_B, (pk_A)^b)

  MPInt D = CipherHash(pk_A_str + pk_B_str + pk_A_mul_b_str, ecc_group);

  // 2. Compute s_{x,i} and lambda_{i,S}
  // 2.1 Compute s_{x,i} = H_5(id_i, D)
  std::vector<MPInt> S;  // S = {s_{x,0},...,s_{x,t-1}}
  std::string D_str = D.ToString();
  for (size_t i = 0; i < cfrags.size(); i++) {
    std::string id_i_str = (cfrags)[i].id.ToString();
    MPInt s_x_i = CipherHash(id_i_str + D_str, ecc_group);
    S.push_back(s_x_i);
  }

  // 2.2 Compute lambda_{i,S}

  std::vector<MPInt> lambdas;
  for (size_t i = 0; i < cfrags.size(); i++) {
    MPInt lambda_i(1);
    for (size_t j = 0; j < cfrags.size(); j++) {
      if (i != j) {
        MPInt S_j_0 = S[j];
        MPInt S_i = S[i];

        MPInt sxj_sub_sxi = S_j_0.SubMod(S_i, ecc_group->GetOrder());
        MPInt sxj_sub_sxi_inv = sxj_sub_sxi.InvertMod(ecc_group->GetOrder());

        MPInt S_j_1 = S[j];
        MPInt sxj_sub_sxi_inv_mul_sxj =
            sxj_sub_sxi_inv.MulMod(S_j_1, ecc_group->GetOrder());

        lambda_i =
            lambda_i.MulMod(sxj_sub_sxi_inv_mul_sxj, ecc_group->GetOrder());
      }
    }
    lambdas.push_back(lambda_i);
  }

  // 3. Compute E' and V'
  EcPoint E_prime = ecc_group->Mul(cfrags[0].E_1, lambdas[0]);
  EcPoint V_prime = ecc_group->Mul(cfrags[0].V_1, lambdas[0]);

  for (size_t i = 1; i < cfrags.size(); i++) {
    EcPoint E_prime_i = ecc_group->Mul(cfrags[i].E_1, lambdas[i]);
    E_prime = ecc_group->Add(E_prime, E_prime_i);
    EcPoint V_prime_i = ecc_group->Mul(cfrags[i].V_1, lambdas[i]);
    V_prime = ecc_group->Add(V_prime, V_prime_i);
  }

  // 4. Compute d = H_3(X_A,pk_B,(X_A)^b)
  std::string X_A_str = std::string(ecc_group->SerializePoint(cfrags[0].X_A));
  EcPoint X_A_mul_b = ecc_group->Mul(cfrags[0].X_A, sk_B.x);
  std::string X_A_mul_b_str = std::string(ecc_group->SerializePoint(X_A_mul_b));

  MPInt d = CipherHash(X_A_str + pk_B_str + X_A_mul_b_str, ecc_group);

  // 5. Compute DEK, i.e., K=KDF((E'· V')^d)

  EcPoint E_prime_add_V_prime = ecc_group->Add(E_prime, V_prime);
  EcPoint E_prime_add_V_prime_mul_d = ecc_group->Mul(E_prime_add_V_prime, d);

  std::string K_string =
      std::string(ecc_group->SerializePoint(E_prime_add_V_prime_mul_d));

  std::vector<uint8_t> K = KDF(K_string, 16);

  return K;
}
}  // namespace yacl::crypto

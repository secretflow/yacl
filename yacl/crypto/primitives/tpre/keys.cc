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

#include "yacl/crypto/primitives/tpre/keys.h"

#include <vector>

namespace yacl::crypto {

std::pair<Keys::PublicKey, Keys::PrivateKey> Keys::GenerateKeyPair(
    const std::unique_ptr<EcGroup>& ecc_group) const {
  EcPoint g = ecc_group->GetGenerator();

  // sample random from ecc group
  MPInt max = ecc_group->GetOrder();
  MPInt x;
  MPInt::RandomLtN(max, &x);

  // compute y = g^x
  EcPoint y = ecc_group->MulBase(x);
  // Assign private key
  Keys::PrivateKey private_key = {x};
  // Assign public key
  Keys::PublicKey public_key = {g, y};

  std::pair<Keys::PublicKey, Keys::PrivateKey> key_pair;
  key_pair.first = public_key;
  key_pair.second = private_key;
  return key_pair;
}

// // Generates re-ecnryption key
std::vector<Keys::KFrag> Keys::GenerateReKey(
    const std::unique_ptr<EcGroup>& ecc_group, const PrivateKey& sk_A,
    const PublicKey& pk_A, const PublicKey& pk_B, int N, int t) const {
  MPInt zero_bn(0);
  MPInt one_bn(1);
  MPInt ecc_group_order = ecc_group->GetOrder();

  // 1. Select x_A randomly and calculation X_ A=g^{x_A}
  MPInt max = ecc_group_order;
  MPInt x_A;
  MPInt::RandomLtN(ecc_group_order, &x_A);

  EcPoint X_A = ecc_group->MulBase(x_A);

  // 2. Compute d = H_3(X_A, pk_B, (pk_B)^{X_A}), where d is the result of a
  // non-interactive Diffie-Hellman key exchange between B's keypair and the
  // ephemeral key pair (x_A, X_A).

  std::string pk_B_str = std::string(ecc_group->SerializePoint(pk_B.y));
  std::string pk_B_mul_x_A_str =
      std::string(ecc_group->SerializePoint(ecc_group->Mul(pk_B.y, x_A)));
  std::string X_A_str = std::string(ecc_group->SerializePoint(X_A));

  MPInt d = CipherHash(X_A_str + pk_B_str + pk_B_mul_x_A_str, ecc_group);

  // 3. Generate random polynomial coefficients {f_1,...,f_{t-1}} and calculate
  // coefficients f_ 0
  MPInt d_inv = d.InvertMod(ecc_group_order);

  std::vector<MPInt> coefficients;  // coefficients include {f_0,...,f_{t-1}}

  MPInt coefficient_0 =
      sk_A.x.MulMod(d_inv, ecc_group_order);  // f_0 = a * d^{-1} mod q
  coefficients.push_back(coefficient_0);
  for (int i = 1; i <= t - 1; i++) {
    // Here, t-1 coefficients f_1,...,f_{t-1} are randomly generated.
    MPInt f_i;
    MPInt::RandomLtN(max, &f_i);
    coefficients.push_back(f_i);
  }

  // 4. Generate a polynomial via coefficient

  // 5. Compute D=H_6(pk_A, pk_B, pk^{a}_{B}), where a is the secret key of A
  std::string pk_A_str = std::string(ecc_group->SerializePoint(pk_A.y));
  std::string pk_B_mul_a_str =
      std::string(ecc_group->SerializePoint(ecc_group->Mul(pk_B.y, sk_A.x)));

  MPInt D = CipherHash(pk_A_str + pk_B_str + pk_B_mul_a_str, ecc_group);

  // 6. Compute KFrags

  std::vector<MPInt> y;
  std::vector<MPInt> id;
  std::vector<MPInt> s_x;
  std::vector<EcPoint> Y;
  std::vector<MPInt> rk;
  std::vector<EcPoint> U_1;
  std::vector<MPInt> z_1;
  std::vector<MPInt> z_2;
  std::vector<Keys::KFrag> kfrags;

  MPInt r_tmp_0;
  MPInt::RandomLtN(max, &r_tmp_0);
  EcPoint U = ecc_group->MulBase(r_tmp_0);
  // Cycle to generate each element of kfrags
  for (int i = 0; i <= N - 1; i++) {
    MPInt r_tmp_1;
    MPInt::RandomLtN(max, &r_tmp_1);
    y.push_back(r_tmp_1);

    MPInt r_tmp_2;
    MPInt::RandomLtN(max, &r_tmp_2);
    id.push_back(r_tmp_2);

    s_x.push_back(CipherHash(id[i].ToString() + D.ToString(), ecc_group));

    Y.push_back(ecc_group->MulBase(y[i]));

    // Compute polynomial to obtain rk[i]
    MPInt rk_tmp = coefficients[0];
    MPInt s_x_exp_j = zero_bn;
    MPInt coeff_mul_s_x_exp_j = zero_bn;

    for (int j = 1; j <= t - 1; j++) {
      s_x_exp_j = s_x[i];
      s_x_exp_j = s_x_exp_j.PowMod(MPInt(j), ecc_group_order);
      coeff_mul_s_x_exp_j = coefficients[j].MulMod(s_x_exp_j, ecc_group_order);
      rk_tmp = rk_tmp.AddMod(coeff_mul_s_x_exp_j, ecc_group_order);
    }

    rk.push_back(rk_tmp);

    EcPoint U_mul_rk = ecc_group->Mul(U, rk_tmp);
    U_1.push_back(U_mul_rk);

    z_1.push_back(CipherHash(
        std::string(ecc_group->SerializePoint(Y[i])) + id[i].ToString() +
            std::string(ecc_group->SerializePoint(pk_A.y)) +
            std::string(ecc_group->SerializePoint(pk_B.y)) +
            std::string(ecc_group->SerializePoint(U_1[i])) +
            std::string(ecc_group->SerializePoint(X_A)),
        ecc_group));

    MPInt y_tmp = y[i];
    MPInt x_mul_z_1 = sk_A.x.MulMod(z_1[i], ecc_group_order);
    z_2.push_back(y_tmp.SubMod(x_mul_z_1, ecc_group_order));

    Keys::KFrag kfrag = {id[i], rk[i], X_A, U, U_1[i], z_1[i], z_2[i]};

    kfrags.push_back(kfrag);
  }

  return kfrags;
}
}  // namespace yacl::crypto

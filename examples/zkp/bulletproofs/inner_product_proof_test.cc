// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "gtest/gtest.h"

// Core ECC and Proof classes
#include "zkp/bulletproofs/ipa_config.h"
#include "zkp/bulletproofs/inner_product_proof.h"

// YACL dependencies needed for testing
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/tools/ro.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/crypto/hash/hash_utils.h"
// #include "yacl/math/mpint/mp_int_enforce.h" // Likely unused directly
// #include "yacl/base/byte_container_view.h"  // Likely unused directly
// #include "yacl/base/exception.h"            // Likely unused directly
// #include "yacl/utils/scope_guard.h"         // Likely unused directly
// #include "yacl/crypto/rand/rand.h"          // MPInt::RandomLtN handles randomness

namespace examples::zkp {

using namespace yacl::crypto;
using namespace yacl::math;

namespace {

// 创建随机向量
std::vector<MPInt> CreateRandomVectors(const std::shared_ptr<EcGroup>& curve,
                                     size_t count) {
  std::vector<MPInt> vectors;
  vectors.reserve(count);
  auto order = curve->GetOrder();
  for (size_t i = 0; i < count; ++i) {
    MPInt value;
    MPInt::RandomLtN(order, &value);
    vectors.push_back(value);
  }
  return vectors;
}

// 创建随机点
std::vector<EcPoint> CreateRandomPoints(const std::shared_ptr<EcGroup>& curve,
                                      size_t count) {
  std::vector<EcPoint> points;
  points.reserve(count);
  for (size_t i = 0; i < count; ++i) {
    MPInt scalar;
    MPInt::RandomLtN(curve->GetOrder(), &scalar);
    points.push_back(curve->Mul(curve->GetGenerator(), scalar));
  }
  return points;
}

}  // namespace

class InnerProductProofTest : public ::testing::Test {
 protected:
  std::shared_ptr<EcGroup> curve_;

  void SetUp() override {
    // 使用与sigma相同的方式创建曲线
    curve_ = EcGroupFactory::Instance().Create(kIpaEcName, 
                                              yacl::ArgLib = kIpaEcLib);
  }

  void TestInnerProductProof(size_t size) {
    // 创建随机向量
    auto a = CreateRandomVectors(curve_, size);
    auto b = CreateRandomVectors(curve_, size);

    // 计算内积
    MPInt c;
    MPInt temp;
    MPInt::MulMod(a[0], b[0], curve_->GetOrder(), &temp);
    c = temp;
    for (size_t i = 1; i < size; ++i) {
      MPInt::MulMod(a[i], b[i], curve_->GetOrder(), &temp);
      MPInt::AddMod(c, temp, curve_->GetOrder(), &c);
    }

    // 创建随机点作为生成元
    auto g = CreateRandomPoints(curve_, size);
    auto h = CreateRandomPoints(curve_, size);

    // 创建随机点Q
    MPInt scalar;
    MPInt::RandomLtN(curve_->GetOrder(), &scalar);
    EcPoint Q = curve_->Mul(curve_->GetGenerator(), scalar);

    // 创建G_factors和H_factors
    std::vector<MPInt> G_factors;
    std::vector<MPInt> H_factors;
    for (size_t i = 0; i < size; ++i) {
      MPInt one;
      one.Set(1);
      G_factors.push_back(one);
      H_factors.push_back(one);
    }

    // 创建证明
    RandomOracle prover_transcript(HashAlgorithm::SHA256);
    auto proof = InnerProductProof::Create(
        &prover_transcript,
        Q,
        G_factors,
        H_factors,
        g,
        h,
        a,
        b);

    // 验证证明
    RandomOracle verifier_transcript(HashAlgorithm::SHA256);
    auto result = proof.Verify(
        size,
        &verifier_transcript,
        G_factors,
        H_factors,
        Q, // P和Q暂时使用同一个点
        Q,
        g,
        h);

    ASSERT_EQ(result, InnerProductProof::Error::kOk);
  }
};

TEST_F(InnerProductProofTest, TestSize2) {
  TestInnerProductProof(2);
}

TEST_F(InnerProductProofTest, TestSize4) {
  TestInnerProductProof(4);
}

TEST_F(InnerProductProofTest, TestSize8) {
  TestInnerProductProof(8);
}

TEST_F(InnerProductProofTest, TestSize32) {
  TestInnerProductProof(32);
}

TEST_F(InnerProductProofTest, TestSize64) {
  TestInnerProductProof(64);
}

// 测试固定的向量内积计算
TEST_F(InnerProductProofTest, InnerProductCalculation) {
  std::vector<MPInt> a = {MPInt(1), MPInt(2), MPInt(3), MPInt(4)};
  std::vector<MPInt> b = {MPInt(2), MPInt(3), MPInt(4), MPInt(5)};

  ASSERT_EQ(a.size(), b.size());
  size_t n = a.size();

  MPInt calculated_c;
  MPInt temp;
  MPInt::MulMod(a[0], b[0], curve_->GetOrder(), &temp);
  calculated_c = temp;
  for (size_t i = 1; i < n; ++i) {
    MPInt::MulMod(a[i], b[i], curve_->GetOrder(), &temp);
    MPInt::AddMod(calculated_c, temp, curve_->GetOrder(), &calculated_c);
  }

  MPInt expected_c;
  expected_c.Set(40); // 1*2 + 2*3 + 3*4 + 4*5 = 2 + 6 + 12 + 20 = 40
  // 确保结果在模范围内
  expected_c = expected_c.Mod(curve_->GetOrder());

  ASSERT_EQ(calculated_c, expected_c);
}

}  // namespace examples::zkp
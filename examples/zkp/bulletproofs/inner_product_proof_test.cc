#include "gtest/gtest.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/tools/ro.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/math/mpint/mp_int_enforce.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/utils/scope_guard.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "zkp/bulletproofs/ipa_config.h"
#include "zkp/bulletproofs/inner_product_proof.h"

namespace examples::zkp {

namespace {

// Helper function to create a test curve
std::shared_ptr<yacl::crypto::EcGroup> TestHelperCreate() {
  return yacl::crypto::EcGroupFactory::Instance().Create(
      kIpaEcName, yacl::ArgLib = kIpaEcLib);
}

// Helper function to create random points
std::vector<yacl::crypto::EcPoint> CreateRandomPoints(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    size_t count) {
  std::vector<yacl::crypto::EcPoint> points;
  points.reserve(count);
  for (size_t i = 0; i < count; ++i) {
    yacl::math::MPInt scalar;
    yacl::math::MPInt::RandomLtN(curve->GetOrder(), &scalar);
    points.push_back(curve->Mul(curve->GetGenerator(), scalar));
  }
  return points;
}

// Helper function to create random vectors
std::vector<yacl::math::MPInt> CreateRandomVectors(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    size_t count) {
  std::vector<yacl::math::MPInt> vectors;
  vectors.reserve(count);
  for (size_t i = 0; i < count; ++i) {
    yacl::math::MPInt value;
    yacl::math::MPInt::RandomLtN(curve->GetOrder(), &value);
    vectors.push_back(value);
  }
  return vectors;
}

} // namespace

// Test case for inner product proof with size 2
TEST(InnerProductProofTest, TestInnerProductProofSize2) {
  auto curve = TestHelperCreate();
  // 创建配置但不使用，后续可能会使用
  // auto config = GetInnerProduct(2);

  // Create random vectors
  auto a = CreateRandomVectors(curve, 2);
  auto b = CreateRandomVectors(curve, 2);

  // Compute inner product
  yacl::math::MPInt c;
  yacl::math::MPInt temp;
  yacl::math::MPInt::MulMod(a[0], b[0], curve->GetOrder(), &temp);
  c = temp;
  yacl::math::MPInt::MulMod(a[1], b[1], curve->GetOrder(), &temp);
  yacl::math::MPInt::AddMod(c, temp, curve->GetOrder(), &c);

  // Create random points for generators
  auto g = CreateRandomPoints(curve, 2);
  auto h = CreateRandomPoints(curve, 2);

  // Create random point Q
  yacl::math::MPInt scalar;
  yacl::math::MPInt::RandomLtN(curve->GetOrder(), &scalar);
  yacl::crypto::EcPoint Q = curve->Mul(curve->GetGenerator(), scalar);

  // Create G_factors and H_factors as vectors of 1
  std::vector<yacl::math::MPInt> G_factors;
  std::vector<yacl::math::MPInt> H_factors;
  for (size_t i = 0; i < 2; ++i) {
    yacl::math::MPInt one;
    one.Set(1);
    G_factors.push_back(one);
    H_factors.push_back(one);
  }

  // Create proof
  yacl::crypto::RandomOracle prover_transcript(yacl::crypto::HashAlgorithm::SHA256);
  auto proof = InnerProductProof::Create(
      &prover_transcript,
      Q,
      G_factors,
      H_factors,
      g,
      h,
      a,
      b);

  // Verify proof
  yacl::crypto::RandomOracle verifier_transcript(yacl::crypto::HashAlgorithm::SHA256);
  auto result = proof.Verify(
      2,
      &verifier_transcript,
      G_factors,
      H_factors,
      Q,  // P和Q暂时使用同一个点
      Q,
      g,
      h);

  ASSERT_EQ(result, InnerProductProof::Error::kOk);
}

// Test case for inner product proof with size 4
TEST(InnerProductProofTest, TestInnerProductProofSize4) {
  auto curve = TestHelperCreate();
  // 创建配置但不使用，后续可能会使用
  // auto config = GetInnerProduct(4);

  // Create random vectors
  auto a = CreateRandomVectors(curve, 4);
  auto b = CreateRandomVectors(curve, 4);

  // Compute inner product
  yacl::math::MPInt c;
  yacl::math::MPInt temp;
  yacl::math::MPInt::MulMod(a[0], b[0], curve->GetOrder(), &temp);
  c = temp;
  for (size_t i = 1; i < 4; ++i) {
    yacl::math::MPInt::MulMod(a[i], b[i], curve->GetOrder(), &temp);
    yacl::math::MPInt::AddMod(c, temp, curve->GetOrder(), &c);
  }

  // Create random points for generators
  auto g = CreateRandomPoints(curve, 4);
  auto h = CreateRandomPoints(curve, 4);

  // Create random point Q
  yacl::math::MPInt scalar;
  yacl::math::MPInt::RandomLtN(curve->GetOrder(), &scalar);
  yacl::crypto::EcPoint Q = curve->Mul(curve->GetGenerator(), scalar);

  // Create G_factors and H_factors as vectors of 1
  std::vector<yacl::math::MPInt> G_factors;
  std::vector<yacl::math::MPInt> H_factors;
  for (size_t i = 0; i < 4; ++i) {
    yacl::math::MPInt one;
    one.Set(1);
    G_factors.push_back(one);
    H_factors.push_back(one);
  }

  // Create proof
  yacl::crypto::RandomOracle prover_transcript(yacl::crypto::HashAlgorithm::SHA256);
  auto proof = InnerProductProof::Create(
      &prover_transcript,
      Q,
      G_factors,
      H_factors,
      g,
      h,
      a,
      b);

  // Verify proof
  yacl::crypto::RandomOracle verifier_transcript(yacl::crypto::HashAlgorithm::SHA256);
  auto result = proof.Verify(
      4,
      &verifier_transcript,
      G_factors,
      H_factors,
      Q,  // P和Q暂时使用同一个点
      Q,
      g,
      h);

  ASSERT_EQ(result, InnerProductProof::Error::kOk);
}

// Test case for inner product proof with size 8
TEST(InnerProductProofTest, TestInnerProductProofSize8) {
  auto curve = TestHelperCreate();
  // 创建配置但不使用，后续可能会使用
  // auto config = GetInnerProduct(8);

  // Create random vectors
  auto a = CreateRandomVectors(curve, 8);
  auto b = CreateRandomVectors(curve, 8);

  // Compute inner product
  yacl::math::MPInt c;
  yacl::math::MPInt temp;
  yacl::math::MPInt::MulMod(a[0], b[0], curve->GetOrder(), &temp);
  c = temp;
  for (size_t i = 1; i < 8; ++i) {
    yacl::math::MPInt::MulMod(a[i], b[i], curve->GetOrder(), &temp);
    yacl::math::MPInt::AddMod(c, temp, curve->GetOrder(), &c);
  }

  // Create random points for generators
  auto g = CreateRandomPoints(curve, 8);
  auto h = CreateRandomPoints(curve, 8);

  // Create random point Q
  yacl::math::MPInt scalar;
  yacl::math::MPInt::RandomLtN(curve->GetOrder(), &scalar);
  yacl::crypto::EcPoint Q = curve->Mul(curve->GetGenerator(), scalar);

  // Create G_factors and H_factors as vectors of 1
  std::vector<yacl::math::MPInt> G_factors;
  std::vector<yacl::math::MPInt> H_factors;
  for (size_t i = 0; i < 8; ++i) {
    yacl::math::MPInt one;
    one.Set(1);
    G_factors.push_back(one);
    H_factors.push_back(one);
  }

  // Create proof
  yacl::crypto::RandomOracle prover_transcript(yacl::crypto::HashAlgorithm::SHA256);
  auto proof = InnerProductProof::Create(
      &prover_transcript,
      Q,
      G_factors,
      H_factors,
      g,
      h,
      a,
      b);

  // Verify proof
  yacl::crypto::RandomOracle verifier_transcript(yacl::crypto::HashAlgorithm::SHA256);
  auto result = proof.Verify(
      8,
      &verifier_transcript,
      G_factors,
      H_factors,
      Q,  // P和Q暂时使用同一个点
      Q,
      g,
      h);

  ASSERT_EQ(result, InnerProductProof::Error::kOk);
}

}  // namespace examples::zkp
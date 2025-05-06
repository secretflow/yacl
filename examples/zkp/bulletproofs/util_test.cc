#include "zkp/bulletproofs/util.h"

#include <gtest/gtest.h>
#include <vector>
#include <memory>
#include <stdexcept> // Include for stdexcept
#include "bp_config.h"

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/ecc/ec_point.h" // For EcGroupFactory
#include "yacl/math/mpint/mp_int.h"
#include "yacl/base/exception.h" // Include for yacl::Exception

// Bring types and specific functions into scope for the test file
namespace examples::zkp {
namespace {


using yacl::math::MPInt;

class UtilTest : public ::testing::Test {
 protected:
  void SetUp() override {
    try {
      curve_ = yacl::crypto::EcGroupFactory::Instance().Create(
          kBpEcName, yacl::ArgLib = kBpEcLib);
      order_ = curve_->GetOrder();
      ec_available_ = true;
    } catch (const yacl::Exception& e) {
      ec_available_ = false;
      std::cerr << "Warning: EC operations not available, skipping tests: "
                << e.what() << std::endl;
    }
  }

  void CheckEcAvailable() {
      if (!ec_available_) {
          GTEST_SKIP() << "Skipping test because EC operations are not available";
      }
  }

  std::shared_ptr<yacl::crypto::EcGroup> curve_;
  yacl::math::MPInt order_;
  bool ec_available_ = false;
};

// Test InnerProduct
TEST_F(UtilTest, InnerProductTest) {
  CheckEcAvailable();

  std::vector<MPInt> a = {MPInt(1), MPInt(2), MPInt(3)};
  std::vector<MPInt> b = {MPInt(4), MPInt(5), MPInt(6)};
  MPInt expected = MPInt(32).Mod(order_);

  EXPECT_EQ(examples::zkp::InnerProduct(a, b, curve_), expected);

  std::vector<MPInt> empty;
  EXPECT_EQ(examples::zkp::InnerProduct(empty, empty, curve_), MPInt(0));

  std::vector<MPInt> c = {MPInt(1)};
  EXPECT_THROW(examples::zkp::InnerProduct(a, c, curve_), yacl::Exception);
}

// Test AddVec
TEST_F(UtilTest, AddVecTest) {
  CheckEcAvailable();
  std::vector<MPInt> a = {MPInt(1), MPInt(10), order_ - MPInt(1)};
  std::vector<MPInt> b = {MPInt(4), MPInt(5), MPInt(2)};
  std::vector<MPInt> expected = {
      MPInt(5).Mod(order_),
      MPInt(15).Mod(order_),
      MPInt(1).Mod(order_)
  };

  std::vector<MPInt> result = examples::zkp::AddVec(a, b, curve_);
  ASSERT_EQ(result.size(), expected.size());
  for (size_t i = 0; i < result.size(); ++i) {
      EXPECT_EQ(result[i], expected[i]) << "Mismatch at index " << i;
  }

  std::vector<MPInt> c = {MPInt(1)};
  EXPECT_THROW(examples::zkp::AddVec(a, c, curve_), yacl::Exception);
}

// Test ExpIterVector
TEST_F(UtilTest, ExpIterVectorTest) {
  CheckEcAvailable();
  MPInt base(3);
  size_t n = 4;
  std::vector<MPInt> expected = {
      MPInt(1).Mod(order_),
      MPInt(3).Mod(order_),
      MPInt(9).Mod(order_),
      MPInt(27).Mod(order_)
  };

  std::vector<MPInt> result = examples::zkp::ExpIterVector(base, n, curve_);
  ASSERT_EQ(result.size(), expected.size());
  for (size_t i = 0; i < result.size(); ++i) {
      EXPECT_EQ(result[i], expected[i]) << "Mismatch at index " << i;
  }

  EXPECT_TRUE(examples::zkp::ExpIterVector(base, 0, curve_).empty());
}

// Test ScalarExp
TEST_F(UtilTest, ScalarExpTest) {
  CheckEcAvailable();
  MPInt base(5);
  size_t exp = 3;
  MPInt expected = MPInt(125).Mod(order_);

  EXPECT_EQ(examples::zkp::ScalarExp(base, exp, curve_), expected);

  EXPECT_EQ(examples::zkp::ScalarExp(base, 0, curve_), MPInt(1));
}

// Test SumOfPowers
TEST_F(UtilTest, SumOfPowersTest) {
  CheckEcAvailable();
  MPInt base(2);
  size_t n = 4;
  MPInt expected = MPInt(15).Mod(order_);

  EXPECT_EQ(examples::zkp::SumOfPowers(base, n, curve_), expected);

  MPInt base_one(1);
  n = 5;
  MPInt expected_one = MPInt(5).Mod(order_);
  EXPECT_EQ(examples::zkp::SumOfPowers(base_one, n, curve_), expected_one);

  EXPECT_EQ(examples::zkp::SumOfPowers(base, 0, curve_), MPInt(0));
}

// Test Poly2::Eval
TEST_F(UtilTest, Poly2EvalTest) {
  CheckEcAvailable();
  MPInt t0(5), t1(3), t2(2);

  examples::zkp::Poly2 poly(t0, t1, t2);
  MPInt x(4);
  MPInt expected = MPInt(49).Mod(order_);
  EXPECT_EQ(poly.Eval(x, curve_), expected);
}

// Test VecPoly1::Eval
TEST_F(UtilTest, VecPoly1EvalTest) {
  CheckEcAvailable();
  std::vector<MPInt> v0 = {MPInt(1), MPInt(2)};
  std::vector<MPInt> v1 = {MPInt(3), MPInt(4)};

  examples::zkp::VecPoly1 vec_poly(std::move(v0), std::move(v1));
  MPInt x(5);
  std::vector<MPInt> expected = {MPInt(16).Mod(order_), MPInt(22).Mod(order_)};
  std::vector<MPInt> result = vec_poly.Eval(x, curve_);
  ASSERT_EQ(result.size(), expected.size());
  EXPECT_EQ(result[0], expected[0]);
  EXPECT_EQ(result[1], expected[1]);
}

// Test VecPoly1::InnerProduct
TEST_F(UtilTest, VecPoly1InnerProductTest) {
  CheckEcAvailable();

  examples::zkp::VecPoly1 L({MPInt(1), MPInt(3)}, {MPInt(2), MPInt(4)});
  examples::zkp::VecPoly1 R({MPInt(5), MPInt(7)}, {MPInt(6), MPInt(8)});

  MPInt expected_t0 = MPInt(26).Mod(order_);
  MPInt expected_t2 = MPInt(44).Mod(order_);
  MPInt inner_sum = MPInt(138).Mod(order_);
  MPInt expected_t1 = inner_sum.SubMod(expected_t0, order_);
  expected_t1 = expected_t1.SubMod(expected_t2, order_);


  examples::zkp::Poly2 result_poly = L.InnerProduct(R, curve_);

  EXPECT_EQ(result_poly.t0, expected_t0);
  EXPECT_EQ(result_poly.t1, expected_t1);
  EXPECT_EQ(result_poly.t2, expected_t2);
}

} // namespace
} // namespace examples::zkp

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
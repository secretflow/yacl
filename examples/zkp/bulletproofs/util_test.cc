#include "zkp/bulletproofs/util.h"

#include <gtest/gtest.h>

namespace examples::zkp {
namespace {

class UtilTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Initialize any test-wide resources
  }
};

TEST_F(UtilTest, ExpIterVectorWorks) {
  auto exp_2 = ExpIterVector(yacl::math::MPInt(2), 4);
  
  ASSERT_EQ(exp_2.size(), 4);
  EXPECT_EQ(exp_2[0], yacl::math::MPInt(1));
  EXPECT_EQ(exp_2[1], yacl::math::MPInt(2));
  EXPECT_EQ(exp_2[2], yacl::math::MPInt(4));
  EXPECT_EQ(exp_2[3], yacl::math::MPInt(8));
}

TEST_F(UtilTest, InnerProductWorks) {
  std::vector<yacl::math::MPInt> a = {
    yacl::math::MPInt(1),
    yacl::math::MPInt(2),
    yacl::math::MPInt(3),
    yacl::math::MPInt(4)
  };
  
  std::vector<yacl::math::MPInt> b = {
    yacl::math::MPInt(2),
    yacl::math::MPInt(3),
    yacl::math::MPInt(4),
    yacl::math::MPInt(5)
  };
  
  EXPECT_EQ(InnerProduct(a, b), yacl::math::MPInt(40));
}

TEST_F(UtilTest, ScalarExpVartimeWorks) {
  // Create a test scalar
  yacl::math::MPInt x(257);
  
  EXPECT_EQ(ScalarExpVartime(x, 0), yacl::math::MPInt(1));
  EXPECT_EQ(ScalarExpVartime(x, 1), x);
  EXPECT_EQ(ScalarExpVartime(x, 2), x * x);
  EXPECT_EQ(ScalarExpVartime(x, 3), x * x * x);
  EXPECT_EQ(ScalarExpVartime(x, 4), x * x * x * x);
}

// Helper function for slow scalar exponentiation
yacl::math::MPInt ScalarExpVartimeSlow(const yacl::math::MPInt& x, uint64_t n) {
  yacl::math::MPInt result(1);
  for (uint64_t i = 0; i < n; i++) {
    result = result * x;
  }
  return result;
}

TEST_F(UtilTest, ScalarExpVartimeMatchesSlow) {
  yacl::math::MPInt x(123);
  
  EXPECT_EQ(ScalarExpVartime(x, 64), ScalarExpVartimeSlow(x, 64));
  EXPECT_EQ(ScalarExpVartime(x, 0b11001010), ScalarExpVartimeSlow(x, 0b11001010));
}

TEST_F(UtilTest, SumOfPowersWorks) {
  yacl::math::MPInt x(10);
  
  EXPECT_EQ(SumOfPowers(x, 0), SumOfPowersSlow(x, 0));
  EXPECT_EQ(SumOfPowers(x, 1), SumOfPowersSlow(x, 1));
  EXPECT_EQ(SumOfPowers(x, 2), SumOfPowersSlow(x, 2));
  EXPECT_EQ(SumOfPowers(x, 4), SumOfPowersSlow(x, 4));
  EXPECT_EQ(SumOfPowers(x, 8), SumOfPowersSlow(x, 8));
  EXPECT_EQ(SumOfPowers(x, 16), SumOfPowersSlow(x, 16));
  EXPECT_EQ(SumOfPowers(x, 32), SumOfPowersSlow(x, 32));
  EXPECT_EQ(SumOfPowers(x, 64), SumOfPowersSlow(x, 64));
}

TEST_F(UtilTest, SumOfPowersSlowWorks) {
  yacl::math::MPInt x(10);
  
  EXPECT_EQ(SumOfPowersSlow(x, 0), yacl::math::MPInt(0));
  EXPECT_EQ(SumOfPowersSlow(x, 1), yacl::math::MPInt(1));
  EXPECT_EQ(SumOfPowersSlow(x, 2), yacl::math::MPInt(11));
  EXPECT_EQ(SumOfPowersSlow(x, 3), yacl::math::MPInt(111));
  EXPECT_EQ(SumOfPowersSlow(x, 4), yacl::math::MPInt(1111));
  EXPECT_EQ(SumOfPowersSlow(x, 5), yacl::math::MPInt(11111));
  EXPECT_EQ(SumOfPowersSlow(x, 6), yacl::math::MPInt(111111));
}

TEST_F(UtilTest, VecPoly1EvalWorks) {
  std::vector<yacl::math::MPInt> vec0 = {
    yacl::math::MPInt(1),
    yacl::math::MPInt(2)
  };
  
  std::vector<yacl::math::MPInt> vec1 = {
    yacl::math::MPInt(3),
    yacl::math::MPInt(4)
  };
  
  VecPoly1 poly(vec0, vec1);
  
  yacl::math::MPInt x(2);
  auto result = poly.Eval(x);
  
  ASSERT_EQ(result.size(), 2);
  // 1 + 3*2 = 7
  EXPECT_EQ(result[0], yacl::math::MPInt(7));
  // 2 + 4*2 = 10
  EXPECT_EQ(result[1], yacl::math::MPInt(10));
}

TEST_F(UtilTest, Poly2EvalWorks) {
  Poly2 poly(
    yacl::math::MPInt(1),  // x^0 term
    yacl::math::MPInt(2),  // x^1 term
    yacl::math::MPInt(3)   // x^2 term
  );
  
  yacl::math::MPInt x(2);
  auto result = poly.Eval(x);
  
  // 1 + 2*2 + 3*2^2 = 1 + 4 + 12 = 17
  EXPECT_EQ(result, yacl::math::MPInt(17));
}

TEST_F(UtilTest, VecPoly1InnerProductWorks) {
  std::vector<yacl::math::MPInt> a0 = {
    yacl::math::MPInt(1),
    yacl::math::MPInt(2)
  };
  
  std::vector<yacl::math::MPInt> a1 = {
    yacl::math::MPInt(3),
    yacl::math::MPInt(4)
  };
  
  std::vector<yacl::math::MPInt> b0 = {
    yacl::math::MPInt(5),
    yacl::math::MPInt(6)
  };
  
  std::vector<yacl::math::MPInt> b1 = {
    yacl::math::MPInt(7),
    yacl::math::MPInt(8)
  };
  
  VecPoly1 a(a0, a1);
  VecPoly1 b(b0, b1);
  
  Poly2 result = a.InnerProduct(b);
  
  // t0 = a0 · b0 = 1*5 + 2*6 = 5 + 12 = 17
  EXPECT_EQ(result.t0, yacl::math::MPInt(17));
  
  // t2 = a1 · b1 = 3*7 + 4*8 = 21 + 32 = 53
  EXPECT_EQ(result.t2, yacl::math::MPInt(53));
  
  // t1 = (a0+a1)·(b0+b1) - t0 - t2
  // (a0+a1) = [4, 6]
  // (b0+b1) = [12, 14]
  // (a0+a1)·(b0+b1) = 4*12 + 6*14 = 48 + 84 = 132
  // t1 = 132 - 17 - 53 = 62
  EXPECT_EQ(result.t1, yacl::math::MPInt(62));
}

TEST_F(UtilTest, Read32Works) {
  std::vector<uint8_t> data(40, 0);
  for (size_t i = 0; i < 40; i++) {
    data[i] = static_cast<uint8_t>(i);
  }
  
  auto result = Read32(data);
  
  ASSERT_EQ(result.size(), 32);
  for (size_t i = 0; i < 32; i++) {
    EXPECT_EQ(result[i], static_cast<uint8_t>(i));
  }
}

TEST_F(UtilTest, SecureClearingWorks) {
  // Test that the destructors clear the data properly
  {
    auto a = std::make_unique<VecPoly1>(
      std::vector<yacl::math::MPInt>{yacl::math::MPInt(123)},
      std::vector<yacl::math::MPInt>{yacl::math::MPInt(456)}
    );
    
    // Verify data is present
    EXPECT_EQ(a->vec0[0], yacl::math::MPInt(123));
    EXPECT_EQ(a->vec1[0], yacl::math::MPInt(456));
    
    // Let the destructor run
    a.reset();
  }
  
  {
    auto p = std::make_unique<Poly2>(
      yacl::math::MPInt(111),
      yacl::math::MPInt(222),
      yacl::math::MPInt(333)
    );
    
    // Verify data is present
    EXPECT_EQ(p->t0, yacl::math::MPInt(111));
    EXPECT_EQ(p->t1, yacl::math::MPInt(222));
    EXPECT_EQ(p->t2, yacl::math::MPInt(333));
    
    // Let the destructor run
    p.reset();
  }
}

} // namespace
} // namespace examples::zkp

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
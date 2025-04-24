#include "zkp/bulletproofs/util.h"

#include "gtest/gtest.h"
#include "yacl/crypto/ecc/openssl/openssl_group.h"
#include "yacl/crypto/ecc/curve_meta.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/base/exception.h"

namespace examples::zkp {

class UtilTest : public ::testing::Test {
 protected:
  void SetUp() override {
    curve_ = yacl::crypto::openssl::OpensslGroup::Create(
        yacl::crypto::GetCurveMetaByName("secp256k1"));
    ASSERT_NE(curve_, nullptr);
    order_ = curve_->GetOrder();
    // Initialize some basic MPInts for tests
    mp_0_.Set(0);
    mp_1_.Set(1);
    mp_2_.Set(2);
    mp_3_.Set(3);
    mp_4_.Set(4);
    mp_5_.Set(5);
    mp_10_.Set(10);
  }

  std::shared_ptr<EcGroup> curve_;
  MPInt order_;
  MPInt mp_0_, mp_1_, mp_2_, mp_3_, mp_4_, mp_5_, mp_10_;
};

TEST_F(UtilTest, InnerProduct) {
  std::vector<MPInt> a = {mp_1_, mp_2_, mp_3_, mp_4_};
  std::vector<MPInt> b = {mp_2_, mp_3_, mp_4_, mp_5_};
  MPInt expected;
  expected.Set(40);
  // InnerProduct uses modular arithmetic
  // 1*2 + 2*3 + 3*4 + 4*5 = 2 + 6 + 12 + 20 = 40
  EXPECT_EQ(InnerProduct(a, b, order_), expected % order_);

  std::vector<MPInt> c = {mp_1_, mp_2_};
  std::vector<MPInt> d = {mp_1_};
  EXPECT_THROW(InnerProduct(c, d, order_), yacl::Exception);
}

TEST_F(UtilTest, AddVectors) {
   std::vector<MPInt> a = {mp_1_, mp_2_, mp_3_};
   std::vector<MPInt> b = {mp_5_, mp_4_, mp_3_};
   std::vector<MPInt> expected = {MPInt(6), MPInt(6), MPInt(6)};
   auto result = AddVectors(a, b, order_);
   ASSERT_EQ(result.size(), expected.size());
   for(size_t i=0; i<result.size(); ++i) {
       EXPECT_EQ(result[i], expected[i]);
   }
}

TEST_F(UtilTest, Powers) {
    auto powers_of_2 = Powers(mp_2_, 4, order_);
    ASSERT_EQ(powers_of_2.size(), 4);
    EXPECT_EQ(powers_of_2[0], mp_1_); // 2^0
    EXPECT_EQ(powers_of_2[1], mp_2_); // 2^1
    EXPECT_EQ(powers_of_2[2], mp_4_); // 2^2
    EXPECT_EQ(powers_of_2[3], MPInt(8)); // 2^3
}

TEST_F(UtilTest, ScalarExpVartime) {
    EXPECT_EQ(ScalarExpVartime(mp_3_, 0), mp_1_); // 3^0 = 1
    EXPECT_EQ(ScalarExpVartime(mp_3_, 1), mp_3_); // 3^1 = 3
    EXPECT_EQ(ScalarExpVartime(mp_3_, 2), MPInt(9)); // 3^2 = 9
    EXPECT_EQ(ScalarExpVartime(mp_3_, 3), MPInt(27)); // 3^3 = 27
    EXPECT_EQ(ScalarExpVartime(mp_2_, 10), MPInt(1024)); // 2^10 = 1024
}

TEST_F(UtilTest, SumOfPowers) {
    EXPECT_EQ(SumOfPowers(mp_10_, 0, order_), mp_0_);  // 0 terms
    EXPECT_EQ(SumOfPowers(mp_10_, 1, order_), mp_1_);  // 10^0 = 1
    EXPECT_EQ(SumOfPowers(mp_10_, 2, order_), MPInt(11)); // 1 + 10
    EXPECT_EQ(SumOfPowers(mp_10_, 3, order_), MPInt(111)); // 1 + 10 + 100
    EXPECT_EQ(SumOfPowers(mp_10_, 4, order_), MPInt(1111)); // 1 + 10 + 100 + 1000

    // Test optimized path (n=4 is power of 2) indirectly by calling SumOfPowers
    MPInt result_4 = SumOfPowers(mp_10_, 4, order_);
    EXPECT_EQ(result_4, MPInt(1111));

    // Test optimized path (n=8 is power of 2) indirectly by calling SumOfPowers
     MPInt result_8 = SumOfPowers(mp_2_, 8, order_); // 1+2+4+8+16+32+64+128 = 255
     EXPECT_EQ(result_8, MPInt(255));
}

TEST_F(UtilTest, VecPoly1Eval) {
    VecPoly1 poly( {mp_1_, mp_2_}, {mp_3_, mp_4_} ); // (1+3x, 2+4x)
    auto result = poly.Eval(mp_2_); // x=2
    ASSERT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], MPInt(7)); // 1 + 3*2 = 7
    EXPECT_EQ(result[1], MPInt(10)); // 2 + 4*2 = 10
}

TEST_F(UtilTest, Poly2Eval) {
    Poly2 poly(mp_1_, mp_2_, mp_3_); // 1 + 2x + 3x^2
    MPInt result = poly.Eval(mp_2_, order_); // x=2
    // 1 + 2*2 + 3*4 = 1 + 4 + 12 = 17
    EXPECT_EQ(result, MPInt(17));
}

TEST_F(UtilTest, VecPoly1InnerProduct) {
    VecPoly1 p1( {mp_1_, mp_2_}, {mp_3_, mp_1_} ); // a=(1,2), b=(3,1)
    VecPoly1 p2( {mp_2_, mp_1_}, {mp_1_, mp_4_} ); // c=(2,1), d=(1,4)
    // Inner Product = <a,c> + (<a,d> + <b,c>)x + <b,d>x^2
    // t0 = <a,c> = 1*2 + 2*1 = 4
    // t2 = <b,d> = 3*1 + 1*4 = 7
    // <a,d> = 1*1 + 2*4 = 9
    // <b,c> = 3*2 + 1*1 = 7
    // t1 = <a,d> + <b,c> = 9 + 7 = 16
    Poly2 result = p1.InnerProduct(p2, order_);
    EXPECT_EQ(result.a, mp_4_);
    EXPECT_EQ(result.b, MPInt(16));
    EXPECT_EQ(result.c, MPInt(7));
}

// Add tests for VecPoly3 and Poly6 if YACL_ENABLE_YOLOPROOFS is defined
#ifdef YACL_ENABLE_YOLOPROOFS
TEST_F(UtilTest, VecPoly3Eval) {
   VecPoly3 poly = VecPoly3::Zero(1);
   poly.a[0].Set(1);
   poly.b[0].Set(2);
   poly.c[0].Set(3);
   poly.d[0].Set(4);
   // 1 + 2x + 3x^2 + 4x^3
   auto result = poly.Eval(mp_2_, order_); // x=2
   // 1 + 2*2 + 3*4 + 4*8 = 1 + 4 + 12 + 32 = 49
   ASSERT_EQ(result.size(), 1);
   EXPECT_EQ(result[0], MPInt(49));
}

TEST_F(UtilTest, Poly6Eval) {
    // 1x + 2x^2 + 3x^3 + 4x^4 + 5x^5 + 6x^6
    Poly6 poly(mp_1_, mp_2_, mp_3_, mp_4_, MPInt(5), MPInt(6));
    auto result = poly.Eval(mp_2_, order_); // x=2
    // 2 + 2*4 + 3*8 + 4*16 + 5*32 + 6*64
    // 2 + 8 + 24 + 64 + 160 + 384 = 642
    EXPECT_EQ(result, MPInt(642));
}

// Add SpecialInnerProduct test if needed

#endif // YACL_ENABLE_YOLOPROOFS

} // namespace examples::zkp 
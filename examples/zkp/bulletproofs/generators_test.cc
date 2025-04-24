#include "zkp/bulletproofs/generators.h"

#include "gtest/gtest.h"
#include "yacl/crypto/ecc/openssl/openssl_group.h"
#include "yacl/crypto/ecc/curve_meta.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/base/exception.h"

namespace examples::zkp {
  
namespace {

class GeneratorsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    curve_ = yacl::crypto::openssl::OpensslGroup::Create(
        yacl::crypto::GetCurveMetaByName("secp256k1"));
    ASSERT_NE(curve_, nullptr);
  }

  std::shared_ptr<yacl::crypto::EcGroup> curve_;
};

TEST_F(GeneratorsTest, PedersenConstruction) {
  ASSERT_NO_THROW(PedersenGens ped_gens(curve_));
  PedersenGens ped_gens(curve_);

  EXPECT_TRUE(curve_->PointEqual(ped_gens.GetB(), curve_->GetGenerator()));
  EXPECT_FALSE(curve_->IsInfinity(ped_gens.GetBBlinding()));
  EXPECT_FALSE(curve_->PointEqual(ped_gens.GetB(), ped_gens.GetBBlinding()));
}

TEST_F(GeneratorsTest, PedersenCommit) {
  PedersenGens ped_gens(curve_);

  yacl::math::MPInt value(123);
  yacl::math::MPInt blinding(456);

  auto expected_commit = curve_->Add(curve_->MulBase(value),
                                    curve_->Mul(ped_gens.GetBBlinding(), blinding));

  auto actual_commit = ped_gens.Commit(value, blinding);

  EXPECT_TRUE(curve_->PointEqual(actual_commit, expected_commit));

  auto commit_zero_val = ped_gens.Commit(yacl::math::MPInt(0), blinding);
  auto expected_zero_val = curve_->Mul(ped_gens.GetBBlinding(), blinding);
  EXPECT_TRUE(curve_->PointEqual(commit_zero_val, expected_zero_val));

  auto commit_zero_blind = ped_gens.Commit(value, yacl::math::MPInt(0));
  auto expected_zero_blind = curve_->MulBase(value);
  EXPECT_TRUE(curve_->PointEqual(commit_zero_blind, expected_zero_blind));
}

TEST_F(GeneratorsTest, BulletproofGensBasic) {
  constexpr size_t gens_capacity = 64;
  constexpr size_t party_capacity = 4;

  ASSERT_NO_THROW(BulletproofGens bp_gens(curve_, gens_capacity, party_capacity));
  BulletproofGens bp_gens(curve_, gens_capacity, party_capacity);

  EXPECT_EQ(bp_gens.GensCapacity(), gens_capacity);
  EXPECT_EQ(bp_gens.PartyCapacity(), party_capacity);

  for (size_t i = 0; i < party_capacity; ++i) {
      EXPECT_EQ(bp_gens.GetGVec(i).size(), gens_capacity);
      EXPECT_EQ(bp_gens.GetHVec(i).size(), gens_capacity);
      if (gens_capacity > 0) {
          EXPECT_FALSE(curve_->IsInfinity(bp_gens.GetGVec(i)[0]));
          EXPECT_FALSE(curve_->IsInfinity(bp_gens.GetHVec(i)[0]));
      }
      if (gens_capacity > 1) {
          EXPECT_FALSE(curve_->IsInfinity(bp_gens.GetGVec(i)[gens_capacity-1]));
          EXPECT_FALSE(curve_->IsInfinity(bp_gens.GetHVec(i)[gens_capacity-1]));
      }
  }
}

TEST_F(GeneratorsTest, BulletproofGensConsistency) {
  constexpr size_t capacity1 = 32;
  constexpr size_t capacity2 = 64;
  constexpr size_t party_capacity = 2;

  BulletproofGens bp_gens1(curve_, capacity1, party_capacity);
  BulletproofGens bp_gens2(curve_, capacity2, party_capacity);

  for (size_t i = 0; i < party_capacity; ++i) {
      for (size_t j = 0; j < capacity1; ++j) {
          EXPECT_TRUE(curve_->PointEqual(bp_gens1.GetGVec(i)[j], bp_gens2.GetGVec(i)[j]))
            << "G mismatch at party " << i << ", index " << j;
          EXPECT_TRUE(curve_->PointEqual(bp_gens1.GetHVec(i)[j], bp_gens2.GetHVec(i)[j]))
            << "H mismatch at party " << i << ", index " << j;
      }
  }
}

} // namespace anonymous
} // namespace examples::zkp 
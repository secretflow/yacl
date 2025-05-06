#include "zkp/bulletproofs/generators.h"
#include <gtest/gtest.h>

#include "yacl/crypto/ecc/openssl/openssl_group.h"
#include "yacl/crypto/ecc/curve_meta.h"
#include "bp_config.h"

namespace examples::zkp {
namespace {

class GeneratorsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    curve_ = yacl::crypto::EcGroupFactory::Instance().Create(
       kBpEcName,
        yacl::ArgLib = kBpEcLib);
  }

  std::shared_ptr<yacl::crypto::EcGroup> curve_;
};

TEST_F(GeneratorsTest, PedersenCommitmentWorks) {
  PedersenGens pc_gens(curve_);
  
  // Create a commitment to value 10 with blinding factor 20
  yacl::math::MPInt value(10);
  yacl::math::MPInt blinding(20);
  
  yacl::crypto::EcPoint commitment = pc_gens.Commit(value, blinding);
  
  // Verify that it's different from the base points
  EXPECT_FALSE(curve_->PointEqual(commitment, pc_gens.B));
  EXPECT_FALSE(curve_->PointEqual(commitment, pc_gens.B_blinding));
  
  // Verify that different values produce different commitments
  yacl::math::MPInt value2(11);
  yacl::crypto::EcPoint commitment2 = pc_gens.Commit(value2, blinding);
  EXPECT_FALSE(curve_->PointEqual(commitment, commitment2));
  
  // Verify that different blinding factors produce different commitments
  yacl::math::MPInt blinding2(21);
  yacl::crypto::EcPoint commitment3 = pc_gens.Commit(value, blinding2);
  EXPECT_FALSE(curve_->PointEqual(commitment, commitment3));
}

TEST_F(GeneratorsTest, GeneratorsChainProducesDifferentPoints) {
  GeneratorsChain chain(curve_, "test-label");
  
  // Get a few points and verify they're different
  yacl::crypto::EcPoint p1 = chain.Next();
  yacl::crypto::EcPoint p2 = chain.Next();
  yacl::crypto::EcPoint p3 = chain.Next();
  
  EXPECT_FALSE(curve_->PointEqual(p1, p2));
  EXPECT_FALSE(curve_->PointEqual(p1, p3));
  EXPECT_FALSE(curve_->PointEqual(p2, p3));
}

TEST_F(GeneratorsTest, BulletproofGensCapacityIncrease) {
  // Create generators with initial capacity
  BulletproofGens bp_gens(curve_, 32, 8);
  EXPECT_EQ(bp_gens.gens_capacity(), 32);
  EXPECT_EQ(bp_gens.party_capacity(), 8);
  
  // Verify that each party has exactly 32 generators
  for (size_t i = 0; i < 8; i++) {
    EXPECT_EQ(bp_gens.GetGParty(i).size(), 32);
    EXPECT_EQ(bp_gens.GetHParty(i).size(), 32);
  }
  
  // Increase capacity
  bp_gens.IncreaseCapacity(64);
  EXPECT_EQ(bp_gens.gens_capacity(), 64);
  
  // Verify that each party now has 64 generators
  for (size_t i = 0; i < 8; i++) {
    EXPECT_EQ(bp_gens.GetGParty(i).size(), 64);
    EXPECT_EQ(bp_gens.GetHParty(i).size(), 64);
  }
  
  // Verify that increasing to a smaller capacity does nothing
  bp_gens.IncreaseCapacity(32);
  EXPECT_EQ(bp_gens.gens_capacity(), 64);
}

TEST_F(GeneratorsTest, BulletproofGensShareWorks) {
  BulletproofGens bp_gens(curve_, 64, 8);
  
  // Get share for party 3
  BulletproofGensShare share = bp_gens.Share(3);
  
  // Verify we can get subset of generators
  std::vector<yacl::crypto::EcPoint> G_16 = share.G(16);
  std::vector<yacl::crypto::EcPoint> H_16 = share.H(16);
  
  EXPECT_EQ(G_16.size(), 16);
  EXPECT_EQ(H_16.size(), 16);
  
  // They should match the first 16 elements from party 3's vectors
  for (size_t i = 0; i < 16; i++) {
    EXPECT_TRUE(curve_->PointEqual(G_16[i], bp_gens.GetGParty(3)[i]));
    EXPECT_TRUE(curve_->PointEqual(H_16[i], bp_gens.GetHParty(3)[i]));
  }
}

TEST_F(GeneratorsTest, AggregatedGensIterMatches) {
  BulletproofGens bp_gens(curve_, 64, 8);
  
  // Test with different sizes
  auto TestAggregatedGens = [&](size_t n, size_t m) {
    std::vector<yacl::crypto::EcPoint> all_G = bp_gens.GetAllG(n, m);
    std::vector<yacl::crypto::EcPoint> all_H = bp_gens.GetAllH(n, m);
    
    EXPECT_EQ(all_G.size(), n * m);
    EXPECT_EQ(all_H.size(), n * m);
    
    // Build "flat_map" version manually for comparison
    std::vector<yacl::crypto::EcPoint> flat_G;
    std::vector<yacl::crypto::EcPoint> flat_H;
    flat_G.reserve(n * m);
    flat_H.reserve(n * m);
    
    for (size_t i = 0; i < m; i++) {
      const auto& party_G = bp_gens.GetGParty(i);
      const auto& party_H = bp_gens.GetHParty(i);
      
      for (size_t j = 0; j < n; j++) {
        flat_G.push_back(party_G[j]);
        flat_H.push_back(party_H[j]);
      }
    }
    
    // Compare each element
    for (size_t i = 0; i < n * m; i++) {
      EXPECT_TRUE(curve_->PointEqual(all_G[i], flat_G[i]));
      EXPECT_TRUE(curve_->PointEqual(all_H[i], flat_H[i]));
    }
  };
  
  // Test different combinations of sizes
  TestAggregatedGens(64, 8);
  TestAggregatedGens(64, 4);
  TestAggregatedGens(64, 2);
  TestAggregatedGens(64, 1);
  TestAggregatedGens(32, 8);
  TestAggregatedGens(16, 4);
}

TEST_F(GeneratorsTest, ResizingMatchesCreatingBiggerGens) {
  // Create generators with full capacity
  BulletproofGens full_gens(curve_, 64, 8);
  
  // Create generators with smaller capacity and then increase
  BulletproofGens resized_gens(curve_, 32, 8);
  resized_gens.IncreaseCapacity(64);
  
  // Verify that both give the same generators for various sizes
  auto TestGensMatch = [&](size_t n, size_t m) {
    auto full_G = full_gens.GetAllG(n, m);
    auto full_H = full_gens.GetAllH(n, m);
    
    auto resized_G = resized_gens.GetAllG(n, m);
    auto resized_H = resized_gens.GetAllH(n, m);
    
    EXPECT_EQ(full_G.size(), resized_G.size());
    EXPECT_EQ(full_H.size(), resized_H.size());
    
    for (size_t i = 0; i < n * m; i++) {
      EXPECT_TRUE(curve_->PointEqual(full_G[i], resized_G[i]));
      EXPECT_TRUE(curve_->PointEqual(full_H[i], resized_H[i]));
    }
  };
  
  TestGensMatch(64, 8);
  TestGensMatch(32, 8);
  TestGensMatch(16, 8);
}

} // namespace
} // namespace examples::zkp

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
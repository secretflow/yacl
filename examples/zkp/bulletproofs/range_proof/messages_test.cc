#include "zkp/bulletproofs/range_proof/messages.h"

#include <gtest/gtest.h>
#include <vector>
#include <memory>

#include "yacl/crypto/ecc/ecc_spi.h" // For EcGroupFactory, EcGroup
#include "yacl/crypto/rand/rand.h" // For random points/scalars
#include "yacl/math/mpint/mp_int.h"
#include "yacl/base/buffer.h"      // For yacl::Buffer
#include "yacl/base/byte_container_view.h" // For yacl::ByteContainerView

namespace examples::zkp {
namespace {

// ... [Helper functions remain the same] ...

class MessagesTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Initialize curve
    curve_ = yacl::crypto::EcGroupFactory::Instance().Create(
        "secp256k1", yacl::ArgLib = "openssl");
  }

  std::shared_ptr<yacl::crypto::EcGroup> curve_;
};


// Test BitCommitment Serialization/Deserialization
TEST_F(MessagesTest, BitCommitmentSerde) {
  yacl::crypto::EcPoint V = CreateDummyPoint(curve_);
  yacl::crypto::EcPoint A = CreateDummyPoint(curve_);
  yacl::crypto::EcPoint S = CreateDummyPoint(curve_);

  BitCommitment original(V, A, S);

  // Serialize
  yacl::Buffer serialized_bytes;
  ASSERT_NO_THROW({
      serialized_bytes = original.ToBytes(curve_);
  });

  ASSERT_NE(serialized_bytes.size(), 0);

  // Deserialize
  BitCommitment deserialized;
   ASSERT_NO_THROW({
       deserialized = BitCommitment::FromBytes(curve_, serialized_bytes);
   });

  // Compare (using PointEqual for points)
  EXPECT_TRUE(curve_->PointEqual(original.GetV(), deserialized.GetV()));
  EXPECT_TRUE(curve_->PointEqual(original.GetA(), deserialized.GetA()));
  EXPECT_TRUE(curve_->PointEqual(original.GetS(), deserialized.GetS()));
}

// Test BitChallenge Serialization/Deserialization
TEST_F(MessagesTest, BitChallengeSerde) {
  yacl::math::MPInt y = CreateDummyScalar(curve_);
  yacl::math::MPInt z = CreateDummyScalar(curve_);

  BitChallenge original(y, z);

  // Serialize
  yacl::Buffer serialized_bytes;
  ASSERT_NO_THROW({
    serialized_bytes = original.ToBytes();
  });

   ASSERT_NE(serialized_bytes.size(), 0);

  // Deserialize
  BitChallenge deserialized;
  ASSERT_NO_THROW({
      deserialized = BitChallenge::FromBytes(serialized_bytes);
  });

  // Compare
  EXPECT_EQ(original.GetY(), deserialized.GetY());
  EXPECT_EQ(original.GetZ(), deserialized.GetZ());
}

// Test PolyCommitment Serialization/Deserialization
TEST_F(MessagesTest, PolyCommitmentSerde) {
  yacl::crypto::EcPoint T1 = CreateDummyPoint(curve_);
  yacl::crypto::EcPoint T2 = CreateDummyPoint(curve_);

  PolyCommitment original(T1, T2);

  // Serialize
  yacl::Buffer serialized_bytes;
   ASSERT_NO_THROW({
       serialized_bytes = original.ToBytes(curve_);
   });

   ASSERT_NE(serialized_bytes.size(), 0);

  // Deserialize
  PolyCommitment deserialized;
  ASSERT_NO_THROW({
      deserialized = PolyCommitment::FromBytes(curve_, serialized_bytes);
  });

  // Compare
  EXPECT_TRUE(curve_->PointEqual(original.GetT1(), deserialized.GetT1()));
  EXPECT_TRUE(curve_->PointEqual(original.GetT2(), deserialized.GetT2()));
}

// Test PolyChallenge Serialization/Deserialization
TEST_F(MessagesTest, PolyChallengeSerde) {
  yacl::math::MPInt x = CreateDummyScalar(curve_);

  PolyChallenge original(x);

  // Serialize
  yacl::Buffer serialized_bytes;
  ASSERT_NO_THROW({
      serialized_bytes = original.ToBytes();
  });

  ASSERT_NE(serialized_bytes.size(), 0);

  // Deserialize
  PolyChallenge deserialized;
  ASSERT_NO_THROW({
      deserialized = PolyChallenge::FromBytes(serialized_bytes);
  });

  // Compare
  EXPECT_EQ(original.GetX(), deserialized.GetX());
}

// Test ProofShare Serialization/Deserialization
TEST_F(MessagesTest, ProofShareSerde) {
  yacl::math::MPInt t_x = CreateDummyScalar(curve_);
  yacl::math::MPInt t_x_blinding = CreateDummyScalar(curve_);
  yacl::math::MPInt e_blinding = CreateDummyScalar(curve_);
  size_t n = 8; // Example vector size
  std::vector<yacl::math::MPInt> l_vec;
  std::vector<yacl::math::MPInt> r_vec;
  l_vec.reserve(n);
  r_vec.reserve(n);
  for (size_t i = 0; i < n; ++i) {
      l_vec.push_back(CreateDummyScalar(curve_));
      r_vec.push_back(CreateDummyScalar(curve_));
  }

  ProofShare original(t_x, t_x_blinding, e_blinding, l_vec, r_vec); // Pass l_vec by value (implicitly copied)

  // Serialize
  yacl::Buffer serialized_bytes;
  ASSERT_NO_THROW({
      serialized_bytes = original.ToBytes();
  });

  ASSERT_NE(serialized_bytes.size(), 0);

  // Deserialize
  ProofShare deserialized;
   ASSERT_NO_THROW({
       deserialized = ProofShare::FromBytes(serialized_bytes);
   });

  // Compare scalars
  EXPECT_EQ(original.GetTX(), deserialized.GetTX());
  EXPECT_EQ(original.GetTXBlinding(), deserialized.GetTXBlinding());
  EXPECT_EQ(original.GetEBlinding(), deserialized.GetEBlinding());

  // Compare vectors
  EXPECT_TRUE(original.GetLVec() == deserialized.GetLVec());
  EXPECT_TRUE(original.GetRVec() == deserialized.GetRVec());

  // Verify sizes (redundant if CompareMPVecs works, but good check)
  EXPECT_EQ(deserialized.GetLVec().size(), n);
  EXPECT_EQ(deserialized.GetRVec().size(), n);
}

// Test Deserialization Errors (Partial data)
TEST_F(MessagesTest, DeserializationErrors) {
    // Test BitCommitment
    BitCommitment original_bc(CreateDummyPoint(curve_), CreateDummyPoint(curve_), CreateDummyPoint(curve_));
    yacl::Buffer bc_bytes = original_bc.ToBytes(curve_);
    yacl::Buffer short_bc_bytes(bc_bytes.data(), bc_bytes.size() > 0 ? bc_bytes.size() / 2 : 0); // Truncated data, handle size=0
    EXPECT_THROW(BitCommitment::FromBytes(curve_, short_bc_bytes), yacl::Exception);

    // Test BitChallenge
    BitChallenge original_bch(CreateDummyScalar(curve_), CreateDummyScalar(curve_));
    yacl::Buffer bch_bytes = original_bch.ToBytes();
    yacl::Buffer short_bch_bytes(bch_bytes.data(), bch_bytes.size() > 0 ? bch_bytes.size() / 2 : 0);
    EXPECT_THROW(BitChallenge::FromBytes(short_bch_bytes), yacl::Exception);

    // Test PolyCommitment
    PolyCommitment original_pc(CreateDummyPoint(curve_), CreateDummyPoint(curve_));
    yacl::Buffer pc_bytes = original_pc.ToBytes(curve_);
    yacl::Buffer short_pc_bytes(pc_bytes.data(), pc_bytes.size() > 0 ? pc_bytes.size() / 2 : 0);
    EXPECT_THROW(PolyCommitment::FromBytes(curve_, short_pc_bytes), yacl::Exception);

    // Test PolyChallenge
    PolyChallenge original_pch(CreateDummyScalar(curve_));
    yacl::Buffer pch_bytes = original_pch.ToBytes();
    yacl::Buffer short_pch_bytes(pch_bytes.data(), pch_bytes.size() > sizeof(size_t) ? sizeof(size_t) : 0); // Only size or less
    EXPECT_THROW(PolyChallenge::FromBytes(short_pch_bytes), yacl::Exception);

     // Test ProofShare
    size_t n = 4;
    std::vector<yacl::math::MPInt> l_vec(n), r_vec(n);
    for(size_t i=0; i<n; ++i) { l_vec[i]=CreateDummyScalar(curve_); r_vec[i]=CreateDummyScalar(curve_); }
    ProofShare original_ps(CreateDummyScalar(curve_), CreateDummyScalar(curve_), CreateDummyScalar(curve_), l_vec, r_vec);
    yacl::Buffer ps_bytes = original_ps.ToBytes();
    yacl::Buffer short_ps_bytes(ps_bytes.data(), ps_bytes.size() > 0 ? ps_bytes.size() / 2 : 0);
    EXPECT_THROW(ProofShare::FromBytes(short_ps_bytes), yacl::Exception);
}


} // namespace
} // namespace examples::zkp

// Boilerplate main function for Google Test
int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
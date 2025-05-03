#include "zkp/bulletproofs/range_proof/party.h"

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <cmath> // For std::pow
#include <utility> // For std::move

#include "yacl/crypto/ecc/ecc_spi.h"        // For EcGroupFactory, EcGroup
#include "yacl/crypto/rand/rand.h"         // For random scalars
#include "zkp/bulletproofs/generators.h"   // For BulletproofGens, PedersenGens
#include "zkp/bulletproofs/range_proof/messages.h" // For message types
#include "zkp/bulletproofs/util.h"         // For VecPoly1, Poly2, etc.

namespace examples::zkp {
namespace {

class PartyTest : public ::testing::Test {
 protected:
  // Use standard bit sizes
  const size_t n8_ = 8;
  const size_t n32_ = 32;
  const size_t party_capacity_ = 4; // Must be >= max party index tested

  void SetUp() override {
    // Initialize curve
    curve_ = yacl::crypto::EcGroupFactory::Instance().Create(
        "secp256k1", yacl::ArgLib = "openssl");
    order_ = curve_->GetOrder();

    // Initialize generators - ensure capacity >= max n tested and party_capacity
    size_t bp_gens_capacity = std::max({n8_, n32_, (size_t)16}); // Max n needed + buffer
    pc_gens_ptr_ = std::make_unique<PedersenGens>(curve_);
    bp_gens_ptr_ = std::make_unique<BulletproofGens>(curve_, bp_gens_capacity, party_capacity_);
  }

  std::shared_ptr<yacl::crypto::EcGroup> curve_;
  yacl::math::MPInt order_;
  std::unique_ptr<PedersenGens> pc_gens_ptr_;
  std::unique_ptr<BulletproofGens> bp_gens_ptr_;

  // Helper to create a valid value within range [0, 2^n)
  uint64_t CreateValueInRange(size_t n) {
      if (n >= 64) return 1234567890123456789ULL; // Example large value
      uint64_t max_val_exclusive = 1ULL << n;
      // Create a value roughly in the middle
      return max_val_exclusive / 2 + (max_val_exclusive / 4);
  }
};

// Test Party::New factory function
TEST_F(PartyTest, NewParty) {
  uint64_t v = CreateValueInRange(n32_);
  yacl::math::MPInt blinding = CreateDummyScalar(curve_);

  ASSERT_NO_THROW({
    auto party_state = Party::New(*bp_gens_ptr_, *pc_gens_ptr_, v, blinding, n32_);
  });

  // Test invalid bitsize
  ASSERT_THROW(Party::New(*bp_gens_ptr_, *pc_gens_ptr_, v, blinding, 7), yacl::Exception);
  ASSERT_THROW(Party::New(*bp_gens_ptr_, *pc_gens_ptr_, v, blinding, 65), yacl::Exception);

  // Test insufficient generator capacity for n
  BulletproofGens insufficient_bp_gens(curve_, n32_ - 1, party_capacity_);
  ASSERT_THROW(Party::New(insufficient_bp_gens, *pc_gens_ptr_, v, blinding, n32_), yacl::Exception);

  // Test value out of range
  uint64_t v_out_of_range = 1ULL << n8_; // Value is 2^8, max allowed is 2^8 - 1
  ASSERT_THROW(Party::New(*bp_gens_ptr_, *pc_gens_ptr_, v_out_of_range, blinding, n8_), yacl::Exception);
}

// Test PartyAwaitingPosition::AssignPosition transition
TEST_F(PartyTest, AssignPosition) {
  uint64_t v = CreateValueInRange(n8_);
  yacl::math::MPInt blinding = CreateDummyScalar(curve_);
  auto party_state1 = Party::New(*bp_gens_ptr_, *pc_gens_ptr_, v, blinding, n8_);

  size_t party_index = 1; // Example index


  // PartyAwaitingBitChallenge party_state2; // Remove this line
  BitCommitment bit_commitment;

  ASSERT_NO_THROW({
      auto result = party_state1.AssignPosition(party_index);
      // Check if the returned points are non-identity (basic check)
      ASSERT_FALSE(curve_->IsInfinity(result.second.GetV()));
      ASSERT_FALSE(curve_->IsInfinity(result.second.GetA()));
      ASSERT_FALSE(curve_->IsInfinity(result.second.GetS()));

      PartyAwaitingBitChallenge party_state2 = std::move(result.first); // Initialize here
      bit_commitment = result.second;
      // party_state2 goes out of scope here, but that's okay for this test
  });

   // Test invalid party index
   size_t invalid_index = party_capacity_; // Index >= capacity is invalid
   // Need to recreate state1 as it was moved from
   auto party_state1_again = Party::New(*bp_gens_ptr_, *pc_gens_ptr_, v, blinding, n8_);
   ASSERT_THROW(party_state1_again.AssignPosition(invalid_index), yacl::Exception);
}

// Test PartyAwaitingBitChallenge::ApplyChallenge transition
TEST_F(PartyTest, ApplyBitChallenge) {
  uint64_t v = CreateValueInRange(n8_);
  yacl::math::MPInt blinding = CreateDummyScalar(curve_);
  auto party_state1 = Party::New(*bp_gens_ptr_, *pc_gens_ptr_, v, blinding, n8_);
  size_t party_index = 0;
  auto [party_state2, bit_commitment] = party_state1.AssignPosition(party_index); // Direct initialization

  // Create dummy challenges
  yacl::math::MPInt y_challenge = CreateDummyScalar(curve_);
  yacl::math::MPInt z_challenge = CreateDummyScalar(curve_);
  BitChallenge bit_challenge(y_challenge, z_challenge);


  // PartyAwaitingPolyChallenge party_state3; // Remove this line
  PolyCommitment poly_commitment;

  ASSERT_NO_THROW({
    auto result = party_state2.ApplyChallenge(bit_challenge);
    // Check if the returned points are non-identity (basic check)
    ASSERT_FALSE(curve_->IsInfinity(result.second.GetT1()));
    ASSERT_FALSE(curve_->IsInfinity(result.second.GetT2()));

    PartyAwaitingPolyChallenge party_state3 = std::move(result.first); // Initialize here
    poly_commitment = result.second;
    // party_state3 goes out of scope here
  });
}


// Test PartyAwaitingPolyChallenge::ApplyChallenge transition
TEST_F(PartyTest, ApplyPolyChallenge) {
  // Setup: Go through the first two stages using C++14 style
  uint64_t v = CreateValueInRange(n8_);
  yacl::math::MPInt blinding = CreateDummyScalar(curve_);
  auto party_state1_setup = Party::New(*bp_gens_ptr_, *pc_gens_ptr_, v, blinding, n8_);
  size_t party_index = 0;

  std::pair<PartyAwaitingBitChallenge, BitCommitment> result1_setup =
      party_state1_setup.AssignPosition(party_index);
  PartyAwaitingBitChallenge party_state2_setup = std::move(result1_setup.first);

  BitChallenge bit_challenge(CreateDummyScalar(curve_), CreateDummyScalar(curve_));

  std::pair<PartyAwaitingPolyChallenge, PolyCommitment> result2_setup =
      party_state2_setup.ApplyChallenge(bit_challenge);
  // We need party_state3 later, so capture it (move constructor is okay)
  PartyAwaitingPolyChallenge party_state3_setup = std::move(result2_setup.first);

  // Create dummy PolyChallenge (must be non-zero)
  yacl::math::MPInt x_challenge = CreateDummyScalar(curve_);
  PolyChallenge poly_challenge(x_challenge);

  ProofShare proof_share;
  // Use the setup state directly if its ApplyChallenge is const.
  // Assuming ApplyChallenge is const based on header:
  ASSERT_NO_THROW({ 
      // If ApplyChallenge were non-const or consumed state, we would recreate here.
      // Since it seems const, we can use the state we prepared.
      proof_share = party_state3_setup.ApplyChallenge(poly_challenge);
  }); // Closing parenthesis and semicolon for ASSERT_NO_THROW

  // Basic checks on the ProofShare content
  ASSERT_FALSE(proof_share.GetTX().IsZero());
  ASSERT_FALSE(proof_share.GetTXBlinding().IsZero());
  ASSERT_FALSE(proof_share.GetEBlinding().IsZero());
  ASSERT_EQ(proof_share.GetLVec().size(), n8_);
  ASSERT_EQ(proof_share.GetRVec().size(), n8_);
  ASSERT_FALSE(proof_share.GetLVec().empty());
  ASSERT_FALSE(proof_share.GetRVec().empty());


   // Test with zero challenge (should throw)
   PolyChallenge zero_poly_challenge(yacl::math::MPInt(0));
   // We need a valid party_state3 object again.
   { // Use scope to manage lifetime
        auto ps1_zero = Party::New(*bp_gens_ptr_, *pc_gens_ptr_, v, blinding, n8_);
        std::pair<PartyAwaitingBitChallenge, BitCommitment> res1_zero =
             ps1_zero.AssignPosition(party_index);
        PartyAwaitingBitChallenge ps2_zero = std::move(res1_zero.first);

        BitChallenge bc_orig_zero = bit_challenge; // Copy original bit challenge
        std::pair<PartyAwaitingPolyChallenge, PolyCommitment> res2_zero =
             ps2_zero.ApplyChallenge(bc_orig_zero);
        PartyAwaitingPolyChallenge ps3_zero = std::move(res2_zero.first);

        ASSERT_THROW(ps3_zero.ApplyChallenge(zero_poly_challenge), yacl::Exception);
   }
}


} // namespace
} // namespace examples::zkp

// Boilerplate main function for Google Test
int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
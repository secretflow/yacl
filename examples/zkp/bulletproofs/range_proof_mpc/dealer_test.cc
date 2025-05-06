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

#include "zkp/bulletproofs/range_proof_mpc/dealer.h"

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <utility> // For std::move

#include "yacl/crypto/ecc/ecc_spi.h"        // For EcGroupFactory, EcGroup
#include "yacl/crypto/rand/rand.h"         // For random scalars/points
#include "range_proof_config.h"
#include "zkp/bulletproofs/generators.h"   // For BulletproofGens, PedersenGens
#include "zkp/bulletproofs/range_proof_mpc/messages.h" // For message types
#include "zkp/bulletproofs/range_proof_mpc/range_proof_mpc.h" // For RangeProof, IsPowerOfTwo
#include "zkp/bulletproofs/simple_transcript.h" // For SimpleTranscript
#include "zkp/bulletproofs/util.h"         // For InnerProductProof definition (needed by RangeProof)

namespace examples::zkp {
namespace {




class DealerTest : public ::testing::Test {
 protected:
  const size_t n_ = 8;  // Example bitsize
  const size_t m_ = 4;  // Example number of parties (must be power of 2)

  void SetUp() override {
    // Initialize curve
    curve_ = yacl::crypto::EcGroupFactory::Instance().Create(
        kRangeProofEcName, yacl::ArgLib = kRangeProofEcLib);

    // Initialize generators - ensure capacity >= n and m
    // Add some buffer to capacities
    size_t bp_gens_capacity = std::max(n_, (size_t)16); // e.g., 16 or n
    size_t bp_party_capacity = std::max(m_, (size_t)4); // e.g., 4 or m
    pc_gens_ptr_ = std::make_unique<PedersenGens>(curve_);
    bp_gens_ptr_ = std::make_unique<BulletproofGens>(curve_, bp_gens_capacity, bp_party_capacity);

    // Initialize transcript for each test potentially
    // transcript_ = std::make_unique<SimpleTranscript>("dealer_test_transcript");
  }

   // Helper to get a fresh transcript for a test
  std::unique_ptr<SimpleTranscript> GetFreshTranscript() {
      return std::make_unique<SimpleTranscript>("dealer_test_transcript");
  }


  std::shared_ptr<yacl::crypto::EcGroup> curve_;
  std::unique_ptr<PedersenGens> pc_gens_ptr_;
  std::unique_ptr<BulletproofGens> bp_gens_ptr_;
  // Removed transcript_ from here, create fresh for each test path

  // Helper to create dummy BitCommitments
  std::vector<BitCommitment> CreateDummyBitCommitments(size_t count) {
    std::vector<BitCommitment> commitments;
    for (size_t i = 0; i < count; ++i) {
      commitments.emplace_back(
          CreateDummyPoint(curve_), // V_j
          CreateDummyPoint(curve_), // A_j
          CreateDummyPoint(curve_)  // S_j
      );
    }
    return commitments;
  }

  // Helper to create dummy PolyCommitments
  std::vector<PolyCommitment> CreateDummyPolyCommitments(size_t count) {
     std::vector<PolyCommitment> commitments;
    for (size_t i = 0; i < count; ++i) {
      commitments.emplace_back(
          CreateDummyPoint(curve_), // T1_j
          CreateDummyPoint(curve_)  // T2_j
      );
    }
    return commitments;
  }

   // Helper to create dummy ProofShares
  std::vector<ProofShare> CreateDummyProofShares(size_t count, size_t vec_n, bool malformed_size = false) {
     std::vector<ProofShare> shares;
     for (size_t i = 0; i < count; ++i) {
       size_t current_n = malformed_size ? (vec_n > 0 ? vec_n - 1 : 0) : vec_n; // Make size wrong if requested
       std::vector<yacl::math::MPInt> l_vec(current_n);
       std::vector<yacl::math::MPInt> r_vec(current_n);
       for(size_t k=0; k < current_n; ++k) {
           l_vec[k] = CreateDummyScalar(curve_);
           r_vec[k] = CreateDummyScalar(curve_);
       }
       shares.emplace_back(
            CreateDummyScalar(curve_), // t_x
            CreateDummyScalar(curve_), // t_x_blinding
            CreateDummyScalar(curve_), // e_blinding
            std::move(l_vec),
            std::move(r_vec)
       );
     }
     return shares;
  }
};

// Test Dealer::New factory function
TEST_F(DealerTest, NewDealer) {
  auto transcript = GetFreshTranscript(); // Use fresh transcript
  ASSERT_NO_THROW({
    auto dealer_state = Dealer::New(*bp_gens_ptr_, *pc_gens_ptr_, *transcript, n_, m_);
  });

  // Test invalid bitsize
  // Need fresh transcripts for each independent test path starting with Dealer::New
  auto transcript_b1 = GetFreshTranscript();
  ASSERT_THROW(Dealer::New(*bp_gens_ptr_, *pc_gens_ptr_, *transcript_b1, 7, m_), yacl::Exception);
  auto transcript_b2 = GetFreshTranscript();
  ASSERT_THROW(Dealer::New(*bp_gens_ptr_, *pc_gens_ptr_, *transcript_b2, 65, m_), yacl::Exception);

  // Test invalid party count (not power of 2)
  auto transcript_p1 = GetFreshTranscript();
  ASSERT_THROW(Dealer::New(*bp_gens_ptr_, *pc_gens_ptr_, *transcript_p1, n_, 3), yacl::Exception);
  auto transcript_p2 = GetFreshTranscript();
  ASSERT_THROW(Dealer::New(*bp_gens_ptr_, *pc_gens_ptr_, *transcript_p2, n_, 0), yacl::Exception);

  // Test insufficient generator capacity (adjust capacities in SetUp if needed for these tests)
  // Create insufficient generators locally for this test
  // BulletproofGens insufficient_bp_gens(curve_, n_ - 1, m_); // n capacity too low
  // auto transcript_g1 = GetFreshTranscript();
  // ASSERT_THROW(Dealer::New(insufficient_bp_gens, *pc_gens_ptr_, *transcript_g1, n_, m_), yacl::Exception);

  // BulletproofGens insufficient_bp_gens_m(curve_, n_, m_ - 1); // m capacity too low
  // auto transcript_g2 = GetFreshTranscript();
  // ASSERT_THROW(Dealer::New(insufficient_bp_gens_m, *pc_gens_ptr_, *transcript_g2, n_, m_), yacl::Exception);
}

// Test the full happy path using ReceiveTrustedShares
TEST_F(DealerTest, FullProtocolFlowTrusted) {
  auto transcript = GetFreshTranscript(); // Use fresh transcript for this flow

  // 1. Initialize Dealer
  auto dealer_state1 = Dealer::New(*bp_gens_ptr_, *pc_gens_ptr_, *transcript, n_, m_);
  // SimpleTranscript initial_transcript = *transcript; // Keep copy if verifying later

  // 2. Receive Bit Commitments
  auto bit_commitments = CreateDummyBitCommitments(m_);

  auto result1 = dealer_state1.ReceiveBitCommitments(bit_commitments);
  DealerAwaitingPolyCommitments dealer_state2 = std::move(result1.first);
  BitChallenge bit_challenge = result1.second;
  ASSERT_FALSE(bit_challenge.GetY().IsZero());
  ASSERT_FALSE(bit_challenge.GetZ().IsZero());

  // 3. Receive Poly Commitments
  auto poly_commitments = CreateDummyPolyCommitments(m_);

   auto result2 = dealer_state2.ReceivePolyCommitments(poly_commitments);
   DealerAwaitingProofShares dealer_state3 = std::move(result2.first);
   PolyChallenge poly_challenge = result2.second;
   ASSERT_FALSE(poly_challenge.GetX().IsZero());

  // 4. Receive Trusted Shares
  auto proof_shares = CreateDummyProofShares(m_, n_);
  RangeProofMPC proof;
  ASSERT_NO_THROW({
    proof = dealer_state3.ReceiveTrustedShares(proof_shares);
  });
  // Basic check on proof structure (if fields were public)
}

// Test error on wrong number of bit commitments
TEST_F(DealerTest, ReceiveBitCommitmentsError) {
  auto transcript1 = GetFreshTranscript();
  auto dealer_state1 = Dealer::New(*bp_gens_ptr_, *pc_gens_ptr_, *transcript1, n_, m_);
  auto wrong_commitments1 = CreateDummyBitCommitments(m_ - 1);
  ASSERT_THROW(dealer_state1.ReceiveBitCommitments(wrong_commitments1), yacl::Exception);

  // Need fresh transcript and dealer for the second case
  auto transcript2 = GetFreshTranscript();
  auto dealer_state2 = Dealer::New(*bp_gens_ptr_, *pc_gens_ptr_, *transcript2, n_, m_);
  auto wrong_commitments2 = CreateDummyBitCommitments(m_ + 1);
  ASSERT_THROW(dealer_state2.ReceiveBitCommitments(wrong_commitments2), yacl::Exception);
}

// Test error on wrong number of poly commitments
TEST_F(DealerTest, ReceivePolyCommitmentsError) {
    auto transcript = GetFreshTranscript(); // Use one transcript for this sequence
    auto dealer_state1 = Dealer::New(*bp_gens_ptr_, *pc_gens_ptr_, *transcript, n_, m_);
    auto bit_commitments = CreateDummyBitCommitments(m_);
    auto [dealer_state2, bit_challenge] = dealer_state1.ReceiveBitCommitments(bit_commitments);

    // Test with too few poly commitments
    auto wrong_poly_commitments1 = CreateDummyPolyCommitments(m_ - 1);
    // Can't reuse dealer_state2 after a move, need to recreate the path or clone if allowed
    // Let's recreate the path for clarity, though less efficient
    {
        auto transcript_case1 = GetFreshTranscript();
        auto state1 = Dealer::New(*bp_gens_ptr_, *pc_gens_ptr_, *transcript_case1, n_, m_);
        auto [state2, bc] = state1.ReceiveBitCommitments(bit_commitments); // Use original bit_commitments
        ASSERT_THROW(state2.ReceivePolyCommitments(wrong_poly_commitments1), yacl::Exception);
    }


    // Test with too many poly commitments
    auto wrong_poly_commitments2 = CreateDummyPolyCommitments(m_ + 1);
     {
        auto transcript_case2 = GetFreshTranscript();
        auto state1 = Dealer::New(*bp_gens_ptr_, *pc_gens_ptr_, *transcript_case2, n_, m_);
        auto [state2, bc] = state1.ReceiveBitCommitments(bit_commitments); // Use original bit_commitments
        ASSERT_THROW(state2.ReceivePolyCommitments(wrong_poly_commitments2), yacl::Exception);
    }
}

// Test error on wrong number of proof shares
TEST_F(DealerTest, ReceiveProofSharesError) {
    auto transcript = GetFreshTranscript(); // One transcript for the setup path
    auto dealer_state1 = Dealer::New(*bp_gens_ptr_, *pc_gens_ptr_, *transcript, n_, m_);
    auto bit_commitments = CreateDummyBitCommitments(m_);
    auto [dealer_state2, bit_challenge] = dealer_state1.ReceiveBitCommitments(bit_commitments);
    auto poly_commitments = CreateDummyPolyCommitments(m_);
    auto [dealer_state3, poly_challenge] = dealer_state2.ReceivePolyCommitments(poly_commitments);

    // Test ReceiveTrustedShares with too few shares
    auto wrong_shares1 = CreateDummyProofShares(m_ - 1, n_);
    // Need to recreate path to state3 or ensure state3 can be reused (depends on implementation details not shown)
    // Recreating path:
    {
        auto transcript_case1 = GetFreshTranscript();
        auto state1 = Dealer::New(*bp_gens_ptr_, *pc_gens_ptr_, *transcript_case1, n_, m_);
        auto [state2, bc] = state1.ReceiveBitCommitments(bit_commitments);
        auto [state3, pc] = state2.ReceivePolyCommitments(poly_commitments);
        ASSERT_THROW(state3.ReceiveTrustedShares(wrong_shares1), yacl::Exception);
    }

    // Test ReceiveTrustedShares with too many shares
    auto wrong_shares2 = CreateDummyProofShares(m_ + 1, n_);
     {
        auto transcript_case2 = GetFreshTranscript();
        auto state1 = Dealer::New(*bp_gens_ptr_, *pc_gens_ptr_, *transcript_case2, n_, m_);
        auto [state2, bc] = state1.ReceiveBitCommitments(bit_commitments);
        auto [state3, pc] = state2.ReceivePolyCommitments(poly_commitments);
        ASSERT_THROW(state3.ReceiveTrustedShares(wrong_shares2), yacl::Exception);
    }

    // Test ReceiveShares (which also calls AssembleShares first)
    {
        auto transcript_case3 = GetFreshTranscript();
        auto state1 = Dealer::New(*bp_gens_ptr_, *pc_gens_ptr_, *transcript_case3, n_, m_);
        auto [state2, bc] = state1.ReceiveBitCommitments(bit_commitments);
        auto [state3, pc] = state2.ReceivePolyCommitments(poly_commitments);
        ASSERT_THROW(state3.ReceiveShares(wrong_shares1), yacl::Exception); // Use too few shares
    }
}


// Test error on malformed proof shares (wrong vector sizes)
TEST_F(DealerTest, AssembleSharesMalformedSize) {
    auto transcript = GetFreshTranscript(); // One transcript for setup path
    auto dealer_state1 = Dealer::New(*bp_gens_ptr_, *pc_gens_ptr_, *transcript, n_, m_);
    auto bit_commitments = CreateDummyBitCommitments(m_);
    auto [dealer_state2, bit_challenge] = dealer_state1.ReceiveBitCommitments(bit_commitments);
    auto poly_commitments = CreateDummyPolyCommitments(m_);
    auto [dealer_state3, poly_challenge] = dealer_state2.ReceivePolyCommitments(poly_commitments);

    // Create shares with incorrect vector sizes
    auto malformed_shares = CreateDummyProofShares(m_, n_, true); // Pass true to trigger malformed size

    // Test ReceiveTrustedShares (calls AssembleShares)
    {
        auto transcript_case1 = GetFreshTranscript();
        auto state1 = Dealer::New(*bp_gens_ptr_, *pc_gens_ptr_, *transcript_case1, n_, m_);
        auto [state2, bc] = state1.ReceiveBitCommitments(bit_commitments);
        auto [state3, pc] = state2.ReceivePolyCommitments(poly_commitments);
        ASSERT_THROW(state3.ReceiveTrustedShares(malformed_shares), yacl::Exception);
    }

   // Test ReceiveShares (also calls AssembleShares)
    {
        auto transcript_case2 = GetFreshTranscript();
        auto state1 = Dealer::New(*bp_gens_ptr_, *pc_gens_ptr_, *transcript_case2, n_, m_);
        auto [state2, bc] = state1.ReceiveBitCommitments(bit_commitments);
        auto [state3, pc] = state2.ReceivePolyCommitments(poly_commitments);
        ASSERT_THROW(state3.ReceiveShares(malformed_shares), yacl::Exception);
    }
}


} // namespace
} // namespace examples::zkp

// Boilerplate main function for Google Test
int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
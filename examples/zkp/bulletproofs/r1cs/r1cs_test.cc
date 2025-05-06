#include "zkp/bulletproofs/r1cs/r1cs_prover.h" // Include prover and verifier headers
#include "zkp/bulletproofs/r1cs/r1cs_verifier.h"
#include "zkp/bulletproofs/r1cs/r1cs.h" // Include base R1CS definitions

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <cmath>   // For std::pow
#include <numeric> // For std::accumulate

#include "yacl/crypto/ecc/ecc_spi.h"        // For EcGroupFactory, EcGroup
#include "yacl/crypto/rand/rand.h"         // For random scalars
#include "zkp/bulletproofs/generators.h"   // For BulletproofGens, PedersenGens
#include "zkp/bulletproofs/simple_transcript.h" // For SimpleTranscript
#include "zkp/bulletproofs/util.h"         // For helpers like NextPowerOfTwo

namespace examples::zkp {
namespace {

// Define R1CSError alias if not defined globally
using R1CSError = yacl::Exception;

// Helper function for R1CS tests: creates Prover, Verifier, adds constraints, proves, verifies.
// Gadget function takes Prover OR Verifier OR RandomizingProver OR RandomizingVerifier
template <typename CS>
void ExampleGadget(CS* cs, Variable x_var, Variable out_var) {
    LinearCombination x_lc(x_var);

    // x * x = x_sq
    auto [x_sq_l, x_sq_r, x_sq_var] = cs->Multiply(x_lc, x_lc);

    // x_sq * x = x_cub
    LinearCombination x_sq_lc(x_sq_var);
    auto [x_cub_l, x_cub_r, x_cub_var] = cs->Multiply(x_sq_lc, x_lc);

    // Constraint: x_cub + x + 5 - out = 0
    // Note: 5 and out are handled as LinearCombinations implicitly
    LinearCombination constraint = LinearCombination(x_cub_var) + x_var + 5 - out_var;
    cs->Constrain(std::move(constraint));
}

// Example randomized gadget part
template <typename RCS> // RCS = RandomizingProver* or RandomizingVerifier*
void ExampleRandomizedGadgetPart(RCS* cs, Variable x_var, const yacl::math::MPInt& expected_x) {
     auto z = cs->ChallengeScalar("random_challenge");

     // Dummy constraint: z*x - z*expected_x = 0
     LinearCombination dummy_rand_lc = z * x_var - z * expected_x; // Use MPInt directly
     cs->Constrain(std::move(dummy_rand_lc));
}


class R1CSProofTest : public ::testing::Test {
 protected:
    void SetUp() override {
        curve_ = yacl::crypto::EcGroupFactory::Instance().Create("secp256k1", yacl::ArgLib = "openssl");
        order_ = curve_->GetOrder();
        pc_gens_ = std::make_unique<PedersenGens>(curve_);
    }

    // Helper to run the test
    void RunTest(size_t n_multipliers_expected_in_gadget, bool use_randomization) {
        // BP gens capacity needs to be next power of 2 >= total multipliers
        // Calculate total expected multipliers based on gadget and randomization
        size_t total_multipliers = n_multipliers_expected_in_gadget + (use_randomization ? 0 : 0); // Add 1 if rand gadget adds multiplier
        size_t padded_n = NextPowerOfTwo(total_multipliers);
        if (padded_n == 0 && total_multipliers > 0) padded_n = 1;
        BulletproofGens bp_gens(curve_, padded_n, 1); // m=1 party

        SimpleTranscript prover_transcript("R1CS Test");
        SimpleTranscript verifier_transcript("R1CS Test");

        // Create Prover and Verifier
        Prover prover(pc_gens_.get(), &prover_transcript);
        Verifier verifier(&verifier_transcript);

        // --- Define Gadget Instance ---
        yacl::math::MPInt v_out(35); // x^3 + x + 5 = 3^3 + 3 + 5 = 27+3+5 = 35
        yacl::math::MPInt v_x(3);
        yacl::math::MPInt v_out_blinding, v_x_blinding;
        v_out_blinding.RandomLtN(order_, &v_out_blinding);
        v_x_blinding.RandomLtN(order_, &v_x_blinding);

        // Prover commits secrets
        auto [out_comm_p, out_var_p] = prover.Commit(v_out, v_out_blinding);
        auto [x_comm_p, x_var_p] = prover.Commit(v_x, v_x_blinding);

        // Verifier commits public commitments
        auto out_var_v = verifier.Commit(curve_->DeserializePoint(curve_->SerializePoint(out_comm_p))); // Pass copy
        auto x_var_v = verifier.Commit(curve_->DeserializePoint(curve_->SerializePoint(x_comm_p))); // Pass copy


        // Apply Phase 1 constraints
        ExampleGadget(&prover, x_var_p, out_var_p);
        ExampleGadget(&verifier, x_var_v, out_var_v);

        // Specify Phase 2 constraints (optional)
        if (use_randomization) {
             prover.SpecifyRandomizedConstraints(
                 [&](RandomizingProver* rp) { ExampleRandomizedGadgetPart(rp, x_var_p, v_x); }
             );
             verifier.SpecifyRandomizedConstraints(
                 [&](RandomizingVerifier* rv) { ExampleRandomizedGadgetPart(rv, x_var_v, v_x); }
             );
        }

        // Check metrics match before proving/verifying
        R1CSMetrics prover_metrics = prover.GetMetrics();
        R1CSMetrics verifier_metrics = verifier.GetMetrics();
        ASSERT_EQ(prover_metrics.multipliers, verifier_metrics.multipliers);
        ASSERT_EQ(prover_metrics.constraints, verifier_metrics.constraints);
        ASSERT_EQ(prover_metrics.phase_one_constraints, verifier_metrics.phase_one_constraints);
        ASSERT_EQ(prover_metrics.phase_two_constraints, verifier_metrics.phase_two_constraints);
        // Check against expected gadget size
        // Note: ExampleGadget adds 2 multipliers and 3 constraints (1 implicit, 2 explicit for Multiply) + 1 final constraint = 5
        size_t expected_constraints_p1 = 5;
        size_t expected_multipliers = 2;
        size_t expected_constraints_p2 = use_randomization ? 1 : 0; // Dummy constraint adds 1
        ASSERT_EQ(prover_metrics.phase_one_constraints, expected_constraints_p1);
        ASSERT_EQ(prover_metrics.phase_two_constraints, expected_constraints_p2);
        ASSERT_EQ(prover_metrics.multipliers, expected_multipliers); // Check total multipliers


        // --- Prover generates proof ---
        R1CSProof proof;
        ASSERT_NO_THROW({
            proof = prover.Prove(bp_gens);
        });

        // --- Verifier verifies proof ---
        bool verification_result = false;
         ASSERT_NO_THROW({
             // Pass references to generators
             verification_result = verifier.Verify(proof, *pc_gens_, bp_gens);
         });

        ASSERT_TRUE(verification_result) << "R1CS verification failed (randomized=" << use_randomization << ")";

         // --- Test Serialization/Deserialization ---
        yacl::Buffer proof_bytes;
        ASSERT_NO_THROW({ proof_bytes = proof.ToBytes(curve_); });
        ASSERT_NE(proof_bytes.size(), 0);

        R1CSProof deserialized_proof;
        ASSERT_NO_THROW({ deserialized_proof = R1CSProof::FromBytes(proof_bytes, curve_); });

        // Verify deserialized proof
        SimpleTranscript verifier_transcript2("R1CS Test"); // Fresh transcript
        Verifier verifier2(&verifier_transcript2);
        // Need to re-apply commitments and constraints to verifier2
        verifier2.Commit(curve_->DeserializePoint(curve_->SerializePoint(out_comm_p)));
        verifier2.Commit(curve_->DeserializePoint(curve_->SerializePoint(x_comm_p)));
        ExampleGadget(&verifier2, x_var_v, out_var_v); // Re-apply constraints
        if (use_randomization) {
             verifier2.SpecifyRandomizedConstraints(
                 [&](RandomizingVerifier* rv) { ExampleRandomizedGadgetPart(rv, x_var_v, v_x); }
             );
        }

        bool verification_result2 = false;
        ASSERT_NO_THROW({
            verification_result2 = verifier2.Verify(deserialized_proof, *pc_gens_, bp_gens);
        });
        ASSERT_TRUE(verification_result2) << "R1CS verification failed after serde (randomized=" << use_randomization << ")";

    }

    std::shared_ptr<yacl::crypto::EcGroup> curve_;
    yacl::math::MPInt order_;
    std::unique_ptr<PedersenGens> pc_gens_;
    // bp_gens created locally in test
};

// Test cases
TEST_F(R1CSProofTest, ProveAndVerify_Simple_NoRandom) {
    RunTest(2, false); // 2 multipliers for x^3 + x + 5 = 35
}

TEST_F(R1CSProofTest, ProveAndVerify_Simple_WithRandom) {
     RunTest(2, true); // Gadget has 2 multipliers, rand adds 0 mult, 1 constraint
}

// Add more tests for larger N and different gadgets if needed
// TEST_F(R1CSProofTest, ProveAndVerify_Larger_NoRandom) {
//     // Define a gadget with ~10 multipliers
//     // RunTest(10, false);
// }

// TEST_F(R1CSProofTest, ProveAndVerify_Larger_WithRandom) {
//     // Define a gadget with ~12 multipliers
//     // RunTest(12, true);
// }


} // namespace
} // namespace examples::zkp

// Boilerplate main function for Google Test
int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
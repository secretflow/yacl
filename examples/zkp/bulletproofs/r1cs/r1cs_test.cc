#include "zkp/bulletproofs/r1cs/r1cs_prover.h" // Include prover and verifier headers
#include "zkp/bulletproofs/r1cs/r1cs_verifier.h"
#include "zkp/bulletproofs/r1cs/r1cs.h" // Include base R1CS definitions

#include <gtest/gtest.h>
#include <memory>
#include <vector>

#include "yacl/crypto/ecc/ecc_spi.h"        // For EcGroupFactory, EcGroup
#include "yacl/crypto/rand/rand.h"         // For random scalars
#include "zkp/bulletproofs/generators.h"   // For BulletproofGens, PedersenGens
#include "zkp/bulletproofs/simple_transcript.h" // For SimpleTranscript
#include "zkp/bulletproofs/util.h"         // For helpers

namespace examples::zkp {
namespace {

// Helper function for R1CS tests: creates Prover, Verifier, adds constraints, proves, verifies.
void TestR1CS(size_t n_multipliers, bool use_randomization) {
    // Setup Curve, Transcript, Generators
    auto curve = yacl::crypto::EcGroupFactory::Instance().Create("secp256k1", yacl::ArgLib = "openssl");
    auto order = curve->GetOrder();
    PedersenGens pc_gens(curve);

    // BP gens capacity needs to be next power of 2 >= n_multipliers
    size_t padded_n = NextPowerOfTwo(n_multipliers); // Ensure this helper is available
    if (padded_n == 0 && n_multipliers > 0) padded_n = 1;
    YACL_ENFORCE(padded_n >= n_multipliers, "Padding logic error");
    BulletproofGens bp_gens(curve, padded_n, 1); // m=1 party

    SimpleTranscript prover_transcript("R1CS Test");
    SimpleTranscript verifier_transcript("R1CS Test"); // MUST be same label

    // Create Prover and Verifier
    Prover prover(&pc_gens, &prover_transcript);
    Verifier verifier(&verifier_transcript);

    // --- Define Gadget (Example: Prove knowledge of x such that x^3 + x + 5 = 35) ---
    // Requires 2 multiplications:
    // x*x = x_sq
    // x_sq*x = x_cub

    // Allocate commitment for the result (35)
    yacl::math::MPInt v_out(35);
    yacl::math::MPInt v_out_blinding; v_out_blinding.RandomLtN(order, &v_out_blinding);
    auto [out_comm, out_var] = prover.Commit(v_out, v_out_blinding);
    verifier.Commit(out_comm);

    // Allocate commitment for the secret input x (e.g., x=3)
    yacl::math::MPInt v_x(3);
    yacl::math::MPInt v_x_blinding; v_x_blinding.RandomLtN(order, &v_x_blinding);
    auto [x_comm, x_var] = prover.Commit(v_x, v_x_blinding);
    verifier.Commit(x_comm);

    // Define the gadget constraints (shared logic)
    auto define_constraints = [&](Prover* p, Verifier* v) {
        // x * x = x_sq
        LinearCombination x_lc(x_var); // x
        std::tuple<Variable, Variable, Variable> vars1;
        if (p) vars1 = p->Multiply(x_lc, x_lc); // Prover provides assignments
        if (v) vars1 = v->Multiply(x_lc, x_lc); // Verifier only defines structure
        Variable x_sq_var = std::get<2>(vars1); // Output variable for x^2

        // x_sq * x = x_cub
         LinearCombination x_sq_lc(x_sq_var);
         std::tuple<Variable, Variable, Variable> vars2;
         if (p) vars2 = p->Multiply(x_sq_lc, x_lc);
         if (v) vars2 = v->Multiply(x_sq_lc, x_lc);
         Variable x_cub_var = std::get<2>(vars2); // Output variable for x^3

         // Constraint: x_cub + x + 5 - 35 = 0
         LinearCombination constraint = LinearCombination(x_cub_var) + x_var + LinearCombination(5) - out_var;

         if (p) p->Constrain(constraint);
         if (v) v->Constrain(constraint);
    };

    // Define optional randomized constraints
    auto define_randomized = [&](RandomizingProver* rp, RandomizingVerifier* rv) {
        // Example: Add a dummy randomized constraint if use_randomization is true
        if (!use_randomization) return;

         yacl::math::MPInt z;
         if (rp) z = rp->ChallengeScalar("random_challenge");
         if (rv) z = rv->ChallengeScalar("random_challenge");

         // Dummy constraint: z*x - z*3 = 0 (prover knows x=3)
         LinearCombination dummy_rand_lc = z * x_var - z * LinearCombination(3);
         if (rp) rp->Constrain(dummy_rand_lc);
         if (rv) rv->Constrain(dummy_rand_lc);
    };

    // --- Apply constraints to Prover and Verifier ---
    define_constraints(&prover, nullptr);
    define_constraints(nullptr, &verifier);

    if (use_randomization) {
        prover.SpecifyRandomizedConstraints([&](RandomizingProver* rp) { define_randomized(rp, nullptr); });
        verifier.SpecifyRandomizedConstraints([&](RandomizingVerifier* rv) { define_randomized(nullptr, rv); });
    }


    // --- Prover generates proof ---
    R1CSProof proof;
    ASSERT_NO_THROW({
        proof = prover.Prove(bp_gens);
    });

    // --- Verifier verifies proof ---
    bool verification_result = false;
     ASSERT_NO_THROW({
         verification_result = verifier.Verify(proof, pc_gens, bp_gens);
     });

    ASSERT_TRUE(verification_result) << "R1CS verification failed (n=" << n_multipliers
                                     << ", randomized=" << use_randomization << ")";

     // --- Test Serialization/Deserialization ---
    yacl::Buffer proof_bytes;
    ASSERT_NO_THROW({ proof_bytes = proof.ToBytes(curve); });
    ASSERT_NE(proof_bytes.size(), 0);

    R1CSProof deserialized_proof;
    ASSERT_NO_THROW({ deserialized_proof = R1CSProof::FromBytes(proof_bytes, curve); });

    // Verify deserialized proof
    SimpleTranscript verifier_transcript2("R1CS Test"); // Fresh transcript
    Verifier verifier2(&verifier_transcript2);
    // Need to re-apply commitments and constraints to verifier2
    verifier2.Commit(out_comm);
    verifier2.Commit(x_comm);
    define_constraints(nullptr, &verifier2);
     if (use_randomization) {
        verifier2.SpecifyRandomizedConstraints([&](RandomizingVerifier* rv) { define_randomized(nullptr, rv); });
    }

    bool verification_result2 = false;
     ASSERT_NO_THROW({
         verification_result2 = verifier2.Verify(deserialized_proof, pc_gens, bp_gens);
     });
     ASSERT_TRUE(verification_result2) << "R1CS verification failed after serde (n=" << n_multipliers
                                       << ", randomized=" << use_randomization << ")";

}


// Test cases
TEST_F(R1CSProofTest, ProveAndVerify_Simple_NoRandom) {
    TestR1CS(2, false); // 2 multipliers for x^3 + x + 5 = 35
}

TEST_F(R1CSProofTest, ProveAndVerify_Simple_WithRandom) {
     TestR1CS(3, true); // 2 for gadget + 1 dummy multiplier in randomized phase
}

TEST_F(R1CSProofTest, ProveAndVerify_Larger_NoRandom) {
    TestR1CS(10, false); // Test padding, needs more complex gadget definition
}

TEST_F(R1CSProofTest, ProveAndVerify_Larger_WithRandom) {
     TestR1CS(12, true); // Test padding, needs more complex gadget definition
}


} // namespace
} // namespace examples::zkp

// Boilerplate main function for Google Test
int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
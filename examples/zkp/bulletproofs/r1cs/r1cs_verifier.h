#pragma once

#include <vector>
#include <memory>
#include <functional>
#include <optional>

#include "zkp/bulletproofs/r1cs/r1cs.h" // Include base definitions
#include "yacl/base/exception.h"

namespace examples::zkp {

// Forward declarations
class PedersenGens;
class BulletproofGens;

// Forward declare RandomizingVerifier
class RandomizingVerifier;


/**
 * @brief R1CS Verifier implementation based on reference   code.
 */
class Verifier {
public:
     // Type for deferred constraints callback
    using RandomizationCallback = std::function<void(RandomizingVerifier*)>;

    /**
     * @brief Construct a new Verifier instance.
     *
     * @param transcript The proof transcript.
     */
    explicit Verifier(SimpleTranscript* transcript);

    // --- ConstraintSystem Methods ---
    SimpleTranscript* Transcript();
    std::tuple<Variable, Variable, Variable> Multiply(LinearCombination left, LinearCombination right);
    Variable Allocate(std::optional<yacl::math::MPInt> assignment); // Assignment ignored
    std::tuple<Variable, Variable, Variable> AllocateMultiplier(
        std::optional<std::pair<yacl::math::MPInt, yacl::math::MPInt>> input_assignments); // Assignment ignored
    R1CSMetrics GetMetrics() const;
    void Constrain(LinearCombination lc);

    // --- Randomization ---
     void SpecifyRandomizedConstraints(RandomizationCallback callback);

    // --- High-level Variable Commitment ---
    Variable Commit(const yacl::crypto::EcPoint& V_commitment);

    // --- Verifying ---
    /**
     * @brief Consumes the Verifier to verify an R1CSProof.
     *
     * @param proof The proof to verify.
     * @param pc_gens Pedersen generators.
     * @param bp_gens Bulletproof generators. Capacity must be sufficient.
     * @return bool True if the proof is valid, false otherwise.
     * @throws yacl::Exception on errors (e.g., insufficient generators, format error).
     */
    bool Verify(const R1CSProof& proof,
                const PedersenGens& pc_gens,
                const BulletproofGens& bp_gens);


 private:
    friend class RandomizingVerifier; // Allow access

    SimpleTranscript* transcript_;
    std::vector<LinearCombination> constraints_;
    size_t num_vars_ = 0; // Tracks number of multipliers for weight vector sizes
    std::vector<yacl::crypto::EcPoint> V_commitments_; // Store commitments added
    std::vector<RandomizationCallback> deferred_constraints_;
    std::optional<size_t> pending_multiplier_;
    size_t num_multipliers_phase1_ = 0;

     // Internal helper for finalizing constraints
     void FlattenedConstraints(
         const yacl::math::MPInt& z,
         const std::shared_ptr<yacl::crypto::EcGroup>& curve,
         std::vector<yacl::math::MPInt>& wL,
         std::vector<yacl::math::MPInt>& wR,
         std::vector<yacl::math::MPInt>& wO,
         std::vector<yacl::math::MPInt>& wV,
         yacl::math::MPInt& wc); // Also computes wc

     // Internal helper to run randomization phase
     void RunRandomizationPhase();
};


/**
 * @brief Wrapper for the Verifier during the randomization phase.
 */
class RandomizingVerifier {
public:
    // --- ConstraintSystem Methods (forwarded) ---
    SimpleTranscript* Transcript() { return verifier_->Transcript(); }
    std::tuple<Variable, Variable, Variable> Multiply(LinearCombination left, LinearCombination right) {
        return verifier_->Multiply(std::move(left), std::move(right));
    }
     Variable Allocate(std::optional<yacl::math::MPInt> assignment) {
         return verifier_->Allocate(std::move(assignment));
     }
     std::tuple<Variable, Variable, Variable> AllocateMultiplier(
         std::optional<std::pair<yacl::math::MPInt, yacl::math::MPInt>> input_assignments) {
         return verifier_->AllocateMultiplier(std::move(input_assignments));
     }
     R1CSMetrics GetMetrics() const { return verifier_->GetMetrics(); }
     void Constrain(LinearCombination lc) { verifier_->Constrain(std::move(lc)); }

    // --- RandomizedConstraintSystem Method ---
    yacl::math::MPInt ChallengeScalar(const std::string& label);

private:
    friend class Verifier;
    explicit RandomizingVerifier(Verifier* v) : verifier_(v) {}
    Verifier* verifier_;
};


} // namespace examples::zkp
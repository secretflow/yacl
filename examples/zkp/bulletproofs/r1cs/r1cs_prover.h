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

// --- Prover Secrets (for RAII/zeroization) ---
// Not implementing Drop for zeroization here for simplicity,
// relies on MPInt/vector destructors. Add ClearOnDrop if needed.
struct R1CSProverSecrets {
    std::vector<yacl::math::MPInt> a_L;
    std::vector<yacl::math::MPInt> a_R;
    std::vector<yacl::math::MPInt> a_O;
    std::vector<yacl::math::MPInt> v;
    std::vector<yacl::math::MPInt> v_blinding;
};

// Forward declare RandomizingProver
class RandomizingProver;

/**
 * @brief R1CS Prover implementation based on reference   code.
 */
class Prover {
 public:
    // Type for deferred constraints callback
    using RandomizationCallback = std::function<void(RandomizingProver*)>; // Ptr avoids lifetime issues with std::function

    /**
     * @brief Construct a new Prover instance.
     *
     * @param pc_gens Pedersen generators.
     * @param transcript The proof transcript.
     */
    Prover(const PedersenGens* pc_gens, SimpleTranscript* transcript);

    // --- ConstraintSystem Methods ---
    SimpleTranscript* Transcript();
    std::tuple<Variable, Variable, Variable> Multiply(LinearCombination left, LinearCombination right);
    Variable Allocate(std::optional<yacl::math::MPInt> assignment); // Use std::optional
    std::tuple<Variable, Variable, Variable> AllocateMultiplier(
        std::optional<std::pair<yacl::math::MPInt, yacl::math::MPInt>> input_assignments);
    R1CSMetrics GetMetrics() const;
    void Constrain(LinearCombination lc);

    // --- Randomization ---
    void SpecifyRandomizedConstraints(RandomizationCallback callback);

    // --- High-level Variable Commitment ---
    std::pair<yacl::crypto::EcPoint, Variable> Commit(
        const yacl::math::MPInt& v, const yacl::math::MPInt& v_blinding);

    // --- Proving ---
    /**
     * @brief Consumes the Prover to produce an R1CSProof.
     *
     * @param bp_gens Bulletproof generators. Capacity must be sufficient.
     * @return R1CSProof The generated proof.
     * @throws yacl::Exception on errors (e.g., insufficient generators).
     */
    R1CSProof Prove(const BulletproofGens& bp_gens);

    // Helper to evaluate linear combinations (used internally and potentially by gadgets)
    yacl::math::MPInt EvalLC(const LinearCombination& lc) const;


 private:
    friend class RandomizingProver; // Allow access to transcript and methods

    SimpleTranscript* transcript_; // Use pointer to external transcript
    const PedersenGens* pc_gens_; // Use pointer to external generators
    std::vector<LinearCombination> constraints_; // Phase 1 constraints
    R1CSProverSecrets secrets_;
    std::vector<RandomizationCallback> deferred_constraints_;
    std::optional<size_t> pending_multiplier_;
    size_t num_multipliers_phase1_ = 0; // Track for splitting phases

    // Internal helper for finalizing constraints
    void FlattenedConstraints(
        const yacl::math::MPInt& z,
        const std::shared_ptr<yacl::crypto::EcGroup>& curve, // Need curve for Optimize
        std::vector<yacl::math::MPInt>& wL,
        std::vector<yacl::math::MPInt>& wR,
        std::vector<yacl::math::MPInt>& wO,
        std::vector<yacl::math::MPInt>& wV);

    // Internal helper to run randomization phase
    void RunRandomizationPhase();
};


/**
 * @brief Wrapper for the Prover during the randomization phase.
 *        Provides access to challenge generation.
 */
class RandomizingProver {
public:
    // --- ConstraintSystem Methods (forwarded) ---
    SimpleTranscript* Transcript() { return prover_->Transcript(); }
    std::tuple<Variable, Variable, Variable> Multiply(LinearCombination left, LinearCombination right) {
        return prover_->Multiply(std::move(left), std::move(right));
    }
     Variable Allocate(std::optional<yacl::math::MPInt> assignment) {
         return prover_->Allocate(std::move(assignment));
     }
     std::tuple<Variable, Variable, Variable> AllocateMultiplier(
         std::optional<std::pair<yacl::math::MPInt, yacl::math::MPInt>> input_assignments) {
         return prover_->AllocateMultiplier(std::move(input_assignments));
     }
     R1CSMetrics GetMetrics() const { return prover_->GetMetrics(); }
     void Constrain(LinearCombination lc) { prover_->Constrain(std::move(lc)); }

    // --- RandomizedConstraintSystem Method ---
    yacl::math::MPInt ChallengeScalar(const std::string& label); // Use string for label

private:
    friend class Prover; // Allow Prover to create and access internals
    explicit RandomizingProver(Prover* p) : prover_(p) {}
    Prover* prover_; // Pointer back to the main prover
};


} // namespace examples::zkp
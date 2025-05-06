#pragma once

#include <vector>
#include <memory>
#include <functional>
#include <optional>
#include <map>

#include "zkp/bulletproofs/r1cs/r1cs.h" // Include base definitions
#include "yacl/base/exception.h"

namespace examples::zkp {

// Forward declarations
class PedersenGens;
class BulletproofGens;
class RandomizingVerifier; // Forward declare

/**
 * @brief R1CS Verifier implementation based on reference Rust code.
 */
class Verifier {
public:
     // Type for deferred constraints callback
    using RandomizationCallback = std::function<void(RandomizingVerifier*)>;

    /**
     * @brief Construct a new Verifier instance.
     * @param transcript The proof transcript (non-owning pointer).
     */
    explicit Verifier(SimpleTranscript* transcript);

    // --- ConstraintSystem Methods ---
    /** @brief Get mutable access to the transcript. */
    SimpleTranscript* Transcript();

    /** @brief Allocate and constrain multiplication gate variables (structure only). */
    std::tuple<Variable, Variable, Variable> Multiply(LinearCombination left, LinearCombination right);

    /** @brief Allocate a single low-level variable structure. Assignment ignored. */
    Variable Allocate(std::optional<yacl::math::MPInt> assignment = std::nullopt);

    /** @brief Allocate a full multiplication gate structure. Assignment ignored. */
    std::tuple<Variable, Variable, Variable> AllocateMultiplier(
        std::optional<std::pair<yacl::math::MPInt, yacl::math::MPInt>> input_assignments = std::nullopt);

    /** @brief Get metrics about the constraint system structure. */
    R1CSMetrics GetMetrics() const;

    /** @brief Add a constraint that a linear combination must equal zero. */
    void Constrain(LinearCombination lc);

    // --- Randomization ---
    /** @brief Defer constraints to the randomization phase. */
     void SpecifyRandomizedConstraints(RandomizationCallback callback);

    // --- High-level Variable Commitment ---
    /** @brief Add a commitment V to a high-level variable to the system. */
    Variable Commit(const yacl::crypto::EcPoint& V_commitment);

    // --- Verifying ---
    /**
     * @brief Consumes the Verifier to verify an R1CSProof.
     *
     * @param proof The proof to verify.
     * @param pc_gens Pedersen generators (non-owning reference).
     * @param bp_gens Bulletproof generators (non-owning reference). Capacity must be sufficient.
     * @return bool True if the proof is valid, false otherwise.
     */
    bool Verify(const R1CSProof& proof,
                const PedersenGens& pc_gens,
                const BulletproofGens& bp_gens);


 private:
    friend class RandomizingVerifier; // Allow access

    SimpleTranscript* transcript_;
    std::vector<LinearCombination> constraints_; // Combined constraints
    size_t num_vars_ = 0; // Tracks number of multipliers
    std::vector<yacl::crypto::EcPoint> V_commitments_; // Store commitments added
    std::vector<RandomizationCallback> deferred_constraints_;
    std::optional<size_t> pending_multiplier_;
    size_t num_multipliers_phase1_ = 0;

     // Internal helper for flattening constraints into weight vectors
     void FlattenedConstraints(
         const yacl::math::MPInt& z,
         const std::shared_ptr<yacl::crypto::EcGroup>& curve,
         std::vector<yacl::math::MPInt>& wL, // Output: weights for a_L
         std::vector<yacl::math::MPInt>& wR, // Output: weights for a_R
         std::vector<yacl::math::MPInt>& wO, // Output: weights for a_O
         std::vector<yacl::math::MPInt>& wV, // Output: weights for V
         yacl::math::MPInt& wc);             // Output: constant weight

     // Internal helper to run randomization phase
     void RunRandomizationPhase();

     // Helper to get curve
     std::shared_ptr<yacl::crypto::EcGroup> GetCurve() const; // Needs access somehow, maybe via pc_gens?

};


/**
 * @brief Wrapper for the Verifier during the randomization phase.
 */
class RandomizingVerifier {
public:
    // --- ConstraintSystem Methods (forwarded) ---
    SimpleTranscript* Transcript();
    std::tuple<Variable, Variable, Variable> Multiply(LinearCombination left, LinearCombination right);
    Variable Allocate(std::optional<yacl::math::MPInt> assignment = std::nullopt);
     std::tuple<Variable, Variable, Variable> AllocateMultiplier(
         std::optional<std::pair<yacl::math::MPInt, yacl::math::MPInt>> input_assignments = std::nullopt);
    R1CSMetrics GetMetrics() const;
    void Constrain(LinearCombination lc);

    // --- RandomizedConstraintSystem Method ---
    /** @brief Generate a challenge scalar bound to the transcript state. */
    yacl::math::MPInt ChallengeScalar(const std::string& label);

private:
    friend class Verifier;
    explicit RandomizingVerifier(Verifier* v);
    Verifier* verifier_; // Pointer back to the main verifier state
};


} // namespace examples::zkp
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
class RandomizingProver; // Forward declare

// --- Prover Secrets ---
struct R1CSProverSecrets {
    std::vector<yacl::math::MPInt> a_L;
    std::vector<yacl::math::MPInt> a_R;
    std::vector<yacl::math::MPInt> a_O;
    std::vector<yacl::math::MPInt> v;
    std::vector<yacl::math::MPInt> v_blinding;
};

/**
 * @brief R1CS Prover implementation based on reference Rust code.
 */
class Prover {
 public:
    // Type for deferred constraints callback, takes pointer to avoid lifetime issues
    using RandomizationCallback = std::function<void(RandomizingProver*)>;

    /**
     * @brief Construct a new Prover instance.
     * @param pc_gens Pedersen generators (non-owning pointer).
     * @param transcript The proof transcript (non-owning pointer).
     */
    Prover(const PedersenGens* pc_gens, SimpleTranscript* transcript);

    // --- ConstraintSystem Methods ---
    /** @brief Get mutable access to the transcript. */
    SimpleTranscript* Transcript();

    /** @brief Allocate and constrain multiplication gate variables. */
    std::tuple<Variable, Variable, Variable> Multiply(LinearCombination left, LinearCombination right);

    /** @brief Allocate a single low-level variable (input to a multiplier). */
    Variable Allocate(std::optional<yacl::math::MPInt> assignment);

    /** @brief Allocate a full multiplication gate with inputs/output. */
    std::tuple<Variable, Variable, Variable> AllocateMultiplier(
        std::optional<std::pair<yacl::math::MPInt, yacl::math::MPInt>> input_assignments);

    /** @brief Get metrics about the constraint system. */
    R1CSMetrics GetMetrics() const;

    /** @brief Add a constraint that a linear combination evaluates to zero. */
    void Constrain(LinearCombination lc);

    // --- Randomization ---
    /** @brief Defer constraints to the randomization phase. */
    void SpecifyRandomizedConstraints(RandomizationCallback callback);

    // --- High-level Variable Commitment ---
    /** @brief Commit to a high-level variable 'v' with blinding 'v_blinding'. */
    std::pair<yacl::crypto::EcPoint, Variable> Commit(
        const yacl::math::MPInt& v, const yacl::math::MPInt& v_blinding);

    // --- Proving ---
    /**
     * @brief Consumes the Prover to produce an R1CSProof.
     * @param bp_gens Bulletproof generators (non-owning reference). Capacity must be sufficient.
     * @return R1CSProof The generated proof.
     */
    R1CSProof Prove(const BulletproofGens& bp_gens);

    // --- Helper ---
    /** @brief Evaluate a linear combination using the prover's secret values. */
    yacl::math::MPInt EvalLC(const LinearCombination& lc) const;


 private:
    friend class RandomizingProver; // Allow access

    SimpleTranscript* transcript_;
    const PedersenGens* pc_gens_;
    std::vector<LinearCombination> constraints_; // Combined constraints
    R1CSProverSecrets secrets_;
    std::vector<RandomizationCallback> deferred_constraints_;
    std::optional<size_t> pending_multiplier_;
    size_t num_multipliers_phase1_ = 0; // Track for splitting phases

    // Internal helper for flattening constraints into weight vectors
    void FlattenedConstraints(
        const yacl::math::MPInt& z,
        const std::shared_ptr<yacl::crypto::EcGroup>& curve,
        std::vector<yacl::math::MPInt>& wL, // Output: weights for a_L
        std::vector<yacl::math::MPInt>& wR, // Output: weights for a_R
        std::vector<yacl::math::MPInt>& wO, // Output: weights for a_O
        std::vector<yacl::math::MPInt>& wV  // Output: weights for V
    ); // No wc needed for prover

    // Internal helper to run randomization phase
    void RunRandomizationPhase();

    // Helper for optimized inner product calculation <vec, points[start..end)>
    yacl::crypto::EcPoint InnerProductMultiply(
        const std::shared_ptr<yacl::crypto::EcGroup>& curve,
        const std::vector<yacl::math::MPInt>& vec,
        const std::vector<yacl::crypto::EcPoint>& points, // Assumes points.size() >= end
        size_t start, size_t end // Range [start, end)
    );
     // Overload for full vector IP
     yacl::crypto::EcPoint InnerProductMultiply(
        const std::shared_ptr<yacl::crypto::EcGroup>& curve,
        const std::vector<yacl::math::MPInt>& vec,
        const std::vector<yacl::crypto::EcPoint>& points
    );

     // Helper for padding vectors
     void PadVector(std::vector<yacl::math::MPInt>& vec, size_t target_size, const yacl::math::MPInt& pad_value);

     // Helper to get curve
     std::shared_ptr<yacl::crypto::EcGroup> GetCurve() const;
};


/**
 * @brief Wrapper for the Prover during the randomization phase.
 */
class RandomizingProver {
public:
    // --- ConstraintSystem Methods (forwarded) ---
    SimpleTranscript* Transcript();
    std::tuple<Variable, Variable, Variable> Multiply(LinearCombination left, LinearCombination right);
    Variable Allocate(std::optional<yacl::math::MPInt> assignment);
    std::tuple<Variable, Variable, Variable> AllocateMultiplier(
         std::optional<std::pair<yacl::math::MPInt, yacl::math::MPInt>> input_assignments);
    R1CSMetrics GetMetrics() const;
    void Constrain(LinearCombination lc);

    // --- RandomizedConstraintSystem Method ---
    /** @brief Generate a challenge scalar bound to the transcript state. */
    yacl::math::MPInt ChallengeScalar(const std::string& label);

private:
    friend class Prover;
    explicit RandomizingProver(Prover* p);
    Prover* prover_; // Pointer back to the main prover state
};


} // namespace examples::zkp
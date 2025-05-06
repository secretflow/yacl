#include "zkp/bulletproofs/r1cs/r1cs_verifier.h"

#include <vector>
#include <numeric> // For std::accumulate
#include <optional>
#include <iterator> // For std::back_inserter

#include "zkp/bulletproofs/r1cs/r1cs.h"     // Include base definitions
#include "zkp/bulletproofs/generators.h"
#include "zkp/bulletproofs/util.h"         // For helpers like ExpIterVector etc.
#include "yacl/crypto/rand/rand.h"     

namespace examples::zkp {

// --- Verifier Implementation ---

Verifier::Verifier(SimpleTranscript* transcript)
    : transcript_(transcript), pending_multiplier_(std::nullopt), num_multipliers_phase1_(0) {
    YACL_ENFORCE(transcript_ != nullptr, "Transcript cannot be null");
    transcript_->R1csDomainSep();
}

// Helper to get curve context - assumes it's available via pc_gens in Verify
// This might need adjustment depending on how pc_gens is accessed.
// For now, methods needing curve will take it as arg or assume Verify provides it.
// std::shared_ptr<yacl::crypto::EcGroup> Verifier::GetCurve() const {
//      YACL_THROW("Verifier doesn't own curve directly"); // Needs context
// }


SimpleTranscript* Verifier::Transcript() {
    return transcript_;
}

// Verifier doesn't need assignments, just allocates variables
std::tuple<Variable, Variable, Variable> Verifier::Multiply(
    LinearCombination left, LinearCombination right) {
    size_t idx = num_vars_++; // Increment number of multipliers

    Variable l_var(VariableType::MultiplierLeft, idx);
    Variable r_var(VariableType::MultiplierRight, idx);
    Variable o_var(VariableType::MultiplierOutput, idx);

    // Add constraints: left_lc - l_var = 0, right_lc - r_var = 0
    left -= l_var;
    right -= r_var;
    Constrain(std::move(left));
    Constrain(std::move(right));

    return std::make_tuple(l_var, r_var, o_var);
}

Variable Verifier::Allocate(std::optional<yacl::math::MPInt> /*assignment*/) {
    // Verifier ignores assignment
     if (!pending_multiplier_.has_value()) {
        size_t i = num_vars_++; // Increment count for the new multiplier
        pending_multiplier_ = i;
        return Variable(VariableType::MultiplierLeft, i);
    } else {
        size_t i = pending_multiplier_.value();
        pending_multiplier_ = std::nullopt;
        return Variable(VariableType::MultiplierRight, i);
    }
}

std::tuple<Variable, Variable, Variable> Verifier::AllocateMultiplier(
    std::optional<std::pair<yacl::math::MPInt, yacl::math::MPInt>> /*input_assignments*/) {
    // Verifier ignores assignment
    size_t idx = num_vars_++; // Increment count for the new multiplier

    Variable l_var(VariableType::MultiplierLeft, idx);
    Variable r_var(VariableType::MultiplierRight, idx);
    Variable o_var(VariableType::MultiplierOutput, idx);

    return std::make_tuple(l_var, r_var, o_var);
}


R1CSMetrics Verifier::GetMetrics() const {
     return R1CSMetrics{
        num_vars_, // Number of multipliers tracked by num_vars_
        constraints_.size() + deferred_constraints_.size(),
        constraints_.size(),
        deferred_constraints_.size()
    };
}

void Verifier::Constrain(LinearCombination lc) {
    constraints_.push_back(std::move(lc));
}

void Verifier::SpecifyRandomizedConstraints(RandomizationCallback callback) {
     deferred_constraints_.push_back(std::move(callback));
}

Variable Verifier::Commit(const yacl::crypto::EcPoint& V_commitment) {
    size_t i = V_commitments_.size();
    V_commitments_.push_back(V_commitment); // Store commitment

    // Add commitment to transcript
    // Need curve context for serialization format consistency
    transcript_->AppendPoint("V", V_commitment, nullptr); // Pass nullptr if context unknown here

    return Variable(VariableType::Committed, i);
}


void Verifier::FlattenedConstraints(
    const yacl::math::MPInt& z,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    std::vector<yacl::math::MPInt>& wL,
    std::vector<yacl::math::MPInt>& wR,
    std::vector<yacl::math::MPInt>& wO,
    std::vector<yacl::math::MPInt>& wV,
    yacl::math::MPInt& wc) {

    size_t n = num_vars_;        // Total number of multipliers
    size_t m = V_commitments_.size(); // Total number of committed variables
    const auto& order = curve->GetOrder();

    wL.assign(n, yacl::math::MPInt(0));
    wR.assign(n, yacl::math::MPInt(0));
    wO.assign(n, yacl::math::MPInt(0));
    wV.assign(m, yacl::math::MPInt(0));
    wc = yacl::math::MPInt(0);

    yacl::math::MPInt exp_z = z;
    yacl::math::MPInt minus_one = order - yacl::math::MPInt(1);

    // Important: Process constraints added in *both* phases
    for (const LinearCombination& lc : constraints_) {
        for (const auto& term : lc.terms) {
            const Variable& var = term.first;
            const yacl::math::MPInt& coeff = term.second;
            yacl::math::MPInt weighted_coeff = exp_z.MulMod(coeff, order);

            switch (var.type) {
                case VariableType::MultiplierLeft:
                     YACL_ENFORCE(var.index < n, "Invalid index in flattened L (Verifier)");
                    wL[var.index] = wL[var.index].AddMod(weighted_coeff, order);
                    break;
                case VariableType::MultiplierRight:
                     YACL_ENFORCE(var.index < n, "Invalid index in flattened R (Verifier)");
                    wR[var.index] = wR[var.index].AddMod(weighted_coeff, order);
                    break;
                case VariableType::MultiplierOutput:
                     YACL_ENFORCE(var.index < n, "Invalid index in flattened O (Verifier)");
                    wO[var.index] = wO[var.index].AddMod(weighted_coeff, order);
                    break;
                case VariableType::Committed:
                     YACL_ENFORCE(var.index < m, "Invalid index in flattened V (Verifier)");
                    wV[var.index] = wV[var.index].AddMod(weighted_coeff.MulMod(minus_one, order), order);
                    break;
                case VariableType::One:
                    wc = wc.AddMod(weighted_coeff.MulMod(minus_one, order), order);
                    break;
                 default:
                    YACL_THROW("Invalid variable type in FlattenedConstraints (Verifier)");
            }
        }
        exp_z = exp_z.MulMod(z, order);
    }
}

void Verifier::RunRandomizationPhase() {
     // Handle any pending multiplier from phase 1
     if (pending_multiplier_.has_value()) {
         pending_multiplier_ = std::nullopt; // Verifier just tracks structure
     }
     num_multipliers_phase1_ = num_vars_; // Record size after phase 1

     if (deferred_constraints_.empty()) {
         transcript_->R1cs1phaseDomainSep();
     } else {
         transcript_->R1cs2phaseDomainSep();
         RandomizingVerifier randomizing_verifier(this);
         std::vector<RandomizationCallback> callbacks = std::move(deferred_constraints_);
         deferred_constraints_.clear();
         for (auto& callback : callbacks) {
             callback(&randomizing_verifier); // Callback modifies Verifier state
         }
         // Handle pending multiplier from phase 2
          if (pending_multiplier_.has_value()) {
            pending_multiplier_ = std::nullopt;
          }
     }
     pending_multiplier_ = std::nullopt; // Clear any pending state
}


bool Verifier::Verify(const R1CSProof& proof,
                      const PedersenGens& pc_gens,
                      const BulletproofGens& bp_gens) {
    // Get curve and order
    auto curve = pc_gens.GetCurve(); // Get curve from pc_gens
    const auto& order = curve->GetOrder();
    yacl::math::MPInt one(1);
    yacl::math::MPInt zero(0);
    yacl::math::MPInt minus_one = order - one;

    // --- Transcript Replay and Challenge Derivation ---
    // 1. Initial State & High-Level Commitments (V)
    transcript_->R1csDomainSep();
    transcript_->AppendU64("m", V_commitments_.size());
    for (const auto& V : V_commitments_) {
        transcript_->AppendPoint("V", V, curve);
    }

    // 2. Phase 1 Commitments (A_I1, A_O1, S1)
    // Use ValidateAndAppendPoint to check for non-identity points, matching Rust
    transcript_->ValidateAndAppendPoint("A_I1", proof.A_I1, curve);
    transcript_->ValidateAndAppendPoint("A_O1", proof.A_O1, curve);
    transcript_->ValidateAndAppendPoint("S1", proof.S1, curve);

    // 3. Run Randomization Phase (executes callbacks, derives challenges internally)
    RunRandomizationPhase(); // Advances transcript state

    // 4. Phase 2 Commitments (A_I2, A_O2, S2)
    // Rust uses append_point here, not validate_and_append_point
    transcript_->AppendPoint("A_I2", proof.A_I2, curve);
    transcript_->AppendPoint("A_O2", proof.A_O2, curve);
    transcript_->AppendPoint("S2", proof.S2, curve);

    // 5. Derive y, z
    yacl::math::MPInt y = transcript_->ChallengeScalar("y", curve);
    yacl::math::MPInt z = transcript_->ChallengeScalar("z", curve);

    // 6. Commitments T1..T6
    // Use ValidateAndAppendPoint matching Rust
    transcript_->ValidateAndAppendPoint("T_1", proof.T_1, curve);
    transcript_->ValidateAndAppendPoint("T_3", proof.T_3, curve);
    transcript_->ValidateAndAppendPoint("T_4", proof.T_4, curve);
    transcript_->ValidateAndAppendPoint("T_5", proof.T_5, curve);
    transcript_->ValidateAndAppendPoint("T_6", proof.T_6, curve);

    // 7. Derive u, x
    yacl::math::MPInt u = transcript_->ChallengeScalar("u", curve);
    yacl::math::MPInt x = transcript_->ChallengeScalar("x", curve);

    // 8. Commit t_x, t_x_blinding, e_blinding
    transcript_->AppendScalar("t_x", proof.t_x);
    transcript_->AppendScalar("t_x_blinding", proof.t_x_blinding);
    transcript_->AppendScalar("e_blinding", proof.e_blinding);

    // 9. Derive w
    yacl::math::MPInt w = transcript_->ChallengeScalar("w", curve);

    // --- Prepare for Verification Check ---
    size_t n = num_vars_; // Total number of multipliers
    size_t n1 = num_multipliers_phase1_;
    size_t n2 = n - n1;
    size_t m = V_commitments_.size();
    size_t padded_n = NextPowerOfTwo(n);
    if (padded_n == 0 && n > 0) padded_n = 1;
    size_t pad = padded_n - n;

    YACL_ENFORCE(bp_gens.gens_capacity() >= padded_n, "Verifier::Verify: BP gens capacity < padded_n");
    auto gens = bp_gens.Share(0); // Get generators for party 0

    // Compute weights wL, wR, wO, wV, wc
    std::vector<yacl::math::MPInt> wL, wR, wO, wV;
    yacl::math::MPInt wc;
    FlattenedConstraints(z, curve, wL, wR, wO, wV, wc);

    // Get IPP verification scalars (advances transcript)
    auto [u_sq, u_inv_sq, s] = proof.ipp_proof.VerificationScalars(padded_n, transcript_, curve);
    YACL_ENFORCE(s.size() == padded_n, "Verifier::Verify: IPP s vector size mismatch");
    std::vector<yacl::math::MPInt> s_inv(s.rbegin(), s.rend());

    yacl::math::MPInt a = proof.ipp_proof.GetA();
    yacl::math::MPInt b = proof.ipp_proof.GetB();

    // --- Assemble Final Verification MSM Check ("mega_check") ---
    yacl::math::MPInt y_inv = y.InvertMod(order);
    std::vector<yacl::math::MPInt> y_inv_pows = ExpIterVector(y_inv, padded_n, curve);

    std::vector<yacl::math::MPInt> mega_scalars;
    std::vector<yacl::crypto::EcPoint> mega_points;
    // Reserve size (approximate)
    size_t reserve_size = m + 14 + 2 * padded_n + 2 * proof.ipp_proof.GetLVec().size();
    mega_scalars.reserve(reserve_size);
    mega_points.reserve(reserve_size);

    // Term 1: A_I1^x
    mega_scalars.push_back(x); mega_points.push_back(proof.A_I1);
    // Term 2: A_O1^x^2
    yacl::math::MPInt x_sq = x.MulMod(x, order);
    mega_scalars.push_back(x_sq); mega_points.push_back(proof.A_O1);
    // Term 3: S1^x^3
    yacl::math::MPInt x_cub = x_sq.MulMod(x, order);
    mega_scalars.push_back(x_cub); mega_points.push_back(proof.S1);
    // Term 4: A_I2^(u*x)
    mega_scalars.push_back(u.MulMod(x, order)); mega_points.push_back(proof.A_I2);
    // Term 5: A_O2^(u*x^2)
    mega_scalars.push_back(u.MulMod(x_sq, order)); mega_points.push_back(proof.A_O2);
    // Term 6: S2^(u*x^3)
    mega_scalars.push_back(u.MulMod(x_cub, order)); mega_points.push_back(proof.S2);

    // Term 7: V_j terms need random challenge r
    yacl::math::MPInt r; r.RandomLtN(order, &r); // Use YACL's RNG
    yacl::math::MPInt rxx = r.MulMod(x_sq, order);
    for (size_t j = 0; j < m; ++j) {
        mega_scalars.push_back(wV[j].MulMod(rxx, order));
        mega_points.push_back(V_commitments_[j]);
    }

    // Term 8: T_i terms
    yacl::math::MPInt rx = r.MulMod(x, order);
    yacl::math::MPInt rxxx = rxx.MulMod(x, order);
    yacl::math::MPInt rxxxx = rxxx.MulMod(x, order);
    yacl::math::MPInt rxxxxx = rxxxx.MulMod(x, order);
    yacl::math::MPInt rxxxxxx = rxxxxx.MulMod(x, order);
    mega_scalars.push_back(rx);      mega_points.push_back(proof.T_1);
    mega_scalars.push_back(rxxx);    mega_points.push_back(proof.T_3);
    mega_scalars.push_back(rxxxx);   mega_points.push_back(proof.T_4);
    mega_scalars.push_back(rxxxxx);  mega_points.push_back(proof.T_5);
    mega_scalars.push_back(rxxxxxx); mega_points.push_back(proof.T_6);

    // Term 9: Pedersen G base B
    // Scalar: w*(t_x - a*b) + r*(x^2*(wc + delta) - t_x)
    // Need R1CS delta = <y^{-n} \circ wR padded, wL padded>
    std::vector<yacl::math::MPInt> padded_wR = wR; PadVector(padded_wR, padded_n, zero); // Pad wR
    std::vector<yacl::math::MPInt> yneg_wR_padded(padded_n);
    for(size_t i=0; i<padded_n; ++i) yneg_wR_padded[i] = padded_wR[i].MulMod(y_inv_pows[i], order);
    std::vector<yacl::math::MPInt> padded_wL = wL; PadVector(padded_wL, padded_n, zero); // Pad wL
    yacl::math::MPInt delta = InnerProduct(padded_wL, yneg_wR_padded, curve);

    yacl::math::MPInt B_scalar_part1 = proof.t_x.SubMod(a.MulMod(b, order), order).MulMod(w, order);
    yacl::math::MPInt B_scalar_part2 = wc.AddMod(delta, order).MulMod(x_sq, order).SubMod(proof.t_x, order).MulMod(r, order);
    mega_scalars.push_back(B_scalar_part1.AddMod(B_scalar_part2, order));
    mega_points.push_back(pc_gens.B); // B

    // Term 10: Pedersen H base B_blinding
    // Scalar: -(e_blinding + r*t_x_blinding)
    yacl::math::MPInt H_scalar = proof.e_blinding.AddMod(r.MulMod(proof.t_x_blinding, order), order);
    mega_scalars.push_back(H_scalar.MulMod(minus_one, order));
    mega_points.push_back(pc_gens.B_blinding); // B_blinding

    // Term 11: Bulletproof G vectors
    // Scalar: u^k * (x*y^{-i}*wR_i - a*s_i)
    std::vector<yacl::crypto::EcPoint> G_basis = gens.G(padded_n);
    yacl::math::MPInt u_pow = one;
    for(size_t i=0; i<padded_n; ++i) {
        if (i == n1) u_pow = u; // Switch u factor
        yacl::math::MPInt g_scalar = x.MulMod(y_inv_pows[i], order);
        g_scalar = g_scalar.MulMod((i < wR.size() ? wR[i] : zero), order); // Use wR padded implicitly via check
        g_scalar = g_scalar.SubMod(a.MulMod(s[i], order), order);
        mega_scalars.push_back(g_scalar.MulMod(u_pow, order));
        mega_points.push_back(G_basis[i]);
    }

    // Term 12: Bulletproof H vectors
    // Scalar: u^k * y^{-i} * (x*wL_i + wO_i - b*s_inv_i - 1)
    std::vector<yacl::crypto::EcPoint> H_basis = gens.H(padded_n);
    u_pow = one;
    for(size_t i=0; i<padded_n; ++i) {
         if (i == n1) u_pow = u;
         yacl::math::MPInt term_in_paren = x.MulMod((i < wL.size() ? wL[i] : zero), order);
         term_in_paren = term_in_paren.AddMod((i < wO.size() ? wO[i] : zero), order);
         term_in_paren = term_in_paren.SubMod(b.MulMod(s_inv[i], order), order);
         term_in_paren = term_in_paren.SubMod(one, order); // Subtract 1
         mega_scalars.push_back(u_pow.MulMod(y_inv_pows[i], order).MulMod(term_in_paren, order));
         mega_points.push_back(H_basis[i]);
    }

    // Term 13: IPP L_vec
    // Scalar: u_sq_j
    const auto& ipp_L_vec = proof.ipp_proof.GetLVec();
    YACL_ENFORCE(u_sq.size() == ipp_L_vec.size(), "IPP L/u_sq size mismatch");
    for(size_t j=0; j < u_sq.size(); ++j) {
        mega_scalars.push_back(u_sq[j]);
        mega_points.push_back(ipp_L_vec[j]);
    }

    // Term 14: IPP R_vec
    // Scalar: u_inv_sq_j
    const auto& ipp_R_vec = proof.ipp_proof.GetRVec();
    YACL_ENFORCE(u_inv_sq.size() == ipp_R_vec.size(), "IPP R/u_inv_sq size mismatch");
    for(size_t j=0; j < u_inv_sq.size(); ++j) {
        mega_scalars.push_back(u_inv_sq[j]);
        mega_points.push_back(ipp_R_vec[j]);
    }

    // --- Final Check ---
    yacl::crypto::EcPoint final_check = MultiScalarMul(curve, mega_scalars, mega_points);

    bool is_identity = curve->IsInfinity(final_check);
     if (!is_identity) {
         std::cerr << "R1CS Verification Failed: Mega-Check MSM is not identity." << std::endl;
     }
    return is_identity;
}


// --- RandomizingVerifier Implementation ---
RandomizingVerifier::RandomizingVerifier(Verifier* v) : verifier_(v) {
    YACL_ENFORCE(verifier_ != nullptr, "Verifier cannot be null");
}

SimpleTranscript* RandomizingVerifier::Transcript() {
     return verifier_->Transcript();
}
std::tuple<Variable, Variable, Variable> RandomizingVerifier::Multiply(LinearCombination left, LinearCombination right) {
    return verifier_->Multiply(std::move(left), std::move(right));
}
Variable RandomizingVerifier::Allocate(std::optional<yacl::math::MPInt> assignment) {
     return verifier_->Allocate(std::move(assignment));
}
std::tuple<Variable, Variable, Variable> RandomizingVerifier::AllocateMultiplier(
     std::optional<std::pair<yacl::math::MPInt, yacl::math::MPInt>> input_assignments) {
     return verifier_->AllocateMultiplier(std::move(input_assignments));
}
R1CSMetrics RandomizingVerifier::GetMetrics() const {
     return verifier_->GetMetrics();
}
void RandomizingVerifier::Constrain(LinearCombination lc) {
     verifier_->Constrain(std::move(lc));
}

yacl::math::MPInt RandomizingVerifier::ChallengeScalar(const std::string& label) {
    // Verifier needs curve context to generate scalar in correct field
    // Assume Verifier can get it, e.g., via pc_gens passed to Verify
    // This implies the RandomizationCallback needs access to curve somehow,
    // or ChallengeScalar needs curve passed in.
    // Let's assume the Verifier has a way to get the curve (e.g., stores it).
    // If not, this needs refactoring.
    // **Temporary:** Assuming verifier stores curve or pc_gens pointer.
    // This part is tricky without seeing the full Verifier structure.
    // *** Placeholder - needs proper curve access ***
     std::shared_ptr<yacl::crypto::EcGroup> curve_ptr = nullptr; // = verifier_->GetCurve();
     YACL_ENFORCE(curve_ptr != nullptr, "Curve context needed for ChallengeScalar");
     return verifier_->Transcript()->ChallengeScalar(label, curve_ptr);
}


} // namespace examples::zkp
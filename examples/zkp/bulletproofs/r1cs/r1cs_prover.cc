#include "zkp/bulletproofs/r1cs/r1cs_prover.h"

#include <vector>
#include <numeric> // For std::accumulate
#include <optional>

#include "zkp/bulletproofs/r1cs/r1cs.h" // Include base definitions
#include "zkp/bulletproofs/generators.h"
#include "zkp/bulletproofs/util.h" // For helpers like ExpIterVector etc.
#include "yacl/crypto/Rand/Rand.h" // For random scalars

// Make sure fmt is included if using fmt::format in exceptions
#include "yacl/base/fmt_logging.h"

namespace examples::zkp {

// --- Prover Implementation ---

Prover::Prover(const PedersenGens* pc_gens, SimpleTranscript* transcript)
    : transcript_(transcript), pc_gens_(pc_gens), pending_multiplier_(std::nullopt) {
    YACL_ENFORCE(transcript_ != nullptr, "Transcript cannot be null");
    YACL_ENFORCE(pc_gens_ != nullptr, "PedersenGens cannot be null");
    transcript_->R1csDomainSep(); 
}

SimpleTranscript* Prover::Transcript() {
    return transcript_;
}

std::tuple<Variable, Variable, Variable> Prover::Multiply(
    LinearCombination left, LinearCombination right) {
    // Evaluate linear combinations to get scalar values
    yacl::math::MPInt l = EvalLC(left);
    yacl::math::MPInt r = EvalLC(right);
    yacl::math::MPInt o = l.MulMod(r, pc_gens_->GetCurve()->GetOrder()); // Ensure curve context

    // Allocate variables for l, r, o
    size_t idx = secrets_.a_L.size(); // Index for the new multiplier gate
    secrets_.a_L.push_back(l);
    secrets_.a_R.push_back(r);
    secrets_.a_O.push_back(o);

    Variable l_var(VariableType::MultiplierLeft, idx);
    Variable r_var(VariableType::MultiplierRight, idx);
    Variable o_var(VariableType::MultiplierOutput, idx);

    // Add constraints: left_lc - l_var = 0, right_lc - r_var = 0
    left = left - l_var;   // Uses operator-
    right = right - r_var; // Uses operator-
    Constrain(std::move(left));
    Constrain(std::move(right));

    return std::make_tuple(l_var, r_var, o_var);
}

Variable Prover::Allocate(std::optional<yacl::math::MPInt> assignment) {
    YACL_ENFORCE(assignment.has_value(), "Prover::Allocate requires an assignment");
    const yacl::math::MPInt& scalar = assignment.value();

    if (!pending_multiplier_.has_value()) {
        // Start a new multiplier
        size_t i = secrets_.a_L.size();
        pending_multiplier_ = i;
        secrets_.a_L.push_back(scalar);
        secrets_.a_R.push_back(yacl::math::MPInt(0)); // Placeholder
        secrets_.a_O.push_back(yacl::math::MPInt(0)); // Placeholder
        return Variable(VariableType::MultiplierLeft, i);
    } else {
        // Complete the pending multiplier
        size_t i = pending_multiplier_.value();
        pending_multiplier_ = std::nullopt; // Clear pending state
        secrets_.a_R[i] = scalar;
        // Calculate output: O = L * R
        secrets_.a_O[i] = secrets_.a_L[i].MulMod(secrets_.a_R[i], pc_gens_->GetCurve()->GetOrder());
        return Variable(VariableType::MultiplierRight, i);
    }
}

std::tuple<Variable, Variable, Variable> Prover::AllocateMultiplier(
    std::optional<std::pair<yacl::math::MPInt, yacl::math::MPInt>> input_assignments) {
    YACL_ENFORCE(input_assignments.has_value(), "Prover::AllocateMultiplier requires assignments");
    const auto& [l, r] = input_assignments.value();
    yacl::math::MPInt o = l.MulMod(r, pc_gens_->GetCurve()->GetOrder());

    size_t idx = secrets_.a_L.size();
    secrets_.a_L.push_back(l);
    secrets_.a_R.push_back(r);
    secrets_.a_O.push_back(o);

    Variable l_var(VariableType::MultiplierLeft, idx);
    Variable r_var(VariableType::MultiplierRight, idx);
    Variable o_var(VariableType::MultiplierOutput, idx);

    return std::make_tuple(l_var, r_var, o_var);
}

R1CSMetrics Prover::GetMetrics() const {
    // Note: deferred_constraints might contain multiple actual constraints
    return R1CSMetrics{
        secrets_.a_L.size(), // Multipliers = number of L values
        constraints_.size() + deferred_constraints_.size(), // Total constraints = phase1 + phase2 callbacks
        constraints_.size(), // Phase 1 constraints
        deferred_constraints_.size() // Phase 2 Callbacks (approximates phase 2 constraints)
    };
}

void Prover::Constrain(LinearCombination lc) {
    // Optional: Check evaluation is zero? Requires curve context.
    // yacl::math::MPInt eval = EvalLC(lc);
    // YACL_ENFORCE(eval.IsZero(), "Constraint does not evaluate to zero");
    constraints_.push_back(std::move(lc));
}

void Prover::SpecifyRandomizedConstraints(RandomizationCallback callback) {
    deferred_constraints_.push_back(std::move(callback));
}

std::pair<yacl::crypto::EcPoint, Variable> Prover::Commit(
    const yacl::math::MPInt& v, const yacl::math::MPInt& v_blinding) {
    size_t i = secrets_.v.size();
    secrets_.v.push_back(v);
    secrets_.v_blinding.push_back(v_blinding);

    // Commit using Pedersen Gens
    yacl::crypto::EcPoint V = pc_gens_->Commit(v, v_blinding);

    // Need to decide on a convention. Let's assume AppendPoint handles it.
    transcript_->AppendPoint("V", V, pc_gens_->GetCurve()); // Pass curve for serialization

    return {V, Variable(VariableType::Committed, i)};
}


yacl::math::MPInt Prover::EvalLC(const LinearCombination& lc) const {
    yacl::math::MPInt sum(0);
    const auto& order = pc_gens_->GetCurve()->GetOrder(); // Need curve context

    for (const auto& term : lc.terms) {
        const Variable& var = term.first;
        const yacl::math::MPInt& coeff = term.second;
        yacl::math::MPInt val;

        switch (var.type) {
            case VariableType::MultiplierLeft:
                YACL_ENFORCE(var.index < secrets_.a_L.size(), "Invalid var index");
                val = secrets_.a_L[var.index];
                break;
            case VariableType::MultiplierRight:
                 YACL_ENFORCE(var.index < secrets_.a_R.size(), "Invalid var index");
                val = secrets_.a_R[var.index];
                break;
            case VariableType::MultiplierOutput:
                 YACL_ENFORCE(var.index < secrets_.a_O.size(), "Invalid var index");
                val = secrets_.a_O[var.index];
                break;
            case VariableType::Committed:
                 YACL_ENFORCE(var.index < secrets_.v.size(), "Invalid var index");
                val = secrets_.v[var.index];
                break;
            case VariableType::One:
                val = yacl::math::MPInt(1);
                break;
        }
        sum = sum.AddMod(coeff.MulMod(val, order), order);
    }
    return sum;
}


void Prover::FlattenedConstraints(
    const yacl::math::MPInt& z,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    std::vector<yacl::math::MPInt>& wL,
    std::vector<yacl::math::MPInt>& wR,
    std::vector<yacl::math::MPInt>& wO,
    std::vector<yacl::math::MPInt>& wV) {

    size_t n = secrets_.a_L.size(); // Total number of multipliers
    size_t m = secrets_.v.size();   // Total number of committed variables
    const auto& order = curve->GetOrder();

    wL.assign(n, yacl::math::MPInt(0));
    wR.assign(n, yacl::math::MPInt(0));
    wO.assign(n, yacl::math::MPInt(0));
    wV.assign(m, yacl::math::MPInt(0));

    yacl::math::MPInt exp_z = z;
    yacl::math::MPInt minus_one = order - yacl::math::MPInt(1);

    for (LinearCombination& lc : constraints_) { // Process constraints
        // Optional: Optimize before processing
        // lc.Optimize(curve);
        for (const auto& term : lc.terms) {
            const Variable& var = term.first;
            const yacl::math::MPInt& coeff = term.second;
            yacl::math::MPInt weighted_coeff = exp_z.MulMod(coeff, order);

            switch (var.type) {
                case VariableType::MultiplierLeft:
                    wL[var.index] = wL[var.index].AddMod(weighted_coeff, order);
                    break;
                case VariableType::MultiplierRight:
                    wR[var.index] = wR[var.index].AddMod(weighted_coeff, order);
                    break;
                case VariableType::MultiplierOutput:
                    wO[var.index] = wO[var.index].AddMod(weighted_coeff, order);
                    break;
                case VariableType::Committed:
                    // We need -(exp_z * coeff) = exp_z * coeff * (-1)
                    wV[var.index] = wV[var.index].AddMod(weighted_coeff.MulMod(minus_one, order), order);
                    break;
                case VariableType::One:
                    // Prover ignores constant terms in weights
                    break;
            }
        }
        exp_z = exp_z.MulMod(z, order); // z^k -> z^(k+1)
    }
}


void Prover::RunRandomizationPhase() {
    // Handle any half-assigned multiplier from phase 1
    if (pending_multiplier_.has_value()) {
        size_t i = pending_multiplier_.value();
        // If right is still zero, output must be zero.
        // Assign a_R = 0 explicitly, a_O is already 0.
        secrets_.a_R[i] = yacl::math::MPInt(0);
        secrets_.a_O[i] = yacl::math::MPInt(0);
        pending_multiplier_ = std::nullopt;
    }
    num_multipliers_phase1_ = secrets_.a_L.size(); // Record size after phase 1

    if (deferred_constraints_.empty()) {
        transcript_->R1cs1phaseDomainSep();
    } else {
        transcript_->R1cs2phaseDomainSep();
        RandomizingProver randomizing_prover(this);
        // Execute callbacks
        // Need to take ownership to avoid iterator invalidation if callback adds constraints
        std::vector<RandomizationCallback> callbacks = std::move(deferred_constraints_);
        deferred_constraints_.clear(); // Ensure it's empty
        for (auto& callback : callbacks) {
            callback(&randomizing_prover); // Callback modifies the Prover state via the wrapper
        }
        // Handle any half-assigned multiplier from phase 2
        if (pending_multiplier_.has_value()) {
             size_t i = pending_multiplier_.value();
             secrets_.a_R[i] = yacl::math::MPInt(0); // Assign R=0, O=0
             secrets_.a_O[i] = yacl::math::MPInt(0);
             pending_multiplier_ = std::nullopt;
        }
    }
     // Clear pending multiplier after phase 2 finishes or if there was no phase 2
     pending_multiplier_ = std::nullopt;
}


R1CSProof Prover::Prove(const BulletproofGens& bp_gens) {
    auto curve = pc_gens_->GetCurve();
    const auto& order = curve->GetOrder();
    yacl::math::MPInt one(1);
    yacl::math::MPInt zero(0);

    // --- Phase 1 Commitments ---
    // Commit a length suffix for the number of high-level variables 'm'
    transcript_->AppendUint64("m", secrets_.v.size()); 

    // Create transcript RNG - simplified, just use YACL random for blindings


    // Commit to the first-phase low-level witness variables (aL1, aR1, aO1)
    RunRandomizationPhase(); // This completes phase 1 and potentially phase 2 constraints/vars
    size_t n1 = num_multipliers_phase1_;
    size_t n = secrets_.a_L.size(); // Total multipliers after phase 2
    size_t n2 = n - n1;

    YACL_ENFORCE(bp_gens.gens_capacity() >= n, "Prover::Prove: BP gens capacity < n");
    auto gens = bp_gens.Share(0); // Use party 0 share for single party proof

    // Generate blinding factors for phase 1
    yacl::math::MPInt i_blinding1, o_blinding1, s_blinding1;
    i_blinding1.RandomLtN(order, &i_blinding1);
    o_blinding1.RandomLtN(order, &o_blinding1);
    s_blinding1.RandomLtN(order, &s_blinding1);
    std::vector<yacl::math::MPInt> s_L1(n1), s_R1(n1);
    for(size_t i=0; i<n1; ++i) {
        s_L1[i].RandomLtN(order, &s_L1[i]);
        s_R1[i].RandomLtN(order, &s_R1[i]);
    }

    // Compute A_I1, A_O1, S1
    yacl::crypto::EcPoint A_I1 = pc_gens_->Commit(zero, i_blinding1); // i_blinding1 * H
    A_I1 = curve->Add(A_I1, InnerProductMultiply(curve, secrets_.a_L, gens.G(n1), 0, n1)); // <a_L1, G1>
    A_I1 = curve->Add(A_I1, InnerProductMultiply(curve, secrets_.a_R, gens.H(n1), 0, n1)); // <a_R1, H1>

    yacl::crypto::EcPoint A_O1 = pc_gens_->Commit(zero, o_blinding1); // o_blinding1 * H
    A_O1 = curve->Add(A_O1, InnerProductMultiply(curve, secrets_.a_O, gens.G(n1), 0, n1)); // <a_O1, G1>

    yacl::crypto::EcPoint S1 = pc_gens_->Commit(zero, s_blinding1); // s_blinding1 * H
    S1 = curve->Add(S1, InnerProductMultiply(curve, s_L1, gens.G(n1))); // <s_L1, G1>
    S1 = curve->Add(S1, InnerProductMultiply(curve, s_R1, gens.H(n1))); // <s_R1, H1>

    // Commit A_I1, A_O1, S1 to transcript
    transcript_->AppendPoint("A_I1", A_I1, curve);
    transcript_->AppendPoint("A_O1", A_O1, curve);
    transcript_->AppendPoint("S1", S1, curve);

    // --- Phase 2 Commitments ---
    bool has_phase2 = (n2 > 0);
    yacl::math::MPInt i_blinding2(0), o_blinding2(0), s_blinding2(0);
    std::vector<yacl::math::MPInt> s_L2(n2), s_R2(n2); // Empty if n2=0
    yacl::crypto::EcPoint A_I2 = curve->MulBase(zero); // Identity
    yacl::crypto::EcPoint A_O2 = curve->MulBase(zero); // Identity
    yacl::crypto::EcPoint S2 = curve->MulBase(zero); // Identity

    if (has_phase2) {
        i_blinding2.RandomLtN(order, &i_blinding2);
        o_blinding2.RandomLtN(order, &o_blinding2);
        s_blinding2.RandomLtN(order, &s_blinding2);
        for(size_t i=0; i<n2; ++i) {
            s_L2[i].RandomLtN(order, &s_L2[i]);
            s_R2[i].RandomLtN(order, &s_R2[i]);
        }

        // Compute A_I2, A_O2, S2 for the second phase variables [n1..n)
        A_I2 = pc_gens_->Commit(zero, i_blinding2);
        A_I2 = curve->Add(A_I2, InnerProductMultiply(curve, secrets_.a_L, gens.G(n), n1, n));
        A_I2 = curve->Add(A_I2, InnerProductMultiply(curve, secrets_.a_R, gens.H(n), n1, n));

        A_O2 = pc_gens_->Commit(zero, o_blinding2);
        A_O2 = curve->Add(A_O2, InnerProductMultiply(curve, secrets_.a_O, gens.G(n), n1, n));

        S2 = pc_gens_->Commit(zero, s_blinding2);
        S2 = curve->Add(S2, InnerProductMultiply(curve, s_L2, gens.G(n), n1, n));
        S2 = curve->Add(S2, InnerProductMultiply(curve, s_R2, gens.H(n), n1, n));
    }

    // Commit A_I2, A_O2, S2 to transcript
    transcript_->AppendPoint("A_I2", A_I2, curve);
    transcript_->AppendPoint("A_O2", A_O2, curve);
    transcript_->AppendPoint("S2", S2, curve);

    // --- Polynomial Construction ---
    yacl::math::MPInt y = transcript_->ChallengeScalar("y", curve);
    yacl::math::MPInt z = transcript_->ChallengeScalar("z", curve);

    std::vector<yacl::math::MPInt> wL, wR, wO, wV;
    FlattenedConstraints(z, curve, wL, wR, wO, wV); // Compute weights

    // Compute VecPoly6 for t(X) poly coefficients, 
    // l_poly.t1 = a_L + y^-n * wR
    // l_poly.t4 = s_L
    // r_poly.t1 = y^n * a_R + wL
    // r_poly.t3 = wO - y^n
    // r_poly.t4 = y^n * s_R
    // Compute coefficients of t(X) = <l(X), r(X)>
    // t1 = <l1, r0> + <l0, r1> --> <(aL + y^-n*wR), (wO - y^n)> + <0, (y^n*aR + wL)> = <(aL + y^-n*wR), (wO - y^n)>
    // t3 = <l1, r2> + <l2, r1> + <l0, r3> + <l3, r0> --> <(aL + y^-n*wR), 0> + <aO, (y^n*aR + wL)> + <0, y^n*sR> + <sL, (wO - y^n)>
    //    = <aO, y^n*aR + wL> + <sL, wO - y^n>
    // t4 = <l1, r3> + <l3, r1> --> <(aL + y^-n*wR), y^n*sR> + <sL, (y^n*aR + wL)>
    // t5 = <l2, r3> + <l3, r2> --> <aO, y^n*sR> + <sL, 0> = <aO, y^n*sR>
    // t6 = <l3, r3> --> <sL, y^n*sR>

    yacl::math::MPInt y_inv = y.InvertMod(order);
    std::vector<yacl::math::MPInt> y_inv_pows = ExpIterVector(y_inv, n, curve);
    std::vector<yacl::math::MPInt> y_pows = ExpIterVector(y, n, curve);

    yacl::math::MPInt t1(0), t3(0), t4(0), t5(0), t6(0);
    std::vector<yacl::math::MPInt> s_L_full = s_L1; s_L_full.insert(s_L_full.end(), s_L2.begin(), s_L2.end());
    std::vector<yacl::math::MPInt> s_R_full = s_R1; s_R_full.insert(s_R_full.end(), s_R2.begin(), s_R2.end());

    for(size_t i=0; i<n; ++i) {
        yacl::math::MPInt l1_i = secrets_.a_L[i].AddMod(y_inv_pows[i].MulMod(wR[i], order), order);
        yacl::math::MPInt r0_i = wO[i].SubMod(y_pows[i], order);
        yacl::math::MPInt r1_i = y_pows[i].MulMod(secrets_.a_R[i], order).AddMod(wL[i], order);
        yacl::math::MPInt l2_i = secrets_.a_O[i];
        yacl::math::MPInt l3_i = s_L_full[i];
        yacl::math::MPInt r3_i = y_pows[i].MulMod(s_R_full[i], order);

        t1 = t1.AddMod(l1_i.MulMod(r0_i, order), order);
        t3 = t3.AddMod(l2_i.MulMod(r1_i, order), order).AddMod(l3_i.MulMod(r0_i, order), order);
        t4 = t4.AddMod(l1_i.MulMod(r3_i, order), order).AddMod(l3_i.MulMod(r1_i, order), order);
        t5 = t5.AddMod(l2_i.MulMod(r3_i, order), order);
        t6 = t6.AddMod(l3_i.MulMod(r3_i, order), order);
    }

    // Generate blinding factors t_i_blinding
    yacl::math::MPInt t_1_blinding, t_3_blinding, t_4_blinding, t_5_blinding, t_6_blinding;
    t_1_blinding.RandomLtN(order, &t_1_blinding);
    t_3_blinding.RandomLtN(order, &t_3_blinding);
    t_4_blinding.RandomLtN(order, &t_4_blinding);
    t_5_blinding.RandomLtN(order, &t_5_blinding);
    t_6_blinding.RandomLtN(order, &t_6_blinding);

    // Compute commitments T_i
    yacl::crypto::EcPoint T_1 = pc_gens_->Commit(t1, t_1_blinding);
    yacl::crypto::EcPoint T_3 = pc_gens_->Commit(t3, t_3_blinding);
    yacl::crypto::EcPoint T_4 = pc_gens_->Commit(t4, t_4_blinding);
    yacl::crypto::EcPoint T_5 = pc_gens_->Commit(t5, t_5_blinding);
    yacl::crypto::EcPoint T_6 = pc_gens_->Commit(t6, t_6_blinding);

    // Commit T_i to transcript
    transcript_->AppendPoint("T_1", T_1, curve);
    transcript_->AppendPoint("T_3", T_3, curve);
    transcript_->AppendPoint("T_4", T_4, curve);
    transcript_->AppendPoint("T_5", T_5, curve);
    transcript_->AppendPoint("T_6", T_6, curve);

    // --- Evaluation and IPP ---
    yacl::math::MPInt u = transcript_->ChallengeScalar("u", curve); // Challenge for combining phase 1/2
    yacl::math::MPInt x = transcript_->ChallengeScalar("x", curve); // Evaluation challenge

    // Compute t(x) = t1*x + t3*x^3 + t4*x^4 + t5*x^5 + t6*x^6 + delta(y,z)*x^2
    // delta(y,z) is the term <aL - z*1 - sL*x, y^n(aR+z*1+sR*x) + zz*2^n>, i.e. <l(X), r(X) without polynomial terms>
    // The constant term t0 and quadratic term t2 are implicitly included via delta(y,z)*x^2?
    // Let's re-evaluate t(x) directly from polynomial eval.
    // t_poly = <l(X), r(X)>, t_poly is degree 6
    // Need VecPoly6 and Poly6 from util, or compute coeffs manually as done above for t1..t6
    // The special_inner_product gives t1..t6. We need t0 and t2.
    // t0 = <l0, r0> = <0, wO - y^n> = 0
    // t2 = <l1,r1>+<l0,r2>+<l2,r0> = <(aL+y^-n*wR), (y^n*aR+wL)> + <0,0> + <aO, (wO-y^n)>
    // t2 = <aL, y^n*aR> + <aL, wL> + <y^-n*wR, y^n*aR> + <y^-n*wR, wL> + <aO, wO> - <aO, y^n>
    // t2 = y^n<aL,aR> + <aL,wL> + <wR,aR> + y^-n<wR,wL> + <aO,wO> - y^n<aO,1>

    // The delta term from range proof is related but not identical.
    // Let's calculate t(x) using the evaluated coefficients.
    yacl::math::MPInt t_x = t1.MulMod(x, order);
    yacl::math::MPInt x_pow = x; // x^1
    x_pow = x_pow.MulMod(x, order); // x^2
    // t_x = t_x.AddMod(t2.MulMod(x_pow, order), order); // t2 needs calculation
    x_pow = x_pow.MulMod(x, order); // x^3
    t_x = t_x.AddMod(t3.MulMod(x_pow, order), order);
    x_pow = x_pow.MulMod(x, order); // x^4
    t_x = t_x.AddMod(t4.MulMod(x_pow, order), order);
    x_pow = x_pow.MulMod(x, order); // x^5
    t_x = t_x.AddMod(t5.MulMod(x_pow, order), order);
    x_pow = x_pow.MulMod(x, order); // x^6
    t_x = t_x.AddMod(t6.MulMod(x_pow, order), order);
    // Add < vec(1), wV > * z^2 ? No, this is t2 blinding.

    // Compute t_x_blinding = sum(z^(Q+1)*<1,wV> * v_blinding) * x^2 + t1_b*x + t3_b*x^3 + ... + t6_b*x^6
    yacl::math::MPInt t_2_blinding(0);
    for(size_t i=0; i<secrets_.v.size(); ++i) {
        t_2_blinding = t_2_blinding.AddMod(wV[i].MulMod(secrets_.v_blinding[i], order), order);
    }
    yacl::math::MPInt t_x_blinding = t_1_blinding.MulMod(x, order);
    x_pow = x.MulMod(x, order); // x^2
    t_x_blinding = t_x_blinding.AddMod(t_2_blinding.MulMod(x_pow, order), order);
    x_pow = x_pow.MulMod(x, order); // x^3
    t_x_blinding = t_x_blinding.AddMod(t_3_blinding.MulMod(x_pow, order), order);
    x_pow = x_pow.MulMod(x, order); // x^4
    t_x_blinding = t_x_blinding.AddMod(t_4_blinding.MulMod(x_pow, order), order);
    x_pow = x_pow.MulMod(x, order); // x^5
    t_x_blinding = t_x_blinding.AddMod(t_5_blinding.MulMod(x_pow, order), order);
    x_pow = x_pow.MulMod(x, order); // x^6
    t_x_blinding = t_x_blinding.AddMod(t_6_blinding.MulMod(x_pow, order), order);


    // Compute l(x), r(x) vectors
    // Need to pad vectors to padded_n
    size_t padded_n = secrets_.a_L.size().next_power_of_two(); // Need next_power_of_two helper
    if (padded_n == 0 && n > 0) padded_n = 1; // Handle n=0 case if necessary
    size_t pad = padded_n - n;

    std::vector<yacl::math::MPInt> l_vec(padded_n);
    std::vector<yacl::math::MPInt> r_vec(padded_n);
    yacl::math::MPInt current_exp_y = y_pows.back().MulMod(y, order); // y^n
    yacl::math::MPInt minus_one_mod = order - one;

    for(size_t i=0; i<n; ++i) {
        yacl::math::MPInt l1_i = secrets_.a_L[i].AddMod(y_inv_pows[i].MulMod(wR[i], order), order);
        yacl::math::MPInt l2_i = secrets_.a_O[i];
        yacl::math::MPInt l3_i = s_L_full[i];
        l_vec[i] = l1_i.AddMod(l2_i.MulMod(x, order), order).AddMod(l3_i.MulMod(x.MulMod(x, order), order), order); /
        // Assume l(x) = l_poly.0 + l_poly.1*x + l_poly.2*x^2 + l_poly.3*x^3...
        // comments: l(x) = l_1*x + l_2*x^2 + l_3*x^3. t(x) = <l(x),r(x)>.
        // Our derived t1..t6 match   if l(x) = l1+l2*x+l3*x^2 and r(x)=r0+r1*x+r3*x^3?
        // Let's re-evaluate based on   paper/code: l(X) = (a_L -z*1 + s_L*X^3) + y^{-n} \circ (w_R*X + w_O*X^2) ??? Seems wrong.
        // Let's stick to the   `l_poly.eval(x)` logic: l_vec[i] = l_poly.0[i] + l_poly.1[i]*x;
        l_vec[i] = l_poly.vec0[i].AddMod(l_poly.vec1[i].MulMod(x, order), order);

        // Similarly for r_vec
        r_vec[i] = r_poly.vec0[i].AddMod(r_poly.vec1[i].MulMod(x, order), order);
    }
    // Pad l_vec with 0, r_vec with -y^i
    for (size_t i = n; i < padded_n; ++i) {
        l_vec[i] = zero;
        r_vec[i] = current_exp_y.MulMod(minus_one_mod, order); // -y^i
        current_exp_y = current_exp_y.MulMod(y, order);
    }


    // Blinding for IPP e = x(i_b + x(o_b + x*s_b))
    yacl::math::MPInt i_blinding = i_blinding1.AddMod(u.MulMod(i_blinding2, order), order);
    yacl::math::MPInt o_blinding = o_blinding1.AddMod(u.MulMod(o_blinding2, order), order);
    yacl::math::MPInt s_blinding = s_blinding1.AddMod(u.MulMod(s_blinding2, order), order);
    yacl::math::MPInt e_blinding = o_blinding.AddMod(s_blinding.MulMod(x, order), order);
    e_blinding = i_blinding.AddMod(e_blinding.MulMod(x, order), order);
    e_blinding = e_blinding.MulMod(x, order);

    // Commit scalars
    transcript_->AppendScalar("t_x", t_x);
    transcript_->AppendScalar("t_x_blinding", t_x_blinding);
    transcript_->AppendScalar("e_blinding", e_blinding); // Use combined blinding

    // IPP Challenge w and Q point
    yacl::math::MPInt w = transcript_->ChallengeScalar("w", curve);
    yacl::crypto::EcPoint Q = curve->Mul(pc_gens_->GetGPoint(), w); // Use G base like   verify

    // IPP Factors: G_factors = u^k (where u=1 for phase 1, u=challenge u for phase 2)
    // H_factors = y^-i * u^k
    std::vector<yacl::math::MPInt> ipp_G_factors(padded_n);
    std::vector<yacl::math::MPInt> ipp_H_factors(padded_n);
    for(size_t i=0; i<n1; ++i) {
        ipp_G_factors[i] = one;
        ipp_H_factors[i] = y_inv_pows[i]; // y^-i * 1
    }
     for(size_t i=n1; i<n; ++i) {
        ipp_G_factors[i] = u;
        ipp_H_factors[i] = y_inv_pows[i].MulMod(u, order); // y^-i * u
    }
     // Padding factors
     for(size_t i=n; i<padded_n; ++i) {
         ipp_G_factors[i] = u;
         ipp_H_factors[i] = y_inv_pows[i].MulMod(u, order); // y^-i * u
     }

    // IPP Generators (padded size)
    std::vector<yacl::crypto::EcPoint> G_ipp = gens.G(padded_n);
    std::vector<yacl::crypto::EcPoint> H_ipp = gens.H(padded_n);

    // Create IPP proof
    InnerProductProof ipp_proof = InnerProductProof::Create(
        transcript_, curve, Q,
        ipp_G_factors, ipp_H_factors,
        std::move(G_ipp), std::move(H_ipp), // Move generators
        std::move(l_vec), std::move(r_vec)); // Move vectors

    // Construct R1CSProof
    return R1CSProof(has_phase2, A_I1, A_O1, S1, A_I2, A_O2, S2,
                     T_1, T_3, T_4, T_5, T_6,
                     t_x, t_x_blinding, e_blinding,
                     std::move(ipp_proof));
}


// --- RandomizingProver Implementation ---

yacl::math::MPInt RandomizingProver::ChallengeScalar(const std::string& label) {
    // Convert label to bytes if needed by SimpleTranscript
    // Using string label directly if SimpleTranscript supports it
    return prover_->Transcript()->ChallengeScalar(label, prover_->pc_gens_->GetCurve());
}

} // namespace examples::zkp
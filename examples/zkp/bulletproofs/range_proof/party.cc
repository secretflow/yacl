#include "zkp/bulletproofs/range_proof/party.h"

#include <vector>
#include <memory>
#include <utility> // For std::move

#include "yacl/crypto/rand/rand.h"
#include "yacl/math/mpint/mp_int.h"
#include "zkp/bulletproofs/generators.h"
#include "zkp/bulletproofs/range_proof/messages.h"
#include "zkp/bulletproofs/util.h" // Include for Poly2, VecPoly1, ScalarExp, etc.
#include "yacl/base/exception.h"   // Include for yacl::Exception
#include "absl/strings/substitute.h" // Include for Abseil string formatting

namespace examples::zkp {

// ---- Party implementation ----

PartyAwaitingPosition Party::New(
    const BulletproofGens& bp_gens,
    const PedersenGens& pc_gens,
    uint64_t v,
    const yacl::math::MPInt& v_blinding,
    size_t n) {
  // Check that n is a valid bitsize
  if (!(n == 8 || n == 16 || n == 32 || n == 64)) {
    throw yacl::Exception(absl::Substitute("Invalid bitsize ($0), must be 8, 16, 32, or 64", n));
  }
  if (bp_gens.gens_capacity() < n) {
    throw yacl::Exception(absl::Substitute(
        "Bulletproof generators capacity ($0) insufficient for bitsize ($1)",
        bp_gens.gens_capacity(), n));
  }
  return PartyAwaitingPosition(bp_gens, pc_gens, v, v_blinding, n);
}

// ---- PartyAwaitingPosition implementation ----

PartyAwaitingPosition::PartyAwaitingPosition(
    const BulletproofGens& bp_gens,
    const PedersenGens& pc_gens,
    uint64_t v,
    const yacl::math::MPInt& v_blinding,
    size_t n)
    // Initializer list order matches declaration in party.h
    : bp_gens_(bp_gens),
      pc_gens_(pc_gens),
      n_(n),
      v_(v),
      v_blinding_(v_blinding)
       {
  uint64_t max_value = (n == 64) ? UINT64_MAX : (1ULL << n);
  if (v >= max_value) {
      throw yacl::Exception(absl::Substitute(
          "Value $0 is out of range for bitsize $1 (max is $2)",
           v, n, max_value -1));
  }
  V_ = pc_gens_.Commit(yacl::math::MPInt(v), v_blinding_);
}

PartyAwaitingPosition::~PartyAwaitingPosition() {
  v_ = 0;
}

std::pair<PartyAwaitingBitChallenge, BitCommitment>
PartyAwaitingPosition::AssignPosition(size_t j) const {
  if (bp_gens_.party_capacity() <= j) {
    throw yacl::Exception(absl::Substitute(
        "Party index $0 out of bounds for generator capacity $1",
        j, bp_gens_.party_capacity()));
  }

  auto curve = pc_gens_.GetCurve();
  YACL_ENFORCE(curve != nullptr, "Curve is null in PartyAwaitingPosition");
  const auto& order = curve->GetOrder();

  yacl::math::MPInt a_blinding;
  a_blinding.RandomLtN(order, &a_blinding);
  yacl::math::MPInt s_blinding;
  s_blinding.RandomLtN(order, &s_blinding);

  yacl::crypto::EcPoint A = curve->Mul(pc_gens_.B_blinding, a_blinding);

  auto share = bp_gens_.Share(j);
  auto party_gens_G = share.G(n_);
  auto party_gens_H = share.H(n_);
  YACL_ENFORCE(party_gens_G.size() == n_ && party_gens_H.size() == n_,
               "Incorrect number of generators obtained for party");

  yacl::math::MPInt one(1);
  yacl::math::MPInt minus_one = order.SubMod(one, order); // Calculate -1 mod order

  for (size_t i = 0; i < n_; ++i) {
    bool bit_set = ((v_ >> i) & 1) == 1;
    if (bit_set) {
      A = curve->Add(A, party_gens_G[i]);
    } else {
      A = curve->Add(A, curve->Mul(party_gens_H[i], minus_one));
    }
  }

  std::vector<yacl::math::MPInt> s_L; s_L.reserve(n_);
  std::vector<yacl::math::MPInt> s_R; s_R.reserve(n_);
  for (size_t i = 0; i < n_; ++i) {
    yacl::math::MPInt s_L_i;
    s_L_i.RandomLtN(order, &s_L_i);
    s_L.push_back(s_L_i);
    yacl::math::MPInt s_R_i;
    s_R_i.RandomLtN(order, &s_R_i);
    s_R.push_back(s_R_i);
  }

  yacl::crypto::EcPoint S = curve->Mul(pc_gens_.B_blinding, s_blinding);
  for (size_t i = 0; i < n_; ++i) {
    S = curve->Add(S, curve->Mul(party_gens_G[i], s_L[i]));
    S = curve->Add(S, curve->Mul(party_gens_H[i], s_R[i]));
  }

  BitCommitment commitment(V_, A, S);

  PartyAwaitingBitChallenge next_state(
      n_,                       // size_t n
      j,                       // size_t j
      pc_gens_,                // const PedersenGens& pc_gens
      curve,                   // const std::shared_ptr<...>& curve
      v_,                      // uint64_t v
      v_blinding_,             // const MPInt& v_blinding
      a_blinding,              // const MPInt& a_blinding
      s_blinding,              // const MPInt& s_blinding
      std::move(s_L),          // std::vector<MPInt> s_L
      std::move(s_R)           // std::vector<MPInt> s_R
  );

  return {std::move(next_state), commitment};
}

// ---- PartyAwaitingBitChallenge implementation ----

PartyAwaitingBitChallenge::PartyAwaitingBitChallenge(
    size_t n,
    size_t j,
    const PedersenGens& pc_gens,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    uint64_t v,
    const yacl::math::MPInt& v_blinding,
    const yacl::math::MPInt& a_blinding,
    const yacl::math::MPInt& s_blinding,
    std::vector<yacl::math::MPInt> s_L,
    std::vector<yacl::math::MPInt> s_R)
    // Initializer list order matches declaration in party.h
    : n_(n),
      j_(j),
      pc_gens_(pc_gens),
      curve_(curve),
      v_(v),
      v_blinding_(v_blinding),
      a_blinding_(a_blinding),
      s_blinding_(s_blinding),
      s_L_(std::move(s_L)),
      s_R_(std::move(s_R)) {
  YACL_ENFORCE(curve_ != nullptr, "Curve cannot be null in PartyAwaitingBitChallenge");
}

PartyAwaitingBitChallenge::~PartyAwaitingBitChallenge() {}

std::pair<PartyAwaitingPolyChallenge, PolyCommitment>
PartyAwaitingBitChallenge::ApplyChallenge(const BitChallenge& challenge) const {
  const auto& order = curve_->GetOrder();
  const yacl::math::MPInt& y = challenge.GetY();
  const yacl::math::MPInt& z = challenge.GetZ();

  yacl::math::MPInt offset_y = ScalarExp(y, j_ * n_, curve_);
  yacl::math::MPInt offset_z = ScalarExp(z, j_, curve_);
  yacl::math::MPInt z_sq = z.MulMod(z, order);
  yacl::math::MPInt offset_zz = z_sq.MulMod(offset_z, order);

  VecPoly1 l_poly = VecPoly1::Zero(n_);
  VecPoly1 r_poly = VecPoly1::Zero(n_);

  yacl::math::MPInt one(1);
  yacl::math::MPInt two(2);
  std::vector<yacl::math::MPInt> y_pows = ExpIterVector(y, n_, curve_);
  std::vector<yacl::math::MPInt> two_pows = ExpIterVector(two, n_, curve_);

  for (size_t i = 0; i < n_; ++i) {
    yacl::math::MPInt a_L_i((v_ >> i) & 1);
    yacl::math::MPInt a_R_i = a_L_i.SubMod(one, order);
    l_poly.vec0[i] = a_L_i.SubMod(z, order);
    l_poly.vec1[i] = s_L_[i];
    yacl::math::MPInt current_y_pow = y_pows[i].MulMod(offset_y, order);
    yacl::math::MPInt term1_factor = a_R_i.AddMod(z, order);
    yacl::math::MPInt term1 = current_y_pow.MulMod(term1_factor, order);
    yacl::math::MPInt term2 = offset_zz.MulMod(two_pows[i], order);
    r_poly.vec0[i] = term1.AddMod(term2, order);
    r_poly.vec1[i] = current_y_pow.MulMod(s_R_[i], order);
  }

  Poly2 t_poly = l_poly.InnerProduct(r_poly, curve_);

  yacl::math::MPInt t_1_blinding;
  t_1_blinding.RandomLtN(order, &t_1_blinding);
  yacl::math::MPInt t_2_blinding;
  t_2_blinding.RandomLtN(order, &t_2_blinding);

  yacl::crypto::EcPoint T_1 = pc_gens_.Commit(t_poly.t1, t_1_blinding);
  yacl::crypto::EcPoint T_2 = pc_gens_.Commit(t_poly.t2, t_2_blinding);

  PolyCommitment poly_commitment(T_1, T_2);

  // Call constructor with parameters in the correct order matching the declaration
  PartyAwaitingPolyChallenge next_state(
      offset_zz,               // const MPInt& offset_zz
      std::move(l_poly),       // VecPoly1&& l_poly
      std::move(r_poly),       // VecPoly1&& r_poly
      t_poly,                  // const Poly2& t_poly
      v_blinding_,             // const MPInt& v_blinding
      a_blinding_,             // const MPInt& a_blinding
      s_blinding_,             // const MPInt& s_blinding
      t_1_blinding,            // const MPInt& t_1_blinding
      t_2_blinding,            // const MPInt& t_2_blinding
      curve_                   // const std::shared_ptr<...>& curve
  );

  return {std::move(next_state), poly_commitment};
}

// ---- PartyAwaitingPolyChallenge implementation ----

PartyAwaitingPolyChallenge::PartyAwaitingPolyChallenge(
    const yacl::math::MPInt& offset_zz,
    VecPoly1&& l_poly,
    VecPoly1&& r_poly,
    const Poly2& t_poly,
    const yacl::math::MPInt& v_blinding,
    const yacl::math::MPInt& a_blinding,
    const yacl::math::MPInt& s_blinding,
    const yacl::math::MPInt& t_1_blinding,
    const yacl::math::MPInt& t_2_blinding,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve)
    // Initializer list order MUST match declaration order in party.h
    : offset_zz_(offset_zz),
      l_poly_(std::move(l_poly)),
      r_poly_(std::move(r_poly)),
      t_poly_(t_poly),
      v_blinding_(v_blinding),
      a_blinding_(a_blinding),
      s_blinding_(s_blinding),
      t_1_blinding_(t_1_blinding),
      t_2_blinding_(t_2_blinding),
      curve_(curve) {
  YACL_ENFORCE(curve_ != nullptr, "Curve cannot be null in PartyAwaitingPolyChallenge");
}

PartyAwaitingPolyChallenge::~PartyAwaitingPolyChallenge() {}

ProofShare PartyAwaitingPolyChallenge::ApplyChallenge(
    const PolyChallenge& challenge) const {
  const auto& order = curve_->GetOrder();
  const yacl::math::MPInt& x = challenge.GetX();

  if (x.IsZero()) {
    throw yacl::Exception("Malicious dealer: challenge x is zero");
  }

  Poly2 t_blinding_poly(
      offset_zz_.MulMod(v_blinding_, order),
      t_1_blinding_,
      t_2_blinding_
  );

  yacl::math::MPInt t_x = t_poly_.Eval(x, curve_);
  yacl::math::MPInt t_x_blinding = t_blinding_poly.Eval(x, curve_);
  yacl::math::MPInt e_blinding = a_blinding_.AddMod(s_blinding_.MulMod(x, order), order);
  std::vector<yacl::math::MPInt> l_vec = l_poly_.Eval(x, curve_);
  std::vector<yacl::math::MPInt> r_vec = r_poly_.Eval(x, curve_);

  return ProofShare(
    t_x,
    t_x_blinding,
    e_blinding,
    std::move(l_vec),
    std::move(r_vec)
  );
}

} // namespace examples::zkp
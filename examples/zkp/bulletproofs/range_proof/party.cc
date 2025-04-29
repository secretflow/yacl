#include "zkp/bulletproofs/range_proof/party.h"

#include "yacl/crypto/rand/rand.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/math/mpint/mp_int.h"
#include "zkp/bulletproofs/generators.h"
#include "zkp/bulletproofs/range_proof/messages.h"
#include "zkp/bulletproofs/util.h"

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
    throw yacl::Exception("Invalid bitsize, must be 8, 16, 32, or 64");
  }
  
  // Check that generators are sufficient
  if (bp_gens.gens_capacity() < n) {
    throw yacl::Exception("Generators capacity is insufficient for the bitsize");
  }
  
  // Create the initial party state
  return PartyAwaitingPosition(bp_gens, pc_gens, v, v_blinding, n);
}

// ---- PartyAwaitingPosition implementation ----

PartyAwaitingPosition::PartyAwaitingPosition(
    const BulletproofGens& bp_gens,
    const PedersenGens& pc_gens,
    uint64_t v,
    const yacl::math::MPInt& v_blinding,
    size_t n)
    : bp_gens_(bp_gens),
      pc_gens_(pc_gens),
      n_(n),
      v_(v),
      v_blinding_(v_blinding) {
  // Create the value commitment V = v*G + v_blinding*H
  V_ = pc_gens_.Commit(yacl::math::MPInt(v), v_blinding_);
}

PartyAwaitingPosition::~PartyAwaitingPosition() {
  // Clear sensitive data when going out of scope
  v_ = 0;
  v_blinding_ = yacl::math::MPInt(0);
}

std::pair<PartyAwaitingBitChallenge, BitCommitment> 
PartyAwaitingPosition::AssignPosition(size_t j) const {
  if (bp_gens_.party_capacity() <= j) {
    throw yacl::Exception("Party index out of bounds");
  }
  
  auto curve = bp_gens_.GetCurve();
  
  // Generate random blinding factors
  yacl::math::MPInt a_blinding;
  yacl::math::MPInt::RandomExactBits(curve->GetField().BitCount(), &a_blinding);
  
  // Compute A = <a_L, G> + <a_R, H> + a_blinding * B_blinding
  yacl::crypto::EcPoint A = curve->Mul(pc_gens_.GetHPoint(), a_blinding);
  
  // Get party's share of generators
  auto party_gens_G = bp_gens_.GetGParty(j);
  auto party_gens_H = bp_gens_.GetHParty(j);
  
  // For each bit, add the appropriate generator
  for (size_t i = 0; i < n_; i++) {
    bool bit_set = ((v_ >> i) & 1) == 1;
    if (bit_set) {
      A = curve->Add(A, party_gens_G[i]);
    } else {
      A = curve->Sub(A, party_gens_H[i]);
    }
  }
  
  // Generate random blinding factors for S
  yacl::math::MPInt s_blinding;
  yacl::math::MPInt::RandomExactBits(curve->GetField().BitCount(), &s_blinding);
  
  // Generate random s_L and s_R vectors
  std::vector<yacl::math::MPInt> s_L;
  std::vector<yacl::math::MPInt> s_R;
  s_L.reserve(n_);
  s_R.reserve(n_);
  
  for (size_t i = 0; i < n_; i++) {
    yacl::math::MPInt s_L_i, s_R_i;
    yacl::math::MPInt::RandomExactBits(curve->GetField().BitCount(), &s_L_i);
    yacl::math::MPInt::RandomExactBits(curve->GetField().BitCount(), &s_R_i);
    s_L.push_back(std::move(s_L_i));
    s_R.push_back(std::move(s_R_i));
  }
  
  // Compute S = <s_L, G> + <s_R, H> + s_blinding * B_blinding
  yacl::crypto::EcPoint S = curve->Mul(pc_gens_.GetHPoint(), s_blinding);
  
  for (size_t i = 0; i < n_; i++) {
    S = curve->Add(S, curve->Mul(party_gens_G[i], s_L[i]));
    S = curve->Add(S, curve->Mul(party_gens_H[i], s_R[i]));
  }
  
  // Create commitment
  BitCommitment commitment{V_, A, S};
  
  // Create next state
  PartyAwaitingBitChallenge next_state(
      n_, v_, v_blinding_, j, pc_gens_, 
      a_blinding, s_blinding, std::move(s_L), std::move(s_R));
  
  return {std::move(next_state), commitment};
}

// ---- PartyAwaitingBitChallenge implementation ----

PartyAwaitingBitChallenge::PartyAwaitingBitChallenge(
    size_t n,
    uint64_t v,
    const yacl::math::MPInt& v_blinding,
    size_t j,
    const PedersenGens& pc_gens,
    const yacl::math::MPInt& a_blinding,
    const yacl::math::MPInt& s_blinding,
    std::vector<yacl::math::MPInt> s_L,
    std::vector<yacl::math::MPInt> s_R)
    : n_(n),
      v_(v),
      v_blinding_(v_blinding),
      j_(j),
      pc_gens_(pc_gens),
      a_blinding_(a_blinding),
      s_blinding_(s_blinding),
      s_L_(std::move(s_L)),
      s_R_(std::move(s_R)) {}

PartyAwaitingBitChallenge::~PartyAwaitingBitChallenge() {
  // Clear sensitive data when going out of scope
  v_ = 0;
  v_blinding_ = yacl::math::MPInt(0);
  a_blinding_ = yacl::math::MPInt(0);
  s_blinding_ = yacl::math::MPInt(0);
  
  // Clear vectors
  for (auto& s : s_L_) {
    s = yacl::math::MPInt(0);
  }
  for (auto& s : s_R_) {
    s = yacl::math::MPInt(0);
  }
}

std::pair<PartyAwaitingPolyChallenge, PolyCommitment>
PartyAwaitingBitChallenge::ApplyChallenge(const BitChallenge& challenge) const {  
  auto curve = pc_gens_.GetCurve();
  
  // Calculate offset values based on party position
  yacl::math::MPInt offset_y = ScalarExpVartime(challenge.GetY(), static_cast<uint64_t>(j_ * n_));
  yacl::math::MPInt offset_z = ScalarExpVartime(challenge.GetZ(), static_cast<uint64_t>(j_));
  
  // Calculate vectors l0, l1, r0, r1 for polynomial calculation
  VecPoly1 l_poly = VecPoly1::Zero(n_);
  VecPoly1 r_poly = VecPoly1::Zero(n_);
  
  yacl::math::MPInt offset_zz = challenge.GetZ() * challenge.GetZ() * offset_z;
  yacl::math::MPInt exp_y = offset_y; // Start at y^j
  yacl::math::MPInt exp_2 = yacl::math::MPInt(1); // Start at 2^0 = 1
  
  for (size_t i = 0; i < n_; i++) {
    // Compute a_L[i] and a_R[i]
    yacl::math::MPInt a_L_i((v_ >> i) & 1);
    yacl::math::MPInt a_R_i = a_L_i - yacl::math::MPInt(1);
    
    // Update the polynomials
    l_poly.vec0[i] = a_L_i - challenge.GetZ();
    l_poly.vec1[i] = s_L_[i];
    r_poly.vec0[i] = exp_y * (a_R_i + challenge.GetZ()) + offset_zz * exp_2;
    r_poly.vec1[i] = exp_y * s_R_[i];
    
    // Update exponentials for next iteration
    exp_y = exp_y * challenge.GetY();
    exp_2 = exp_2 + exp_2;
  }
  
  // Compute t_poly = l_poly * r_poly
  Poly2 t_poly = l_poly.InnerProduct(r_poly, curve);
  
  // Generate random blinding factors for T_1 and T_2
  yacl::math::MPInt t_1_blinding, t_2_blinding;
  yacl::math::MPInt::RandomExactBits(curve->GetField().BitCount(), &t_1_blinding);
  yacl::math::MPInt::RandomExactBits(curve->GetField().BitCount(), &t_2_blinding);
  
  // Compute commitments T_1 and T_2
  yacl::crypto::EcPoint T_1 = pc_gens_.Commit(t_poly.t1, t_1_blinding);
  yacl::crypto::EcPoint T_2 = pc_gens_.Commit(t_poly.t2, t_2_blinding);
  
  // Create polynomial commitment
  PolyCommitment poly_commitment{T_1, T_2};
  
  // Create next state
  PartyAwaitingPolyChallenge next_state(
      offset_zz, l_poly, r_poly, t_poly,
      v_blinding_, a_blinding_, s_blinding_,
      t_1_blinding, t_2_blinding);
  
  return {std::move(next_state), poly_commitment};
}

// ---- PartyAwaitingPolyChallenge implementation ----

PartyAwaitingPolyChallenge::PartyAwaitingPolyChallenge(
    const yacl::math::MPInt& offset_zz,
    const VecPoly1& l_poly,
    const VecPoly1& r_poly,
    const Poly2& t_poly,
    const yacl::math::MPInt& v_blinding,
    const yacl::math::MPInt& a_blinding,
    const yacl::math::MPInt& s_blinding,
    const yacl::math::MPInt& t_1_blinding,
    const yacl::math::MPInt& t_2_blinding,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve)
    : offset_zz_(offset_zz),
      l_poly_(l_poly, curve),
      r_poly_(r_poly, curve),
      t_poly_(t_poly, curve),
      v_blinding_(v_blinding),
      a_blinding_(a_blinding),
      s_blinding_(s_blinding),
      t_1_blinding_(t_1_blinding),
      t_2_blinding_(t_2_blinding) {}

PartyAwaitingPolyChallenge::~PartyAwaitingPolyChallenge() {
  // Clear sensitive data when going out of scope
  v_blinding_ = yacl::math::MPInt(0);
  a_blinding_ = yacl::math::MPInt(0);
  s_blinding_ = yacl::math::MPInt(0);
  t_1_blinding_ = yacl::math::MPInt(0);
  t_2_blinding_ = yacl::math::MPInt(0);
  
  // Note: l_poly_, r_poly_, and t_poly_ are cleared in their own destructors
}

ProofShare PartyAwaitingPolyChallenge::ApplyChallenge(
    const PolyChallenge& challenge) const {
  // Prevent a malicious dealer from annihilating the blinding factors
  if (challenge.GetX() == yacl::math::MPInt(0)) {
    throw yacl::Exception("Malicious dealer: challenge.x is zero");
  }
  
  // Create t_blinding_poly = offset_zz * v_blinding + t_1_blinding*x + t_2_blinding*x^2
  Poly2 t_blinding_poly(
      offset_zz_ * v_blinding_,
      t_1_blinding_,
      t_2_blinding_);
  
  // Evaluate polynomials at the challenge point x
  yacl::math::MPInt t_x = t_poly_.Eval(challenge.GetX(), curve_);
  yacl::math::MPInt t_x_blinding = t_blinding_poly.Eval(challenge.GetX(), curve_);
  yacl::math::MPInt e_blinding = a_blinding_ + s_blinding_ * challenge.GetX();
  std::vector<yacl::math::MPInt> l_vec = l_poly_.Eval(challenge.GetX());
  std::vector<yacl::math::MPInt> r_vec = r_poly_.Eval(challenge.GetX());
  
  // Create and return the proof share
  return ProofShare{
    t_x,
    t_x_blinding,
    e_blinding,
    std::move(l_vec),
    std::move(r_vec)
  };
}

} // namespace examples::zkp
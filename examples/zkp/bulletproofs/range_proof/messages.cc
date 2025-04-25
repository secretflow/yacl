#include "zkp/bulletproofs/messages.h"

#include <algorithm>
#include <stdexcept>

#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::zkp {

//-------------------- BitCommitment --------------------

BitCommitment::BitCommitment(
    const yacl::crypto::EcPoint& V_j,
    const yacl::crypto::EcPoint& A_j,
    const yacl::crypto::EcPoint& S_j)
    : V_j_(V_j), A_j_(A_j), S_j_(S_j) {}

yacl::Buffer BitCommitment::ToBytes() const {
  yacl::Buffer result;
  
  // Serialize V_j_
  std::vector<uint8_t> V_bytes = V_j_.Serialize();
  size_t V_size = V_bytes.size();
  result.append(&V_size, sizeof(size_t));
  result.append(V_bytes.data(), V_bytes.size());
  
  // Serialize A_j_
  std::vector<uint8_t> A_bytes = A_j_.Serialize();
  size_t A_size = A_bytes.size();
  result.append(&A_size, sizeof(size_t));
  result.append(A_bytes.data(), A_bytes.size());
  
  // Serialize S_j_
  std::vector<uint8_t> S_bytes = S_j_.Serialize();
  size_t S_size = S_bytes.size();
  result.append(&S_size, sizeof(size_t));
  result.append(S_bytes.data(), S_bytes.size());
  
  return result;
}

BitCommitment BitCommitment::FromBytes(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    yacl::ByteContainerView bytes) {
  const uint8_t* data = bytes.data();
  size_t offset = 0;
  
  // Deserialize V_j
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for V_j size");
  }
  size_t V_size;
  std::memcpy(&V_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + V_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for V_j");
  }
  yacl::crypto::EcPoint V_j = curve->DecodePoint(
      yacl::ByteContainerView(data + offset, V_size));
  offset += V_size;
  
  // Deserialize A_j
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for A_j size");
  }
  size_t A_size;
  std::memcpy(&A_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + A_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for A_j");
  }
  yacl::crypto::EcPoint A_j = curve->DecodePoint(
      yacl::ByteContainerView(data + offset, A_size));
  offset += A_size;
  
  // Deserialize S_j
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for S_j size");
  }
  size_t S_size;
  std::memcpy(&S_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + S_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for S_j");
  }
  yacl::crypto::EcPoint S_j = curve->DecodePoint(
      yacl::ByteContainerView(data + offset, S_size));
  
  return BitCommitment(V_j, A_j, S_j);
}

//-------------------- BitChallenge --------------------

BitChallenge::BitChallenge(
    const yacl::math::MPInt& y,
    const yacl::math::MPInt& z)
    : y_(y), z_(z) {}

yacl::Buffer BitChallenge::ToBytes() const {
  yacl::Buffer result;
  
  // Serialize y_
  std::vector<uint8_t> y_bytes = y_.ToBytes();
  size_t y_size = y_bytes.size();
  result.append(&y_size, sizeof(size_t));
  result.append(y_bytes.data(), y_bytes.size());
  
  // Serialize z_
  std::vector<uint8_t> z_bytes = z_.ToBytes();
  size_t z_size = z_bytes.size();
  result.append(&z_size, sizeof(size_t));
  result.append(z_bytes.data(), z_bytes.size());
  
  return result;
}

BitChallenge BitChallenge::FromBytes(yacl::ByteContainerView bytes) {
  const uint8_t* data = bytes.data();
  size_t offset = 0;
  
  // Deserialize y
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for y size");
  }
  size_t y_size;
  std::memcpy(&y_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + y_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for y");
  }
  yacl::math::MPInt y = yacl::math::MPInt::FromBytes(
      yacl::ByteContainerView(data + offset, y_size));
  offset += y_size;
  
  // Deserialize z
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for z size");
  }
  size_t z_size;
  std::memcpy(&z_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + z_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for z");
  }
  yacl::math::MPInt z = yacl::math::MPInt::FromBytes(
      yacl::ByteContainerView(data + offset, z_size));
  
  return BitChallenge(y, z);
}

//-------------------- PolyCommitment --------------------

PolyCommitment::PolyCommitment(
    const yacl::crypto::EcPoint& T_1_j,
    const yacl::crypto::EcPoint& T_2_j)
    : T_1_j_(T_1_j), T_2_j_(T_2_j) {}

yacl::Buffer PolyCommitment::ToBytes() const {
  yacl::Buffer result;
  
  // Serialize T_1_j_
  std::vector<uint8_t> T1_bytes = T_1_j_.Serialize();
  size_t T1_size = T1_bytes.size();
  result.append(&T1_size, sizeof(size_t));
  result.append(T1_bytes.data(), T1_bytes.size());
  
  // Serialize T_2_j_
  std::vector<uint8_t> T2_bytes = T_2_j_.Serialize();
  size_t T2_size = T2_bytes.size();
  result.append(&T2_size, sizeof(size_t));
  result.append(T2_bytes.data(), T2_bytes.size());
  
  return result;
}

PolyCommitment PolyCommitment::FromBytes(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    yacl::ByteContainerView bytes) {
  const uint8_t* data = bytes.data();
  size_t offset = 0;
  
  // Deserialize T_1_j
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for T_1_j size");
  }
  size_t T1_size;
  std::memcpy(&T1_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + T1_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for T_1_j");
  }
  yacl::crypto::EcPoint T_1_j = curve->DecodePoint(
      yacl::ByteContainerView(data + offset, T1_size));
  offset += T1_size;
  
  // Deserialize T_2_j
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for T_2_j size");
  }
  size_t T2_size;
  std::memcpy(&T2_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + T2_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for T_2_j");
  }
  yacl::crypto::EcPoint T_2_j = curve->DecodePoint(
      yacl::ByteContainerView(data + offset, T2_size));
  
  return PolyCommitment(T_1_j, T_2_j);
}

//-------------------- PolyChallenge --------------------

PolyChallenge::PolyChallenge(const yacl::math::MPInt& x)
    : x_(x) {}

yacl::Buffer PolyChallenge::ToBytes() const {
  yacl::Buffer result;
  
  // Serialize x_
  std::vector<uint8_t> x_bytes = x_.ToBytes();
  size_t x_size = x_bytes.size();
  result.append(&x_size, sizeof(size_t));
  result.append(x_bytes.data(), x_bytes.size());
  
  return result;
}

PolyChallenge PolyChallenge::FromBytes(yacl::ByteContainerView bytes) {
  const uint8_t* data = bytes.data();
  size_t offset = 0;
  
  // Deserialize x
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for x size");
  }
  size_t x_size;
  std::memcpy(&x_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + x_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for x");
  }
  yacl::math::MPInt x = yacl::math::MPInt::FromBytes(
      yacl::ByteContainerView(data + offset, x_size));
  
  return PolyChallenge(x);
}

//-------------------- ProofShare --------------------

ProofShare::ProofShare(
    const yacl::math::MPInt& t_x,
    const yacl::math::MPInt& t_x_blinding,
    const yacl::math::MPInt& e_blinding,
    std::vector<yacl::math::MPInt> l_vec,
    std::vector<yacl::math::MPInt> r_vec)
    : t_x_(t_x),
      t_x_blinding_(t_x_blinding),
      e_blinding_(e_blinding),
      l_vec_(std::move(l_vec)),
      r_vec_(std::move(r_vec)) {}

void ProofShare::CheckSize(
    size_t expected_n,
    const BulletproofGens& bp_gens,
    size_t j) const {
  if (l_vec_.size() != expected_n) {
    throw yacl::Exception("l_vec size mismatch");
  }
  
  if (r_vec_.size() != expected_n) {
    throw yacl::Exception("r_vec size mismatch");
  }
  
  if (expected_n > bp_gens.gens_capacity()) {
    throw yacl::Exception("Bitsize exceeds generators capacity");
  }
  
  if (j >= bp_gens.party_capacity()) {
    throw yacl::Exception("Party index out of bounds");
  }
}

void ProofShare::AuditShare(
    const BulletproofGens& bp_gens,
    const PedersenGens& pc_gens,
    size_t j,
    const BitCommitment& bit_commitment,
    const BitChallenge& bit_challenge,
    const PolyCommitment& poly_commitment,
    const PolyChallenge& poly_challenge) const {
  const size_t n = l_vec_.size();
  
  // Check sizes first
  CheckSize(n, bp_gens, j);
  
  auto curve = bp_gens.GetCurve();
  
  // Extract challenge values
  const yacl::math::MPInt& y = bit_challenge.GetY();
  const yacl::math::MPInt& z = bit_challenge.GetZ();
  const yacl::math::MPInt& x = poly_challenge.GetX();
  
  // Precompute some variables
  yacl::math::MPInt zz = z * z;
  yacl::math::MPInt minus_z = yacl::math::MPInt::Zero() - z;
  yacl::math::MPInt z_j = ScalarExpVartime(z, j); // z^j
  yacl::math::MPInt y_jn = ScalarExpVartime(y, j * n); // y^(j*n)
  yacl::math::MPInt y_jn_inv = y_jn.Inverse(curve->GetField()); // y^(-j*n)
  yacl::math::MPInt y_inv = y.Inverse(curve->GetField()); // y^(-1)
  
  // Verify that t_x = <l_vec, r_vec>
  yacl::math::MPInt t_x_check = InnerProduct(l_vec_, r_vec_);
  if (t_x_ != t_x_check) {
    throw yacl::Exception("t_x doesn't match inner product of l_vec and r_vec");
  }
  
  // Compute P_check = A_j + x*S_j - e_blinding*B_blinding + <g, G> + <h, H>
  // Where g = -z - l_i
  // And h = z + y^(-i-j*n) * (-r_i + z^2 * z^j * 2^i)
  
  // First prepare all scalars for the multiscalar multiplication
  std::vector<yacl::math::MPInt> scalars;
  scalars.reserve(3 + 2 * n);
  
  // Coefficients for A_j, S_j, B_blinding
  scalars.push_back(yacl::math::MPInt(1));
  scalars.push_back(x);
  scalars.push_back(yacl::math::MPInt::Zero() - e_blinding_);
  
  // Compute scalars for G generators (coefficients for l_vec)
  std::vector<yacl::math::MPInt> exp_2 = ExpIterVector(yacl::math::MPInt(2), n);
  std::vector<yacl::math::MPInt> exp_y_inv = ExpIterVector(y_inv, n);
  
  for (size_t i = 0; i < n; i++) {
    scalars.push_back(minus_z - l_vec_[i]);
  }
  
  // Compute scalars for H generators (coefficients for r_vec)
  for (size_t i = 0; i < n; i++) {
    yacl::math::MPInt h_i = z + 
        exp_y_inv[i] * y_jn_inv * (yacl::math::MPInt::Zero() - r_vec_[i]) + 
        exp_y_inv[i] * y_jn_inv * (zz * z_j * exp_2[i]);
    scalars.push_back(h_i);
  }
  
  // Now prepare all points for the multiscalar multiplication
  std::vector<yacl::crypto::EcPoint> points;
  points.reserve(3 + 2 * n);
  
  // A_j, S_j, B_blinding
  points.push_back(bit_commitment.GetA());
  points.push_back(bit_commitment.GetS());
  points.push_back(pc_gens.GetHPoint());
  
  // G generators
  auto G_j = bp_gens.GetGParty(j);
  for (size_t i = 0; i < n; i++) {
    points.push_back(G_j[i]);
  }
  
  // H generators
  auto H_j = bp_gens.GetHParty(j);
  for (size_t i = 0; i < n; i++) {
    points.push_back(H_j[i]);
  }
  
  // Compute P_check = ∑ scalars[i] * points[i]
  yacl::crypto::EcPoint P_check = curve->MultiScalarMul(scalars, points);
  
  // P_check should be the identity element
  if (!curve->IsIdentity(P_check)) {
    throw yacl::Exception("P_check verification failed");
  }
  
  // Now verify the t_x blinding factors
  
  // Calculate delta = (z - z^2) * sum_of_powers(y, n) * y^(j*n) - z * z^2 * sum_of_powers(2, n) * z^j
  yacl::math::MPInt sum_of_powers_y = SumOfPowers(y, n);
  yacl::math::MPInt sum_of_powers_2 = SumOfPowers(yacl::math::MPInt(2), n);
  yacl::math::MPInt delta = (z - zz) * sum_of_powers_y * y_jn - z * zz * sum_of_powers_2 * z_j;
  
  // Reset vectors for t_check calculation
  scalars.clear();
  points.clear();
  
  // Prepare scalars and points for t_check
  scalars.push_back(zz * z_j);
  scalars.push_back(x);
  scalars.push_back(x * x);
  scalars.push_back(delta - t_x_);
  scalars.push_back(yacl::math::MPInt::Zero() - t_x_blinding_);
  
  points.push_back(bit_commitment.GetV());
  points.push_back(poly_commitment.GetT1());
  points.push_back(poly_commitment.GetT2());
  points.push_back(pc_gens.GetGPoint());
  points.push_back(pc_gens.GetHPoint());
  
  // Compute t_check = ∑ scalars[i] * points[i]
  yacl::crypto::EcPoint t_check = curve->MultiScalarMul(scalars, points);
  
  // t_check should be the identity element
  if (!curve->IsIdentity(t_check)) {
    throw yacl::Exception("t_check verification failed");
  }
}

yacl::Buffer ProofShare::ToBytes() const {
  yacl::Buffer result;
  
  // Serialize t_x_
  std::vector<uint8_t> t_x_bytes = t_x_.ToBytes();
  size_t t_x_size = t_x_bytes.size();
  result.append(&t_x_size, sizeof(size_t));
  result.append(t_x_bytes.data(), t_x_bytes.size());
  
  // Serialize t_x_blinding_
  std::vector<uint8_t> t_x_blinding_bytes = t_x_blinding_.ToBytes();
  size_t t_x_blinding_size = t_x_blinding_bytes.size();
  result.append(&t_x_blinding_size, sizeof(size_t));
  result.append(t_x_blinding_bytes.data(), t_x_blinding_bytes.size());
  
  // Serialize e_blinding_
  std::vector<uint8_t> e_blinding_bytes = e_blinding_.ToBytes();
  size_t e_blinding_size = e_blinding_bytes.size();
  result.append(&e_blinding_size, sizeof(size_t));
  result.append(e_blinding_bytes.data(), e_blinding_bytes.size());
  
  // Serialize l_vec_
  size_t l_vec_size = l_vec_.size();
  result.append(&l_vec_size, sizeof(size_t));
  
  for (const auto& l : l_vec_) {
    std::vector<uint8_t> l_bytes = l.ToBytes();
    size_t l_size = l_bytes.size();
    result.append(&l_size, sizeof(size_t));
    result.append(l_bytes.data(), l_bytes.size());
  }
  
  // Serialize r_vec_
  size_t r_vec_size = r_vec_.size();
  result.append(&r_vec_size, sizeof(size_t));
  
  for (const auto& r : r_vec_) {
    std::vector<uint8_t> r_bytes = r.ToBytes();
    size_t r_size = r_bytes.size();
    result.append(&r_size, sizeof(size_t));
    result.append(r_bytes.data(), r_bytes.size());
  }
  
  return result;
}

ProofShare ProofShare::FromBytes(yacl::ByteContainerView bytes) {
  const uint8_t* data = bytes.data();
  size_t offset = 0;
  
  // Deserialize t_x
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for t_x size");
  }
  size_t t_x_size;
  std::memcpy(&t_x_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + t_x_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for t_x");
  }
  yacl::math::MPInt t_x = yacl::math::MPInt::FromBytes(
      yacl::ByteContainerView(data + offset, t_x_size));
  offset += t_x_size;
  
  // Deserialize t_x_blinding
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for t_x_blinding size");
  }
  size_t t_x_blinding_size;
  std::memcpy(&t_x_blinding_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + t_x_blinding_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for t_x_blinding");
  }
  yacl::math::MPInt t_x_blinding = yacl::math::MPInt::FromBytes(
      yacl::ByteContainerView(data + offset, t_x_blinding_size));
  offset += t_x_blinding_size;
  
  // Deserialize e_blinding
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for e_blinding size");
  }
  size_t e_blinding_size;
  std::memcpy(&e_blinding_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + e_blinding_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for e_blinding");
  }
  yacl::math::MPInt e_blinding = yacl::math::MPInt::FromBytes(
      yacl::ByteContainerView(data + offset, e_blinding_size));
  offset += e_blinding_size;
  
  // Deserialize l_vec
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for l_vec size");
  }
  size_t l_vec_size;
  std::memcpy(&l_vec_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  std::vector<yacl::math::MPInt> l_vec;
  l_vec.reserve(l_vec_size);
  
  for (size_t i = 0; i < l_vec_size; i++) {
    if (offset + sizeof(size_t) > bytes.size()) {
      throw yacl::Exception("Insufficient data for l_vec element size");
    }
    size_t l_size;
    std::memcpy(&l_size, data + offset, sizeof(size_t));
    offset += sizeof(size_t);
    
    if (offset + l_size > bytes.size()) {
      throw yacl::Exception("Insufficient data for l_vec element");
    }
    l_vec.push_back(yacl::math::MPInt::FromBytes(
        yacl::ByteContainerView(data + offset, l_size)));
    offset += l_size;
  }
  
  // Deserialize r_vec
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for r_vec size");
  }
  size_t r_vec_size;
  std::memcpy(&r_vec_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (r_vec_size != l_vec_size) {
    throw yacl::Exception("Vector size mismatch between l_vec and r_vec");
  }
  
  std::vector<yacl::math::MPInt> r_vec;
  r_vec.reserve(r_vec_size);
  
  for (size_t i = 0; i < r_vec_size; i++) {
    if (offset + sizeof(size_t) > bytes.size()) {
      throw yacl::Exception("Insufficient data for r_vec element size");
    }
    size_t r_size;
    std::memcpy(&r_size, data + offset, sizeof(size_t));
    offset += sizeof(size_t);
    
    if (offset + r_size > bytes.size()) {
      throw yacl::Exception("Insufficient data for r_vec element");
    }
    r_vec.push_back(yacl::math::MPInt::FromBytes(
        yacl::ByteContainerView(data + offset, r_size)));
    offset += r_size;
  }
  
  return ProofShare(t_x, t_x_blinding, e_blinding, std::move(l_vec), std::move(r_vec));
}

//-------------------- Utility Functions --------------------

yacl::math::MPInt InnerProduct(
    const std::vector<yacl::math::MPInt>& a,
    const std::vector<yacl::math::MPInt>& b) {
  if (a.size() != b.size()) {
    throw yacl::Exception("Vectors must have same length for inner product");
  }
  
  yacl::math::MPInt result = yacl::math::MPInt::Zero();
  for (size_t i = 0; i < a.size(); i++) {
    result = result + a[i] * b[i];
  }
  
  return result;
}

std::vector<yacl::math::MPInt> ExpIterVector(const yacl::math::MPInt& s, size_t n) {
  std::vector<yacl::math::MPInt> result;
  result.reserve(n);
  
  yacl::math::MPInt current = yacl::math::MPInt(1);
  for (size_t i = 0; i < n; i++) {
    result.push_back(current);
    current = current * s;
  }
  
  return result;
}

yacl::math::MPInt SumOfPowers(const yacl::math::MPInt& s, size_t n) {
  // If s == 1, return n
  if (s == yacl::math::MPInt(1)) {
    return yacl::math::MPInt(n);
  }
  
  // Otherwise compute (1 - s^n) / (1 - s)
  yacl::math::MPInt s_n = ScalarExpVartime(s, n);
  yacl::math::MPInt num = yacl::math::MPInt(1) - s_n;
  yacl::math::MPInt denom = yacl::math::MPInt(1) - s;
  
  // Return num/denom assuming we're in a field
  // This is simplified for demonstration - should be field-specific
  return num / denom;
}

yacl::math::MPInt ScalarExpVartime(const yacl::math::MPInt& x, uint64_t n) {
  if (n == 0) {
    return yacl::math::MPInt(1);
  }
  
  yacl::math::MPInt result = x;
  for (uint64_t i = 1; i < n; i++) {
    result = result * x;
  }
  
  return result;
}

} // namespace examples::zkp
// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "zkp/bulletproofs/range_proof_mpc/messages.h"

#include <algorithm>
#include <stdexcept>

#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/math/mpint/mp_int.h"
#include "zkp/bulletproofs/util.h"

namespace examples::zkp {

//-------------------- BitCommitment --------------------

// Helper function to append data to a Buffer
void AppendToBuffer(yacl::Buffer& buffer, const void* data, size_t data_size) {
  int64_t old_size = buffer.size();
  buffer.resize(old_size + data_size);
  std::memcpy(buffer.data<uint8_t>() + old_size, data, data_size);
}

// Helper function to append a Buffer to another Buffer
void AppendBufferToBuffer(yacl::Buffer& buffer, const yacl::Buffer& data) {
  AppendToBuffer(buffer, data.data(), data.size());
}


BitCommitment::BitCommitment(
    const yacl::crypto::EcPoint& V_j,
    const yacl::crypto::EcPoint& A_j,
    const yacl::crypto::EcPoint& S_j)
    : V_j_(V_j), A_j_(A_j), S_j_(S_j) {}

yacl::Buffer BitCommitment::ToBytes(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
  yacl::Buffer result;
  
  
  // Serialize V_j_ using YACL's EcPoint serialization
  yacl::Buffer V_buf = curve->SerializePoint(V_j_);
  size_t V_size = V_buf.size();
  AppendToBuffer(result, &V_size, sizeof(size_t));
  AppendBufferToBuffer(result, V_buf);
  
  // Serialize A_j_ using YACL's EcPoint serialization
  yacl::Buffer A_buf = curve->SerializePoint(A_j_);
  size_t A_size = A_buf.size();
  AppendToBuffer(result, &A_size, sizeof(size_t));
  AppendBufferToBuffer(result, A_buf);
  
  // Serialize S_j_ using YACL's EcPoint serialization
  yacl::Buffer S_buf = curve->SerializePoint(S_j_);
  size_t S_size = S_buf.size();
  AppendToBuffer(result, &S_size, sizeof(size_t));
  AppendBufferToBuffer(result, S_buf);
  
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
  yacl::crypto::EcPoint V_j = curve->DeserializePoint(
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
  yacl::crypto::EcPoint A_j = curve->DeserializePoint(
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
  yacl::crypto::EcPoint S_j = curve->DeserializePoint(
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
  yacl::Buffer y_buf = y_.Serialize();
  size_t y_size = y_buf.size();
  AppendToBuffer(result, &y_size, sizeof(size_t));
  AppendBufferToBuffer(result, y_buf);
  
  // Serialize z_
  yacl::Buffer z_buf = z_.Serialize();
  size_t z_size = z_buf.size();
  AppendToBuffer(result, &z_size, sizeof(size_t));
  AppendBufferToBuffer(result, z_buf);
  
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
  yacl::math::MPInt y;
  y.Deserialize(yacl::ByteContainerView(data + offset, y_size));
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
  yacl::math::MPInt z;
  z.Deserialize(yacl::ByteContainerView(data + offset, z_size));
  
  return BitChallenge(y, z);
}

//-------------------- PolyCommitment --------------------

PolyCommitment::PolyCommitment(
    const yacl::crypto::EcPoint& T_1_j,
    const yacl::crypto::EcPoint& T_2_j)
    : T_1_j_(T_1_j), T_2_j_(T_2_j) {}

yacl::Buffer PolyCommitment::ToBytes(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
  yacl::Buffer result;

  
  // Serialize T_1_j_ using YACL's EcPoint serialization
  yacl::Buffer T1_buf = curve->SerializePoint(T_1_j_);
  size_t T1_size = T1_buf.size();
  AppendToBuffer(result, &T1_size, sizeof(size_t));
  AppendBufferToBuffer(result, T1_buf);
  
  // Serialize T_2_j_ using YACL's EcPoint serialization
  yacl::Buffer T2_buf = curve->SerializePoint(T_2_j_);
  size_t T2_size = T2_buf.size();
  AppendToBuffer(result, &T2_size, sizeof(size_t));
  AppendBufferToBuffer(result, T2_buf);
  
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
  yacl::crypto::EcPoint T_1_j = curve->DeserializePoint(
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
  yacl::crypto::EcPoint T_2_j = curve->DeserializePoint(
      yacl::ByteContainerView(data + offset, T2_size));
  
  return PolyCommitment(T_1_j, T_2_j);
}

//-------------------- PolyChallenge --------------------

PolyChallenge::PolyChallenge(const yacl::math::MPInt& x)
    : x_(x) {}

yacl::Buffer PolyChallenge::ToBytes() const {
  yacl::Buffer result;
  
  // Serialize x_
  yacl::Buffer x_buf = x_.Serialize();
  size_t x_size = x_buf.size();
  AppendToBuffer(result, &x_size, sizeof(size_t));
  AppendBufferToBuffer(result, x_buf);
  
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
  yacl::math::MPInt x;
  x.Deserialize(yacl::ByteContainerView(data + offset, x_size));
  
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
  yacl::math::MPInt zz = z.MulMod(z, curve->GetOrder());
  yacl::math::MPInt zero = yacl::math::MPInt(0);
  yacl::math::MPInt minus_z = zero.SubMod(z, curve->GetOrder());
  yacl::math::MPInt z_j = ScalarExp(z, j, curve); // z^j
  yacl::math::MPInt y_jn = ScalarExp(y, j * n, curve); // y^(j*n)
  yacl::math::MPInt y_jn_inv = y_jn.InvertMod(curve->GetOrder()); // y^(-j*n)
  yacl::math::MPInt y_inv = y.InvertMod(curve->GetOrder()); // y^(-1)
  
  // Verify that t_x = <l_vec, r_vec>
  yacl::math::MPInt t_x_check = InnerProduct(l_vec_, r_vec_, curve);
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
  scalars.push_back(zero.SubMod(e_blinding_, curve->GetOrder()));
  
  // Compute scalars for G generators (coefficients for l_vec)
  std::vector<yacl::math::MPInt> exp_2 = ExpIterVector(yacl::math::MPInt(2), n, curve);
  std::vector<yacl::math::MPInt> exp_y_inv = ExpIterVector(y_inv, n, curve);
  
  for (size_t i = 0; i < n; i++) {
    scalars.push_back(minus_z.SubMod(l_vec_[i], curve->GetOrder()));
  }
  
  // Compute scalars for H generators (coefficients for r_vec)
  for (size_t i = 0; i < n; i++) {
    yacl::math::MPInt h_i = z.AddMod(
        exp_y_inv[i].MulMod(y_jn_inv, curve->GetOrder()).MulMod(zero.SubMod(r_vec_[i], curve->GetOrder()), curve->GetOrder()).AddMod(
        exp_y_inv[i].MulMod(y_jn_inv, curve->GetOrder()).MulMod(zz.MulMod(z_j, curve->GetOrder()).MulMod(exp_2[i], curve->GetOrder()), curve->GetOrder()), curve->GetOrder()),
        curve->GetOrder());
    scalars.push_back(h_i);
  }
  
  // Now prepare all points for the multiscalar multiplication
  std::vector<yacl::crypto::EcPoint> points;
  points.reserve(3 + 2 * n);
  
  // A_j, S_j, B_blinding
  points.push_back(bit_commitment.GetA());
  points.push_back(bit_commitment.GetS());
  points.push_back(pc_gens.B_blinding);
  
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
    // 从第一个元素开始，避免处理单位元
  yacl::crypto::EcPoint P_check = curve->Mul(points[0], scalars[0]);

  // 从第二个元素开始累加
  for (size_t i = 1; i < scalars.size(); i++) {
      yacl::crypto::EcPoint term = curve->Mul(points[i], scalars[i]);
      P_check = curve->Add(P_check, term);
  }
  
  // P_check should be the identity element
  if (!curve->IsInfinity(P_check)) {
    throw yacl::Exception("P_check verification failed");
  }
  
  // Now verify the t_x blinding factors
  
  // Calculate delta = (z - z^2) * sum_of_powers(y, n) * y^(j*n) - z * z^2 * sum_of_powers(2, n) * z^j
  yacl::math::MPInt sum_of_powers_y = SumOfPowers(y, n, curve);
  yacl::math::MPInt sum_of_powers_2 = SumOfPowers(yacl::math::MPInt(2), n, curve);
  yacl::math::MPInt delta = (z.SubMod(zz, curve->GetOrder())).MulMod(sum_of_powers_y, curve->GetOrder()).MulMod(y_jn, curve->GetOrder()).SubMod(z.MulMod(zz, curve->GetOrder()).MulMod(sum_of_powers_2, curve->GetOrder()).MulMod(z_j, curve->GetOrder()), curve->GetOrder());
  
  // Reset vectors for t_check calculation
  scalars.clear();
  points.clear();
  
  // Prepare scalars and points for t_check
  scalars.push_back(zz.MulMod(z_j, curve->GetOrder()));
  scalars.push_back(x);
  scalars.push_back(x.MulMod(x, curve->GetOrder()));
  scalars.push_back(delta.SubMod(t_x_, curve->GetOrder()));
  scalars.push_back(zero.SubMod(t_x_blinding_, curve->GetOrder()));
  
  points.push_back(bit_commitment.GetV());
  points.push_back(poly_commitment.GetT1());
  points.push_back(poly_commitment.GetT2());
  points.push_back(pc_gens.B);
  points.push_back(pc_gens.B_blinding);
  
  // Compute t_check = ∑ scalars[i] * points[i]
  // 从第一个元素开始，避免处理单位元
  yacl::crypto::EcPoint t_check = curve->Mul(points[0], scalars[0]);

  // 从第二个元素开始累加
  for (size_t i = 1; i < scalars.size(); i++) {
      yacl::crypto::EcPoint term = curve->Mul(points[i], scalars[i]);
      t_check = curve->Add(t_check, term);
  }
  // t_check should be the identity element
  if (!curve->IsInfinity(t_check)) {
    throw yacl::Exception("t_check verification failed");
  }
}

yacl::Buffer ProofShare::ToBytes() const {
  yacl::Buffer result;
  
  // Serialize t_x_
  yacl::Buffer t_x_buf = t_x_.Serialize();
  size_t t_x_size = t_x_buf.size();
  AppendToBuffer(result, &t_x_size, sizeof(size_t));
  AppendBufferToBuffer(result, t_x_buf);
  
  // Serialize t_x_blinding_
  yacl::Buffer t_x_blinding_buf = t_x_blinding_.Serialize();
  size_t t_x_blinding_size = t_x_blinding_buf.size();
  AppendToBuffer(result, &t_x_blinding_size, sizeof(size_t));
  AppendBufferToBuffer(result, t_x_blinding_buf);
  
  // Serialize e_blinding_
  yacl::Buffer e_blinding_buf = e_blinding_.Serialize();
  size_t e_blinding_size = e_blinding_buf.size();
  AppendToBuffer(result, &e_blinding_size, sizeof(size_t));
  AppendBufferToBuffer(result, e_blinding_buf);
  
  // Serialize l_vec_
  size_t l_vec_size = l_vec_.size();
  AppendToBuffer(result, &l_vec_size, sizeof(size_t));
  
  for (const auto& l : l_vec_) {
    yacl::Buffer l_buf = l.Serialize();
    size_t l_size = l_buf.size();
    AppendToBuffer(result, &l_size, sizeof(size_t));
    AppendBufferToBuffer(result, l_buf);
  }
  
  // Serialize r_vec_
  size_t r_vec_size = r_vec_.size();
  AppendToBuffer(result, &r_vec_size, sizeof(size_t));
  
  for (const auto& r : r_vec_) {
    yacl::Buffer r_buf = r.Serialize();
    size_t r_size = r_buf.size();
    AppendToBuffer(result, &r_size, sizeof(size_t));
    AppendBufferToBuffer(result, r_buf);
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
  yacl::math::MPInt t_x;
  t_x.Deserialize(yacl::ByteContainerView(data + offset, t_x_size));
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
  yacl::math::MPInt t_x_blinding;
  t_x_blinding.Deserialize(yacl::ByteContainerView(data + offset, t_x_blinding_size));
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
  yacl::math::MPInt e_blinding;
  e_blinding.Deserialize(yacl::ByteContainerView(data + offset, e_blinding_size));
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
    yacl::math::MPInt l;
    l.Deserialize(yacl::ByteContainerView(data + offset, l_size));
    l_vec.push_back(l);
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
    yacl::math::MPInt r;
    r.Deserialize(yacl::ByteContainerView(data + offset, r_size));
    r_vec.push_back(r);
    offset += r_size;
  }
  
  return ProofShare(t_x, t_x_blinding, e_blinding, std::move(l_vec), std::move(r_vec));
}


} // namespace examples::zkp
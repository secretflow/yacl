// Copyright 2025 @yangjucai.
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

#include "yacl/crypto/experimental/zkp/bulletproofs/generators.h"

#include <array>
#include <cstring>

#include "yacl/crypto/experimental/zkp/bulletproofs/generators.h"

namespace examples::zkp {

// ---- PedersenGens implementation ----

PedersenGens::PedersenGens(std::shared_ptr<yacl::crypto::EcGroup> curve)
    : curve_(std::move(curve)) {
  // B is the standard generator
  B = curve_->GetGenerator();

  // B_blinding is derived from B
  yacl::Buffer b_bytes = curve_->SerializePoint(B);
  B_blinding =
      curve_->HashToCurve(yacl::crypto::HashToCurveStrategy::Autonomous,
                          yacl::ByteContainerView(b_bytes));
}

yacl::crypto::EcPoint PedersenGens::Commit(
    const yacl::math::MPInt& value, const yacl::math::MPInt& blinding) const {
  yacl::crypto::EcPoint term1 = curve_->Mul(B, value);
  yacl::crypto::EcPoint term2 = curve_->Mul(B_blinding, blinding);
  return curve_->Add(term1, term2);
}

// ---- GeneratorsChain implementation ----

GeneratorsChain::GeneratorsChain(std::shared_ptr<yacl::crypto::EcGroup> curve,
                                 const std::string& label)
    : curve_(std::move(curve)) {
  // Initialize the Shake256Hash with the label
  hash_.Reset();
  hash_.Update(label);
}

void GeneratorsChain::FastForward(size_t n) {
  // Just advance the counter, actual generation is lazy
  counter_ += n;
}

yacl::crypto::EcPoint GeneratorsChain::Next() {
  // Generate 64 bytes of output using Shake256Hash
  /***
  TODO: use stream read of Shake256Hash instead of CumulativeHash
  ***/

  size_t start_byte = counter_ * 64;
  size_t end_byte = start_byte + 64;
  auto full_hash = hash_.CumulativeHash(end_byte);
  std::vector<uint8_t> uniform_bytes(full_hash.begin() + start_byte,
                                     full_hash.begin() + end_byte);

  // Increment the counter for the next call
  counter_++;

  // Convert the output to a point on the curve
  return curve_->HashToCurve(yacl::crypto::HashToCurveStrategy::Autonomous,
                             yacl::ByteContainerView(uniform_bytes));
}

// ---- BulletproofGens implementation ----

BulletproofGens::BulletproofGens(std::shared_ptr<yacl::crypto::EcGroup> curve,
                                 size_t gens_capacity, size_t party_capacity)
    : curve_(std::move(curve)),
      gens_capacity_(0),
      party_capacity_(party_capacity) {
  // Initialize empty vectors for each party
  G_vec_.resize(party_capacity);
  H_vec_.resize(party_capacity);

  // Fill with the requested capacity of generators
  IncreaseCapacity(gens_capacity);
}

BulletproofGensShare BulletproofGens::Share(size_t j) const {
  YACL_ENFORCE(j < party_capacity_, "Party index out of bounds");
  return BulletproofGensShare(*this, j);
}

void BulletproofGens::IncreaseCapacity(size_t new_capacity) {
  if (gens_capacity_ >= new_capacity) {
    return;
  }

  for (size_t i = 0; i < party_capacity_; i++) {
    uint32_t party_index = static_cast<uint32_t>(i);

    // Generate G generators
    std::string g_label = "G";
    g_label.append(reinterpret_cast<char*>(&party_index), sizeof(party_index));

    GeneratorsChain g_chain(curve_, g_label);
    g_chain.FastForward(gens_capacity_);

    // Generate new G points
    for (size_t j = gens_capacity_; j < new_capacity; j++) {
      G_vec_[i].emplace_back(g_chain.Next());
    }

    // Generate H generators
    std::string h_label = "H";
    h_label.append(reinterpret_cast<char*>(&party_index), sizeof(party_index));

    GeneratorsChain h_chain(curve_, h_label);
    h_chain.FastForward(gens_capacity_);

    // Generate new H points
    for (size_t j = gens_capacity_; j < new_capacity; j++) {
      H_vec_[i].emplace_back(h_chain.Next());
    }
  }

  gens_capacity_ = new_capacity;
}

const std::vector<yacl::crypto::EcPoint>& BulletproofGens::GetGParty(
    size_t j) const {
  YACL_ENFORCE(j < party_capacity_, "Party index out of bounds");
  return G_vec_[j];
}

const std::vector<yacl::crypto::EcPoint>& BulletproofGens::GetHParty(
    size_t j) const {
  YACL_ENFORCE(j < party_capacity_, "Party index out of bounds");
  return H_vec_[j];
}

std::vector<yacl::crypto::EcPoint> BulletproofGens::GetAllG(size_t n,
                                                            size_t m) const {
  YACL_ENFORCE(n <= gens_capacity_,
               "Generator capacity too small for requested size");
  YACL_ENFORCE(m <= party_capacity_,
               "Party capacity too small for requested size");

  std::vector<yacl::crypto::EcPoint> result;
  result.reserve(n * m);

  for (size_t party_idx = 0; party_idx < m; party_idx++) {
    for (size_t gen_idx = 0; gen_idx < n; gen_idx++) {
      result.emplace_back(G_vec_[party_idx][gen_idx]);
    }
  }

  return result;
}

std::vector<yacl::crypto::EcPoint> BulletproofGens::GetAllH(size_t n,
                                                            size_t m) const {
  YACL_ENFORCE(n <= gens_capacity_,
               "Generator capacity too small for requested size");
  YACL_ENFORCE(m <= party_capacity_,
               "Party capacity too small for requested size");

  std::vector<yacl::crypto::EcPoint> result;
  result.reserve(n * m);

  for (size_t party_idx = 0; party_idx < m; party_idx++) {
    for (size_t gen_idx = 0; gen_idx < n; gen_idx++) {
      result.emplace_back(H_vec_[party_idx][gen_idx]);
    }
  }

  return result;
}

// ---- BulletproofGensShare implementation ----

std::vector<yacl::crypto::EcPoint> BulletproofGensShare::G(size_t n) const {
  YACL_ENFORCE(n <= gens_.gens_capacity_,
               "Requested more generators than available");

  const auto& party_G = gens_.G_vec_[share_];
  return std::vector<yacl::crypto::EcPoint>(party_G.begin(),
                                            party_G.begin() + n);
}

std::vector<yacl::crypto::EcPoint> BulletproofGensShare::H(size_t n) const {
  YACL_ENFORCE(n <= gens_.gens_capacity_,
               "Requested more generators than available");

  const auto& party_H = gens_.H_vec_[share_];
  return std::vector<yacl::crypto::EcPoint>(party_H.begin(),
                                            party_H.begin() + n);
}

}  // namespace examples::zkp
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

#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "yacl/crypto/experimental/zkp/bulletproofs/util.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::zkp {

/**
 * @brief Represents a pair of base points for Pedersen commitments.
 *
 * The Bulletproofs implementation and API is designed to support
 * pluggable bases for Pedersen commitments.
 */
class PedersenGens {
 public:
  yacl::crypto::EcPoint B;
  yacl::crypto::EcPoint B_blinding;
  std::shared_ptr<yacl::crypto::EcGroup> curve_;
  explicit PedersenGens(std::shared_ptr<yacl::crypto::EcGroup> curve)
      : curve_(curve) {
    B = curve_->GetGenerator();
    B_blinding = curve_->HashToCurve(
        yacl::crypto::HashToCurveStrategy::Autonomous, "B_blinding");
  }

  yacl::crypto::EcPoint Commit(const yacl::math::MPInt& value,
                               const yacl::math::MPInt& blinding) const {
    return MultiScalarMul(curve_, {value, blinding}, {B, B_blinding});
  }

  // Return the shared_ptr by value
  std::shared_ptr<yacl::crypto::EcGroup> GetCurve() const { return curve_; }
};

/**
 * @brief Generates a chain of deterministic random points
 */
class GeneratorsChain {
 public:
  /**
   * @brief Creates a chain of generators, determined by the hash of label
   *
   * @param curve The elliptic curve group
   * @param label The seed label
   */
  GeneratorsChain(std::shared_ptr<yacl::crypto::EcGroup> curve,
                  const std::string& label);

  /**
   * @brief Advances the generator chain n times, discarding the results
   *
   * @param n Number of steps to advance
   */
  void FastForward(size_t n);

  /**
   * @brief Get the next point in the chain
   *
   * @return yacl::crypto::EcPoint The next point
   */
  yacl::crypto::EcPoint Next();

 private:
  std::shared_ptr<yacl::crypto::EcGroup> curve_;
  std::array<uint8_t, 32> state_;
  size_t counter_ = 0;
};

/**
 * @brief Forward declaration for BulletproofGensShare
 */
class BulletproofGensShare;

/**
 * @brief The BulletproofGens struct contains all the generators needed
 * for aggregating up to `m` range proofs of up to `n` bits each.
 */
class BulletproofGens {
 public:
  /**
   * @brief Construct a new Bulletproof Gens object
   *
   * @param curve The elliptic curve group
   * @param gens_capacity Number of generators to precompute for each party
   * @param party_capacity Maximum number of parties for aggregated proofs
   */
  BulletproofGens(std::shared_ptr<yacl::crypto::EcGroup> curve,
                  size_t gens_capacity, size_t party_capacity);

  /**
   * @brief Returns j-th share of generators, with an appropriate
   * slice of vectors G and H for the j-th range proof.
   *
   * @param j Party index
   * @return BulletproofGensShare Share for party j
   */
  BulletproofGensShare Share(size_t j) const;

  /**
   * @brief Increases the generators' capacity to the amount specified.
   * If less than or equal to the current capacity, does nothing.
   *
   * @param new_capacity New capacity
   */
  void IncreaseCapacity(size_t new_capacity);

  /**
   * @brief Get the G generators for party j
   */
  const std::vector<yacl::crypto::EcPoint>& GetGParty(size_t j) const;

  /**
   * @brief Get the H generators for party j
   */
  const std::vector<yacl::crypto::EcPoint>& GetHParty(size_t j) const;

  /**
   * @brief Get all G generators for n bits and m parties
   */
  std::vector<yacl::crypto::EcPoint> GetAllG(size_t n, size_t m) const;

  /**
   * @brief Get all H generators for n bits and m parties
   */
  std::vector<yacl::crypto::EcPoint> GetAllH(size_t n, size_t m) const;

  // Getters
  size_t gens_capacity() const { return gens_capacity_; }
  size_t party_capacity() const { return party_capacity_; }
  const std::shared_ptr<yacl::crypto::EcGroup>& GetCurve() const {
    return curve_;
  }

 private:
  std::shared_ptr<yacl::crypto::EcGroup> curve_;
  size_t gens_capacity_;
  size_t party_capacity_;
  std::vector<std::vector<yacl::crypto::EcPoint>> G_vec_;
  std::vector<std::vector<yacl::crypto::EcPoint>> H_vec_;

  friend class BulletproofGensShare;
};

/**
 * @brief Represents a view of the generators used by a specific party in an
 * aggregated proof.
 */
class BulletproofGensShare {
 public:
  /**
   * @brief Get G generators for this party up to size n
   */
  std::vector<yacl::crypto::EcPoint> G(size_t n) const;

  /**
   * @brief Get H generators for this party up to size n
   */
  std::vector<yacl::crypto::EcPoint> H(size_t n) const;

 private:
  friend class BulletproofGens;

  BulletproofGensShare(const BulletproofGens& gens, size_t share)
      : gens_(gens), share_(share) {}

  const BulletproofGens& gens_;
  size_t share_;
};

}  // namespace examples::zkp
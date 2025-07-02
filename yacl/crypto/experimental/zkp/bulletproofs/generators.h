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

#include <memory>
#include <string>
#include <vector>

#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::zkp {

class GeneratorsChain {
 public:
  explicit GeneratorsChain(std::shared_ptr<yacl::crypto::EcGroup> curve,
                           const std::string& label);

  void FastForward(size_t n);

  yacl::crypto::EcPoint Next();

 private:
  std::shared_ptr<yacl::crypto::EcGroup> curve_;
  yacl::crypto::Shake256Hash hash_;
  size_t counter_{0};
};

/**
 * @brief Represents a pair of base points for Pedersen commitments.
 */
class PedersenGens {
 public:
  /**
   * @brief Create a new set of Pedersen generators.
   *
   * @param curve The elliptic curve group.
   */
  explicit PedersenGens(std::shared_ptr<yacl::crypto::EcGroup> curve);

  /**
   * @brief Creates a Pedersen commitment using the value and a blinding factor.
   * This version uses the curve stored internally during construction.
   *
   * @param value The value to commit to.
   * @param blinding The blinding factor.
   * @return yacl::crypto::EcPoint The commitment point.
   */
  yacl::crypto::EcPoint Commit(const yacl::math::MPInt& value,
                               const yacl::math::MPInt& blinding) const;

  // Public generator points
  yacl::crypto::EcPoint B;
  yacl::crypto::EcPoint B_blinding;

 private:
  std::shared_ptr<yacl::crypto::EcGroup> curve_;
};

class BulletproofGensShare;

class BulletproofGens {
 public:
  BulletproofGens(std::shared_ptr<yacl::crypto::EcGroup> curve,
                  size_t gens_capacity, size_t party_capacity);

  BulletproofGensShare Share(size_t j) const;

  void IncreaseCapacity(size_t new_capacity);

  size_t gens_capacity() const { return gens_capacity_; }
  size_t party_capacity() const { return party_capacity_; }

  const std::vector<yacl::crypto::EcPoint>& GetGParty(size_t j) const;
  const std::vector<yacl::crypto::EcPoint>& GetHParty(size_t j) const;

  std::vector<yacl::crypto::EcPoint> GetAllG(size_t n, size_t m) const;
  std::vector<yacl::crypto::EcPoint> GetAllH(size_t n, size_t m) const;

 private:
  friend class BulletproofGensShare;
  std::shared_ptr<yacl::crypto::EcGroup> curve_;
  size_t gens_capacity_;
  size_t party_capacity_;
  std::vector<std::vector<yacl::crypto::EcPoint>> G_vec_;
  std::vector<std::vector<yacl::crypto::EcPoint>> H_vec_;
};

class BulletproofGensShare {
 public:
  BulletproofGensShare(const BulletproofGens& gens, size_t share)
      : gens_(gens), share_(share) {}

  std::vector<yacl::crypto::EcPoint> G(size_t n) const;
  std::vector<yacl::crypto::EcPoint> H(size_t n) const;

 private:
  const BulletproofGens& gens_;
  size_t share_;
};

}  // namespace examples::zkp
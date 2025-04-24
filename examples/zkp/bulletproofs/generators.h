#pragma once

#include <memory>
#include <vector>
#include <string>

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::zkp {

// Generate a vector of generators for use in range proofs
std::vector<yacl::crypto::EcPoint> GenerateGenerators(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    size_t n,
    const std::string& label);

// Represents a pair of base points for Pedersen commitments.
// B: the standard base point (generator) of the curve
// B_blinding: derived from hashing B's bytes
class PedersenGens {
 public:
  explicit PedersenGens(std::shared_ptr<yacl::crypto::EcGroup> curve);

  // Creates a Pedersen commitment: value * B + blinding * B_blinding
  yacl::crypto::EcPoint Commit(const yacl::math::MPInt& value,
                              const yacl::math::MPInt& blinding) const;

  // Getters
  const yacl::crypto::EcPoint& GetB() const { return B_; }
  const yacl::crypto::EcPoint& GetBBlinding() const { return B_blinding_; }

 private:
  std::shared_ptr<yacl::crypto::EcGroup> curve_;
  yacl::crypto::EcPoint B_;         // Base for the committed value
  yacl::crypto::EcPoint B_blinding_; // Base for the blinding factor
};

// The BulletproofGens contains all generators needed for aggregating
// up to m range proofs of up to n bits each.
class BulletproofGens {
 public:
  BulletproofGens(std::shared_ptr<yacl::crypto::EcGroup> curve,
                  size_t gens_capacity,
                  size_t party_capacity);

  // Getters
  size_t GensCapacity() const { return gens_capacity_; }
  size_t PartyCapacity() const { return party_capacity_; }

  // Get G generators for party i
  const std::vector<yacl::crypto::EcPoint>& GetGVec(size_t i) const {
    YACL_ENFORCE(i < party_capacity_, "Party index out of bounds");
    return G_vec_[i];
  }

  // Get H generators for party i
  const std::vector<yacl::crypto::EcPoint>& GetHVec(size_t i) const {
    YACL_ENFORCE(i < party_capacity_, "Party index out of bounds");
    return H_vec_[i];
  }

 private:
  std::shared_ptr<yacl::crypto::EcGroup> curve_;
  size_t gens_capacity_;   // Number of generators for each party
  size_t party_capacity_;  // Number of parties
  std::vector<std::vector<yacl::crypto::EcPoint>> G_vec_; // G generators for each party
  std::vector<std::vector<yacl::crypto::EcPoint>> H_vec_; // H generators for each party

  // Helper function to generate deterministic generators
  std::vector<yacl::crypto::EcPoint> GeneratePartyGens(
      const std::string& label, size_t party_index, bool is_h);
};

} // namespace examples::zkp 
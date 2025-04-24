#include "zkp/bulletproofs/generators.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/hash/ssl_hash.h"
#include "yacl/utils/parallel.h"
#include <string_view>

namespace examples::zkp {

PedersenGens::PedersenGens(std::shared_ptr<yacl::crypto::EcGroup> curve)
    : curve_(std::move(curve)) {
  // Use the standard base point as B
  B_ = curve_->GetGenerator();
  YACL_ENFORCE(!curve_->IsInfinity(B_), "Base generator cannot be infinity");

  // Generate B_blinding by hashing B's serialized bytes
  // This follows the Rust implementation's approach
  auto b_bytes = curve_->SerializePoint(B_);
  
  // Hash the serialized point using SHA256
  yacl::crypto::SslHash hasher(yacl::crypto::HashAlgorithm::SHA256);
  auto hash = hasher.Update(yacl::ByteContainerView(b_bytes)).CumulativeHash();

  // Convert hash to a point
  std::string_view hash_view(reinterpret_cast<const char*>(hash.data()), hash.size());
  B_blinding_ = curve_->HashToCurve(hash_view);

  // Verify the generated point
  YACL_ENFORCE(!curve_->IsInfinity(B_blinding_), 
               "B_blinding cannot be infinity point");
  YACL_ENFORCE(!curve_->PointEqual(B_, B_blinding_),
               "B_blinding cannot equal B");
}

yacl::crypto::EcPoint PedersenGens::Commit(
    const yacl::math::MPInt& value,
    const yacl::math::MPInt& blinding) const {
  // Compute value * B + blinding * B_blinding
  auto term1 = curve_->Mul(B_, value);
  auto term2 = curve_->Mul(B_blinding_, blinding);
  return curve_->Add(term1, term2);
}

BulletproofGens::BulletproofGens(
    std::shared_ptr<yacl::crypto::EcGroup> curve,
    size_t gens_capacity,
    size_t party_capacity)
    : curve_(std::move(curve)),
      gens_capacity_(gens_capacity),
      party_capacity_(party_capacity) {
  
  YACL_ENFORCE(gens_capacity > 0, "gens_capacity must be positive");
  YACL_ENFORCE(party_capacity >= 1, "party_capacity must be at least 1");

  // Initialize vectors
  G_vec_.resize(party_capacity);
  H_vec_.resize(party_capacity);

  // Generate generators for each party in parallel
  yacl::parallel_for(0, party_capacity, [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      // Generate G generators for party i
      G_vec_[i] = GeneratePartyGens("G", i, false);
      // Generate H generators for party i
      H_vec_[i] = GeneratePartyGens("H", i, true);
    }
  });
}

std::vector<yacl::crypto::EcPoint> BulletproofGens::GeneratePartyGens(
    const std::string& label,
    size_t party_index,
    bool is_h) {
  std::vector<yacl::crypto::EcPoint> generators;
  generators.reserve(gens_capacity_);

  // Create unique label for this party's generators
  std::string party_label = label + std::to_string(party_index);
  if (is_h) {
    party_label += "_H";
  } else {
    party_label += "_G";
  }

  // Use SHA256 for deterministic generation
  yacl::crypto::SslHash hasher(yacl::crypto::HashAlgorithm::SHA256);
  hasher.Update(yacl::ByteContainerView("BulletproofGens"));
  hasher.Update(yacl::ByteContainerView(party_label));

  // Generate gens_capacity_ points
  for (size_t i = 0; i < gens_capacity_; ++i) {
    // Add index to make each generator unique
    hasher.Update(yacl::ByteContainerView(std::to_string(i)));
    auto hash = hasher.CumulativeHash();

    // Convert hash to point
    std::string_view hash_view(reinterpret_cast<const char*>(hash.data()), 
                              hash.size());
    auto point = curve_->HashToCurve(hash_view);
    
    // Verify point is valid
    YACL_ENFORCE(!curve_->IsInfinity(point), 
                 "Generated point cannot be infinity");
    
    generators.push_back(point);
  }

  return generators;
}

std::vector<yacl::crypto::EcPoint> GenerateGenerators(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    size_t n,
    const std::string& label) {
  YACL_ENFORCE(curve != nullptr, "GenerateGenerators: Curve cannot be null");
  
  std::vector<yacl::crypto::EcPoint> generators;
  generators.reserve(n);

  // Use SHA256 for deterministic generation
  yacl::crypto::SslHash hasher(yacl::crypto::HashAlgorithm::SHA256);
  
  // Add domain separation
  hasher.Update(yacl::ByteContainerView("generators"));
  hasher.Update(yacl::ByteContainerView(label));
  
  // Generate n points
  for (size_t i = 0; i < n; ++i) {
    // Add counter to make each generator unique
    hasher.Update(yacl::ByteContainerView(std::to_string(i)));
    auto hash = hasher.CumulativeHash();

    // Convert hash to point
    std::string_view hash_view(reinterpret_cast<const char*>(hash.data()), 
                              hash.size());
    auto point = curve->HashToCurve(hash_view);
    
    // Verify point is valid
    YACL_ENFORCE(!curve->IsInfinity(point), 
                 "Generated point cannot be infinity");
    
    generators.push_back(point);
  }

  return generators;
}

} // namespace examples::zkp 
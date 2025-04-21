#include "generators.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/hash/hash_utils.h"
#include <string_view>

namespace examples::zkp {

std::vector<yacl::crypto::EcPoint> GenerateGenerators(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    size_t n,
    const std::string& label) {
  YACL_ENFORCE(curve != nullptr, "GenerateGenerators: Curve cannot be null");
  
  std::vector<yacl::crypto::EcPoint> generators;
  generators.reserve(n);

  // Use a hash function to generate deterministic points
  yacl::crypto::Sha256Hash hasher;
  
  // Add domain separation
  hasher.Update(yacl::ByteContainerView("generators"));
  hasher.Update(yacl::ByteContainerView(label));
  
  // Generate n points
  for (size_t i = 0; i < n; ++i) {
    // Add counter to make each point unique
    uint8_t counter[4] = {
        static_cast<uint8_t>((i >> 24) & 0xFF),
        static_cast<uint8_t>((i >> 16) & 0xFF),
        static_cast<uint8_t>((i >> 8) & 0xFF),
        static_cast<uint8_t>(i & 0xFF)
    };
    hasher.Update(yacl::ByteContainerView(counter, sizeof(counter)));
    
    // Get hash output
    auto hash = hasher.CumulativeHash();
    
    // Map hash to curve point using string_view
    std::string_view hash_view(reinterpret_cast<const char*>(hash.data()), hash.size());
    auto point = curve->HashToCurve(hash_view);
    generators.push_back(point);
  }

  return generators;
}

}  // namespace examples::zkp 
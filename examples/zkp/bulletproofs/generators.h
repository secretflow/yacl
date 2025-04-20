#pragma once

#include <memory>
#include <vector>

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/ecc/ec_point.h"

namespace examples::zkp {

// Generate a vector of generators for use in range proofs
std::vector<yacl::crypto::EcPoint> GenerateGenerators(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    size_t n,
    const std::string& label);

}  // namespace examples::zkp 
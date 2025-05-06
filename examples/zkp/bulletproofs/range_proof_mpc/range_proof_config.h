#pragma once

#include <memory>
#include <string>
#include <vector>

#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::zkp {

// Constants for the curve used in range proof
inline constexpr const char* kRangeProofEcName = "secp256k1";
inline constexpr const char* kRangeProofEcLib = "openssl";

// Range proof type enumeration
enum class RangeProofType {
  // Description: prove that a committed value lies in range [0, 2^n)
  // Secret: value v, blinding factor gamma
  // Statement: C = h^gamma * g^v, where v in [0, 2^n)
  StandardRange,
};

// Range proof configuration class
struct RangeProofConfig {
  RangeProofType type;           // Range proof type
  size_t bit_length;             // Bit length of the range (n in [0, 2^n))
  uint32_t aggregation_size;     // Number of range proofs to aggregate
  yacl::crypto::HashAlgorithm hash_algo =
      yacl::crypto::HashAlgorithm::SHA256;  // Hash algorithm
  yacl::crypto::PointOctetFormat point_format =
      yacl::crypto::PointOctetFormat::Uncompressed;  // Point format

  bool CheckValid() const;
  void SetBitLength(size_t new_bit_length);
  bool operator==(const RangeProofConfig& other) const;
};

// Get standard range proof configuration
RangeProofConfig GetStandardRange(size_t bit_length);

// Set bit length for range proof
void SetBitLength(RangeProofConfig* config, size_t bit_length);

//
// Alias for Range proof systems
//
using RangeWitness = std::vector<yacl::math::MPInt>;
using RangeChallenge = yacl::math::MPInt;
using RangeStatement = yacl::crypto::EcPoint;
using RangeGenerator = std::vector<yacl::crypto::EcPoint>;

// Proof structures
struct RangeProofCommitment {
  yacl::crypto::EcPoint A;
  yacl::crypto::EcPoint S;
  yacl::crypto::EcPoint T1;
  yacl::crypto::EcPoint T2;
};

struct RangeProofScalars {
  yacl::math::MPInt tau_x;
  yacl::math::MPInt mu;
  yacl::math::MPInt t;
};

}  // namespace examples::zkp 
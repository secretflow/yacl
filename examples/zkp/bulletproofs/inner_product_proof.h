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

#pragma once

#include <memory>
#include <vector>
#include <optional>

#include "simple_transcript.h"

#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::zkp {

// Helper function for multi-scalar multiplication (declaration)
yacl::crypto::EcPoint VartimeMultiscalarMul(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const std::vector<yacl::math::MPInt>& scalars,
    const std::vector<yacl::crypto::EcPoint>& points);

class SimpleTranscript;  // Forward declaration

// Add IPPVerificationScalars structure
struct IPPVerificationScalars {
  std::vector<yacl::math::MPInt> challenges;     // u challenges
  std::vector<yacl::math::MPInt> challenges_inv; // u_inv challenges
  std::vector<yacl::math::MPInt> s;             // s vector derived from challenges
  std::vector<yacl::math::MPInt> s_inv;         // s_inv vector
};

class InnerProductProof {
 public:
  // Error enum for verification results
  enum class Error {
    kOk = 0,
    kInvalidArgument,
    kVerificationFailed,
    kInvalidProof,
  };

  // Creates an inner product proof
  static InnerProductProof Create(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      SimpleTranscript& transcript,
      const yacl::crypto::EcPoint& Q,
      const std::vector<yacl::math::MPInt>& G_factors,
      const std::vector<yacl::math::MPInt>& H_factors,
      const std::vector<yacl::crypto::EcPoint>& G_vec,
      const std::vector<yacl::crypto::EcPoint>& H_vec,
      const std::vector<yacl::math::MPInt>& a_vec,
      const std::vector<yacl::math::MPInt>& b_vec);

  // Verifies an inner product proof
  Error Verify(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      size_t n_in,
      SimpleTranscript& transcript,
      const std::vector<yacl::math::MPInt>& G_factors,
      const std::vector<yacl::math::MPInt>& H_factors,
      const yacl::crypto::EcPoint& P,
      const yacl::crypto::EcPoint& Q,
      const std::vector<yacl::crypto::EcPoint>& G_vec,
      const std::vector<yacl::crypto::EcPoint>& H_vec) const;

  // Compute verification scalars
  std::optional<IPPVerificationScalars> ComputeVerificationScalars(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      size_t n_in,
      SimpleTranscript& transcript) const;

  // Serialization
  yacl::Buffer ToBytes() const;
  static InnerProductProof FromBytes(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      const yacl::ByteContainerView& bytes);

  // Get curve instance
  const std::shared_ptr<yacl::crypto::EcGroup>& GetCurve() const { return curve_; }

 private:
  // L and R values for each round
  std::vector<yacl::crypto::EcPoint> L_;
  std::vector<yacl::crypto::EcPoint> R_;
  // Final a and b values
  yacl::math::MPInt a_;
  yacl::math::MPInt b_;
  std::shared_ptr<yacl::crypto::EcGroup> curve_;
};

}  // namespace examples::zkp
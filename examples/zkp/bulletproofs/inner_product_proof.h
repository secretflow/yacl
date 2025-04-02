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

#include "simple_transcript.h"

#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/tools/ro.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::zkp {

// Helper function for multi-scalar multiplication (declaration)
yacl::crypto::EcPoint VartimeMultiscalarMul(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const std::vector<yacl::math::MPInt>& scalars,
    const std::vector<yacl::crypto::EcPoint>& points);

class SimpleTranscript;  // Forward declaration

class InnerProductProof {
 public:
  // Define enum for verification results
  enum class Error {
    kOk = 0,
    kInvalidInput = 1,
    kInvalidProof = 2,
  };

  // Static Create method
  static InnerProductProof Create(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      SimpleTranscript& transcript,  // Changed from pointer to reference
      const yacl::crypto::EcPoint& Q,
      const std::vector<yacl::math::MPInt>& G_factors,
      const std::vector<yacl::math::MPInt>& H_factors,
      const std::vector<yacl::crypto::EcPoint>& G_vec,
      const std::vector<yacl::crypto::EcPoint>& H_vec,
      const std::vector<yacl::math::MPInt>& a_vec,
      const std::vector<yacl::math::MPInt>& b_vec);

  // Verify method
  Error Verify(const std::shared_ptr<yacl::crypto::EcGroup>& curve,
               size_t n_in,                      // Original size
               SimpleTranscript& transcript,  // Changed from pointer to reference
               const std::vector<yacl::math::MPInt>& G_factors,
               const std::vector<yacl::math::MPInt>& H_factors,
               const yacl::crypto::EcPoint& P, const yacl::crypto::EcPoint& Q,
               const std::vector<yacl::crypto::EcPoint>& G_vec,
               const std::vector<yacl::crypto::EcPoint>& H_vec) const;

  // 获取证明组件 (for serialization or debugging)
  const std::vector<yacl::crypto::EcPoint>& GetLvec() const { return L_vec_; }
  const std::vector<yacl::crypto::EcPoint>& GetRvec() const { return R_vec_; }
  const yacl::math::MPInt& GetA() const { return a_; }
  const yacl::math::MPInt& GetB() const { return b_; }

 private:
  std::vector<yacl::crypto::EcPoint> L_vec_;
  std::vector<yacl::crypto::EcPoint> R_vec_;
  yacl::math::MPInt a_;
  yacl::math::MPInt b_;
};

}  // namespace examples::zkp
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

#include <vector>
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/tools/ro.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::zkp {

class InnerProductProof {
 public:
  enum class Error {
    kOk,
    kInvalidProof,
    kInvalidInput,
  };

  // 创建内积证明
  static InnerProductProof Create(
      yacl::crypto::RandomOracle* transcript,
      const yacl::crypto::EcPoint& Q,
      const std::vector<yacl::math::MPInt>& G_factors,
      const std::vector<yacl::math::MPInt>& H_factors,
      const std::vector<yacl::crypto::EcPoint>& G_vec,
      const std::vector<yacl::crypto::EcPoint>& H_vec,
      const std::vector<yacl::math::MPInt>& a_vec,
      const std::vector<yacl::math::MPInt>& b_vec);

  // 验证内积证明
  Error Verify(
      size_t n,
      yacl::crypto::RandomOracle* transcript,
      const std::vector<yacl::math::MPInt>& G_factors,
      const std::vector<yacl::math::MPInt>& H_factors,
      const yacl::crypto::EcPoint& P,
      const yacl::crypto::EcPoint& Q,
      const std::vector<yacl::crypto::EcPoint>& G_vec,
      const std::vector<yacl::crypto::EcPoint>& H_vec) const;

 private:
  std::vector<yacl::math::MPInt> proof_;
};

}  // namespace examples::zkp
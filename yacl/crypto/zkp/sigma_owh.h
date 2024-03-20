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

#include "yacl/crypto/ecc/group_sketch.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/crypto/zkp/sigma_config.h"

namespace yacl::crypto {

// As we abide an unifying view to implement the Sigma-type zero-knowledge
// proof (ZKP) schemes, in which a one-way group homomorphism(OWH) would
// determine a specific scheme. Here we implement the OWH function in class
// `SigmaOWH::ToStatement(...)`.
//   More info, please see class `SigmaProtocol`.
class SigmaOWH {
 public:
  // use seeds to generate group generators
  static SigmaGenerator MakeGenerators(
      const SigmaConfig& config, const std::shared_ptr<EcGroup>& group,
      uint128_t seed = SecureRandU128(),
      HashToCurveStrategy strategy = HashToCurveStrategy::Autonomous);

  static SigmaStatement ToStatement(const SigmaConfig& config,
                                    const std::shared_ptr<EcGroup>& group,
                                    const SigmaGenerator& generators,
                                    const Witness& witness);
};

}  // namespace yacl::crypto

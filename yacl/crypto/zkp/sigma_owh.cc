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

#include "yacl/crypto/zkp/sigma_owh.h"

namespace yacl::crypto {

const std::string kSigmaDefaultSeedPrefix = "YACL-SIGMA-PROOF-SEED";

SigmaGenerator SigmaOWH::MakeGenerators(const SigmaConfig& config,
                                        const std::shared_ptr<EcGroup>& group,
                                        uint128_t seed,
                                        HashToCurveStrategy strategy) {
  SigmaGenerator ret;
  for (size_t i = 0; i < config.num_generator; i++) {
    auto temp = group->HashToCurve(
        strategy, fmt::format("{}-{}-{}-{}", kSigmaDefaultSeedPrefix,
                              int(config.type), seed, i));
    YACL_ENFORCE(
        !group->IsInfinity(temp),
        "Generator should not be 1(identity elements)=infinity in ECC group!");
    ret.emplace_back(temp);
  }
  return ret;
}

namespace {
// num_witness = n
// num_generator = n
// to 1 statement
SigmaStatement EcStatementNN1(const SigmaConfig& config,
                              const std::shared_ptr<EcGroup>& group,
                              const Witness& witness,
                              const SigmaGenerator& generators) {
  auto p = group->Mul(generators[0], witness[0]);
  for (uint64_t i = 1; i < config.num_witness; i++) {
    auto temp = group->Mul(generators[i], witness[i]);
    group->AddInplace(&p, temp);
  }
  return {p};
}

// num_witness = n
// num_generator = n
// to n(=num_statement) statement
SigmaStatement EcStatementNNN(const SigmaConfig& config,
                              const std::shared_ptr<EcGroup>& group,
                              const Witness& witness,
                              const SigmaGenerator& generators) {
  SigmaStatement ret;
  for (uint64_t i = 0; i < config.num_statement; i++) {
    ret.emplace_back(group->Mul(generators[i], witness[i]));
  }
  return ret;
}

// num_witness = 1
// num_generator = n
// to n(=num_statement) statement
SigmaStatement EcStatement1NN(const SigmaConfig& config,
                              const std::shared_ptr<EcGroup>& group,
                              const Witness& witness,
                              const SigmaGenerator& generators) {
  SigmaStatement ret;
  for (uint64_t i = 0; i < config.num_statement; i++) {
    ret.emplace_back(group->Mul(generators[i], witness[0]));
  }
  return ret;
}
}  // namespace

SigmaStatement SigmaOWH::ToStatement(const SigmaConfig& config,
                                     const std::shared_ptr<EcGroup>& group,
                                     const SigmaGenerator& generators,
                                     const Witness& witness) {
  YACL_ENFORCE(config.IsQualified(), "Sigma config is not right!");
  YACL_ENFORCE(witness.size() == config.num_witness,
               "Witness size is {}, it should be {}", witness.size(),
               config.num_witness);
  YACL_ENFORCE(generators.size() >= config.num_generator,
               "Generator size is {}, it should be {}", generators.size(),
               config.num_generator);

  switch (config.type) {
    case SigmaType::Dlog:
    case SigmaType::Pedersen:
    case SigmaType::Representation:
      return EcStatementNN1(config, group, witness, generators);
    case SigmaType::SeveralDlog:
      return EcStatementNNN(config, group, witness, generators);
    case SigmaType::DlogEq:
    case SigmaType::DHTripple:
    case SigmaType::SeveralDlogEq:
      return EcStatement1NN(config, group, witness, generators);
    default:
      YACL_THROW("Not supported Sigma proof type!");
  }
}

}  // namespace yacl::crypto

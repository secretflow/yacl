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

#include "zkp/bulletproofs/ipa/ipa_config.h"

#include <unordered_map>

#include "yacl/base/exception.h"

// Include necessary types directly or ensure they are in ipa_config.h
#include "yacl/crypto/ecc/ec_point.h"     // For PointOctetFormat
#include "yacl/crypto/hash/hash_utils.h"  // For HashAlgorithm

namespace examples::zkp {

bool IpaConfig::CheckValid() const { return witness_count > 0; }

void IpaConfig::SetDynamicNumber(size_t dynamic_number) {
  witness_count = dynamic_number;
}

bool IpaConfig::operator==(const IpaConfig& other) const {
  return type == other.type && witness_count == other.witness_count;
}

namespace {

std::unordered_map<IpaType, IpaConfig> BuildConfigMap() {
  std::unordered_map<IpaType, IpaConfig> configs;

  // Inner product proof
  configs[IpaType::InnerProduct] = IpaConfig{
      .type = IpaType::InnerProduct,
      .witness_count = 0,
      .num_rnd_witness = 0,
      .num_generator = 0,
      .num_statement = 0,
      .hash_algo = yacl::crypto::HashAlgorithm::SHA256,
      .point_format = yacl::crypto::PointOctetFormat::Uncompressed,
  };

  return configs;
}

}  // namespace

IpaConfig GetInnerProduct(size_t witness_count) {
  static const auto configs = BuildConfigMap();
  auto config = configs.at(IpaType::InnerProduct);
  config.witness_count = witness_count;
  return config;
}

void SetDynamicNumber(IpaConfig& config, size_t dynamic_number) {
  config.SetDynamicNumber(dynamic_number);
}

}  // namespace examples::zkp
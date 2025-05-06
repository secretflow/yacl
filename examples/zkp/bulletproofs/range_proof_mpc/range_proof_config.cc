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

#include <string>
#include <unordered_map>
#include "zkp/bulletproofs/range_proof_mpc/range_proof_config.h"

namespace examples::zkp {

bool RangeProofConfig::CheckValid() const {
  if (bit_length == 0) {
    return false;
  }
  if (aggregation_size == 0) {
    return false;
  }
  return true;
}

void RangeProofConfig::SetBitLength(size_t new_bit_length) {
  bit_length = new_bit_length;
}

bool RangeProofConfig::operator==(const RangeProofConfig& other) const {
  return type == other.type && bit_length == other.bit_length &&
         aggregation_size == other.aggregation_size &&
         hash_algo == other.hash_algo && point_format == other.point_format;
}

RangeProofConfig GetStandardRange(size_t bit_length) {
  RangeProofConfig config;
  config.type = RangeProofType::StandardRange;
  config.bit_length = bit_length;
  config.aggregation_size = 1;
  return config;
}

void SetBitLength(RangeProofConfig* config, size_t bit_length) {
  config->SetBitLength(bit_length);
}

}  // namespace examples::zkp 
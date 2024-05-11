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

#include "yacl/crypto/zkp/sigma_config.h"

namespace yacl::crypto {

// 0 means n, user should assign these to actual numbers
const std::vector<SigmaConfig> kSigmaConfig = {
    // type, witness, rnd_witness, generator, statement
    {SigmaType::Dlog, 1, 1, 1, 1},
    {SigmaType::Pedersen, 2, 2, 2, 1},
    {SigmaType::DlogEq, 1, 1, 2, 2},
    {SigmaType::DHTripple, 1, 1, 2, 2},
    // number of witness, random witness and generators should be the same and
    // at least 1
    {SigmaType::Representation, 0, 0, 0, 1, true},
    // number of witness, random witness, generators, challenges and statements
    // should be the same and at least 1
    {SigmaType::SeveralDlog, 0, 0, 0, 0, true},
    // number of generators, statements should be the same and at least 2
    {SigmaType::SeveralDlogEq, 1, 1, 0, 0, true},
    {SigmaType::PedersenMult, 5, 5, 2, 3},
    {SigmaType::PedersenMultOpenOne, 5, 5, 2, 3},
};

bool SigmaConfig::IsQualified() const {
  if (!dyn_size_flag) {
    return Equals(GetSigmaConfig(type));
  }
  // check varied size sigma config(values of varied attrs may are setted by
  // called SigmaConfig.SetXXX(), or default 0)
  switch (type) {
    case SigmaType::Representation:
      // number of witness and generator should be the same and as least 1,
      // number of challenge and statement should be 1.
      return num_statement == 1 && num_witness > 0 &&
             num_witness == num_rnd_witness && num_witness == num_generator;
    case SigmaType::SeveralDlog:
      // number of witness should be as least 1
      // number of witness, challenge, generator and num_statement should be
      // the same
      return num_witness > 0 && num_witness == num_rnd_witness &&
             num_witness == num_generator && num_witness == num_statement;
    case SigmaType::SeveralDlogEq:
      // number of witness should be 1
      // number of generator should as least 2
      // number of generator and num_statement should be the same
      return num_witness == 1 && num_rnd_witness == 1 && num_generator >= 2 &&
             num_generator == num_statement;
    default:
      return false;
  }
}

SigmaConfig SigmaConfig::SetDynNum(uint32_t n) {
  YACL_ENFORCE(dyn_size_flag,
               "The config could not set num because it has no dynamic attr!");
  switch (type) {
    case SigmaType::Representation: {
      this->num_witness = n;
      this->num_rnd_witness = n;
      this->num_generator = n;
      break;
    }
    case SigmaType::SeveralDlog: {
      this->num_witness = n;
      this->num_rnd_witness = n;
      this->num_generator = n;
      this->num_statement = n;
      break;
    }
    case SigmaType::SeveralDlogEq: {
      this->num_generator = n;
      this->num_statement = n;
      break;
    }
    default:
      YACL_THROW("Not supported type(having dynamic attrs)!");
  }
  YACL_ENFORCE(IsQualified());
  return *this;
}

bool SigmaConfig::Equals(SigmaConfig rhs) const {
  return std::tie(type, num_witness, num_rnd_witness, num_generator,
                  num_statement, dyn_size_flag, ro_type, point_format) ==
         std::tie(rhs.type, rhs.num_witness, rhs.num_rnd_witness,
                  rhs.num_generator, rhs.num_statement, rhs.dyn_size_flag,
                  rhs.ro_type, rhs.point_format);
}

std::map<SigmaType, SigmaConfig> BuildSigmaMap() {
  std::map<SigmaType, SigmaConfig> res;
  auto insert = [&res](SigmaType type, const SigmaConfig& config) {
    auto it = res.find(type);
    if (it == res.end()) {
      res.insert({type, config});
    } else {
      // TODO: type to string?, so could ("... {}", type)
      YACL_ENFORCE(it->second.Equals(config), "Duplicate sigma type!");
    }
  };

  for (const auto& s : kSigmaConfig) {
    insert(s.type, s);
  }
  return res;
}

SigmaConfig GetSigmaConfig(SigmaType type) {
  static auto sigma_map = BuildSigmaMap();
  auto it = sigma_map.find(type);
  YACL_ENFORCE(it != sigma_map.end(), "Unsupported sigma type!");
  return it->second;
}

SigmaConfig GetRepresentation(uint64_t num) {
  return GetSigmaConfig(SigmaType::Representation).SetDynNum(num);
}

SigmaConfig GetSeveralDlogEq(uint64_t num) {
  return GetSigmaConfig(SigmaType::SeveralDlogEq).SetDynNum(num);
}

SigmaConfig GetSeveralDlog(uint64_t num) {
  return GetSigmaConfig(SigmaType::SeveralDlog).SetDynNum(num);
}

}  // namespace yacl::crypto

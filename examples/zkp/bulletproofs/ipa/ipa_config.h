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
#include <string>
#include <vector>

#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::zkp {

// Constants for the curve used in inner product argument
inline constexpr const char* kIpaEcName = "secp256k1";
inline constexpr const char* kIpaEcLib = "openssl";

// IPA类型枚举
enum class IpaType {
  // Description: know the inner product of two vectors
  // f : (a, b) -> <a, b> (n n 1)
  // Secret: a, b (vectors of length n)
  // Statement: z = <a, b>
  InnerProduct,
};

// IPA配置类
struct IpaConfig {
  IpaType type;                  // IPA proof type
  size_t witness_count;          // number of witness (in group G)
  uint32_t num_rnd_witness = 0;  // 随机见证数量
  uint32_t num_generator = 0;    // 生成元数量
  uint32_t num_statement = 0;    // 声明数量
  bool dyn_size_flag = false;    // 是否具有动态属性
  yacl::crypto::HashAlgorithm hash_algo =
      yacl::crypto::HashAlgorithm::SHA256;  // 哈希算法
  yacl::crypto::PointOctetFormat point_format =
      yacl::crypto::PointOctetFormat::Uncompressed;  // 点格式

  bool CheckValid() const;
  void SetDynamicNumber(size_t dynamic_number);
  bool operator==(const IpaConfig& other) const;
};

// 获取内积证明配置
IpaConfig GetInnerProduct(size_t witness_count);

// 设置动态数值
void SetDynamicNumber(IpaConfig* config, size_t dynamic_number);

//
// Alias for IPA proof systems
//
using Witness = std::vector<yacl::math::MPInt>;
using Challenge = yacl::math::MPInt;
using IpaProof = std::vector<yacl::math::MPInt>;
using IpaGenerator = std::vector<yacl::crypto::EcPoint>;
using IpaStatement = yacl::crypto::EcPoint;

struct IpaBatchProof {
  IpaProof proof;
  IpaStatement rnd_statement;
};

struct IpaShortProof {
  IpaProof proof;
  Challenge challenge;
};

// 批量证明结构
struct BatchProof {
  std::vector<IpaProof> proofs;
};

// 简短证明结构
struct ShortProof {
  IpaProof proof;
};

}  // namespace examples::zkp
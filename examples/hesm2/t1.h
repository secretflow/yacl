// Copyright 2024 Guowei Ling.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <shared_mutex>
#include <unordered_map>

#include "examples/hesm2/config.h"

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/utils/parallel.h"

namespace examples::hesm2 {

class CuckooT1 {
 public:
  explicit CuckooT1(int jmax)
      : jmax_(jmax), cuckoolen_(static_cast<uint32_t>(jmax * 1.3)) {
    if (jmax_ <= 0) {
      throw std::invalid_argument("jmax must be positive");
    }
    table_v_.resize(cuckoolen_, 0);  // 初始化值为0
    table_k_.resize(cuckoolen_, 0);  // 初始化值为0
  }

  void Initialize() {
    std::vector<yacl::Buffer> XS(jmax_);
    constexpr int64_t batch_size = 1 << 10;  // 可以根据需要调整批处理大小
    if (!ec_group_) {
      throw std::runtime_error("EcGroup not initialized");
    }
    yacl::parallel_for(1, Jmax + 1, batch_size, [&](int64_t beg, int64_t end) {
      for (int64_t i = beg; i < end; ++i) {
        yacl::math::MPInt value(i);
        auto point = ec_group_->MulBase(value);
        // 获取横坐标作为键
        auto affine_point = ec_group_->GetAffinePoint(point);
        auto key = affine_point.x.ToMagBytes(yacl::Endian::native);
        XS[i - 1] = key;
      }
    });
    Insert(XS);
  }

  void Insert(std::vector<yacl::Buffer> data) {
    std::vector<uint8_t> hash_index_;
    hash_index_.resize(cuckoolen_, 0);
    for (int i = 0; i < Jmax; ++i) {
      int v = i + 1;
      uint8_t old_hash_id = 1;
      int j = 0;
      for (; j < maxiter_; ++j) {
        const auto& X = data[v - 1];
        size_t start = (old_hash_id - 1) * 8;
        size_t end = start + 4;
        uint32_t x = GetSubBytesAsUint32(X, end, end + 4);
        uint32_t x_key = x;
        uint32_t h = GetSubBytesAsUint32(X, start, end) % cuckoolen_;
        uint8_t* hash_id_address = &hash_index_[h];
        int* key_index_address = &table_v_[h];
        uint32_t* key_address = &table_k_[h];

        if (*hash_id_address == empty_) {
          *hash_id_address = old_hash_id;
          *key_index_address = v;
          *key_address = x_key;
          break;
        } else {
          std::swap(v, *key_index_address);
          std::swap(old_hash_id, *hash_id_address);
          std::swap(x_key, *key_address);
          old_hash_id = old_hash_id % 3 + 1;
        }
      }
      if (j == maxiter_) {
        SPDLOG_INFO("insert failed, ", i);
        throw std::runtime_error("insert failed, " + std::to_string(i));
      }
    }
  }

  std::pair<int, bool> Op_search(const yacl::Buffer& xbytes) const {
    for (int i = 0; i < 3; ++i) {
      size_t start = i * 8;
      size_t end = start + 4;
      uint32_t x = GetSubBytesAsUint32(xbytes, end, end + 4);
      uint32_t x_key = x;
      uint32_t h = GetSubBytesAsUint32(xbytes, start, end) % cuckoolen_;
      if (table_k_[h] == x_key) {
        return {table_v_[h], true};
      }
    }
    return {0, false};
  }

  void Serialize(const std::string& filename) const {
    std::ofstream ofs(filename, std::ios::binary);
    if (!ofs) {
      throw std::runtime_error("Failed to open file for writing: " + filename);
    }

    ofs.write(reinterpret_cast<const char*>(&jmax_), sizeof(jmax_));
    ofs.write(reinterpret_cast<const char*>(&cuckoolen_), sizeof(cuckoolen_));
    ofs.write(reinterpret_cast<const char*>(table_v_.data()),
              table_v_.size() * sizeof(uint32_t));
    ofs.write(reinterpret_cast<const char*>(table_k_.data()),
              table_k_.size() * sizeof(uint32_t));
  }

  void Deserialize(const std::string& filename) {
    std::ifstream ifs(filename, std::ios::binary);
    if (!ifs) {
      throw std::runtime_error("Failed to open file for reading: " + filename);
    }

    ifs.read(reinterpret_cast<char*>(&jmax_), sizeof(jmax_));
    ifs.read(reinterpret_cast<char*>(&cuckoolen_), sizeof(cuckoolen_));
    table_v_.resize(cuckoolen_);
    table_k_.resize(cuckoolen_);
    ifs.read(reinterpret_cast<char*>(table_v_.data()),
             table_v_.size() * sizeof(uint32_t));
    ifs.read(reinterpret_cast<char*>(table_k_.data()),
             table_k_.size() * sizeof(uint32_t));
  }

  void InitializeEcGroup(std::shared_ptr<yacl::crypto::EcGroup> ec_group) {
    ec_group_ = std::move(ec_group);
  }

 private:
  int jmax_;
  uint32_t cuckoolen_;
  std::shared_ptr<yacl::crypto::EcGroup> ec_group_;
  std::vector<int> table_v_;
  std::vector<uint32_t> table_k_;
  const uint8_t empty_ = 0;
  const int maxiter_ = 500;
  mutable std::shared_mutex mutex_;
};

extern CuckooT1 t1_loaded;

}  // namespace examples::hesm2
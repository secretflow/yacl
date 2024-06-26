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

#include "examples/HESM2/config.h"

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/utils/parallel.h"

class HashMapT1 {
 public:
  explicit HashMapT1(std::shared_ptr<yacl::crypto::EcGroup> ec_group,
                     const std::string& filename = "hashmap_t1.dat")
      : ec_group_(std::move(ec_group)) {
    if (std::filesystem::exists(filename)) {
      Deserialize(filename);
    } else {
      InitializeDefaultEntries();
      Serialize(filename);
    }
  }

  HashMapT1(std::shared_ptr<yacl::crypto::EcGroup> ec_group, bool initialize,
            const std::string& filename = "hashmap_t1.dat")
      : ec_group_(std::move(ec_group)) {
    if (initialize) {
      if (std::filesystem::exists(filename)) {
        Deserialize(filename);
      } else {
        InitializeDefaultEntries();
        Serialize(filename);
      }
    }
  }

  void AddEntry(const yacl::math::MPInt& i) {
    auto point = ec_group_->MulBase(i);
    auto affine_point = ec_group_->GetAffinePoint(point);
    auto key = affine_point.x.ToString();
    std::unique_lock<std::shared_mutex> lock(mutex_);
    map_[key] = i;
  }

  const yacl::math::MPInt* GetValue(const std::string& key) const {
    auto it = map_.find(key);
    if (it != map_.end()) {
      return &it->second;
    }
    return nullptr;
  }

  void Serialize(const std::string& filename) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::ofstream ofs(filename, std::ios::binary);
    if (!ofs) {
      throw std::runtime_error("Failed to open file for writing: " + filename);
    }
    size_t map_size = map_.size();
    ofs.write(reinterpret_cast<const char*>(&map_size), sizeof(map_size));
    for (const auto& [key, value] : map_) {
      size_t key_size = key.size();
      ofs.write(reinterpret_cast<const char*>(&key_size), sizeof(key_size));
      ofs.write(key.data(), key_size);
      auto value_bytes = value.ToMagBytes(yacl::Endian::native);
      size_t value_size = value_bytes.size();
      ofs.write(reinterpret_cast<const char*>(&value_size), sizeof(value_size));
      ofs.write(reinterpret_cast<const char*>(value_bytes.data<uint8_t>()),
                value_size);
    }
  }

  void Deserialize(const std::string& filename) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    std::ifstream ifs(filename, std::ios::binary);
    if (!ifs) {
      throw std::runtime_error("Failed to open file for reading: " + filename);
    }
    size_t map_size;
    ifs.read(reinterpret_cast<char*>(&map_size), sizeof(map_size));
    map_.clear();
    for (size_t i = 0; i < map_size; ++i) {
      size_t key_size;
      ifs.read(reinterpret_cast<char*>(&key_size), sizeof(key_size));
      std::string key(key_size, '\0');
      ifs.read(key.data(), key_size);
      size_t value_size;
      ifs.read(reinterpret_cast<char*>(&value_size), sizeof(value_size));
      yacl::Buffer value_bytes(value_size);
      ifs.read(reinterpret_cast<char*>(value_bytes.data<uint8_t>()),
               value_size);
      yacl::math::MPInt value;
      value.FromMagBytes(value_bytes, yacl::Endian::native);
      map_[key] = std::move(value);
    }
  }

  void InitializeDefaultEntries() {
    constexpr int64_t batch_size = 1 << 10;  // 可以根据需要调整批处理大小
    yacl::parallel_for(1, Jmax + 1, batch_size, [&](int64_t beg, int64_t end) {
      for (int64_t i = beg; i < end; ++i) {
        yacl::math::MPInt value(i);
        AddEntry(value);
      }
    });
  }

  void InitializeEcGroup(std::shared_ptr<yacl::crypto::EcGroup> ec_group) {
    ec_group_ = std::move(ec_group);
  }

 private:
  std::shared_ptr<yacl::crypto::EcGroup> ec_group_;
  std::unordered_map<std::string, yacl::math::MPInt> map_;
  mutable std::shared_mutex mutex_;
};

// extern HashMapT1 t1_loaded;

class CuckooT1 {
 public:
  explicit CuckooT1(int jmax,
                    std::shared_ptr<yacl::crypto::EcGroup> ec_group = nullptr)
      : jmax_(jmax),
        cuckoolen_(static_cast<uint32_t>(jmax * 1.3)),
        ec_group_(std::move(ec_group)) {
    if (jmax_ <= 0) {
      throw std::invalid_argument("jmax must be positive");
    }
    table_v_.resize(cuckoolen_, 0);  // 初始化值为0
    table_k_.resize(cuckoolen_, 0);  // 初始化值为0
  }

  explicit CuckooT1(int jmax)
      : jmax_(jmax), cuckoolen_(static_cast<uint32_t>(jmax * 1.3)) {
    if (jmax_ <= 0) {
      throw std::invalid_argument("jmax must be positive");
    }
    table_v_.resize(cuckoolen_, 0);  // 初始化值为0
    table_k_.resize(cuckoolen_, 0);  // 初始化值为0
  }

  void Initialize() {
    std::vector<yacl::Buffer> XS;
    XS.resize(jmax_);
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
      if (j == maxiter_ - 1) {
        std::cerr << "insert failed, " << i << std::endl;
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

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

#include <fstream>
#include <memory>
#include <shared_mutex>
#include <utility>
#include <vector>

#include "examples/hesm2/config.h"

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::hesm2 {

class T2 {
 public:
  explicit T2(std::shared_ptr<yacl::crypto::EcGroup> ec_group,
              bool initialize = true)
      : ec_group_(std::move(ec_group)) {
    if (initialize) {
      InitializeVector();
    }
  }
  const yacl::crypto::AffinePoint& GetValue(size_t index) const {
    return vec_.at(index);
  }
  const std::vector<yacl::crypto::AffinePoint>& GetVector() const {
    return vec_;
  }
  void Serialize(const std::string& filename) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::ofstream ofs(filename, std::ios::binary);
    if (!ofs) {
      throw std::runtime_error("Failed to open file for writing: " + filename);
    }
    size_t vec_size = vec_.size();
    ofs.write(reinterpret_cast<const char*>(&vec_size), sizeof(vec_size));
    for (const auto& point : vec_) {
      auto x_bytes = point.x.ToMagBytes(yacl::Endian::native);
      auto y_bytes = point.y.ToMagBytes(yacl::Endian::native);
      size_t x_size = x_bytes.size();
      size_t y_size = y_bytes.size();
      ofs.write(reinterpret_cast<const char*>(&x_size), sizeof(x_size));
      ofs.write(reinterpret_cast<const char*>(x_bytes.data<uint8_t>()), x_size);
      ofs.write(reinterpret_cast<const char*>(&y_size), sizeof(y_size));
      ofs.write(reinterpret_cast<const char*>(y_bytes.data<uint8_t>()), y_size);
    }
  }
  void Deserialize(const std::string& filename) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    std::ifstream ifs(filename, std::ios::binary);
    if (!ifs) {
      throw std::runtime_error("Failed to open file for reading: " + filename);
    }
    size_t vec_size;
    ifs.read(reinterpret_cast<char*>(&vec_size), sizeof(vec_size));
    vec_.resize(vec_size);
    for (size_t i = 0; i < vec_size; ++i) {
      size_t x_size;
      size_t y_size;
      ifs.read(reinterpret_cast<char*>(&x_size), sizeof(x_size));
      yacl::Buffer x_bytes(x_size);
      ifs.read(reinterpret_cast<char*>(x_bytes.data<uint8_t>()), x_size);
      yacl::math::MPInt x;
      x.FromMagBytes(x_bytes, yacl::Endian::native);

      ifs.read(reinterpret_cast<char*>(&y_size), sizeof(y_size));
      yacl::Buffer y_bytes(y_size);
      ifs.read(reinterpret_cast<char*>(y_bytes.data<uint8_t>()), y_size);
      yacl::math::MPInt y;
      y.FromMagBytes(y_bytes, yacl::Endian::native);

      vec_[i] = yacl::crypto::AffinePoint{x, y};
    }
  }

  void InitializeVector() {
    vec_.resize(Imax + 1);
    auto G = ec_group_->GetGenerator();
    yacl::math::MPInt Jmax_val(Jmax);
    yacl::math::MPInt two(2);
    yacl::math::MPInt factor = Jmax_val * two;  // Correcting the multiplication
    auto T2basepoint = ec_group_->MulBase(factor);
    for (int i = 0; i <= Imax; ++i) {
      yacl::math::MPInt value(-i);
      auto point = ec_group_->Mul(T2basepoint, value);
      vec_[i] = ec_group_->GetAffinePoint(point);
    }
  }

  void InitializeEcGroup(std::shared_ptr<yacl::crypto::EcGroup> ec_group) {
    ec_group_ = std::move(ec_group);
  }

 private:
  std::shared_ptr<yacl::crypto::EcGroup> ec_group_;
  std::vector<yacl::crypto::AffinePoint> vec_;
  mutable std::shared_mutex mutex_;
};

extern T2 t2_loaded;

}  // namespace examples::hesm2
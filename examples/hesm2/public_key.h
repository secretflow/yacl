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

#include <utility>

#include "yacl/crypto/ecc/ecc_spi.h"

namespace examples::hesm2 {

class PublicKey {
 public:
  PublicKey(yacl::crypto::EcPoint point,
            std::shared_ptr<yacl::crypto::EcGroup> ec_group)
      : point_(point), ec_group_(std::move(ec_group)) {}

  const yacl::crypto::EcPoint& GetPoint() const { return point_; }
  std::shared_ptr<yacl::crypto::EcGroup> GetEcGroup() const {
    return ec_group_;
  }

 private:
  yacl::crypto::EcPoint point_;
  std::shared_ptr<yacl::crypto::EcGroup> ec_group_;
};

}  // namespace examples::hesm2
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

#include "yacl/crypto/ecc/ec_point.h"

namespace examples::hesm2 {

class Ciphertext {
 public:
  Ciphertext(yacl::crypto::EcPoint c1, yacl::crypto::EcPoint c2)
      : c1_(std::move(c1)), c2_(std::move(c2)) {}

  const yacl::crypto::EcPoint& GetC1() const { return c1_; }
  const yacl::crypto::EcPoint& GetC2() const { return c2_; }

 private:
  yacl::crypto::EcPoint c1_;
  yacl::crypto::EcPoint c2_;
};
}  // namespace examples::hesm2
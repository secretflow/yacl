// Copyright 2026 Ant Group Co., Ltd.
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

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"
#include "yacl/math/mpint/mp_int.h"

namespace tecdsa::bigint {

using MPInt = yacl::math::MPInt;

MPInt FromBigEndian(std::span<const uint8_t> bytes);
Bytes ToBigEndian(const MPInt& value);
Bytes ToFixedWidth(const MPInt& value, size_t width);

MPInt NormalizeMod(const MPInt& value, const MPInt& modulus);
MPInt PowMod(const MPInt& base, const MPInt& exponent, const MPInt& modulus);
std::optional<MPInt> TryInvertMod(const MPInt& value, const MPInt& modulus);

MPInt RandomBelow(const MPInt& upper_exclusive);
MPInt RandomZnStar(const MPInt& modulus_n);

}  // namespace tecdsa::bigint

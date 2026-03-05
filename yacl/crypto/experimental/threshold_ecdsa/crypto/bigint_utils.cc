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

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"

#include <algorithm>
#include <cstddef>
#include <optional>
#include <stdexcept>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"

namespace tecdsa::bigint {

MPInt FromBigEndian(std::span<const uint8_t> bytes) {
  MPInt out;
  out.FromMagBytes(bytes, yacl::Endian::big);
  return out;
}

Bytes ToBigEndian(const MPInt& value) {
  if (value < 0) {
    TECDSA_THROW_ARGUMENT("bigint value must be non-negative");
  }

  if (value == 0) {
    return Bytes{0x00};
  }

  const yacl::Buffer mag = value.ToMagBytes(yacl::Endian::big);
  const auto* mag_ptr = mag.data<uint8_t>();
  return Bytes(mag_ptr, mag_ptr + mag.size());
}

Bytes ToFixedWidth(const MPInt& value, size_t width) {
  if (value < 0) {
    TECDSA_THROW_ARGUMENT("cannot export negative integer to fixed width");
  }
  if (width == 0) {
    if (value == 0) {
      return {};
    }
    TECDSA_THROW_ARGUMENT("non-zero integer does not fit zero-width buffer");
  }

  Bytes out(width, 0);
  if (value == 0) {
    return out;
  }

  const yacl::Buffer mag = value.ToMagBytes(yacl::Endian::big);
  const size_t mag_size = mag.size();
  if (mag_size > width) {
    TECDSA_THROW_ARGUMENT("integer does not fit fixed-width buffer");
  }

  const auto* mag_ptr = mag.data<uint8_t>();
  std::copy(mag_ptr,
            mag_ptr + mag_size,
            out.begin() + static_cast<std::ptrdiff_t>(width - mag_size));
  return out;
}

MPInt NormalizeMod(const MPInt& value, const MPInt& modulus) {
  if (modulus <= 0) {
    TECDSA_THROW_ARGUMENT("modulus must be positive");
  }
  return value.Mod(modulus);
}

MPInt PowMod(const MPInt& base, const MPInt& exponent, const MPInt& modulus) {
  if (modulus <= 0) {
    TECDSA_THROW_ARGUMENT("modulus must be positive");
  }
  if (exponent < 0) {
    TECDSA_THROW_ARGUMENT("modular exponent must be non-negative");
  }
  return base.PowMod(exponent, modulus);
}

std::optional<MPInt> TryInvertMod(const MPInt& value, const MPInt& modulus) {
  if (modulus <= 1) {
    return std::nullopt;
  }

  try {
    return value.InvertMod(modulus);
  } catch (const std::runtime_error&) {
    return std::nullopt;
  }
}

MPInt RandomBelow(const MPInt& upper_exclusive) {
  if (upper_exclusive <= 0) {
    TECDSA_THROW_ARGUMENT("random upper bound must be positive");
  }
  return MPInt::RandomLtN(upper_exclusive);
}

MPInt RandomZnStar(const MPInt& modulus_n) {
  if (modulus_n <= 2) {
    TECDSA_THROW_ARGUMENT("modulus must be > 2");
  }

  MPInt candidate;
  MPInt gcd;
  do {
    candidate = RandomBelow(modulus_n);
    gcd = MPInt::Gcd(candidate, modulus_n);
  } while (candidate == 0 || gcd != 1);

  return candidate;
}

}  // namespace tecdsa::bigint

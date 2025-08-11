// Copyright 2025 Guan Yewei
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

#include "yacl/crypto/ecc/hash_to_curve/p384.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

#include "yacl/base/buffer.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/hash_to_curve/hash_to_curve_util.h"
#include "yacl/crypto/hash/hash_interface.h"
#include "yacl/crypto/hash/ssl_hash.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/utils/spi/type_traits.h"

namespace yacl {

crypto::AffinePoint AffinePointAddP384(
  const yacl::math::MPInt& x1,
  const yacl::math::MPInt& y1,
  const yacl::math::MPInt& x2,
  const yacl::math::MPInt& y2,
  const yacl::math::MPInt& p) {
  
  // Handle special case when one point is at infinity
  if (x1.IsZero() && y1.IsZero()) {
    return crypto::AffinePoint(x2, y2);
  }
  if (x2.IsZero() && y2.IsZero()) {
    return crypto::AffinePoint(x1, y1);
  }

  yacl::math::MPInt lambda;
  yacl::math::MPInt x3, y3;
  
  // Check if points are equal
  if (x1 == x2 && y1 == y2) {
    // Point doubling: lambda = (3*x1^2 + a)/(2*y1)
    // For P-384, a = -3
    yacl::math::MPInt x1_squared, numerator, denominator;
    x1_squared = x1 * x1;
    numerator = x1_squared * 3 - 3;  // 3*x1^2 - 3 (since a = -3 for P-384)
    denominator = y1 * 2;            // 2*y1
    
    // Compute lambda = numerator/denominator mod p
    yacl::math::MPInt denominator_inv;
    // denominator.InvertMod(p, &denominator_inv);
    denominator_inv = denominator.InvertMod(p);
    lambda = numerator * denominator_inv;
    lambda %= p;
  } else {
    // Point addition: lambda = (y2 - y1)/(x2 - x1)
    yacl::math::MPInt numerator, denominator;
    numerator = y2 - y1;
    denominator = x2 - x1;
    
    if (denominator.IsZero()) {
      // Return point at infinity
      return crypto::AffinePoint(yacl::math::MPInt(0), yacl::math::MPInt(0));
    }
    
    // lambda = numerator/denominator mod p
    yacl::math::MPInt denominator_inv;
    denominator_inv = denominator.InvertMod(p);
    lambda = numerator * denominator_inv;
    lambda %= p;
  }
  
  // x3 = lambda^2 - x1 - x2
  x3 = lambda * lambda - x1 - x2;
  x3 %= p;
  if (x3.IsNegative()) {
    x3 += p;
  }
  
  // y3 = lambda(x1 - x3) - y1
  y3 = lambda * (x1 - x3) - y1;
  y3 %= p;
  if (y3.IsNegative()) {
    y3 += p;
  }
  
  return crypto::AffinePoint(x3, y3);
}

// P384_XMD:SHA-384_SSWU_NU_
crypto::EcPoint EncodeToCurveP384(yacl::ByteContainerView buffer,
                                  const std::string &dst) {
  YACL_ENFORCE((dst.size() >= 16) && (dst.size() <= 255),
               "domain separation tag length: {} not in 16B-255B", dst.size());

  HashToCurveCtx ctx = GetHashToCurveCtxByName("P-384");
  std::vector<std::vector<uint8_t>> u = HashToField(buffer, 1, 72, ctx, dst);
  yacl::math::MPInt qx;
  yacl::math::MPInt qy;

  std::tie(qx, qy) = MapToCurveSSWU(u[0], ctx);
  // crypto::EcPoint p = MapToCurveSSWU(u[0]);
  crypto::AffinePoint p(qx, qy);

  // Do not need to clear cofactor when h_eff = 1
  // std::vector<uint8_t> p = CompressP256(qx, qy);
  return p;
}

// P384_XMD:SHA-384_SSWU_RO_
crypto::EcPoint HashToCurveP384(yacl::ByteContainerView buffer,
                                                 const std::string &dst) {
  YACL_ENFORCE((dst.size() >= 16) && (dst.size() <= 255),
               "domain separation tag length: {} not in 16B-255B", dst.size());

  HashToCurveCtx ctx = GetHashToCurveCtxByName("P-384");
  std::vector<std::vector<uint8_t>> u = HashToField(buffer, 2, 72, ctx, dst);
  yacl::math::MPInt qx;
  yacl::math::MPInt qy;
  yacl::math::MPInt rx;
  yacl::math::MPInt ry;

  std::tie(qx, qy) = MapToCurveSSWU(u[0], ctx);
  std::tie(rx, ry) = MapToCurveSSWU(u[1], ctx);

  return AffinePointAddP384(qx, qy, rx, ry, ctx.aux.at("p"));
}

yacl::math::MPInt HashToScalarP384(yacl::ByteContainerView buffer,
                                   const std::string &dst) {
  YACL_ENFORCE((dst.size() >= 16) && (dst.size() <= 255),
               "domain separation tag length: {} not in 16B-255B", dst.size());

  HashToCurveCtx ctx = GetHashToCurveCtxByName("P-384");
  return HashToScalar(buffer, 72, ctx, dst);
}

}  // namespace yacl

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

#include "yacl/crypto/ecc/hash_to_curve/p256.h"

#include <cstdint>
#include <cstring>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/curve_meta.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/hash_to_curve/hash_to_curve_util.h"
#include "yacl/math/mpint/mp_int.h"

namespace yacl {

// P256_XMD:SHA-256_SSWU_NU_
// std::vector<uint8_t> EncodeToCurveP256(yacl::ByteContainerView buffer,
crypto::EcPoint EncodeToCurveP256(yacl::ByteContainerView buffer,
                                  const std::string &dst) {
  YACL_ENFORCE((dst.size() >= 16) && (dst.size() <= 255),
               "domain separation tag length: {} not in 16B-255B", dst.size());

  HashToCurveCtx ctx = GetHashToCurveCtxByName("P-256");
  std::vector<std::vector<uint8_t>> u = HashToField(buffer, 1, 48, ctx, dst);
  yacl::math::MPInt qx;
  yacl::math::MPInt qy;

  std::tie(qx, qy) = MapToCurveSSWU(u[0], ctx);
  crypto::AffinePoint p(qx, qy);

  // Do not need to clear cofactor when h_eff = 1
  return p;
}

yacl::math::MPInt HashToScalarP256(yacl::ByteContainerView buffer,
                               const std::string &dst) {
  YACL_ENFORCE((dst.size() >= 16) && (dst.size() <= 255),
               "domain separation tag length: {} not in 16B-255B", dst.size());

  HashToCurveCtx ctx = GetHashToCurveCtxByName("P-256");
  return HashToScalar(buffer, 48, ctx, dst);
}

}  // namespace yacl

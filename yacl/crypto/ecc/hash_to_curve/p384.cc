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

  return AffinePointAddNIST(qx, qy, rx, ry, ctx.aux.at("p"));
}

yacl::math::MPInt HashToScalarP384(yacl::ByteContainerView buffer,
                                   const std::string &dst) {
  YACL_ENFORCE((dst.size() >= 16) && (dst.size() <= 255),
               "domain separation tag length: {} not in 16B-255B", dst.size());

  HashToCurveCtx ctx = GetHashToCurveCtxByName("P-384");
  return HashToScalar(buffer, 72, ctx, dst);
}

}  // namespace yacl

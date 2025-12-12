// Copyright 2024 Ant Group Co., Ltd.
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

#include "yacl/crypto/ecc/hash_to_curve/ristretto255.h"

#include <cstdint>
#include <cstring>
#include <vector>

#include "sodium/crypto_core_ristretto255.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/hash_to_curve/hash_to_curve_util.h"
#include "yacl/math/mpint/mp_int.h"

namespace yacl {

namespace {

constexpr size_t kHashBytes = crypto_core_ristretto255_HASHBYTES;      // 64
constexpr size_t kScalarBytes = crypto_core_ristretto255_SCALARBYTES;  // 32

}  // namespace

crypto::EcPoint EncodeToCurveRistretto255(yacl::ByteContainerView buffer,
                                          const std::string &dst) {
  YACL_ENFORCE((dst.size() >= 16) && (dst.size() <= 255),
               "domain separation tag length: {} not in 16B-255B", dst.size());

  HashToCurveCtx ctx = GetHashToCurveCtxByName("Ristretto255");
  std::vector<uint8_t> uniform_bytes =
      ExpandMessageXmd(buffer, ctx, dst, kHashBytes);

  crypto::Array32 point;
  crypto_core_ristretto255_from_hash(point.data(), uniform_bytes.data());
  return crypto::EcPoint(std::in_place_type<crypto::Array32>, point);
}

crypto::EcPoint HashToCurveRistretto255(yacl::ByteContainerView buffer,
                                        const std::string &dst) {
  YACL_ENFORCE((dst.size() >= 16) && (dst.size() <= 255),
               "domain separation tag length: {} not in 16B-255B", dst.size());

  HashToCurveCtx ctx = GetHashToCurveCtxByName("Ristretto255");
  std::vector<uint8_t> uniform_bytes =
      ExpandMessageXmd(buffer, ctx, dst, kHashBytes * 2);

  crypto::Array32 q0, q1, result;
  crypto_core_ristretto255_from_hash(q0.data(), uniform_bytes.data());
  crypto_core_ristretto255_from_hash(q1.data(),
                                     uniform_bytes.data() + kHashBytes);
  int ret = crypto_core_ristretto255_add(result.data(), q0.data(), q1.data());
  YACL_ENFORCE(ret == 0, "ristretto255_add failed");
  return crypto::EcPoint(std::in_place_type<crypto::Array32>, result);
}

math::MPInt HashToScalarRistretto255(yacl::ByteContainerView buffer,
                                     const std::string &dst) {
  YACL_ENFORCE((dst.size() >= 16) && (dst.size() <= 255),
               "domain separation tag length: {} not in 16B-255B", dst.size());

  HashToCurveCtx ctx = GetHashToCurveCtxByName("Ristretto255");
  std::vector<uint8_t> uniform_bytes =
      ExpandMessageXmd(buffer, ctx, dst, kHashBytes);

  unsigned char scalar[kScalarBytes];
  crypto_core_ristretto255_scalar_reduce(scalar, uniform_bytes.data());

  math::MPInt result(0, 256);
  result.FromMagBytes({scalar, kScalarBytes}, Endian::little);
  return result;
}

}  // namespace yacl

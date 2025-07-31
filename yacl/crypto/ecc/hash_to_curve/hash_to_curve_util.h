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
#pragma once

#include <map>

#include "yacl/base/byte_container_view.h"
#include "yacl/crypto/ecc/curve_meta.h"
#include "yacl/crypto/hash/hash_interface.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/utils/spi/type_traits.h"

namespace yacl {

struct HashToCurveCtx {
  size_t key_size;
  size_t s_in_bytes;
  crypto::HashAlgorithm hash_algo;
  std::map<std::string, yacl::math::MPInt> aux;
  HashToCurveCtx() = default;
};

HashToCurveCtx GetHashToCurveCtxByName(const crypto::CurveName &name);

const yacl::math::MPInt kMp1(1);
const yacl::math::MPInt kMp2(2);

yacl::math::MPInt DeserializeMPInt(yacl::ByteContainerView buffer,
                                   size_t key_size,
                                   yacl::Endian endian = yacl::Endian::native);

void MPIntToBytesWithPad(std::vector<uint8_t> &buf, size_t key_size,
                         yacl::math::MPInt &mp);

std::vector<uint8_t> I2OSP(size_t x, size_t xlen);

// RFC9380 5.3.1.  expand_message_xmd
std::vector<uint8_t> ExpandMessageXmd(yacl::ByteContainerView msg,
                                      HashToCurveCtx &ctx,
                                      yacl::ByteContainerView dst,
                                      size_t len_in_bytes);

// RFC9380 5.2.  hash_to_field Implementation
std::vector<std::vector<uint8_t>> HashToField(yacl::ByteContainerView msg,
                                              size_t count, size_t l,
                                              HashToCurveCtx &ctx,
                                              const std::string &dst);

std::pair<yacl::math::MPInt, yacl::math::MPInt> MapToCurveSSWU(
    yacl::ByteContainerView ubuf, HashToCurveCtx &ctx);

yacl::math::MPInt HashToScalar(yacl::ByteContainerView msg,
                          size_t l,
                          HashToCurveCtx &ctx,
                          const std::string &dst);

bool IsSquare(const yacl::math::MPInt &v, const yacl::math::MPInt &mod);

bool Sgn0(const yacl::math::MPInt &v);

}  // namespace yacl

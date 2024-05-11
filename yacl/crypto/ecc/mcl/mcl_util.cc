// Copyright 2023 Ant Group Co., Ltd.
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

#include "yacl/crypto/ecc/mcl/mcl_util.h"

#include "mcl/gmp_util.hpp"

namespace yacl::crypto {

MPInt Mpz2Mp(const mpz_class& m) {
  const auto* ptr =
      reinterpret_cast<const uint8_t*>(m.getUnit());  // Unit = uint64_t

  MPInt mpi;
  mpi.FromMagBytes({ptr, (m.getBitSize() + 7) / 8}, Endian::little);
  if (m.isNegative()) {
    mpi.NegateInplace();
  }
  return mpi;
}

mpz_class Mp2Mpz(const MPInt& mpi) {
  auto buf = mpi.ToMagBytes(Endian::little);
  mpz_class ret;

  bool flag;
  ret.setArray(&flag, buf.data<uint8_t>(), buf.size());
  YACL_ENFORCE(flag);
  if (mpi.IsNegative()) {
    mpz_class::neg(ret, ret);
  }
  return ret;
}

}  // namespace yacl::crypto

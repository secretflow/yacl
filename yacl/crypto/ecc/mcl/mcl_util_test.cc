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

#include "gtest/gtest.h"

namespace yacl::crypto::test {

TEST(MclFieldTest, MclUtilWorks) {
  // small case
  for (int i = 100; i >= -100; --i) {
    auto mpz = Mp2Mpz(MPInt(i));
    auto mpi = Mpz2Mp(mpz);
    ASSERT_EQ(mpi.Get<int>(), i);
  }

  // big case
  for (int i = 1; i <= 513; ++i) {
    MPInt in;
    MPInt::RandomExactBits(i, &in);

    auto mpz = Mp2Mpz(in);
    ASSERT_EQ((mpz.isZero() ? 0 : mpz.getBitSize()), in.BitCount());
    auto out = Mpz2Mp(mpz);
    ASSERT_EQ(out, in);
  }

  for (int i = 1; i <= 513; ++i) {
    MPInt in;
    MPInt::RandomExactBits(i, &in);
    in.NegateInplace();

    auto mpz = Mp2Mpz(in);
    ASSERT_EQ((mpz.isZero() ? 0 : mpz.getBitSize()), in.BitCount());
    auto out = Mpz2Mp(mpz);
    ASSERT_EQ(out, in);
  }
}
}  // namespace yacl::crypto::test

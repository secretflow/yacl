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

#include "gtest/gtest.h"

#include "yacl/crypto/base/ecc/openssl/openssl_group.h"

namespace yacl::crypto::openssl {
// We only need to test these two functions, other functions will be tested by
// SPI
BIGNUM_PTR Mp2Bn(const MPInt &mp);
MPInt Bn2Mp(const BIGNUM *bn);
}  // namespace yacl::crypto::openssl

namespace yacl::crypto::openssl::test {

TEST(OpensslTest, BnWorks) {
  // small case
  for (int i = 100; i >= -100; --i) {
    auto bn = Mp2Bn(MPInt(i));
    auto mp = Bn2Mp(bn.get());
    ASSERT_EQ(mp.Get<int>(), i);
  }

  // big case
  for (int i = 1; i <= 513; ++i) {
    MPInt in;
    MPInt::RandomExactBits(i, &in);

    auto bn = Mp2Bn(in);
    ASSERT_EQ(BN_num_bits(bn.get()), in.BitCount());
    auto out = Bn2Mp(bn.get());
    ASSERT_EQ(out, in);
  }

  for (int i = 1; i <= 513; ++i) {
    MPInt in;
    MPInt::RandomExactBits(i, &in);
    in.NegateInplace();

    auto bn = Mp2Bn(in);
    ASSERT_EQ(BN_num_bits(bn.get()), in.BitCount());
    auto out = Bn2Mp(bn.get());
    ASSERT_EQ(out, in);
  }
}

}  // namespace yacl::crypto::openssl::test

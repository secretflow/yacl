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

#include <cstdint>

#include "gtest/gtest.h"

#include "yacl/crypto/ecc/openssl/openssl_group.h"
#include "yacl/utils/parallel.h"
#include "yacl/utils/spi/spi_factory.h"

namespace yacl::crypto::openssl {
// We only need to test these two functions, other functions will be tested by
// SPI
UniqueBn Mp2Bn(const MPInt &mp);
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

  auto ec = OpensslGroup::Create(GetCurveMetaByName("prime256v1"));
  auto p = ec->MulBase(333_mp);
  auto affine = ec->GetAffinePoint(p);
  auto p2 = ec->CopyPoint(affine);
  EXPECT_TRUE(ec->PointEqual(p, p2));
}

TEST(OpensslTest, HashToCurveWorks) {
  auto curve = OpensslGroup::Create(GetCurveMetaByName("sm2"));
  auto is_unique = [&](EcPoint p) {
    ASSERT_TRUE(curve->IsInCurveGroup(p));

    static std::vector<EcPoint> v;
    for (const auto &item : v) {
      ASSERT_FALSE(curve->PointEqual(item, p));
    }
    v.emplace_back(std::move(p));
  };

  for (int i = 0; i < 1000; ++i) {
    is_unique(curve->HashToCurve(HashToCurveStrategy::TryAndRehash_SHA2,
                                 fmt::format("id{}", i)));
    is_unique(curve->HashToCurve(HashToCurveStrategy::TryAndRehash_SM,
                                 fmt::format("id{}", i)));
    is_unique(curve->HashToCurve(HashToCurveStrategy::TryAndRehash_BLAKE3,
                                 fmt::format("id{}", i)));
    // Same strategy as above TryAndRehash_BLAKE3
    // is_unique(curve->HashToCurve(fmt::format("id{}", i)));
  }
}

TEST(OpensslTest, AddInplaceWorks) {
  std::shared_ptr<EcGroup> p = OpensslGroup::Create(GetCurveMetaByName("sm2"));
  auto curve = std::dynamic_pointer_cast<OpensslGroup>(p);

  auto p1 = curve->MulBase(1000_mp);
  auto p2 = curve->MulBase(2000_mp);
  curve->AddInplace(&p1, p2);
  ASSERT_TRUE(curve->PointEqual(p1, curve->MulBase(3000_mp)));
}

TEST(OpensslMemLeakTest, MulBaseLeaks) {
  std::shared_ptr<yacl::crypto::EcGroup> ec =
      yacl::crypto::EcGroupFactory::Instance().Create("sm2",
                                                      ArgLib = "openssl");

  yacl::parallel_for(0, 2, [&](int64_t, int64_t) {
    // no memory leak here, but the same code in ecc_test.cc leaks.
    ec->MulBase(0_mp);
  });
}

}  // namespace yacl::crypto::openssl::test

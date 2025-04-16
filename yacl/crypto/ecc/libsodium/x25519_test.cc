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

#include <memory>
#include <string>

#include "gtest/gtest.h"

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/ecc/hash_to_curve/curve25519.h"

namespace yacl::crypto::sodium::test {

// class SodiumTest : public ::testing::Test {
//  protected:
//   std::unique_ptr<EcGroup> ec_ =
//       EcGroupFactory::Instance().Create("curve25519", ArgLib = "libsodium");
// };
//
// TEST_F(SodiumTest, Curve25519HashAndEncodeToCurveWorks) {
//   auto is_unique = [&](EcPoint q) {
//     auto p = ec_->CopyPoint(q);
//     ASSERT_TRUE(ec_->IsInCurveGroup(p));
//     static std::vector<EcPoint> v;
//     for (const auto &item : v) {
//       ASSERT_FALSE(ec_->PointEqual(item, p));
//     }
//     v.emplace_back(std::move(p));
//   };
//   for (int i = 0; i < 1000; ++i) {
//     is_unique(ec_->HashToCurve(HashToCurveStrategy::SHA512_ELL2_NU_,
//                                fmt::format("id{}", i)));
//     is_unique(ec_->HashToCurve(HashToCurveStrategy::SHA512_ELL2_RO_,
//                                fmt::format("id{}", i)));
//   }
// }
}  // namespace yacl::crypto::sodium::test

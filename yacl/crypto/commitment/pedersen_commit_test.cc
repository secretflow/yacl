// Copyright 2022 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "yacl/crypto/commitment/pedersen_commit.h"

#include "gtest/gtest.h"

#include "yacl/crypto/rand/rand.h"

namespace yacl::crypto {

TEST(PedersenCommit, OpenTest) {
  MPInt blind1;
  MPInt blind2;
  MPInt::RandomRoundDown(256, &blind1);
  MPInt::RandomRoundDown(256, &blind2);

  auto value1 = RandBytes(123);
  auto value2 = RandBytes(123);

  auto res1 = PedersenHashAndCommit(value1, blind1);

  EXPECT_EQ(true, PedersenHashAndOpen(res1, value1, blind1));
  EXPECT_EQ(false, PedersenHashAndOpen(res1, value2, blind1));
  EXPECT_EQ(false, PedersenHashAndOpen(res1, value1, blind2));
  EXPECT_EQ(false, PedersenHashAndOpen(res1, value2, blind2));
}

TEST(PedersenCommit, PedersenCommitTest) {
  std::shared_ptr<EcGroup> group =
      EcGroupFactory::Instance().Create(kSigmaEcName, ArgLib = kSigmaEcLib);

  auto rnd_seed1 = RandBytes(32);
  auto rnd_seed2 = RandBytes(32);
  PedersenCommit ctx(group, 12345, HashToCurveStrategy::Autonomous);

  MPInt input;
  MPInt blind;
  MPInt input2;
  MPInt blind2;
  MPInt::RandomExactBits(256, &input);
  MPInt::RandomExactBits(256, &blind);
  MPInt::RandomExactBits(256, &input2);
  MPInt::RandomExactBits(256, &blind2);

  auto commit = ctx.Commit(input, blind);

  EXPECT_TRUE(ctx.Open(commit, input, blind));
  EXPECT_FALSE(ctx.Open(commit, input2, blind2));
}

}  // namespace yacl::crypto

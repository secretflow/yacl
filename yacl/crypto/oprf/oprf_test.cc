// Copyright 2024 Ant Group Co., Ltd.
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

#include "yacl/crypto/oprf/oprf.h"

#include <algorithm>

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

#include "yacl/crypto/oprf/voprf.h"
#include "yacl/math/mpint/mp_int.h"

namespace yacl::crypto {

TEST(ECCTest, HashToGroupWorks) {
  // const auto config = OprfConfig::GetVOPRFDefault();
}

TEST(UtilTest, VOPRFDeriveKeyPairWorks) {
  const auto config = OprfConfig::GetVOPRFDefault();
  auto ctx = std::make_shared<OprfCtx>(config);
  std::array<char, 32> seed;
  std::fill(seed.begin(), seed.end(), 0xa3);
  std::string info = "test key";
  yacl::math::MPInt sk_sm;
  yacl::crypto::EcPoint pk_sm;
  std::tie(sk_sm, pk_sm) = ctx->DeriveKeyPair(seed, info);
  EXPECT_EQ(sk_sm.ToHexString(),
            "CA5D94C8807817669A51B196C34C1B7F8442FDE4334A7121AE4736364312FCA6");
  auto ec = ctx->BorrowEcGroup();
  auto serialized_pkSm = absl::BytesToHexString(absl::string_view(
      reinterpret_cast<const char*>(ec->SerializePoint(pk_sm).data()),
      ec->SerializePoint(pk_sm).size()));
  EXPECT_EQ(serialized_pkSm,
            "03e17e70604bcabe198882c0a1f27a92"
            "441e774224ed9c702e51dd17038b102462");
}

TEST(ProtocolTest, OPRFWorks) {
  // get a default config
  const auto config = OprfConfig::GetDefault();

  auto server = OprfServer(config);
  auto client = OprfClient(config);

  const std::string input = "test_element";

  EcPoint c2s_tape;
  client.Blind(input, &c2s_tape);

  EcPoint s2c_tape;
  server.BlindEvaluate(c2s_tape, &s2c_tape);

  client.Finalize(s2c_tape);
}

TEST(ProtocolTest, VOPRFWorks) {
  // get a default config
  const auto config = OprfConfig::GetVOPRFDefault();
  auto ctx = std::make_shared<OprfCtx>(config);
  EcGroup* ec = ctx->BorrowEcGroup();

  std::array<char, 32> seed;
  std::fill(seed.begin(), seed.end(), 0xa3);
  std::string info = "test key";
  math::MPInt blindness =
      "0x3338fa65ec36e0290022b48eb562889d8"
      "9dbfa691d1cde91517fa222ed7ad364"_mp;

  auto server = VOprfServer(config, seed, info);
  auto client = VOprfClient(config, blindness);

  client.ReceivePKS(server.GetPKS());

  const std::string input = "ZZZZZZZZZZZZZZZZZ";

  EcPoint blindedElement;
  client.Blind(input, &blindedElement);

  auto s_blindedElement = ec->SerializePoint(blindedElement);
  auto s_blindedElement_str = absl::BytesToHexString(
      absl::string_view(reinterpret_cast<const char*>(s_blindedElement.data()),
                        s_blindedElement.size()));
  EXPECT_EQ(
      s_blindedElement_str,
      "03cd0f033e791c4d79dfa9c6ed750f2ac009ec46cd4195ca6fd3800d1e9b887dbd");

  EcPoint evaluatedElement;
  Proof proof;
  math::MPInt proofRandomSclar =
      "0xf9db001266677f62c095021db018cd8cbb"
      "55941d4073698ce45c405d1348b7b1"_mp;
  server.BlindEvaluate(blindedElement, &evaluatedElement, &proof,
                       proofRandomSclar);

  auto s_evaluatedElement = ec->SerializePoint(evaluatedElement);
  auto s_evaluatedElement_str = absl::BytesToHexString(absl::string_view(
      reinterpret_cast<const char*>(s_evaluatedElement.data()),
      s_evaluatedElement.size()));
  EXPECT_EQ(
      s_evaluatedElement_str,
      "030d2985865c693bf7af47ba4d3a3813176576383d19aff003ef7b0784a0d83cf1");

  EXPECT_EQ(
      proof.c.ToHexString() + proof.s.ToHexString(),
      "2787D729C57E3D9512D3AA9E8708AD226BC48E0F1750B0767AAFF73482C44"
      "B8D2873D74EC88AEBD3504961ACEA16790A05C542D9FBFF4FE269A77510DB00ABAB");

  auto output =
      client.Finalize(evaluatedElement, blindedElement, &proof, input);
  EXPECT_EQ(absl::BytesToHexString(absl::string_view(
                reinterpret_cast<const char*>(output.data()), output.size())),
            "771e10dcd6bcd3664e23b8f2a710cfaaa8357747c4a8cbba03133967b5c24f18");
}

}  // namespace yacl::crypto

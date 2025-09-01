// Copyright 2025 Ant Group Co., Ltd.
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

#include "yacl/crypto/pqc/sig.h"

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "spdlog/spdlog.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"

namespace yacl::crypto {

void test_sig(const std::string& sig_name) {
  Sig sig(sig_name);

  // Test key pair generation
  auto [pk, sk] = sig.GenKeyPair();
  EXPECT_EQ(pk.size(), sig.GetPublicKeySize());
  EXPECT_EQ(sk.size(), sig.GetSecretKeySize());

  // Test basic signing and verification
  std::string message = "Hello, World!";
  auto signature = sig.Sign(sk, message);
  EXPECT_TRUE(sig.Verify(pk, message, signature));

  // Test verification with wrong message
  std::string wrong_message = "Wrong message";
  EXPECT_FALSE(sig.Verify(pk, wrong_message, signature));

  // Test verification with wrong signature
  std::vector<uint8_t> wrong_signature(signature.size(), 0);
  EXPECT_FALSE(sig.Verify(pk, message, wrong_signature));

  // Test context-based signing if supported
  if (sig.IsSigWithCtxSupport()) {
    std::string context = "Test context";
    auto ctx_signature = sig.SignWithCtxStr(sk, message, context);
    EXPECT_TRUE(sig.VerifyWithCtxStr(pk, message, ctx_signature, context));

    // Test with wrong context
    std::string wrong_context = "Wrong context";
    EXPECT_FALSE(
        sig.VerifyWithCtxStr(pk, message, ctx_signature, wrong_context));
  }
}

TEST(SigTest, BasicFunctionality) {
  std::vector<std::string> enabled_sigs = Sig::GetEnabledSig();
  for (const auto& sig_name : enabled_sigs) {
    test_sig(sig_name);
  }
}

TEST(SigTest, AlgorithmInfo) {
  auto supported_sigs = Sig::GetSupportedSig();
  EXPECT_EQ(supported_sigs.size(), Sig::GetSigAlgCount());

  std::string sig_name = "Dilithium2";
  Sig sig(sig_name);

  EXPECT_FALSE(sig.GetSigAlgVersion().empty());
  EXPECT_GT(sig.GetClaimedNistLevel(), 0);
  EXPECT_TRUE(sig.IsEufCma());
}

TEST(SigTest, EmptyMessage) {
  std::vector<std::string> enabled_sigs = Sig::GetEnabledSig();
  for (const auto& sig_name : enabled_sigs) {
    Sig sig(sig_name);
    auto [pk, sk] = sig.GenKeyPair();
    std::string empty_message = "";
    auto signature = sig.Sign(sk, empty_message);
    EXPECT_TRUE(sig.Verify(pk, empty_message, signature));
  }
}

}  // namespace yacl::crypto

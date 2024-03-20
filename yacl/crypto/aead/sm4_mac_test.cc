// Copyright 2019 Ant Group Co., Ltd.
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

#include "yacl/crypto/aead/sm4_mac.h"

#include "gtest/gtest.h"

namespace yacl::crypto {

TEST(Sm4Mac, Sm4Mac_shouldOk) {
  // GIVEN
  std::string plaintext = "I am a plaintext.";
  std::string key = "abcdefghabcdefgh";
  std::string iv = "1234567812345678";

  // WHEN
  std::vector<uint8_t> ciphertext = Sm4MteEncrypt(key, iv, plaintext);

  std::vector<uint8_t> decrypted = Sm4MteDecrypt(key, iv, ciphertext);

  // THEN
  EXPECT_EQ(plaintext, std::string(decrypted.begin(), decrypted.end()));
}

}  // namespace yacl::crypto

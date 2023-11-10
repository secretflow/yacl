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

#include <fstream>
#include <iostream>

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

#include "yacl/base/int128.h"
#include "yacl/crypto/base/hash/ssl_hash.h"
#include "yacl/crypto/base/symmetric_crypto.h"
#include "yacl/crypto/tools/prg.h"

namespace yacl::crypto {

constexpr int kDataNum = 10;
std::vector<int> aes_data_len = {16, 16, 16, 32, 32, 32, 48, 48, 48, 64};
std::vector<int> sha256_data_len = {3, 6, 9, 12, 15, 16, 16, 16, 32, 32};

void AesTestData(std::string &file_name,
                 SymmetricCrypto::CryptoType crypto_mode) {
  uint128_t aes_key;
  std::ofstream out_file;
  out_file.open(file_name, std::ios::out /*| std::ios::app*/);

  Prg<uint128_t> prg(0, PRG_MODE::kNistAesCtrDrbg);

  for (int i = 0; i < kDataNum; ++i) {
    std::string aes_plain;
    std::string aes_cipher;
    std::string aes_decrypt;

    aes_key = prg();

    aes_plain.resize(aes_data_len[i]);
    aes_cipher.resize(aes_data_len[i]);
    aes_decrypt.resize(aes_data_len[i]);
    prg.Fill(absl::MakeSpan(aes_plain.data(), aes_plain.size()));

    SymmetricCrypto crypto(crypto_mode, aes_key, 0);

    crypto.Encrypt(
        absl::MakeConstSpan(reinterpret_cast<const uint8_t *>(aes_plain.data()),
                            aes_plain.size()),
        absl::MakeSpan(reinterpret_cast<uint8_t *>(aes_cipher.data()),
                       aes_cipher.size()));
    crypto.Decrypt(
        absl::MakeConstSpan(
            reinterpret_cast<const uint8_t *>(aes_cipher.data()),
            aes_cipher.size()),
        absl::MakeSpan(reinterpret_cast<uint8_t *>(aes_decrypt.data()),
                       aes_decrypt.size()));

    out_file << std::endl << "=====" << i << "=====" << std::endl;

    out_file << "key(" << sizeof(uint128_t) << "): " << std::endl;

    out_file << absl::BytesToHexString(
                    absl::string_view(reinterpret_cast<const char *>(&aes_key),
                                      sizeof(uint128_t)))
             << std::endl;
    out_file << "plain(" << aes_plain.length() << "): " << std::endl;
    out_file << absl::BytesToHexString(aes_plain) << std::endl;
    out_file << "cipher(" << aes_cipher.length() << "): " << std::endl;
    out_file << absl::BytesToHexString(aes_cipher) << std::endl;

    EXPECT_EQ(aes_decrypt, aes_plain);
  }
}

void Sha256TestData(std::string &file_name) {
  std::ofstream out_file;
  out_file.open(file_name, std::ios::out /*| std::ios::app*/);

  // prg
  Prg<uint64_t> prg(0, PRG_MODE::kNistAesCtrDrbg);

  for (size_t i = 0; i < sha256_data_len.size(); ++i) {
    Sha256Hash sha256;
    std::string hash_data(sha256_data_len[i], '\0');
    prg.Fill(absl::MakeSpan(hash_data.data(), hash_data.size()));

    sha256.Update(hash_data);
    std::vector<uint8_t> hash_result = sha256.CumulativeHash();
    out_file << "=====" << i << "=====" << std::endl;
    out_file << "data(" << hash_data.length() << "):" << std::endl;
    out_file << absl::BytesToHexString(hash_data) << std::endl;
    out_file << "hash(" << hash_result.size() << "):" << std::endl;
    out_file << absl::BytesToHexString(std::string_view(
                    reinterpret_cast<const char *>(hash_result.data()),
                    hash_result.size()))
             << std::endl;
  }
}

}  // namespace yacl::crypto

int main(int /*argc*/, char ** /*argv*/) {
  std::string aes_ecb_file_name = "aes_ecb_data.txt";
  std::string aes_ctr_file_name = "aes_ctr_data.txt";
  std::string sha256_file_name = "sha256_data.txt";
  std::string curve25519_file_name = "curve25519_data.txt";

  AesTestData(aes_ecb_file_name,
              yacl::crypto::SymmetricCrypto::CryptoType::AES128_ECB);
  AesTestData(aes_ctr_file_name,
              yacl::crypto::SymmetricCrypto::CryptoType::AES128_CTR);
  yacl::crypto::Sha256TestData(sha256_file_name);

  return 0;
}

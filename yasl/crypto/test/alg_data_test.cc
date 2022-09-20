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

#include "yasl/base/int128.h"
#include "yasl/crypto/pseudo_random_generator.h"
#include "yasl/crypto/ssl_hash.h"
#include "yasl/crypto/symmetric_crypto.h"

extern "C" {

#include "curve25519.h"
}

namespace {
constexpr int kCurve25519ElemSize = 32;
constexpr int kDataNum = 10;
std::vector<int> aes_data_len = {16, 16, 16, 32, 32, 32, 48, 48, 48, 64};
std::vector<int> sha256_data_len = {3, 6, 9, 12, 15, 16, 16, 16, 32, 32};

void AesTestData(std::string &file_name,
                 yasl::SymmetricCrypto::CryptoType crypto_mode) {
  uint128_t aes_key;
  std::ofstream out_file;
  out_file.open(file_name, std::ios::out /*| std::ios::app*/);

  yasl::PseudoRandomGenerator<uint128_t> prg(0,
                                             yasl::PRG_MODE::kNistAesCtrDrbg);

  for (int i = 0; i < kDataNum; ++i) {
    std::string aes_plain;
    std::string aes_cipher;
    std::string aes_decrypt;

    aes_key = prg();

    aes_plain.resize(aes_data_len[i]);
    aes_cipher.resize(aes_data_len[i]);
    aes_decrypt.resize(aes_data_len[i]);
    prg.Fill(absl::MakeSpan(aes_plain.data(), aes_plain.size()));

    yasl::SymmetricCrypto crypto(crypto_mode, aes_key, 0);

    crypto.Encrypt(
        absl::MakeConstSpan((const uint8_t *)aes_plain.data(),
                            aes_plain.size()),
        absl::MakeSpan((uint8_t *)aes_cipher.data(), aes_cipher.size()));
    crypto.Decrypt(
        absl::MakeConstSpan((const uint8_t *)aes_cipher.data(),
                            aes_cipher.size()),
        absl::MakeSpan((uint8_t *)aes_decrypt.data(), aes_decrypt.size()));

    out_file << std::endl << "=====" << i << "=====" << std::endl;

    out_file << "key(" << sizeof(uint128_t) << "): " << std::endl;

    out_file << absl::BytesToHexString(absl::string_view((const char *)&aes_key,
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
  yasl::PseudoRandomGenerator<uint64_t> prg(0, yasl::PRG_MODE::kNistAesCtrDrbg);

  for (size_t i = 0; i < sha256_data_len.size(); ++i) {
    yasl::crypto::Sha256Hash sha256;
    std::string hash_data(sha256_data_len[i], '\0');
    prg.Fill(absl::MakeSpan(hash_data.data(), hash_data.size()));

    sha256.Update(hash_data);
    std::vector<uint8_t> hash_result = sha256.CumulativeHash();
    out_file << "=====" << i << "=====" << std::endl;
    out_file << "data(" << hash_data.length() << "):" << std::endl;
    out_file << absl::BytesToHexString(hash_data) << std::endl;
    out_file << "hash(" << hash_result.size() << "):" << std::endl;
    out_file << absl::BytesToHexString(std::string_view(
                    (const char *)hash_result.data(), hash_result.size()))
             << std::endl;
  }
}

void Curve25519TestData(std::string &file_name) {
  std::ofstream out_file;
  out_file.open(file_name, std::ios::out /*| std::ios::app*/);

  // prg
  yasl::PseudoRandomGenerator<uint64_t> prg(0, yasl::PRG_MODE::kNistAesCtrDrbg);

  for (size_t i = 0; i < sha256_data_len.size(); ++i) {
    std::array<uint8_t, kCurve25519ElemSize> private_x;
    std::array<uint8_t, kCurve25519ElemSize> public_x;
    std::array<uint8_t, kCurve25519ElemSize> private_y;
    std::array<uint8_t, kCurve25519ElemSize> public_y;
    std::array<uint8_t, kCurve25519ElemSize> share_x;
    std::array<uint8_t, kCurve25519ElemSize> share_y;

    prg.Fill(absl::MakeSpan(private_x.data(), private_x.size()));
    prg.Fill(absl::MakeSpan(private_y.data(), private_y.size()));

    curve25519_donna_basepoint(public_x.data(), private_x.data());
    curve25519_donna_basepoint(public_y.data(), private_y.data());

    curve25519_donna(share_x.data(), private_x.data(), public_y.data());
    curve25519_donna(share_y.data(), private_y.data(), public_x.data());

    EXPECT_EQ(share_x, share_y);

    out_file << "=====" << i << "=====" << std::endl;
    out_file << "private x(" << private_x.size() << "):" << std::endl;
    out_file << absl::BytesToHexString(std::string_view(
                    (const char *)private_x.data(), share_x.size()))
             << std::endl;
    out_file << "public x(" << public_x.size() << "):" << std::endl;
    out_file << absl::BytesToHexString(std::string_view(
                    (const char *)public_x.data(), share_x.size()))
             << std::endl;
    out_file << "private y(" << private_y.size() << "):" << std::endl;
    out_file << absl::BytesToHexString(std::string_view(
                    (const char *)private_y.data(), share_x.size()))
             << std::endl;
    out_file << "public y(" << public_y.size() << "):" << std::endl;
    out_file << absl::BytesToHexString(std::string_view(
                    (const char *)public_y.data(), share_x.size()))
             << std::endl;
    out_file << "share y(" << share_x.size() << "):" << std::endl;
    out_file << absl::BytesToHexString(std::string_view(
                    (const char *)share_x.data(), share_x.size()))
             << std::endl;
  }
}

}  // namespace

int main(int argc, char **argv) {
  std::string aes_ecb_file_name = "aes_ecb_data.txt";
  std::string aes_ctr_file_name = "aes_ctr_data.txt";
  std::string sha256_file_name = "sha256_data.txt";
  std::string curve25519_file_name = "curve25519_data.txt";

  AesTestData(aes_ecb_file_name, yasl::SymmetricCrypto::CryptoType::AES128_ECB);
  AesTestData(aes_ctr_file_name, yasl::SymmetricCrypto::CryptoType::AES128_CTR);
  Sha256TestData(sha256_file_name);
  Curve25519TestData(curve25519_file_name);

  return 0;
}
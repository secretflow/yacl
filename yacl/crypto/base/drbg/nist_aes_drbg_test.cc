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

#include "yacl/crypto/base/drbg/nist_aes_drbg.h"

#include <future>
#include <random>
#include <string>
#include <vector>

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"
#include "spdlog/spdlog.h"

#include "yacl/crypto/base/drbg/entropy_source.h"

// test vector from NIST Cryptographic-Standards-and-Guidelines
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/CTR_DRBG_withDF.pdf
//
namespace yacl::crypto {

namespace {

struct TestData {
  // entropy input
  std::array<std::string, 3> entropy;
  int entropy_count = 0;
  // nonce
  std::string nonce;
  // PredictionResistance NOT ENABLED returned random bytes
  std::array<std::string, 2> returned_bytes;

  // PredictionResistance ENABLED returned random bytes
  std::array<std::string, 2> pr_returned_bytes;
};

TestData strength128_test_vector = {
    {"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
     "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F",
     "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"},
    0,
    "2021222324252627",
    {"8cf59c8cf6888b96eb1c1e3e79d82387af08a9e5ff75e23f1fbcd4559b6b997e",
     "69cdef912c692d61b1da4c05146b52eb7b8849bd87937835328254ec25a9180e"},
    {"bff4b85d68c84529f24f69f9acf1756e29ba648ddeb825c225fa32ba490ef4a9",
     "9BD2635137A52AF7D0FCBEFEFB97EA93A0F4C438BD98956C0DACB04F15EE25B3"}  //
};

TestData strength192_test_vector = {
    {"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
     "021222324252627",
     "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA"
     "0A1A2A3A4A5A6A7",
     "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE"
     "0E1E2E3E4E5E6E7"},  //
    0,
    "202122232425262728292A2B",
    {"1A646BB1D38BD2AEA30CF5C5D812A624B50D3ECA99E508B25B5448A8B96C0F2E",
     "0920CB32A773E0FF4BBBF90ACB1D7044E15B629AFB3C7F9FE26673E3E7BE4727"},
    {"D1C68E369E5AE5CFB656431713DC972E54B87DA6326D0D49D1C1165370049FDB",
     "615A26371F46583EA33ED75709D0EE555C62EC04433648A7C62FD43D2764D52F"}  //
};

TestData strength256_test_vector = {
    {"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232"
     "425262728292A2B2C2D2E2F",
     "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A"
     "4A5A6A7A8A9AAABACADAEAF",
     "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E"
     "4E5E6E7E8E9EAEBECEDEEEF"},  //
    0,
    "202122232425262728292A2B2C2D2E2F",  //
    {"E686DD55F758FD91BA7CB726FE0B573A180AB67439FFBDFE5EC28FB37A16A53B",
     "8DA6CC59E703CED07D58D96E5B6D7836C32599735B734F88C1A73B53C7A6D82E"},  //
    {"D1E9C737B6EBAED765A0D4E4C6EAEBE267F5E9193680FDFFA62F4865B3F009EC",
     "259DC78CCFAEC4210C30AF815E4F75A5662B7DA4B41013BDC00302DFB6076492"}  //
};

TestData *GetTestDataByEntropyLen(int entropy_bits) {
  TestData *test_data_ptr;
  switch (entropy_bits) {
    case 256:
      test_data_ptr = &strength256_test_vector;
      break;
    case 192:
      test_data_ptr = &strength192_test_vector;
      break;
    case 128:
    default:
      test_data_ptr = &strength128_test_vector;
      break;
  }
  return test_data_ptr;
}

SecurityStrengthFlags GetTestDataByStrengthFlag(int bits) {
  switch (bits) {
    case 256:
      return SecurityStrengthFlags::kStrength256;
    case 192:
      return SecurityStrengthFlags::kStrength192;
    case 128:
    default:
      return SecurityStrengthFlags::kStrength128;
  }
}

class NistFixEntropySource : public IEntropySource {
 public:
  NistFixEntropySource(int strength_bit) {
    SecurityStrengthFlags strength_flag =
        GetTestDataByStrengthFlag(strength_bit);
    data_ = GetTestDataByEntropyLen(strength_bit);
    entropy_bytes_ = GetEntropyBytes(strength_flag);
    nonce_bytes_ = GetNonceBytes(strength_flag);
  }

  ~NistFixEntropySource() override = default;

  std::string GetEntropy(size_t entropy_bytes) override {
    std::string ret;

    if (entropy_bytes == static_cast<size_t>(entropy_bytes_)) {
      ret = absl::HexStringToBytes(data_->entropy[entropy_count_]);
      entropy_count_++;
      entropy_count_ %= 3;
    } else if (entropy_bytes == static_cast<size_t>(nonce_bytes_)) {
      ret = absl::HexStringToBytes(data_->nonce);
    } else {
      YACL_THROW("not support entropy_bytes:{}", entropy_bytes);
    }
    return ret;
  }

  uint64_t GetEntropy() override { return 0; }

 private:
  int entropy_bytes_ = 0;
  int nonce_bytes_ = 0;
  int entropy_count_ = 0;
  TestData *data_;
};

// with fix entropy from NIST standard
// No PR
void NistAesDrbgFixEntropy(int strength_bit) {
  SecurityStrengthFlags strength_flag = GetTestDataByStrengthFlag(strength_bit);

  std::shared_ptr<IEntropySource> fix_seed_entropy_source =
      std::make_shared<NistFixEntropySource>(strength_bit);
  NistAesDrbg ctr_drbg(fix_seed_entropy_source, 0, strength_flag);

  size_t random_size = 32;
  std::vector<uint8_t> random_buf1 = ctr_drbg.Generate(random_size);
  absl::string_view random_buf_strview =
      absl::string_view((const char *)random_buf1.data(), random_buf1.size());

  TestData *test_data_ptr = GetTestDataByEntropyLen(strength_bit);
  std::string returned_str1 =
      absl::HexStringToBytes(test_data_ptr->returned_bytes[0]);
  EXPECT_EQ(std::string_view(returned_str1), random_buf_strview);

  std::vector<uint8_t> random_buf2 = ctr_drbg.Generate(random_size);

  absl::string_view random_buf_strview2 =
      absl::string_view((const char *)random_buf2.data(), random_buf2.size());

  EXPECT_NE(random_buf1, random_buf2);

  std::string returned_str2 =
      absl::HexStringToBytes(test_data_ptr->returned_bytes[1]);
  EXPECT_EQ(std::string_view(returned_str2), random_buf_strview2);
}

// with fix entropy from NIST standard
// PR Enabled
void NistAesDrbgFixEntropyPREnable(int strength_bit) {
  SecurityStrengthFlags strength_flag = GetTestDataByStrengthFlag(strength_bit);
  std::shared_ptr<IEntropySource> nist_aes_entropy_source =
      std::make_shared<NistFixEntropySource>(strength_bit);
  NistAesDrbg ctr_drbg(nist_aes_entropy_source, 0, strength_flag);

  size_t random_size = 32;
  std::vector<uint8_t> random_buf1 =
      ctr_drbg.Generate(random_size, PredictionResistanceFlags::kYes);
  absl::string_view random_buf_strview =
      absl::string_view((const char *)random_buf1.data(), random_buf1.size());

  TestData *test_data_ptr = GetTestDataByEntropyLen(strength_bit);

  std::string returned_str1 =
      absl::HexStringToBytes(test_data_ptr->pr_returned_bytes[0]);
  EXPECT_EQ(std::string_view(returned_str1), random_buf_strview);

  std::vector<uint8_t> random_buf2 =
      ctr_drbg.Generate(random_size, PredictionResistanceFlags::kYes);
  absl::string_view random_buf_strview2 =
      absl::string_view((const char *)random_buf2.data(), random_buf2.size());

  EXPECT_NE(random_buf1, random_buf2);

  std::string returned_str2 =
      absl::HexStringToBytes(test_data_ptr->pr_returned_bytes[1]);
  EXPECT_EQ(std::string_view(returned_str2), random_buf_strview2);
}

// Entropy from intel RNG
void NistAesDrbgIntelRNGEntropy(uint128_t seed, int strength_bit) {
  SecurityStrengthFlags strength_flag = GetTestDataByStrengthFlag(strength_bit);

  NistAesDrbg ctr_drbg(seed, strength_flag);

  size_t random_size = 32;
  std::vector<uint8_t> random_buf1 = ctr_drbg.Generate(random_size);

  std::vector<uint8_t> random_buf2 = ctr_drbg.Generate(random_size);

  EXPECT_NE(random_buf1, random_buf2);

  ctr_drbg.FillPRand(absl::MakeSpan(random_buf1));
  ctr_drbg.FillPRand(absl::MakeSpan(random_buf2));
  EXPECT_NE(random_buf1, random_buf2);

  for (size_t idx = 0; idx < 100; idx++) {
    std::vector<uint8_t> random_buf3 = ctr_drbg.Generate(random_size);
    std::vector<uint8_t> random_buf4 = ctr_drbg.Generate(random_size);
    EXPECT_NE(random_buf3, random_buf4);
  }
  for (size_t idx = 0; idx < 100; idx++) {
    std::vector<uint8_t> random_buf3 =
        ctr_drbg.Generate(random_size, PredictionResistanceFlags::kYes);
    std::vector<uint8_t> random_buf4 =
        ctr_drbg.Generate(random_size, PredictionResistanceFlags::kYes);
    EXPECT_NE(random_buf3, random_buf4);
  }
}

}  // namespace

// Entropy from intel RNG
TEST(CtrDrngTest, TestWithIntelRNGEntropy) {
  std::vector<int> stength_vec = {128, 192, 256};
  for (auto &iter : stength_vec) {
    NistAesDrbgIntelRNGEntropy(0, iter);
  }

  std::random_device rd;
  std::mt19937 mt19937_random(rd());
  uint64_t seed1, seed2;
  seed1 = mt19937_random();
  seed2 = mt19937_random();
  uint128_t seed = MakeUint128(seed1, seed2);
  for (auto &iter : stength_vec) {
    NistAesDrbgIntelRNGEntropy(seed, iter);
  }
}

// with fix entropy from NIST standard
// PredictionResistance NOT ENABLED
TEST(CtrDrngTest, TestWithFixEntropy) {
  std::vector<int> stength_vec = {128, 192, 256};
  for (auto &iter : stength_vec) {
    NistAesDrbgFixEntropy(iter);
  }
}

// with fix entropy from NIST standard
// PredictionResistance ENABLED
TEST(CtrDrngTest, TestWithFixEntropyPREnabled) {
  std::vector<int> stength_vec = {128, 192, 256};
  for (auto &iter : stength_vec) {
    NistAesDrbgFixEntropyPREnable(iter);
  }
}

TEST(CtrDrngTest, TestMultiThreadWithFixEntropy) {
  std::future<void> f_ctr_drbg_128 =
      std::async([&] { NistAesDrbgFixEntropy(128); });
  std::future<void> f_ctr_drbg_192 =
      std::async([&] { NistAesDrbgFixEntropy(192); });
  std::future<void> f_ctr_drbg_256 =
      std::async([&] { NistAesDrbgFixEntropy(256); });

  f_ctr_drbg_128.get();
  f_ctr_drbg_192.get();
  f_ctr_drbg_256.get();
}

TEST(CtrDrngTest, TestMultiThreadWithPREnabled) {
  std::future<void> f_ctr_drbg_128 =
      std::async([&] { NistAesDrbgFixEntropyPREnable(128); });
  std::future<void> f_ctr_drbg_192 =
      std::async([&] { NistAesDrbgFixEntropyPREnable(192); });
  std::future<void> f_ctr_drbg_256 =
      std::async([&] { NistAesDrbgFixEntropyPREnable(256); });

  f_ctr_drbg_128.get();
  f_ctr_drbg_192.get();
  f_ctr_drbg_256.get();
}

TEST(CtrDrngTest, TestHealthCheck) {
  SecurityStrengthFlags strength_flag = GetTestDataByStrengthFlag(128);

  NistAesDrbg ctr_drbg(0, strength_flag);

  size_t random_size = (1 << 17) + 13;
  std::vector<uint8_t> random_buf1 = ctr_drbg.Generate(random_size);

  std::vector<uint8_t> random_buf2(random_size);
  ctr_drbg.FillPRandBytes(absl::MakeSpan(random_buf2));

  EXPECT_NE(random_buf1, random_buf2);

  EXPECT_EQ(true, ctr_drbg.HealthCheck());
}

}  // namespace yacl::crypto

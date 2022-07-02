#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

#include "yasl/base/exception.h"
#include "yasl/crypto/hmac_sha256.h"
#include "yasl/crypto/hmac_sm3.h"

namespace yasl::crypto {

template <typename T>
class HmacTest : public testing::Test {
 public:
  struct TestData {
    // HMAC key
    std::string key;
    // HMAC data
    std::string vector1;
    // HMAC result
    std::string result1;
    // HMAC data
    std::string vector2;
    // HMAC result
    std::string result2;
    // vector2 without vector1 prefix.
    std::string suffix;
  };

  void SetUp() override {
    // The following two test vectors are got by openssl commands:
    // echo -n 'abc' | openssl sm3 -hmac "key_for_hmac"
    // echo -n 'abcdefabcdef' | openssl sm3 -hmac "key_for_hmac"
    test_data_sm3_ = {
        "key_for_hmac",
        "abc",
        "fadeb019e650084096778fa548c0eb47072bb3d6e802c8e2f0033045a55b919f",
        "abcdefabcdef",
        "935110bcb7391158eaf5d54cc49bcde4802e708fa585d794559a021821369a63",
        "defabcdef"};
    // The following two test vectors are got by openssl commands:
    // echo -n 'abc' | openssl sha256 -hmac "key_for_hmac"
    // echo -n 'abcdefabcdef' | openssl sha256 -hmac "key_for_hmac"
    test_data_sha256_ = {
        "key_for_hmac",
        "abc",
        "1c390b90a39a07cbc94ee6cc9c0086a1617d133d0238a2417c89081cb1b3704a",
        "abcdefabcdef",
        "ed9547cd0d707caa7ce4a7549862079827ba43b49803e1dab937bca37a8eb324",
        "defabcdef"};
  }

 protected:
  const TestData& Data() {
    if (std::is_same<T, HmacSm3>::value) {
      return test_data_sm3_;
    } else if (std::is_same<T, HmacSha256>::value) {
      return test_data_sha256_;
    }

    YASL_THROW("Unsupported typename!");
  }

  TestData test_data_sm3_;
  TestData test_data_sha256_;
};

using MyTypes = ::testing::Types<HmacSm3, HmacSha256>;
TYPED_TEST_SUITE(HmacTest, MyTypes);

TYPED_TEST(HmacTest, TestVector1) {
  std::vector<uint8_t> mac =
      TypeParam(this->Data().key).Update(this->Data().vector1).CumulativeMac();
  EXPECT_EQ(absl::BytesToHexString(
                absl::string_view((const char*)mac.data(), mac.size())),
            this->Data().result1);
}

TYPED_TEST(HmacTest, TestVector2) {
  std::vector<uint8_t> mac =
      TypeParam(this->Data().key).Update(this->Data().vector2).CumulativeMac();
  EXPECT_EQ(absl::BytesToHexString(
                absl::string_view((const char*)mac.data(), mac.size())),
            this->Data().result2);
}

// Verify that calling Reset() after addition of some data resets the object to
// a clean state, allowing a new hmac operation to take place.
TYPED_TEST(HmacTest, ResetBetweenUpdates) {
  std::vector<uint8_t> mac = TypeParam(this->Data().key)
                                 .Update(this->Data().vector1)
                                 .Reset()
                                 .Update(this->Data().vector2)
                                 .CumulativeMac();
  EXPECT_EQ(absl::BytesToHexString(
                absl::string_view((const char*)mac.data(), mac.size())),
            this->Data().result2);
}

// Verify that the correct hmac is computed when the input is added over several
// calls to Update.
TYPED_TEST(HmacTest, MultipleUpdates) {
  TypeParam hmac(this->Data().key);
  std::vector<uint8_t> mac = hmac.Update(this->Data().vector1).CumulativeMac();
  EXPECT_EQ(absl::BytesToHexString(
                absl::string_view((const char*)mac.data(), mac.size())),
            this->Data().result1);

  mac = hmac.Update(this->Data().suffix).CumulativeMac();
  EXPECT_EQ(absl::BytesToHexString(
                absl::string_view((const char*)mac.data(), mac.size())),
            this->Data().result2);
}

}  // namespace yasl::crypto

#include "yasl/crypto/gcm_crypto.h"

#include <memory>

#include "gtest/gtest.h"
#include "openssl/evp.h"

#include "yasl/base/exception.h"

namespace yasl::crypto {

namespace {

constexpr char key_128[] = "1234567812345678";
constexpr char key_256[] = "12345678123456781234567812345678";
constexpr char iv_96[] = "000000000000";

}  // namespace

template <typename T>
class AesGcmCryptoTest : public testing::Test {};
using MyTypes = ::testing::Types<Aes128GcmCrypto, Aes256GcmCrypto>;
TYPED_TEST_SUITE(AesGcmCryptoTest, MyTypes);

TYPED_TEST(AesGcmCryptoTest, EncryptDecrypt_ShouldOk) {
  std::string key;
  if (std::is_same<TypeParam, Aes128GcmCrypto>::value) {
    key = std::string(key_128);
  } else if (std::is_same<TypeParam, Aes256GcmCrypto>::value) {
    key = std::string(key_256);
  }
  TypeParam crypto(key, ByteContainerView(iv_96, sizeof(iv_96) - 1));
  std::string plaintext = "I am a plaintext.";
  std::string aad = "This is additional authenticated data.";
  // WHEN
  std::vector<uint8_t> ciphertext(plaintext.size());
  std::vector<uint8_t> mac(16);
  crypto.Encrypt(plaintext, aad,
                 absl::MakeSpan(ciphertext.data(), ciphertext.size()),
                 absl::MakeSpan(mac.data(), mac.size()));
  std::vector<uint8_t> decrypted(plaintext.size());
  crypto.Decrypt(ciphertext, aad, mac,
                 absl::MakeSpan(decrypted.data(), decrypted.size()));
  // THEN
  EXPECT_EQ(plaintext, std::string(decrypted.begin(), decrypted.end()));
}

TYPED_TEST(AesGcmCryptoTest,
           EncryptDecrypt_withErrorGMAC_ShouldThrowException) {
  std::string key;
  if (std::is_same<TypeParam, Aes128GcmCrypto>::value) {
    key = std::string(key_128);
  } else if (std::is_same<TypeParam, Aes256GcmCrypto>::value) {
    key = std::string(key_256);
  }
  TypeParam crypto(key, ByteContainerView(iv_96, sizeof(iv_96) - 1));
  std::string plaintext = "I am a plaintext.";
  std::string aad = "This is additional authenticated data.";
  // WHEN
  std::vector<uint8_t> ciphertext(plaintext.size());
  std::vector<uint8_t> mac(16);
  crypto.Encrypt(plaintext, aad,
                 absl::MakeSpan(ciphertext.data(), ciphertext.size()),
                 absl::MakeSpan(mac.data(), mac.size()));
  std::vector<uint8_t> decrypted(plaintext.size());
  mac[0] += 1;
  // THEN
  EXPECT_ANY_THROW({
    crypto.Decrypt(ciphertext, aad, mac,
                   absl::MakeSpan(decrypted.data(), decrypted.size()));
  });
}

TYPED_TEST(AesGcmCryptoTest, EncryptDecrypt_withErrorAAD_ShouldThrowException) {
  // GIVEN
  std::string key;
  if (std::is_same<TypeParam, Aes128GcmCrypto>::value) {
    key = std::string(key_128);
  } else if (std::is_same<TypeParam, Aes256GcmCrypto>::value) {
    key = std::string(key_256);
  }
  TypeParam crypto(key, ByteContainerView(iv_96, sizeof(iv_96) - 1));
  std::string plaintext = "I am a plaintext.";
  std::string aad = "This is additional authenticated data.";
  // WHEN
  std::vector<uint8_t> ciphertext(plaintext.size());
  std::vector<uint8_t> mac(16);
  crypto.Encrypt(plaintext, aad,
                 absl::MakeSpan(ciphertext.data(), ciphertext.size()),
                 absl::MakeSpan(mac.data(), mac.size()));
  std::vector<uint8_t> decrypted(plaintext.size());
  aad[0] += 1;
  // THEN
  EXPECT_ANY_THROW({
    crypto.Decrypt(ciphertext, aad, mac,
                   absl::MakeSpan(decrypted.data(), decrypted.size()));
  });
}

}  // namespace yasl::crypto

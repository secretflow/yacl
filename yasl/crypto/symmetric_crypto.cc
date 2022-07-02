#include "yasl/crypto/symmetric_crypto.h"

#include "openssl/aes.h"
#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/evp.h"

#include "yasl/base/exception.h"

namespace yasl {
namespace {

constexpr size_t kBatchSize = 1024;

const EVP_CIPHER* CreateEvpCipher(SymmetricCrypto::CryptoType type) {
  switch (type) {
    case SymmetricCrypto::CryptoType::AES128_ECB:
      return EVP_aes_128_ecb();
    case SymmetricCrypto::CryptoType::AES128_CBC:
      return EVP_aes_128_cbc();
    case SymmetricCrypto::CryptoType::AES128_CTR:
      return EVP_aes_128_ctr();
    case SymmetricCrypto::CryptoType::SM4_ECB:
      return EVP_sm4_ecb();
    case SymmetricCrypto::CryptoType::SM4_CBC:
      return EVP_sm4_cbc();
    case SymmetricCrypto::CryptoType::SM4_CTR:
      return EVP_sm4_ctr();
    default:
      YASL_THROW("unknown crypto type: {}", static_cast<int>(type));
  }
}

EVP_CIPHER_CTX* CreateEVPCipherCtx(SymmetricCrypto::CryptoType type,
                                   uint128_t key, uint128_t iv, int enc) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

  EVP_CIPHER_CTX_init(ctx);

  // This uses AES-128, so the key must be 128 bits.
  const EVP_CIPHER* cipher = CreateEvpCipher(type);
  YASL_ENFORCE(sizeof(key) == EVP_CIPHER_key_length(cipher));
  const auto* key_data = reinterpret_cast<const uint8_t*>(&key);

  // cbc mode need to set iv
  if ((type == SymmetricCrypto::CryptoType::AES128_ECB) ||
      (type == SymmetricCrypto::CryptoType::SM4_ECB)) {
    YASL_ENFORCE(
        EVP_CipherInit_ex(ctx, cipher, nullptr, key_data, nullptr, enc));
  } else {
    /**
     * @brief cbc and ctr mode set iv
     * for ctr the iv is the initiator counter, most case counter set 0
     */
    const auto* iv_data = reinterpret_cast<const uint8_t*>(&iv);
    YASL_ENFORCE(
        EVP_CipherInit_ex(ctx, cipher, nullptr, key_data, iv_data, enc));
  }

  // No padding needed for aligned blocks.
  YASL_ENFORCE(EVP_CIPHER_CTX_set_padding(ctx, 0));

  return ctx;
}

// int128 family requires alignment of 16, so we cannot just cast data into
// (u)int128_t and copy it.
uint128_t CopyDataAsUint128(const uint8_t* data) {
  uint128_t ret;
  for (size_t idx = 0; idx < sizeof(uint128_t); ++idx) {
    reinterpret_cast<uint8_t*>(&ret)[idx] = data[idx];
  }
  return ret;
}

}  // namespace

SymmetricCrypto::SymmetricCrypto(CryptoType type, uint128_t key, uint128_t iv)
    : type_(type), key_(key), initial_vector_(iv) {
  enc_ctx_ = CreateEVPCipherCtx(type_, key_, initial_vector_, 1);
  dec_ctx_ = CreateEVPCipherCtx(type_, key_, initial_vector_, 0);
}

SymmetricCrypto::SymmetricCrypto(CryptoType type, ByteContainerView key,
                                 ByteContainerView iv)
    : type_(type),
      key_(CopyDataAsUint128(key.data())),
      initial_vector_(CopyDataAsUint128(iv.data())) {
  enc_ctx_ = CreateEVPCipherCtx(type_, key_, initial_vector_, 1);
  dec_ctx_ = CreateEVPCipherCtx(type_, key_, initial_vector_, 0);
}

void SymmetricCrypto::Decrypt(absl::Span<const uint8_t> ciphertext,
                              absl::Span<uint8_t> plaintext) const {
  if ((type_ != SymmetricCrypto::CryptoType::AES128_CTR) &&
      (type_ != SymmetricCrypto::CryptoType::SM4_CTR)) {
    if (ciphertext.size() % BlockSize() != 0) {
      YASL_THROW("Requires size can be divided by block_size={}.", BlockSize());
    }
  }
  YASL_ENFORCE(plaintext.size() == ciphertext.size());

  EVP_CIPHER_CTX* ctx;
  if ((type_ == SymmetricCrypto::CryptoType::AES128_ECB) ||
      (type_ == SymmetricCrypto::CryptoType::SM4_ECB)) {
    ctx = dec_ctx_;
  } else {
    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_CIPHER_CTX_copy(ctx, dec_ctx_);
  }

  size_t left = plaintext.size();
  size_t i = 0;

  while (left > 0) {
    int n = std::min<size_t>(left, kBatchSize);
    int out_length;
    int rc =
        EVP_CipherUpdate(ctx, plaintext.data() + i * kBatchSize, &out_length,
                         ciphertext.data() + i * kBatchSize, n);
    YASL_ENFORCE(rc, "Fail to decrypt, rc={}", rc);
    i++;
    left -= n;
  }

  // Does not require `Finalize` for aligned inputs.

  if ((type_ != SymmetricCrypto::CryptoType::AES128_ECB) &&
      (type_ != SymmetricCrypto::CryptoType::SM4_ECB)) {
    EVP_CIPHER_CTX_free(ctx);
  }
}

void SymmetricCrypto::Encrypt(absl::Span<const uint8_t> plaintext,
                              absl::Span<uint8_t> ciphertext) const {
  if ((type_ != SymmetricCrypto::CryptoType::AES128_CTR) &&
      (type_ != SymmetricCrypto::CryptoType::SM4_CTR)) {
    if (ciphertext.size() % BlockSize() != 0) {
      YASL_THROW("Requires size can be divided by block_size={}.", BlockSize());
    }
  }
  YASL_ENFORCE(plaintext.size() == ciphertext.size());

  EVP_CIPHER_CTX* ctx;
  if ((type_ == SymmetricCrypto::CryptoType::AES128_ECB) ||
      (type_ == SymmetricCrypto::CryptoType::SM4_ECB)) {
    ctx = enc_ctx_;
  } else {
    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_CIPHER_CTX_copy(ctx, enc_ctx_);
  }

  size_t left = plaintext.size();
  size_t i = 0;

  while (left > 0) {
    int n = std::min<size_t>(left, kBatchSize);
    int outlen;
    int rc = EVP_CipherUpdate(ctx, ciphertext.data() + i * kBatchSize, &outlen,
                              plaintext.data() + i * kBatchSize, n);
    YASL_ENFORCE(rc, "Fail to encrypt, rc={}", rc);
    i++;
    left -= n;
  }

  // Does not require `Finalize` for aligned inputs.

  if ((type_ != SymmetricCrypto::CryptoType::AES128_ECB) &&
      (type_ != SymmetricCrypto::CryptoType::SM4_ECB)) {
    EVP_CIPHER_CTX_free(ctx);
  }
}

uint128_t SymmetricCrypto::Encrypt(uint128_t input) const {
  uint128_t ret;
  Encrypt(absl::Span<const uint8_t>(reinterpret_cast<const uint8_t*>(&input),
                                    sizeof(input)),
          absl::Span<uint8_t>(reinterpret_cast<uint8_t*>(&ret), sizeof(ret)));
  return ret;
}

uint128_t SymmetricCrypto::Decrypt(uint128_t input) const {
  uint128_t ret;
  Decrypt(absl::Span<const uint8_t>(reinterpret_cast<const uint8_t*>(&input),
                                    sizeof(input)),
          absl::Span<uint8_t>(reinterpret_cast<uint8_t*>(&ret), sizeof(ret)));
  return ret;
}

void SymmetricCrypto::Encrypt(absl::Span<const uint128_t> plaintext,
                              absl::Span<uint128_t> ciphertext) const {
  auto in = absl::Span<const uint8_t>(
      reinterpret_cast<const uint8_t*>(plaintext.data()),
      plaintext.size() * sizeof(uint128_t));
  auto out = absl::Span<uint8_t>(reinterpret_cast<uint8_t*>(ciphertext.data()),
                                 ciphertext.size() * sizeof(uint128_t));
  Encrypt(in, out);
}

void SymmetricCrypto::Decrypt(absl::Span<const uint128_t> ciphertext,
                              absl::Span<uint128_t> plaintext) const {
  auto in = absl::Span<const uint8_t>(
      reinterpret_cast<const uint8_t*>(ciphertext.data()),
      ciphertext.size() * sizeof(uint128_t));
  auto out = absl::Span<uint8_t>(reinterpret_cast<uint8_t*>(plaintext.data()),
                                 plaintext.size() * sizeof(uint128_t));
  Decrypt(in, out);
}

}  // namespace yasl

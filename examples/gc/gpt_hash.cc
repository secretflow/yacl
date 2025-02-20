#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// 手动进行 SHA256 预处理
void sha256_preprocess(uint8_t *input_data, size_t input_len,
                       uint8_t **padded_data, size_t *padded_len) {
  size_t pad_len = input_len + 1 + 8;  // +1 for 0x80 and +8 for length
  size_t rem = pad_len % 64;
  if (rem > 0) {
    pad_len += (64 - rem);
  }

  // Allocate memory for padded data
  *padded_data = (uint8_t *)malloc(pad_len);
  *padded_len = pad_len;

  // Copy original data
  memcpy(*padded_data, input_data, input_len);

  // Append the "1" bit (0x80)
  (*padded_data)[input_len] = 0x80;

  // Append zeros
  memset(*padded_data + input_len + 1, 0, pad_len - input_len - 9);

  // Append original length in bits (big-endian)
  uint64_t bit_len = input_len * 8;
  for (int i = 0; i < 8; ++i) {
    (*padded_data)[pad_len - 1 - i] = (bit_len >> (i * 8)) & 0xff;
  }
}

int main() {
  // 原始输入数据
  const char *data = "Hello, OpenSSL!";
  size_t data_len = strlen(data);

  // 进行 SHA256 预处理
  uint8_t *padded_data;
  size_t padded_len;
  sha256_preprocess((uint8_t *)data, data_len, &padded_data, &padded_len);

  // 使用 OpenSSL 计算 SHA256 哈希
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  unsigned char hash[32];

  // 初始化 SHA256 上下文
  EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);

  // 将预处理后的数据输入 OpenSSL
  EVP_DigestUpdate(mdctx, padded_data, padded_len);

  // 获取最终哈希值
  EVP_DigestFinal_ex(mdctx, hash, NULL);

  // 打印哈希值
  printf("SHA256 hash: ");
  for (int i = 0; i < 32; i++) {
    printf("%02x", hash[i]);
  }
  printf("\n");

  // 释放资源
  EVP_MD_CTX_free(mdctx);
  free(padded_data);

  return 0;
}
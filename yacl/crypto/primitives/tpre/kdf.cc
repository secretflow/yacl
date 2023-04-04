#include "kdf.h"

namespace yacl::crypto {

std::vector<uint8_t> KDF(absl::string_view Z, size_t key_len) {
  unsigned int counter = 1;
  unsigned char C[4] = {0};
  int dgst_len = 32;
  int index = (key_len + 32) / 32;
  std::vector<uint8_t> key_bytes;

  for (int i = 0; i < index; i++) {
    {
      C[0] = (counter >> 24) & 0xFF;
      C[1] = (counter >> 16) & 0xFF;
      C[2] = (counter >> 8) & 0xFF;
      C[3] = (counter)&0xFF;
    }

    std::string C_str(reinterpret_cast<char*>(C), 4);
    absl::string_view C_view(C_str);
    std::string Z_join_C = std::string(Z) + std::string(C_view);
    std::array<uint8_t, 32> dgst = Sm3(Z_join_C);

    if (i == index - 1) {
      if (key_len % 32 != 0) {
        dgst_len = (key_len) % 32;
      } else {
        dgst_len = 0;
      }
    }
    key_bytes.insert(key_bytes.end(), dgst.begin(), dgst.begin() + dgst_len);
    counter++;
  }
  return key_bytes;
}

}  // namespace yacl::crypto

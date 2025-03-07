#include <bits/stdc++.h>
// #include <stdint.h>

#include <cstdint>

#include "absl/strings/escaping.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/crypto/block_cipher/symmetric_crypto.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/io/circuit/bristol_fashion.h"
#include "yacl/utils/circuit_executor.h"

// using namespace std;
// using namespace yacl;
// void sha256_preprocess(uint8_t *input_data, size_t input_len,
//                        uint8_t **padded_data, size_t *padded_len) {
//   size_t pad_len = input_len + 1 + 8;  // +1 for 0x80 and +8 for length
//   size_t rem = pad_len % 64;
//   if (rem > 0) {
//     pad_len += (64 - rem);
//   }

//   // Allocate memory for padded data
//   *padded_data = (uint8_t *)malloc(pad_len);
//   *padded_len = pad_len;

//   // Copy original data
//   memcpy(*padded_data, input_data, input_len);

//   // Append the "1" bit (0x80)
//   (*padded_data)[input_len] = 0x80;

//   // Append zeros
//   memset(*padded_data + input_len + 1, 0, pad_len - input_len - 9);

//   // Append original length in bits (big-endian)
//   uint64_t bit_len = input_len * 8;
//   for (int i = 0; i < 8; ++i) {
//     (*padded_data)[pad_len - 1 - i] = (bit_len >> (i * 8)) & 0xff;
//   }
// }

uint8_t reverse_bits(uint8_t byte) {
  byte = (byte & 0xF0) >> 4 | (byte & 0x0F) << 4;
  byte = (byte & 0xCC) >> 2 | (byte & 0x33) << 2;
  byte = (byte & 0xAA) >> 1 | (byte & 0x55) << 1;
  return byte;
}

std::vector<uint8_t> preprocess(const std::vector<uint8_t> &message) {
  // 步骤 1: 填充消息
  size_t original_length = message.size() * 8;  // 原始消息的比特长度
  std::vector<uint8_t> padded_message = message;

  // 添加 1 位
  padded_message.push_back(0x80);

  // 添加 0 位，直到长度为 448 位（56 字节）
  while ((padded_message.size() * 8) % 512 != 448) {
    padded_message.push_back(0x00);
  }
  // std::cout << "11  " << padded_message.size() * 8 << endl;
  // std::cout << "origin_len" << original_length << endl;
  // vector<uint8_t> temp;
  // 添加原始消息长度（64 位）
  for (int i = 7; i >= 0; --i) {
    padded_message.push_back((original_length >> (i * 8)) & 0xFF);
    // temp.push_back((original_length >> (i * 8)) & 0xFF);
  }
  // std::cout << "len:";
  // for (int i = 0; i < temp.size(); i++) {
  //   bitset<8> b(temp[i]);
  //   std::cout << b << ' ';
  // }
  // std::cout << endl;

  return padded_message;
}

// uint128_t ReverseBytes(uint128_t x) {
//   auto byte_view = ByteContainerView(&x, sizeof(x));
//   uint128_t ret = 0;
//   auto buf = std::vector<uint8_t>(sizeof(ret));
//   for (size_t i = 0; i < byte_view.size(); ++i) {
//     buf[byte_view.size() - i - 1] = byte_view[i];
//   }
//   std::memcpy(&ret, buf.data(), buf.size());
//   return ret;
// }

// std::string uint128ToBinaryString(__uint128_t value) {
//   std::string result;
//   for (int i = 127; i >= 0; --i) {
//     result += ((value >> i) & 1) ? '1' : '0';
//   }
//   return result;
// }

// uint128_t CopyDataAsUint128(const uint8_t *data, bool flag) {
//   uint128_t ret;
//   int len = flag ? sizeof(uint128_t) / 2 : sizeof(uint128_t);
//   for (int idx = 0; idx < len; ++idx) {
//     reinterpret_cast<uint8_t *>(&ret)[idx] = data[idx];
//     // std::cout << uint128ToBinaryString(ret) << endl;
//   }
//   return ret;
// }

// std::vector<uint8_t> stringToBinary(const std::string &str) {
//   std::vector<uint8_t> binaryData(str.begin(), str.end());
//   return binaryData;
// }

// std::string uint128ToString(__uint128_t value) {
//   if (value == 0) return "0";

//   std::string result;
//   while (value > 0) {
//     result.insert(result.begin(), '0' + static_cast<char>(value % 10));
//     value /= 10;
//   }
//   return result;
// }

// template <typename T>
// void PlainExecutor<T>::Finalize(absl::Span<T> outputs) {
//   // YACL_ENFORCE(outputs.size() >= circ_->nov);

//   size_t index = wires_.size();
//   for (size_t i = 0; i < circ_->nov; ++i) {
//     int half_num_wire = circ_->now[i] / 2;

//     dynamic_bitset<T> result(circ_->now[i]);

//     for (size_t j = 0; j < circ_->now[i]; ++j) {
//       result[j % 128] =
//           wires_[index - circ_->now[i] +
//                  j];  // 得到的是逆序的二进制值   对应的混淆电路计算为
//                       // LSB ^ d  输出线路在后xx位
//       if (j % 128 == 127) {
//         outputs[circ_->nov - i - 1] =
//             *(uint128_t*)result.data();  // 先得到最后位置上的
//         index -= circ_->now[i];
//         std::cout << std::hex << outputs[circ_->nov - i - 1] << "\t";
//       }
//     }
//   }
//   std::cout << endl;
// }

// template <typename T>
// void PlainExecutor<T>::SetupInputs(
//     vector<uint8_t> inputs_bi) {  // Span方便指针的使用
//   // YACL_ENFORCE(inputs.size() == circ_->niv);
//   for (auto input : inputs_bi) {
//     wires_.append(
//         std::bitset<8>(input).begin(),
//         std::bitset<8>(input).end());  // 直接转换为二进制 输入线路在前128位
//   }
//   wires_.resize(circ_->nw);
// }

// #include <bits/stdc++.h>

// std::vector<uint8_t> stringToBinary(const std::string& str) {
//   std::vector<uint8_t> binaryData(str.begin(), str.end());
//   return binaryData;
// }

// int main() {
//   std::string str = "Hello";
//   std::vector<uint8_t> binaryData = stringToBinary(str);

//   // 打印二进制数据
//   for (uint8_t byte : binaryData) {
//     std::std::cout << std::bitset<8>(byte) << " ";
//   }
//   std::std::cout << std::endl;

//   return 0;
// }

// void get_sha256_initial_hash_values(uint32_t hash[8]) {
//   // SHA256 的初始哈希值（每个值为 32 位）
//   hash[0] = 0x6a09e667;
//   hash[1] = 0xbb67ae85;
//   hash[2] = 0x3c6ef372;
//   hash[3] = 0xa54ff53a;
//   hash[4] = 0x510e527f;
//   hash[5] = 0x9b05688c;
//   hash[6] = 0x1f83d9ab;
//   hash[7] = 0x5be0cd19;
// }
int main() {
  // const char *data = "Hello, OpenSSL!";
  // size_t data_len = strlen(data);

  // // 进行 SHA256 预处理
  // uint8_t *padded_data;
  // size_t padded_len;
  // sha256_preprocess((uint8_t *)data, data_len, &padded_data, &padded_len);
  // std::cout << "预处理：";
  // for (int i = 0; i < 64; i++) {
  //   std::cout << std::hex << static_cast<int>(padded_data[i]);
  // }
  // std::cout << endl;

  // vector<uint8_t> data_vec(padded_data, padded_data + 64);

  std::string input;
  std::cout << "请输入:";
  std::cin >> input;
  std::vector<uint8_t> message(input.begin(), input.end());

  // 预处理消息
  std::vector<uint8_t> data_vec = preprocess(message);

  // std::vector<uint32_t> hash_vec = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
  //                                   0xa54ff53a, 0x510e527f, 0x9b05688c,
  //                                   0x1f83d9ab, 0x5be0cd19};

  /*
  Initial hash value, reference:
  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
  Section 5.3
  */
  std::vector<uint8_t> byte_hash_vec = {
      0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3,
      0x72, 0xa5, 0x4f, 0xf5, 0x3a, 0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05,
      0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19};

  // 遍历 hash_vec 并将每个 uint32_t 分解为 4 个字节存储到 byte_hash_vec 中
  // for (uint32_t value : hash_vec) {
  //   byte_hash_vec.push_back(value >> 24 & 0xFF);
  //   byte_hash_vec.push_back((value >> 16) & 0xFF);
  //   byte_hash_vec.push_back((value >> 8) & 0xFF);
  //   byte_hash_vec.push_back((value) & 0xFF);
  // }
  for (auto &elem : data_vec) {
    elem = reverse_bits(elem);
  }
  for (auto &elem : byte_hash_vec) {
    elem = reverse_bits(elem);
  }
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

  reverse(data_vec.begin(), data_vec.end());

  reverse(byte_hash_vec.begin(), byte_hash_vec.end());
#endif
  // std::cout << "hash";
  // for (int i = 0; i < 32; i++) {
  //   bitset<8> b(byte_hash_vec[i]);
  //   std::cout << b;
  // }
  // std::cout << endl;

  std::vector<uint8_t> input_vec;

  for (auto &elem : data_vec) {
    input_vec.push_back(elem);
  }
  for (auto &elem : byte_hash_vec) {
    input_vec.push_back(elem);
  }

  // std::vector<uint128_t> output_vec(input_vec.size() / 16);

  // for (size_t i = 0; i < output_vec.size(); ++i) {
  //   uint128_t value = 0;
  //   for (size_t j = 0; j < 16; ++j) {
  //     value |= static_cast<uint128_t>(input_vec[i * 16 + j]) << (j * 8);
  //   }
  //   output_vec[i] = value;
  // }

  // for (auto &elem : output_vec) {
  //   bitset<128> b(elem);
  //   std::cout << b;
  // }
  // std::cout << endl;

  std::vector<uint8_t> result(32);
  std::string pth_str = fmt::format("{}/yacl/io/circuit/data/sha256.txt",
                                    std::filesystem::current_path().string());
  yacl::PlainExecutor<uint8_t> exec;
  // std::cout << "指针内容：" << *(uint8_t *)input_vec.data() << endl;

  exec.LoadCircuitFile(pth_str);
  exec.wires_.resize(exec.circ_->nw);
  for (size_t i = 0; i < input_vec.size(); ++i) {
    for (int j = 0; j < 8; ++j) {
      exec.wires_[i * 8 + j] = (input_vec[i] >> (7 - j)) & 1;  // 逐位赋值
    }
  }

  // exec.SetupInputs(absl::MakeSpan(input_vec));  // 拼成一个vector

  exec.Exec();

  exec.Finalize(absl::MakeSpan(result));

  reverse(result.begin(), result.end());
  for (int i = 0; i < 32; i++) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(result[i]);
    // std::cout << result[i];
    // bitset<8> bits(result[i]);
    // std::cout << bits;
  }
  std::cout << std::endl;
  // std::cout << std::hex << static_cast<int>(result[1]) << "\t" << result[0]
  // << endl;

  return 0;
}
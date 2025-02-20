#include <boost/dynamic_bitset.hpp>
#include <iostream>
#include <vector>

void copyVectorToDynamicBitset(const std::vector<uint8_t>& vec,
                               boost::dynamic_bitset<uint8_t>& bitset) {
  // 清空原有的 bitset 内容
  bitset.clear();

  // 设置 bitset 的大小为 vec.size() * 8（每个 uint8_t 有 8 位）
  bitset.resize(vec.size() * 8);

  // 遍历 vec 中的每个字节
  for (size_t i = 0; i < vec.size(); ++i) {
    uint8_t byte = vec[i];
    for (int j = 0; j < 8; ++j) {
      // 从最低位开始设置位
      bitset[i * 8 + j] = (byte >> j) & 1;
    }
  }
}

int main() {
  std::vector<uint8_t> vec = {0x01, 0x02, 0x03};  // 示例数据
  boost::dynamic_bitset<uint8_t> bitset;

  copyVectorToDynamicBitset(vec, bitset);

  // 打印 bitset 的内容
  std::cout << "Bitset contents: ";
  for (size_t i = 0; i < bitset.size(); ++i) {
    std::cout << bitset[i];
  }
  std::cout << std::endl;

  return 0;
}
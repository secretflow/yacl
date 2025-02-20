#include <iostream>
#include <string>
#include <unordered_map>

std::string hexToBinary(const std::string& hex) {
  std::unordered_map<char, std::string> hexToBinaryMap = {
      {'0', "0000"}, {'1', "0001"}, {'2', "0010"}, {'3', "0011"},
      {'4', "0100"}, {'5', "0101"}, {'6', "0110"}, {'7', "0111"},
      {'8', "1000"}, {'9', "1001"}, {'A', "1010"}, {'B', "1011"},
      {'C', "1100"}, {'D', "1101"}, {'E', "1110"}, {'F', "1111"}};

  std::string binary = "";
  for (char c : hex) {
    c = toupper(c);  // 转换为大写字母以匹配映射
    if (hexToBinaryMap.find(c) != hexToBinaryMap.end()) {
      binary += hexToBinaryMap[c];
    } else {
      std::cerr << "Invalid hex character: " << c << std::endl;
      return "";  // 返回空字符串表示错误
    }
  }
  return binary;
}

int main() {
  std::string hexInput;
  std::cout << "Enter a hexadecimal string: ";
  std::cin >> hexInput;

  std::string binaryOutput = hexToBinary(hexInput);
  if (!binaryOutput.empty()) {
    std::cout << "Binary representation: " << binaryOutput << std::endl;
  }

  return 0;
}

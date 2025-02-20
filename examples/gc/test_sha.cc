#include <bits/stdc++.h>

#include "absl/strings/escaping.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/crypto/block_cipher/symmetric_crypto.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/io/circuit/bristol_fashion.h"
#include "yacl/utils/circuit_executor.h"
using namespace std;
using namespace yacl;

using uint256_t = std::array<uint128_t, 2>;
using uint512_t = std::array<uint128_t, 4>;

template <typename T>
void PlainExecutor<T>::Finalize(absl::Span<T> outputs) {
  // YACL_ENFORCE(outputs.size() >= circ_->nov);

  size_t index = wires_.size();
  for (size_t i = 0; i < circ_->nov; ++i) {
    int half_num_wire = circ_->now[i] / 2;

    dynamic_bitset<T> result(circ_->now[i]);

    for (size_t j = 0; j < circ_->now[i]; ++j) {
      result[j % 128] =
          wires_[index - circ_->now[i] +
                 j];  // 得到的是逆序的二进制值   对应的混淆电路计算为
                      // LSB ^ d  输出线路在后xx位
      if (j % 128 == 127) {
        outputs[circ_->nov - i - 1] =
            *(uint128_t*)result.data();  // 先得到最后位置上的
        index -= circ_->now[i];
        cout << std::hex << outputs[circ_->nov - i - 1] << "\t";
      }
    }
  }
  cout << endl;
}

int main() {
  //   std::vector<uint8_t> data = {0x61, 0x62, 0x63};  // 表示 "abc"
  std::vector<uint128_t> inputs = {
      crypto::FastRandU128(), crypto::FastRandU128(), crypto::FastRandU128(),
      crypto::FastRandU128(), 9110772664878759871,    6885964247225200029};
  for (int i = 0; i < 4; i++) {
    cout << inputs[i];
  }
  cout << endl;

  uint512_t input = {crypto::FastRandU128(), crypto::FastRandU128(),
                     crypto::FastRandU128(), crypto::FastRandU128()};
  vector<uint128_t> result(2);

  // 将 vector 转换为 absl::Span
  // ByteContainerView data_view(data);
  std::vector<uint8_t> data = {
      0x6a, 0x09, 0xe6, 0x67,  // H0
      0xbb, 0x67, 0xae, 0x85,  // H1
      0x3c, 0x6e, 0xf3, 0x72,  // H2
      0xa5, 0x4f, 0xf5, 0x3a,  // H3
      0x51, 0x0e, 0x52, 0x7f,  // H4
      0x9b, 0x05, 0x68, 0x8c,  // H5
      0x1f, 0x83, 0xd9, 0xab,  // H6
      0x5b, 0xe0, 0xcd, 0x19   // H7
  };
  // auto byte_view_init = ByteContainerView(&data, 32);
  ByteContainerView byte_view_init(data);
  string s = "wH6jKt2bGlUkQX8Mv0YD93jf4A1aCbz2P5EqVnSLRWNmJZOTpoBR3xdhFV7W6gXk";
  vector<uint8_t> byteArray(s.begin(), s.end());
  for (int i = 0; i < 32; i++) {
    byteArray.push_back(data[i]);
  }
  // for(auto a: byteArray){
  //   cout << a << endl;
  // }
  // auto byte_view_s = ByteContainerView(&s, 64);
  // ByteContainerView byte_view_s(s);
  // vector<ByteContainerView> inputs{byte_view_s, byte_view_init};
  // cout << "type" << byte_view_s[0] << endl;

  string str = fmt::format("{}/yacl/io/circuit/data/sha256.txt",
                           std::filesystem::current_path().string());
  PlainExecutor<uint128_t> exec;

  exec.LoadCircuitFile(str);
  exec.SetupInputs(absl::MakeSpan(inputs));
  exec.Exec();
  exec.Finalize(absl::MakeSpan(result));

  // cout << result[0] << "\t" << result[1] << endl;

  // cout << result[0] << "\t" << result[1];

  //   std::array<uint8_t, 32> hash = yacl::crypto::Sha256(data_view);
  //   for (auto byte : hash) {
  //     std::cout << std::hex << std::setw(2) << std::setfill('0') <<
  //     (int)byte;
  //   }
  //   std::cout << std::endl;
  //   uint32_t H0 = 0x6a09e667;
  //   uint32_t H1 = 0xbb67ae85;
  //   uint32_t H2 = 0x3c6ef372;
  //   uint32_t H3 = 0xa54ff53a;
  //   uint32_t H4 = 0x510e527f;
  //   uint32_t H5 = 0x9b05688c;
  //   uint32_t H6 = 0x1f83d9ab;
  //   uint32_t H7 = 0x5be0cd19;

  //   // 拼接前 4 个 32 位整数
  //   uint64_t high = ((uint64_t)H0 << 96) | ((uint64_t)H1 << 64) |
  //                   ((uint64_t)H2 << 32) | (uint64_t)H3;

  //   // 拼接后 4 个 32 位整数
  //   uint64_t low = ((uint64_t)H4 << 96) | ((uint64_t)H5 << 64) |
  //                  ((uint64_t)H6 << 32) | (uint64_t)H7;
  //   // 输出结果
  //   std::cout << "High 128 bits" << high << std::endl;
  //   std::cout << "Low 128 bits" << low << std::endl;
  return 0;
}
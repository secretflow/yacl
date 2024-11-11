// Copyright 2024 Ant Group Co., Ltd.
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

#include "yacl/utils/circuit_executor.h"

using namespace std;

namespace yacl {

namespace {
class PlaintextCore {
 public:
  static bool xor_gate(bool x, bool y) { return x ^ y; }
  static bool and_gate(bool x, bool y) { return x && y; }
  static bool inv_gate(bool x) { return !x; }
};
}  // namespace

template <typename T>
void PlainExecutor<T>::LoadCircuitFile(const std::string& path) {
  io::CircuitReader reader(path);
  reader.ReadAll();
  circ_ = reader.StealCirc();
}

std::string dynamic_bitset_to_string(const boost::dynamic_bitset<>& bits) {
  std::string str(bits.size(), '0');  // 创建一个与位集大小相同的字符串
  for (size_t i = 0; i < bits.size(); ++i) {
    if (bits[i]) {
      str[bits.size() - 1 - i] = '1';  // 反向填充字符串
    }
  }
  return str;
}

template <typename T>
void PlainExecutor<T>::SetupInputs(
    absl::Span<T> inputs) {  // Span方便指针的使用
                             // YACL_ENFORCE(inputs.size() == circ_->niv);
                             // for (auto input : inputs) {
  //   wires_.append(input);  // 直接转换为二进制  输入线路在前128位
  // }

  // memccpy(wires_.data(), inputs.data(), 1, sizeof(inputs));
  inputs.size();
  wires_.resize(circ_->nw);
}

template <typename T>
void PlainExecutor<T>::Exec() {
  // wires_.resize(circ_->nw);
  // for (int i = 2; i < 514; i++) {
  //   wires_[i - 2] = wires_[i];
  // }
  // cout << "线路输入：";
  // cout << wires_.size() << endl;
  // for (int i = 0; i < 768; i++) {
  //   cout << wires_[i];
  // }
  // // cout << dynamic_bitset_to_string(wires_) << endl;
  // cout << endl;
  // Evaluate all gates, sequentially
  for (const auto& gate : circ_->gates) {
    switch (gate.op) {
      case io::BFCircuit::Op::XOR: {
        const auto& iw0 = wires_.operator[](gate.iw[0]);  // 取到具体值
        const auto& iw1 = wires_.operator[](gate.iw[1]);
        wires_.set(gate.ow[0], PlaintextCore::xor_gate(iw0, iw1));
        break;
      }
      case io::BFCircuit::Op::AND: {
        const auto& iw0 = wires_.operator[](gate.iw[0]);
        const auto& iw1 = wires_.operator[](gate.iw[1]);
        wires_.set(gate.ow[0], PlaintextCore::and_gate(iw0, iw1));
        break;
      }
      case io::BFCircuit::Op::INV: {
        const auto& iw0 = wires_.operator[](gate.iw[0]);
        wires_.set(gate.ow[0], PlaintextCore::inv_gate(iw0));
        break;
      }
      case io::BFCircuit::Op::EQ: {
        wires_.set(gate.ow[0], gate.iw[0]);
        break;
      }
      case io::BFCircuit::Op::EQW: {
        const auto& iw0 = wires_.operator[](gate.iw[0]);
        wires_.set(gate.ow[0], iw0);
        break;
      }
      case io::BFCircuit::Op::MAND: { /* multiple ANDs */
        YACL_THROW("Unimplemented MAND gate");
        break;
      }
      default:
        YACL_THROW("Unknown Gate Type: {}", (int)gate.op);
    }
  }
}

// template <typename T>
// void PlainExecutor<T>::Finalize(absl::Span<T> outputs) {
//   YACL_ENFORCE(outputs.size() >= circ_->nov);

//   size_t index = wires_.size();
//   for (size_t i = 0; i < circ_->nov; ++i) {
//     dynamic_bitset<T> result(circ_->now[i]);
//     for (size_t j = 0; j < circ_->now[i]; ++j) {
//       result[j] = wires_[index - circ_->now[i] +
//                          j];  // 得到的是逆序的二进制值 对应的混淆电路计算为
//                               // LSB ^ d  输出线路在后xx位
//     }
//     outputs[circ_->nov - i - 1] = *(uint8_t*)result.data();
//     // outputs[circ_->nov - i - 1] = *(uint128_t*)result.data();
//     index -= circ_->now[i];
//   }
// }

template <typename T>
void PlainExecutor<T>::Finalize(absl::Span<T> outputs) {
  // YACL_ENFORCE(outputs.size() >= circ_->nov);

  size_t index = wires_.size();
  // reverse(wires_ + wires_.size() - 256, wires_ + wires_.size());
  // int arr[256];
  // for (int i = 0; i < 256; i++) {
  //   arr[i] = wires_[index - 256 + i];
  // }
  // for (int i = 0; i < 256; i++) {
  //   wires_[index - 256 + i] = arr[255 - i];
  // }

  // for (int i = 0; i < 256; i++) {
  //   cout << wires_[index - 256 + i];
  // }
  // reverse(wires_ + index - 256, wires_ + index - 250);
  // int start = index - 256;
  // int end = index;
  // while (start < end) {
  //   // 交换 start 和 end 的位
  //   bool temp = wires_[start];
  //   wires_[start] = wires_[end - 1];
  //   wires_[end - 1] = temp;

  //   // 移动指针
  //   ++start;
  //   --end;
  // }

  cout << endl;
  for (size_t i = 0; i < 32; ++i) {
    dynamic_bitset<T> result(8);
    for (size_t j = 0; j < 8; ++j) {
      result[j] =
          wires_[index - 8 + j];  // 得到的是逆序的二进制值 对应的混淆电路计算为
                                  // LSB ^ d  输出线路在后xx位
    }
    outputs[32 - i - 1] = *(uint8_t*)result.data();
    // outputs[circ_->nov - i - 1] = *(uint128_t*)result.data();
    index -= 8;
  }
}

template class PlainExecutor<uint8_t>;
template class PlainExecutor<uint128_t>;
// template class PlainExecutor<Buffer>;

}  // namespace yacl

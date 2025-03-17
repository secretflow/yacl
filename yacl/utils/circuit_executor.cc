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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <numeric>

#include "yacl/base/exception.h"
#include "yacl/io/circuit/bristol_fashion.h"

namespace yacl {

namespace {
class PlaintextCore {
 public:
  static bool xor_gate(bool x, bool y) { return x ^ y; }
  static bool and_gate(bool x, bool y) { return x && y; }
  static bool inv_gate(bool x) { return !x; }
};
}  // namespace

void PlainExecutor::LoadCircuitFile(const std::string& path) {
  io::CircuitReader reader(path);
  reader.ReadAll();
  circ_ = reader.StealCirc();
}

void PlainExecutor::SetupInputs(ByteContainerView bytes) {
  YACL_ENFORCE(std::accumulate(circ_->niw.cbegin(), circ_->niw.cend(),
                               static_cast<io::BFCircuit::GateWireType>(0)) ==
                   bytes.size() * 8,
               "mismatch input size and input wire size.");
  wires_.resize(circ_->nw);

  std::memcpy(wires_.data(), bytes.data(), bytes.size());
}

template <typename T>
void PlainExecutor::SetupInputs(absl::Span<T> inputs) {
  YACL_ENFORCE(inputs.size() == circ_->niv);

  dynamic_bitset<BlockType> input_wires;
  input_wires.resize(sizeof(T) * 8 * inputs.size());
  std::memcpy(input_wires.data(), inputs.data(), inputs.size() * sizeof(T));
  wires_.append(input_wires);
  wires_.resize(circ_->nw);
}

void PlainExecutor::Exec() {
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
        wires_.set(gate.ow[0], (gate.iw[0] != 0U));
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

std::vector<uint8_t> PlainExecutor::Finalize() {
  // Count the total number of output wires (a.k.a. output bits)
  size_t total_out_bitnum = 0;
  for (size_t i = 0; i < circ_->nov; ++i) {
    total_out_bitnum += circ_->now[i];
  }

  const auto out_size = (total_out_bitnum + 7) / 8;
  std::vector<uint8_t> out(out_size);

  size_t index = wires_.size();
  for (size_t i = 0; i < out_size; ++i) {
    dynamic_bitset<BlockType> result(8);
    for (size_t j = 0; j < 8; ++j) {
      result[j] = wires_[index - 8 + j];
    }
    out[out_size - i - 1] = *(static_cast<uint8_t*>(result.data()));
    index -= 8;
  }
  std::reverse(out.begin(), out.end());
  return out;
}

template <typename T>
void PlainExecutor::Finalize(absl::Span<T> outputs) {
  YACL_ENFORCE(outputs.size() >= circ_->nov);
  YACL_ENFORCE(std::all_of(circ_->now.begin(), circ_->now.end(),
                           [](const auto n) { return n <= sizeof(T) * 8; }));

  size_t index = wires_.size();
  for (size_t i = 0; i < circ_->nov; ++i) {
    dynamic_bitset<T> result(circ_->now[i]);
    for (size_t j = 0; j < circ_->now[i]; ++j) {
      result[j] = wires_[index - circ_->now[i] + j];
    }
    outputs[circ_->nov - i - 1] = *result.data();
    index -= circ_->now[i];
  }
}

template void PlainExecutor::SetupInputs<>(absl::Span<uint64_t> inputs);

template void PlainExecutor::SetupInputs<>(absl::Span<uint128_t> inputs);

template void PlainExecutor::Finalize<>(absl::Span<uint64_t> outputs);

template void PlainExecutor::Finalize<>(absl::Span<uint128_t> outputs);

}  // namespace yacl
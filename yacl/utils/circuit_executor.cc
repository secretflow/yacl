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

template <typename T>
void PlainExecutor<T>::SetupInputs(absl::Span<T> inputs) {
  YACL_ENFORCE(inputs.size() == circ_->niv);
  for (auto input : inputs) {
    wires_.append(input);
  }
  wires_.resize(circ_->nw);
}

template <typename T>
void PlainExecutor<T>::Exec() {
  // Evaluate all gates, sequentially
  for (const auto& gate : circ_->gates) {
    switch (gate.op) {
      case io::BFCircuit::Op::XOR: {
        const auto& iw0 = wires_.operator[](gate.iw[0]);
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

template <typename T>
void PlainExecutor<T>::Finalize(absl::Span<T> outputs) {
  YACL_ENFORCE(outputs.size() >= circ_->nov);

  size_t index = wires_.size();
  for (size_t i = 0; i < circ_->nov; ++i) {
    dynamic_bitset<T> result(circ_->now[i]);
    for (size_t j = 0; j < circ_->now[i]; ++j) {
      result[j] = wires_[index - circ_->now[i] + j];
    }
    outputs[circ_->nov - i - 1] = *(T*)result.data();
    index -= circ_->now[i];
  }
}

template class PlainExecutor<uint64_t>;
template class PlainExecutor<uint128_t>;

}  // namespace yacl

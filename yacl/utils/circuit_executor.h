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

#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "yacl/base/dynamic_bitset.h"
#include "yacl/io/circuit/bristol_fashion.h"

namespace yacl {

// plaintext protocol that executes everything without link

class PlainExecutor {
 public:
  using BlockType = uint8_t;

  // Constructor
  explicit PlainExecutor() = default;

  // Load circuit from file (local operation)
  void LoadCircuitFile(const std::string &path);

  ///
  /// Load inputs functions: Setup the input wire (local operation)
  ///
  // general setup function, just copies the memory to internal wires_
  void SetupInputs(ByteContainerView bytes);

  // fast path for circuit with "small" bits (e.g. <= 128)
  template <typename T = uint64_t>
  void SetupInputs(absl::Span<T> inputs);

  // Execute the circuit
  void Exec();

  ///
  /// Get results functions: Finalize and get the result
  ///
  //
  // general finalize, get result from wires_
  std::vector<uint8_t> Finalize();

  // fast path for circuit with "small" bits (e.g. <= 128)
  template <typename T = uint64_t>
  void Finalize(absl::Span<T> outputs);

 private:
  // NOTE: please make sure you use the correct order of wires
  dynamic_bitset<BlockType> wires_;      // shares
  std::shared_ptr<io::BFCircuit> circ_;  // bristol fashion circuit
};

}  // namespace yacl

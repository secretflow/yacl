// // Copyright 2024 Ant Group Co., Ltd.
// //
// // Licensed under the Apache License, Version 2.0 (the "License");
// // you may not use this file except in compliance with the License.
// // You may obtain a copy of the License at
// //
// //   http://www.apache.org/licenses/LICENSE-2.0
// //
// // Unless required by applicable law or agreed to in writing, software
// // distributed under the License is distributed on an "AS IS" BASIS,
// // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// // See the License for the specific language governing permissions and
// // limitations under the License.

// #pragma once

// #include <memory>

// #include "yacl/base/buffer.h"
// #include "yacl/base/dynamic_bitset.h"
// #include "yacl/io/circuit/bristol_fashion.h"

// namespace yacl {

// // plaintext protocol that executes everything without link
// template <typename T = uint64_t>
// class PlainExecutor {
//  public:
//   // Constructor
//   explicit PlainExecutor() = default;

//   // Load circuit from file (local operation)
//   void LoadCircuitFile(const std::string &path);

//   // Setup the input wire (local operation)
//   // template <typename T = uint64_t>
//   void SetupInputs(absl::Span<T> inputs);
//   // void SetupInputs(std::vector<uint8_t> inputs_bi);
//   // Execute the circuit
//   void Exec();

//   // Finalize and get the result
//   // template <typename T = uint64_t>
//   void Finalize(absl::Span<T> outputs);

//  public:
//   // NOTE: please make sure you use the correct order of wires
//   dynamic_bitset<uint8_t> wires_;  // shares   GC的时候这里要重新写vector
//                                    // <uint128_t> 是否可以，以及顺序问题
//   std::shared_ptr<io::BFCircuit> circ_;  // bristol fashion circuit
// };

// }  // namespace yacl

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

#include <memory>

#include "yacl/base/dynamic_bitset.h"
#include "yacl/io/circuit/bristol_fashion.h"

namespace yacl {

// plaintext protocol that executes everything without link

template <typename T = uint64_t>
class PlainExecutor {
 public:
  // Constructor
  explicit PlainExecutor() = default;

  // Load circuit from file (local operation)
  void LoadCircuitFile(const std::string &path);

  // Setup the input wire (local operation)
  void SetupInputs(absl::Span<T> inputs);

  // Execute the circuit
  void Exec();

  // Finalize and get the result
  void Finalize(absl::Span<T> outputs);

 private:
  // NOTE: please make sure you use the correct order of wires
  dynamic_bitset<T> wires_;              // shares
  std::shared_ptr<io::BFCircuit> circ_;  // bristol fashion circuit
};

}  // namespace yacl
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
#include <string>
#include <vector>

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/io/stream/file_io.h"
#include "yacl/io/stream/interface.h"

namespace yacl::io {

// Bristol Fashion Circuit
// see: https://nigelsmart.github.io/MPC-Circuits/
class BFCircuit {
 public:
  using GateNumType = uint32_t;
  // now, assume small circuit only
  using GateWireType = uint32_t;

  GateNumType ng = 0;   // number of gates
  GateWireType nw = 0;  // number of wires

  uint32_t niv;                  // number of input values
  std::vector<GateNumType> niw;  // number of wires per each input values
  uint32_t nov;                  // number of output values
  std::vector<GateNumType> now;  // number of wires per each output values

  // circuit operations
  enum class Op { XOR, AND, INV, EQ, EQW, MAND };

  // Gate definition
  class Gate {
   public:
    GateNumType niw = 0;           // number of input wires
    GateNumType now = 0;           // number of output wires
    std::vector<GateWireType> iw;  // lists of input wires
    std::vector<GateWireType> ow;  // lists of output wires
    Op op;
  };

  void PrintSummary();

  std::vector<Gate> gates;
};

// bristol fashion circuit file reader
class CircuitReader {
 public:
  explicit CircuitReader(const std::string &path) {
    Reset();
    Init(path);
  }

  ~CircuitReader() = default;

  void ReadMeta();
  void ReadAllGates();
  void ReadAll() { ReadAllGates(); }

  std::unique_ptr<BFCircuit> StealCirc() {
    YACL_ENFORCE(circ_ != nullptr);
    return std::move(circ_);
  }

  void Reset() {
    if (in_ != nullptr) {
      in_->Close();
    }
    if (circ_ != nullptr) {
      circ_.reset();
    }
  }

  void Init(const std::string &path) {
    in_ = std::unique_ptr<io::InputStream>(new io::FileInputStream(path));
    circ_ = std::make_unique<BFCircuit>();  // get a new circ instance
  }

 private:
  std::unique_ptr<BFCircuit> circ_;

  // io-related infos
  std::unique_ptr<io::InputStream> in_;
  size_t metadata_length_ = 0;
};

class BuiltinBFCircuit {
 public:
  static const std::string CircDataDir;

  static std::string Add64Path() {
    return fmt::format("{}/adder64.txt", CircDataDir);
  }

  static std::string Sub64Path() {
    return fmt::format("{}/sub64.txt", CircDataDir);
  }

  static std::string Neg64Path() {
    return fmt::format("{}/neg64.txt", CircDataDir);
  }

  static std::string Mul64Path() {
    return fmt::format("{}/mult64.txt", CircDataDir);
  }

  static std::string Div64Path() {
    return fmt::format("{}/divide64.txt", CircDataDir);
  }

  static std::string UDiv64Path() {
    return fmt::format("{}/udivide64.txt", CircDataDir);
  }

  static std::string EqzPath() {
    return fmt::format("{}/zero_equal.txt", CircDataDir);
  }

  // NOTE: For AES-128 the wire orders are in the reverse order as used in
  // the examples given in our earlier `Bristol Format', thus bit 0 becomes bit
  // 127 etc, for key, plaintext and message.
  //
  // see: https://nigelsmart.github.io/MPC-Circuits/
  static std::string Aes128Path() {
    return fmt::format("{}/aes_128.txt", CircDataDir);
  }

  // NOTE: sha256 needs two inputs, a 512 bit buffer, and a 256 bit previous
  // digest value
  //
  static std::string Sha256Path() {
    return fmt::format("{}/sha256.txt", CircDataDir);
  }

  // Prepare (append & tweak) the input sha256 message before fed to the sha256
  // bristol circuit.
  //
  // For more details, please check:
  // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
  //
  // NOTE since we are using dynamic_bitset for bristol format circuit
  // representation, the actual bit operation here is slightly different from
  // the standards.
  static std::vector<uint8_t> PrepareSha256Input(ByteContainerView input);
};

}  // namespace yacl::io

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

#include <array>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "spdlog/spdlog.h"

#include "yacl/base/exception.h"
#include "yacl/io/stream/file_io.h"
#include "yacl/io/stream/interface.h"

namespace yacl::io {

// Bristol Fashion Circuit
// see: https://nigelsmart.github.io/MPC-Circuits/
class BFCircuit {
 public:
  uint32_t ng = 0;            // number of gates
  uint32_t nw = 0;            // number of wires
  uint32_t niv;               // number of input values
  std::vector<uint32_t> niw;  // number of wires per each input values
  uint32_t nov;               // number of output values
  std::vector<uint32_t> now;  // number of wires per each output values

  // circuit oeprations
  enum class Op { XOR, AND, INV, EQ, EQW, MAND };

  // Gate definition
  class Gate {
   public:
    uint32_t niw = 0;          // numer of input wires
    uint32_t now = 0;          // number of output wires
    std::vector<uint32_t> iw;  // lists of input wires
    std::vector<uint32_t> ow;  // lists of output wires
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
      circ_.release();
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
  static std::string Add64Path() {
    return fmt::format("{}/yacl/io/circuit/data/adder64.txt",
                       std::filesystem::current_path().string());
  }

  static std::string Sub64Path() {
    return fmt::format("{}/yacl/io/circuit/data/sub64.txt",
                       std::filesystem::current_path().string());
  }

  static std::string Neg64Path() {
    return fmt::format("{}/yacl/io/circuit/data/neg64.txt",
                       std::filesystem::current_path().string());
  }

  static std::string Mul64Path() {
    return fmt::format("{}/yacl/io/circuit/data/mult64.txt",
                       std::filesystem::current_path().string());
  }

  static std::string Div64Path() {
    return fmt::format("{}/yacl/io/circuit/data/divide64.txt",
                       std::filesystem::current_path().string());
  }

  static std::string UDiv64Path() {
    return fmt::format("{}/yacl/io/circuit/data/udivide64.txt",
                       std::filesystem::current_path().string());
  }

  static std::string EqzPath() {
    return fmt::format("{}/yacl/io/circuit/data/zero_equal.txt",
                       std::filesystem::current_path().string());
  }

  // NOTE: For AES-128 the wire orders are in the reverse order as used in
  // the examples given in our earlier `Bristol Format', thus bit 0 becomes bit
  // 127 etc, for key, plaintext and message.
  //
  // see: https://nigelsmart.github.io/MPC-Circuits/
  static std::string Aes128Path() {
    return fmt::format("{}/yacl/io/circuit/data/aes_128.txt",
                       std::filesystem::current_path().string());
  }

  // NOTE: sha256 needs two inputs, a 512 bit buffer, and a 256 bit previous
  // digest value
  //
  // static std::string Sha256Path() {
  //   return fmt::format("{}/yacl/io/circuit/data/sha256.txt",
  //                      std::filesystem::current_path().string());
  // }
};

}  // namespace yacl::io

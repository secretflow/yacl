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

#include "yacl/io/circuit/bristol_fashion.h"

#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"

#include "yacl/base/exception.h"

namespace yacl::io {

void BFCircuit::PrintSummary() {
  SPDLOG_INFO("number of gates: {}", ng);
  SPDLOG_INFO("number of wires: {}", nw);
  SPDLOG_INFO("number of input values: {}", niv);
  for (size_t i = 0; i < niw.size(); ++i) {
    SPDLOG_INFO("  [{}] input value => {} wires ", i, niw[i]);
  }
  SPDLOG_INFO("number of output values: {}", nov);
  for (size_t i = 0; i < now.size(); ++i) {
    SPDLOG_INFO("  [{}] output value => {} wires ", i, now[i]);
  }
}

void CircuitReader::ReadMeta() {
  YACL_ENFORCE(circ_ != nullptr);
  YACL_ENFORCE(in_ != nullptr);
  // make sure that the input stream is at the begining of the file
  in_->Seekg(0);

  std::string ret;

  // first line
  in_->GetLine(&ret);
  {
    std::vector<std::string> splits = absl::StrSplit(ret, ' ');
    YACL_ENFORCE(splits.size() == 2, "{}", ret);
    YACL_ENFORCE(absl::SimpleAtoi(splits[0], &circ_->ng));
    YACL_ENFORCE(absl::SimpleAtoi(splits[1], &circ_->nw));
  }

  // second line
  in_->GetLine(&ret);
  {
    std::vector<std::string> splits = absl::StrSplit(ret, ' ');
    YACL_ENFORCE(absl::SimpleAtoi(splits[0], &circ_->niv));

    /* it's okay to have more columns, but we'll stick with the niv */
    YACL_ENFORCE(splits.size() >= circ_->niv + 1);
    circ_->niw.resize(circ_->niv);
    for (size_t i = 0; i < circ_->niv; ++i) {
      YACL_ENFORCE(absl::SimpleAtoi(splits[i + 1], &circ_->niw[i]));
    }
  }

  // third line
  in_->GetLine(&ret);
  {
    std::vector<std::string> splits = absl::StrSplit(ret, ' ');
    YACL_ENFORCE(absl::SimpleAtoi(splits[0], &circ_->nov));

    /* it's okay to have more columns, but we'll stick with the nov */
    YACL_ENFORCE(splits.size() >= circ_->nov + 1);
    circ_->now.resize(circ_->nov);
    for (size_t i = 0; i < circ_->nov; ++i) {
      YACL_ENFORCE(absl::SimpleAtoi(splits[i + 1], &circ_->now[i]));
    }
  }

  // circ_->PrintSummary();
  metadata_length_ = in_->Tellg();
}

void CircuitReader::ReadAllGates() {
  YACL_ENFORCE(circ_ != nullptr);
  YACL_ENFORCE(in_ != nullptr);
  if (metadata_length_ == 0) {
    ReadMeta();
  }
  in_->Seekg(metadata_length_);
  std::string ret;

  // first empty line
  in_->GetLine(&ret);  // skip the first empty line

  // the following lines
  circ_->gates.resize(circ_->ng);  // resize the gates
  for (size_t i = 0; i < circ_->ng; ++i) {
    in_->GetLine(&ret);
    std::vector<std::string> splits = absl::StrSplit(ret, ' ');
    YACL_ENFORCE(absl::SimpleAtoi(splits[0], &circ_->gates[i].niw));
    YACL_ENFORCE(absl::SimpleAtoi(splits[1], &circ_->gates[i].now));

    /* it's okay to have more columns, but we'll stick with the niw and now */
    YACL_ENFORCE(splits.size() >=
                 circ_->gates[i].niw + circ_->gates[i].now + 2);
    circ_->gates[i].iw.resize(circ_->gates[i].niw);
    circ_->gates[i].ow.resize(circ_->gates[i].now);

    for (size_t j = 0; j < circ_->gates[i].niw; ++j) {
      YACL_ENFORCE(absl::SimpleAtoi(splits[2 + j], &circ_->gates[i].iw[j]));
    }
    for (size_t j = 0; j < circ_->gates[i].now; ++j) {
      YACL_ENFORCE(absl::SimpleAtoi(splits[2 + circ_->gates[i].niw + j],
                                    &circ_->gates[i].ow[j]));
    }

    /* check gate inputs num and op */
    auto op_str = splits[circ_->gates[i].niw + circ_->gates[i].now + 2];
    YACL_ENFORCE(circ_->gates[i].now == 1);

    if (op_str == "XOR") {
      YACL_ENFORCE(circ_->gates[i].niw == 2);
      circ_->gates[i].op = BFCircuit::Op::XOR;
    } else if (op_str == "AND") {
      YACL_ENFORCE(circ_->gates[i].niw == 2);
      circ_->gates[i].op = BFCircuit::Op::AND;
    } else if (op_str == "INV") {
      YACL_ENFORCE(circ_->gates[i].niw == 1);
      circ_->gates[i].op = BFCircuit::Op::INV;
    } else if (op_str == "EQ") {
      YACL_ENFORCE(circ_->gates[i].niw == 1);
      circ_->gates[i].op = BFCircuit::Op::EQ;
    } else if (op_str == "EQW") {
      YACL_ENFORCE(circ_->gates[i].niw == 1);
      circ_->gates[i].op = BFCircuit::Op::EQW;
    } else if (op_str == "MAND") {
      YACL_ENFORCE(circ_->gates[i].niw == circ_->gates[i].now * 2);
      circ_->gates[i].op = BFCircuit::Op::MAND;
    } else {
      YACL_THROW("Unknown Gate Type: {}", op_str);
    }
  }
}

}  // namespace yacl::io

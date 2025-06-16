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

#include <vector>

#include "examples/gc/mitccrh.h"
#include "fmt/format.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/int128.h"
#include "yacl/io/circuit/bristol_fashion.h"
#include "yacl/link/context.h"
#include "yacl/link/factory.h"

using namespace std;
using namespace yacl;
using namespace yacl::crypto;

class EvaluatorSHA256 {
 public:
  uint128_t delta;
  uint128_t inv_constant;
  uint128_t start_point;
  MITCCRH<8> mitccrh;

  std::vector<uint128_t> wires_;
  std::vector<uint128_t> gb_value;
  yacl::io::BFCircuit circ_;
  std::shared_ptr<yacl::link::Context> lctx;

  // The number of and gate is 22573
  uint128_t table[22573][2];
  uint128_t input;
  int num_ot = 768;  // input bit
  int send_bytes = 0;

  uint128_t all_one_uint128_t = ~static_cast<__uint128_t>(0);
  uint128_t select_mask[2] = {0, all_one_uint128_t};
  void setup() {
    size_t world_size = 2;
    yacl::link::ContextDesc ctx_desc;

    for (size_t rank = 0; rank < world_size; rank++) {
      const auto id = fmt::format("id-{}", rank);
      const auto host = fmt::format("127.0.0.1:{}", 10086 + rank);
      ctx_desc.parties.push_back({id, host});
    }

    lctx = yacl::link::FactoryBrpc().CreateContext(ctx_desc, 1);
    lctx->ConnectToMesh();

    // delta, inv_constant, start_point
    uint128_t tmp[3];
    yacl::Buffer r = lctx->Recv(0, "tmp");
    const uint128_t* buffer_data = r.data<const uint128_t>();
    memcpy(tmp, buffer_data, sizeof(uint128_t) * 3);

    delta = tmp[0];
    inv_constant = tmp[1];
    start_point = tmp[2];

    mitccrh.setS(start_point);
  }

  void inputProcess(yacl::io::BFCircuit& param_circ_) {
    circ_ = param_circ_;
    gb_value.resize(circ_.nw);
    wires_.resize(circ_.nw);

    yacl::Buffer r = lctx->Recv(0, "garbleInput1");

    const uint128_t* buffer_data = r.data<const uint128_t>();

    memcpy(wires_.data(), buffer_data, sizeof(uint128_t) * num_ot);
  }
  void recvTable() {
    yacl::Buffer r = lctx->Recv(0, "table");
    const uint128_t* buffer_data = r.data<const uint128_t>();
    int k = 0;
    for (size_t i = 0; i < 22573; i++) {
      for (int j = 0; j < 2; j++) {
        table[i][j] = buffer_data[k];
        k++;
      }
    }
  }

  uint128_t EVAND(uint128_t A, uint128_t B, const uint128_t* table_item,
                  MITCCRH<8>* mitccrh_pointer) {
    uint128_t HA, HB, W;
    int sa, sb;

    sa = getLSB(A);
    sb = getLSB(B);

    uint128_t H[2];
    H[0] = A;
    H[1] = B;
    mitccrh_pointer->hash<2, 1>(H);
    HA = H[0];
    HB = H[1];

    W = HA ^ HB;
    W = W ^ (select_mask[sa] & table_item[0]);
    W = W ^ (select_mask[sb] & table_item[1]);
    W = W ^ (select_mask[sb] & A);
    return W;
  }

  void EV() {
    int table_cursor = 0;
    for (size_t i = 0; i < circ_.gates.size(); i++) {
      auto gate = circ_.gates[i];
      switch (gate.op) {
        case yacl::io::BFCircuit::Op::XOR: {
          const auto& iw0 = wires_.operator[](gate.iw[0]);
          const auto& iw1 = wires_.operator[](gate.iw[1]);
          wires_[gate.ow[0]] = iw0 ^ iw1;
          break;
        }
        case yacl::io::BFCircuit::Op::AND: {
          const auto& iw0 = wires_.operator[](gate.iw[0]);
          const auto& iw1 = wires_.operator[](gate.iw[1]);
          wires_[gate.ow[0]] = EVAND(iw0, iw1, table[table_cursor], &mitccrh);
          table_cursor++;
          break;
        }
        case yacl::io::BFCircuit::Op::INV: {
          const auto& iw0 = wires_.operator[](gate.iw[0]);
          wires_[gate.ow[0]] = iw0 ^ inv_constant;
          break;
        }
        case yacl::io::BFCircuit::Op::EQ: {
          wires_[gate.ow[0]] = gate.iw[0];
          break;
        }
        case yacl::io::BFCircuit::Op::EQW: {
          const auto& iw0 = wires_.operator[](gate.iw[0]);
          wires_[gate.ow[0]] = iw0;
          break;
        }
        case yacl::io::BFCircuit::Op::MAND: { /* multiple ANDs */
          YACL_THROW("Unimplemented MAND gate");
          break;
        }
        default:
          YACL_THROW("Unknown Gate Type: {}", (int)gate.op);
      }
    }
  }
  void sendOutput() {
    size_t index = wires_.size();
    int start = index - circ_.now[0];
    lctx->Send(
        0,
        yacl::ByteContainerView(wires_.data() + start, sizeof(uint128_t) * 256),
        "output");

    send_bytes = sizeof(uint128_t) * 256;
  }
};
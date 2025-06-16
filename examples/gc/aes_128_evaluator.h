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
#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/io/circuit/bristol_fashion.h"
#include "yacl/kernel/ot_kernel.h"
#include "yacl/link/context.h"
#include "yacl/link/factory.h"

using namespace std;
using namespace yacl;
using namespace yacl::crypto;

namespace {

using OtMsg = uint128_t;
using OtMsgPair = std::array<OtMsg, 2>;
using OtChoices = dynamic_bitset<uint128_t>;

}  // namespace

class EvaluatorAES {
 public:
  uint128_t delta;
  uint128_t inv_constant;
  uint128_t start_point;
  MITCCRH<8> mitccrh;

  std::vector<uint128_t> wires_;
  std::vector<uint128_t> gb_value;
  yacl::io::BFCircuit circ_;
  std::shared_ptr<yacl::link::Context> lctx;

  // The number of and gate is 6400
  uint128_t table[6400][2];
  uint128_t input;
  int num_ot = 128;  // input bit of evaluator
  int send_bytes = 0;
  uint128_t all_one_uint128_t = ~static_cast<uint128_t>(0);
  uint128_t select_mask[2] = {0, all_one_uint128_t};

  yacl::crypto::OtRecvStore ot_recv =
      OtRecvStore(num_ot, yacl::crypto::OtStoreType::Normal);

  void setup() {
    size_t world_size = 2;
    yacl::link::ContextDesc ctx_desc;

    for (size_t rank = 0; rank < world_size; rank++) {
      const auto id = fmt::format("id-{}", rank);
      const auto host = fmt::format("127.0.0.1:{}", 10010 + rank);
      ctx_desc.parties.push_back({id, host});
    }

    lctx = yacl::link::FactoryBrpc().CreateContext(ctx_desc, 1);
    lctx->ConnectToMesh();

    // OT off-line
    const auto ext_algorithm = yacl::crypto::OtKernel::ExtAlgorithm::SoftSpoken;
    yacl::crypto::OtKernel kernel1(yacl::crypto::OtKernel::Role::Receiver,
                                   ext_algorithm);
    kernel1.init(lctx);
    kernel1.eval_rot(lctx, num_ot, &ot_recv);

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

  uint128_t inputProcess(yacl::io::BFCircuit& param_circ_) {
    circ_ = param_circ_;
    gb_value.resize(circ_.nw);
    wires_.resize(circ_.nw);

    yacl::dynamic_bitset<uint128_t> bi_val;

    input = yacl::crypto::FastRandU128();

    bi_val.append(input);

    yacl::Buffer r = lctx->Recv(0, "garbleInput1");

    const uint128_t* buffer_data = r.data<const uint128_t>();

    memcpy(wires_.data(), buffer_data, sizeof(uint128_t) * num_ot);

    return input;
  }
  void recvTable() {
    yacl::Buffer r = lctx->Recv(0, "table");
    const uint128_t* buffer_data = r.data<const uint128_t>();
    int k = 0;
    for (size_t i = 0; i < 6400; i++) {
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
    int and_num = 0;
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
          wires_[gate.ow[0]] = EVAND(iw0, iw1, table[and_num], &mitccrh);
          and_num++;
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
    lctx->Send(0,
               yacl::ByteContainerView(wires_.data() + start,
                                       sizeof(uint128_t) * num_ot),
               "output");
    send_bytes += sizeof(uint128_t) * num_ot;
  }
  void onLineOT() {
    yacl::dynamic_bitset<uint128_t> choices;
    choices.append(input);

    yacl::dynamic_bitset<uint128_t> ot = ot_recv.CopyBitBuf();
    ot.resize(choices.size());

    yacl::dynamic_bitset<uint128_t> masked_choices = ot ^ choices;
    lctx->Send(
        0, yacl::ByteContainerView(masked_choices.data(), sizeof(uint128_t)),
        "masked_choice");
    send_bytes += sizeof(uint128_t);

    auto buf = lctx->Recv(lctx->NextRank(), "");
    std::vector<OtMsgPair> batch_recv(num_ot);
    std::memcpy(batch_recv.data(), buf.data(), buf.size());
    for (int j = 0; j < num_ot; ++j) {
      auto idx = num_ot + j;
      wires_[idx] = batch_recv[j][choices[j]] ^ ot_recv.GetBlock(j);
    }
  }
};
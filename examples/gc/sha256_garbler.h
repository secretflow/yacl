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

#include "absl/types/span.h"
#include "examples/gc/mitccrh.h"
#include "fmt/format.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/hash/ssl_hash.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/io/circuit/bristol_fashion.h"
#include "yacl/link/context.h"
#include "yacl/link/factory.h"

using namespace std;
using namespace yacl;

class GarblerSHA256 {
 public:
  std::shared_ptr<yacl::link::Context> lctx;
  uint128_t delta;
  uint128_t inv_constant;
  uint128_t start_point;
  MITCCRH<8> mitccrh;

  std::vector<uint128_t> wires_;
  std::vector<uint128_t> gb_value;
  yacl::io::BFCircuit circ_;

  // The number of and gate is 22573
  uint128_t table[22573][2];

  uint128_t input;
  uint128_t input_EV;
  vector<uint8_t> message;

  int num_ot = 768;  // input bit
  int send_bytes = 0;
  uint128_t all_one_uint128_t_ = ~static_cast<__uint128_t>(0);
  uint128_t select_mask_[2] = {0, all_one_uint128_t_};

  yacl::crypto::OtSendStore ot_send =
      yacl::crypto::OtSendStore(num_ot, yacl::crypto::OtStoreType::Normal);

  void setup() {
    size_t world_size = 2;
    yacl::link::ContextDesc ctx_desc;

    for (size_t rank = 0; rank < world_size; rank++) {
      const auto id = fmt::format("id-{}", rank);
      const auto host = fmt::format("127.0.0.1:{}", 10086 + rank);
      ctx_desc.parties.push_back({id, host});
    }

    lctx = yacl::link::FactoryBrpc().CreateContext(ctx_desc, 0);
    lctx->ConnectToMesh();

    // delta, inv_constant, start_point
    auto tmp = yacl::crypto::SecureRandVec<uint128_t>(3);
    tmp[0] = tmp[0] | 1;
    lctx->Send(1,
               yacl::ByteContainerView(static_cast<void*>(tmp.data()),
                                       sizeof(uint128_t) * 3),
               "tmp");
    send_bytes += sizeof(uint128_t) * 3;

    delta = tmp[0];
    inv_constant = tmp[1] ^ delta;
    start_point = tmp[2];

    mitccrh.setS(start_point);
  }

  vector<uint8_t> inputProcess(yacl::io::BFCircuit& param_circ_) {
    circ_ = param_circ_;
    gb_value.resize(circ_.nw);
    wires_.resize(circ_.nw);

    message = crypto::FastRandBytes(crypto::RandLtN(32));
    auto in_buf = io::BuiltinBFCircuit::PrepareSha256Input(message);
    auto sha256_result = crypto::Sha256Hash().Update(message).CumulativeHash();

    dynamic_bitset<uint8_t> bi_val;
    bi_val.resize(circ_.nw);
    std::memcpy(bi_val.data(), in_buf.data(), in_buf.size());

    int num_of_input_wires = 0;
    for (size_t i = 0; i < circ_.niv; ++i) {
      num_of_input_wires += circ_.niw[i];
    }

    auto rands = yacl::crypto::SecureRandVec<uint128_t>(num_of_input_wires);
    for (int i = 0; i < num_of_input_wires; i++) {
      gb_value[i] = rands[i];
    }

    for (int i = 0; i < 768; i++) {
      wires_[i] = gb_value[i] ^ (select_mask_[bi_val[i]] & delta);
    }

    lctx->Send(
        1, yacl::ByteContainerView(wires_.data(), sizeof(uint128_t) * num_ot),
        "garbleInput1");
    send_bytes += sizeof(uint128_t) * num_ot;

    return sha256_result;
  }

  uint128_t GBAND(uint128_t LA0, uint128_t A1, uint128_t LB0, uint128_t B1,
                  uint128_t* table_item, MITCCRH<8>* mitccrh_pointer) {
    bool pa = getLSB(LA0);
    bool pb = getLSB(LB0);

    uint128_t HLA0, HA1, HLB0, HB1;
    uint128_t tmp, W0;
    uint128_t H[4];

    H[0] = LA0;
    H[1] = A1;
    H[2] = LB0;
    H[3] = B1;

    mitccrh_pointer->hash<2, 2>(H);

    HLA0 = H[0];
    HA1 = H[1];
    HLB0 = H[2];
    HB1 = H[3];

    table_item[0] = HLA0 ^ HA1;
    table_item[0] = table_item[0] ^ (select_mask_[pb] & delta);

    W0 = HLA0;
    W0 = W0 ^ (select_mask_[pa] & table_item[0]);

    tmp = HLB0 ^ HB1;
    table_item[1] = tmp ^ LA0;

    W0 = W0 ^ HLB0;
    W0 = W0 ^ (select_mask_[pb] & tmp);
    return W0;
  }
  void GB() {
    int table_cursor = 0;
    for (size_t i = 0; i < circ_.gates.size(); i++) {
      auto gate = circ_.gates[i];
      switch (gate.op) {
        case yacl::io::BFCircuit::Op::XOR: {
          const auto& iw0 = gb_value.operator[](gate.iw[0]);
          const auto& iw1 = gb_value.operator[](gate.iw[1]);
          gb_value[gate.ow[0]] = iw0 ^ iw1;
          break;
        }
        case yacl::io::BFCircuit::Op::AND: {
          const auto& iw0 = gb_value.operator[](gate.iw[0]);
          const auto& iw1 = gb_value.operator[](gate.iw[1]);
          gb_value[gate.ow[0]] = GBAND(iw0, iw0 ^ delta, iw1, iw1 ^ delta,
                                       table[table_cursor], &mitccrh);
          table_cursor++;
          break;
        }
        case yacl::io::BFCircuit::Op::INV: {
          const auto& iw0 = gb_value.operator[](gate.iw[0]);
          gb_value[gate.ow[0]] = iw0 ^ inv_constant;
          break;
        }
        case yacl::io::BFCircuit::Op::EQ: {
          gb_value[gate.ow[0]] = gate.iw[0];
          break;
        }
        case yacl::io::BFCircuit::Op::EQW: {
          const auto& iw0 = gb_value.operator[](gate.iw[0]);
          gb_value[gate.ow[0]] = iw0;
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

  void sendTable() {
    lctx->Send(1, yacl::ByteContainerView(table, sizeof(uint128_t) * 2 * 22573),
               "table");
    send_bytes += sizeof(uint128_t) * 2 * 22573;
  }

  vector<uint8_t> decode() {
    size_t index = wires_.size();
    int start = index - circ_.now[0];

    yacl::Buffer r = lctx->Recv(1, "output");

    memcpy(wires_.data() + start, r.data(), sizeof(uint128_t) * 256);

    const auto out_size = 32;
    std::vector<uint8_t> out(out_size);

    for (size_t i = 0; i < out_size; ++i) {
      dynamic_bitset<uint8_t> result(8);
      for (size_t j = 0; j < 8; ++j) {
        result[j] =
            getLSB(wires_[index - 8 + j]) ^ getLSB(gb_value[index - 8 + j]);
      }
      out[out_size - i - 1] = *(static_cast<uint8_t*>(result.data()));
      index -= 8;
    }
    std::reverse(out.begin(), out.end());

    return out;
  }

  template <typename T>
  void finalize(absl::Span<T>& outputs) {
    size_t index = wires_.size();

    for (size_t i = 0; i < circ_.nov; ++i) {
      yacl::dynamic_bitset<T> result(circ_.now[i]);
      for (size_t j = 0; j < circ_.now[i]; ++j) {
        int wire_index = index - circ_.now[i] + j;
        result[j] = getLSB(wires_[wire_index]) ^ getLSB(gb_value[wire_index]);
      }

      outputs[circ_.nov - i - 1] = *(T*)result.data();
      index -= circ_.now[i];
    }
  }
};
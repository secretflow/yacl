#pragma once
#include <algorithm>
#include <future>
#include <type_traits>
#include <vector>

#include "absl/types/span.h"
#include "examples/gc/mitccrh.h"
#include "fmt/format.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/io/circuit/bristol_fashion.h"
#include "yacl/io/stream/file_io.h"
#include "yacl/kernel/algorithms/base_ot.h"
#include "yacl/kernel/algorithms/iknp_ote.h"
#include "yacl/kernel/type/ot_store_utils.h"
#include "yacl/link/context.h"
#include "yacl/link/factory.h"
#include "yacl/link/test_util.h"
#include "yacl/crypto/block_cipher/symmetric_crypto.h"
#include "yacl/utils/circuit_executor.h"
#include "yacl/kernel/ot_kernel.h"
#include "yacl/kernel/type/ot_store_utils.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/crypto/hash/ssl_hash.h"
using namespace std;
using namespace yacl;
namespace {
using uint128_t = __uint128_t;
using OtMsg = uint128_t;
using OtMsgPair = std::array<OtMsg, 2>;
using OtChoices = dynamic_bitset<uint128_t>;

}





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
  //根据电路改
  uint128_t table[135073][2];

  //输入数据类型需要修改
  uint128_t input;
  uint128_t input_EV;
  vector<uint8_t> message;
    //num_ot根据输入改
  int num_ot = 768;
uint128_t all_one_uint128_t_ = ~static_cast<__uint128_t>(0);
uint128_t select_mask_[2] = {0, all_one_uint128_t_};

  yacl::crypto::OtSendStore ot_send =  yacl::crypto::OtSendStore(num_ot, yacl::crypto::OtStoreType::Normal);



  void setup() {
    // 通信环境初始化
    size_t world_size = 2;
    yacl::link::ContextDesc ctx_desc;

    for (size_t rank = 0; rank < world_size; rank++) {
      const auto id = fmt::format("id-{}", rank);
      const auto host = fmt::format("127.0.0.1:{}", 10086 + rank);
      ctx_desc.parties.push_back({id, host});
    }
    
    lctx = yacl::link::FactoryBrpc().CreateContext(ctx_desc,
                                                   0);  
    lctx->ConnectToMesh();

    //OT off-line
    const auto ext_algorithm = yacl::crypto::OtKernel::ExtAlgorithm::SoftSpoken;
    yacl::crypto::OtKernel kernel0(yacl::crypto::OtKernel::Role::Sender, ext_algorithm);
    kernel0.init(lctx);
    kernel0.eval_rot(lctx, num_ot, &ot_send);

    // delta, inv_constant, start_point 初始化并发送给evaluator
    uint128_t tmp[3];

    random_uint128_t(tmp, 3);
    tmp[0] = tmp[0] | 1;
    lctx->Send(1, yacl::ByteContainerView(tmp, sizeof(uint128_t) * 3), "tmp");
    std::cout << "tmpSend" << std::endl;

    delta = tmp[0];
    inv_constant = tmp[1] ^ delta;
    start_point = tmp[2];

    // 秘钥生成
    mitccrh.setS(start_point);
  }

  // 包扩 输入值生成和混淆，garbler混淆值的发送
  vector<uint8_t> inputProcess(yacl::io::BFCircuit param_circ_) {
    circ_ = param_circ_;
    gb_value.resize(circ_.nw);
    wires_.resize(circ_.nw);

    //输入位数有关
    message = crypto::FastRandBytes(crypto::RandLtN(32));
    auto in_buf = io::BuiltinBFCircuit::PrepareSha256Input(message); 
    auto sha256_result = crypto::Sha256Hash().Update(message).CumulativeHash();
    for(int i = 0; i < 32; i++){
      cout <<int(sha256_result[i]) << " ";
    }
    cout << endl;
    
    dynamic_bitset<uint8_t> bi_val;
    bi_val.resize(circ_.nw);
    std::memcpy(bi_val.data(), in_buf.data(), in_buf.size());

    // 混淆过程
    int num_of_input_wires = 0;
    for (size_t i = 0; i < circ_.niv; ++i) {
      num_of_input_wires += circ_.niw[i];
    }
    
    random_uint128_t(gb_value.data(), num_of_input_wires);

    for(int i = 0; i < 768; i++){
      
        wires_[i] = gb_value[i] ^ (select_mask_[bi_val[i]] & delta);
      
    }

    lctx->Send(1,
               yacl::ByteContainerView(wires_.data(), sizeof(uint128_t) * num_ot),
               "garbleInput1");

    std::cout << "sendInput1" << std::endl;

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

    for (size_t i = 0; i < circ_.gates.size(); i++) {
      auto gate = circ_.gates[i];
      switch (gate.op) {
        case yacl::io::BFCircuit::Op::XOR: {
          const auto& iw0 = gb_value.operator[](gate.iw[0]);  // 取到具体值
          const auto& iw1 = gb_value.operator[](gate.iw[1]);
          gb_value[gate.ow[0]] = iw0 ^ iw1;
          break;
        }
        case yacl::io::BFCircuit::Op::AND: {
          const auto& iw0 = gb_value.operator[](gate.iw[0]);
          const auto& iw1 = gb_value.operator[](gate.iw[1]);
          gb_value[gate.ow[0]] = GBAND(iw0, iw0 ^ delta, iw1, iw1 ^ delta,
                                        table[i], &mitccrh);
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
    lctx->Send(1,
               yacl::ByteContainerView(table, sizeof(uint128_t) * 2 * circ_.ng),
               "table");
    std::cout << "sendTable" << std::endl;
  }
  vector<uint8_t>  decode() {
    // 现接收计算结果
    size_t index = wires_.size();
    int start = index - circ_.now[0];

    yacl::Buffer r = lctx->Recv(1, "output");
    // vector<uint8_t> out(96);

    memcpy(wires_.data() + start, r.data(), sizeof(uint128_t) * 256);
    std::cout << "recvOutput" << std::endl;
    
    const auto out_size = 32;
    std::vector<uint8_t> out(out_size);

    for (size_t i = 0; i < out_size; ++i) {
      dynamic_bitset<uint8_t> result(8);
      for (size_t j = 0; j < 8; ++j) {
        result[j] = getLSB(wires_[index - 8 + j]) ^ getLSB(gb_value[index - 8 + j]);
      }
      out[out_size - i - 1] = *(static_cast<uint8_t*>(result.data()));
      index -= 8;
    }
    std::reverse(out.begin(), out.end());

    auto sha256_result = crypto::Sha256Hash().Update(message).CumulativeHash();
    
    if(sha256_result.size() == out.size() && std::equal(out.begin(), out.end(), sha256_result.begin())) cout<<"YES!!!"<<endl;
    
    return out;
    
    // for(int i = 0; i < 32; i++){
    //   cout <<int(out[i]) << " ";
    // }
    // cout << endl;
    
  }


  /********
   * 
   * 
   * 可能有bug
   * 
   * **********/
  template <typename T>
  void finalize(absl::Span<T> outputs) { 
  // YACL_ENFORCE(outputs.size() >= circ_->nov);

    size_t index = wires_.size();

    for (size_t i = 0; i < circ_.nov; ++i) {
      yacl::dynamic_bitset<T> result(circ_.now[i]);
      for (size_t j = 0; j < circ_.now[i]; ++j) {
        int wire_index = index - circ_.now[i] + j;
        result[j] = getLSB(wires_[wire_index]) ^
                    getLSB(gb_value[wire_index]);  // 得到的是逆序的二进制值
                                                  // 对应的混淆电路计算为LSB ^ d
                                                  // 输出线路在后xx位
      }
    
      outputs[circ_.nov - i - 1] = *(T*)result.data();
      index -= circ_.now[i];
    }
  }
  void onlineOT(){

    auto buf = lctx->Recv(1, "masked_choice");

    dynamic_bitset<uint128_t> masked_choices(num_ot);
    std::memcpy(masked_choices.data(), buf.data(), buf.size());

    std::vector<OtMsgPair> batch_send(num_ot);

    for (int j = 0; j < num_ot; ++j) {
      auto idx = num_ot + j;
      if (!masked_choices[j]) {
        batch_send[j][0] = ot_send.GetBlock(j, 0) ^ gb_value[idx];
        batch_send[j][1] = ot_send.GetBlock(j, 1) ^ gb_value[idx] ^ delta;
      } else {
        batch_send[j][0] = ot_send.GetBlock(j, 1) ^ gb_value[idx];
        batch_send[j][1] = ot_send.GetBlock(j, 0) ^ gb_value[idx] ^ delta;
      }
    }

    lctx->SendAsync(
        lctx->NextRank(),
        ByteContainerView(batch_send.data(), sizeof(uint128_t) * num_ot * 2),
        "");
  }

};
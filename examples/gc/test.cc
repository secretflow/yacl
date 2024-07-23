#include <algorithm>

#include "absl/strings/escaping.h"
#include "absl/types/span.h"
#include "examples/gc/mitccrh.h"
#include "fmt/format.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/io/circuit/bristol_fashion.h"
#include "yacl/io/stream/file_io.h"
#include "yacl/kernel/algorithms/base_ot.h"
#include "yacl/kernel/algorithms/iknp_ote.h"
#include "yacl/link/test_util.h"
#include "yacl/utils/circuit_executor.h"
using namespace yacl;
using namespace std;
namespace {
using uint128_t = __uint128_t;
}

const uint128_t all_one_uint128_t = ~static_cast<__uint128_t>(0);
const uint128_t select_mask[2] = {0, all_one_uint128_t};

std::shared_ptr<io::BFCircuit> circ_;
vector<uint128_t> wires_;
vector<uint128_t> gb_value;

// enum class Op {
//   adder64,   √
//   aes_128,   √
//   divide64,  √
//   mult2_64,
//   mult64,    √
//   neg64,     √
//   sha256,
//   sub64,     √
//   udivide64, √
//   zero_equal √
// }

inline uint128_t Aes128(uint128_t k, uint128_t m) {
  crypto::SymmetricCrypto enc(crypto::SymmetricCrypto::CryptoType::AES128_ECB,
                              k);
  return enc.Encrypt(m);
}

uint128_t ReverseBytes(uint128_t x) {
  auto byte_view = ByteContainerView(&x, sizeof(x));
  uint128_t ret = 0;
  auto buf = std::vector<uint8_t>(sizeof(ret));
  for (size_t i = 0; i < byte_view.size(); ++i) {
    buf[byte_view.size() - i - 1] = byte_view[i];
  }
  std::memcpy(&ret, buf.data(), buf.size());
  return ret;
}

uint128_t GBAND(uint128_t LA0, uint128_t A1, uint128_t LB0, uint128_t B1,
                uint128_t delta, uint128_t* table, MITCCRH<8>* mitccrh) {
  bool pa = getLSB(LA0);
  bool pb = getLSB(LB0);

  uint128_t HLA0, HA1, HLB0, HB1;
  uint128_t tmp, W0;
  uint128_t H[4];

  H[0] = LA0;
  H[1] = A1;
  H[2] = LB0;
  H[3] = B1;

  mitccrh->hash<2, 2>(H);

  HLA0 = H[0];
  HA1 = H[1];
  HLB0 = H[2];
  HB1 = H[3];

  table[0] = HLA0 ^ HA1;
  table[0] = table[0] ^ (select_mask[pb] & delta);

  W0 = HLA0;
  W0 = W0 ^ (select_mask[pa] & table[0]);

  tmp = HLB0 ^ HB1;
  table[1] = tmp ^ LA0;

  W0 = W0 ^ HLB0;
  W0 = W0 ^ (select_mask[pb] & tmp);
  return W0;
}

uint128_t EVAND(uint128_t A, uint128_t B, const uint128_t* table,
                MITCCRH<8>* mitccrh) {
  uint128_t HA, HB, W;
  int sa, sb;

  sa = getLSB(A);
  sb = getLSB(B);

  uint128_t H[2];
  H[0] = A;
  H[1] = B;
  mitccrh->hash<2, 1>(H);
  HA = H[0];
  HB = H[1];

  W = HA ^ HB;
  W = W ^ (select_mask[sa] & table[0]);
  W = W ^ (select_mask[sb] & table[1]);
  W = W ^ (select_mask[sb] & A);
  return W;
}

template <typename T>
void finalize(absl::Span<T> outputs) {
  // YACL_ENFORCE(outputs.size() >= circ_->nov);

  size_t index = wires_.size();

  for (size_t i = 0; i < circ_->nov; ++i) {
    dynamic_bitset<T> result(circ_->now[i]);
    for (size_t j = 0; j < circ_->now[i]; ++j) {
      int wire_index = index - circ_->now[i] + j;
      result[j] = getLSB(wires_[wire_index]) ^
                  getLSB(gb_value[wire_index]);  // 得到的是逆序的二进制值
                                                 // 对应的混淆电路计算为LSB ^ d
                                                 // 输出线路在后xx位
    }
    outputs[circ_->nov - i - 1] = *(uint128_t*)result.data();
    index -= circ_->now[i];
  }
}

int main() {
  // 参与方的设置，需要参照halfgate_gen/eva和sh_gen/eva   以下是一些用到的变量
  // constant[2]     0为全局delta   1为not门用到的public label
  // 秘钥相关   mitch  秘钥初始化start_point, shared_prg
  const int kWorldSize = 2;
  int num_ot = 64;  // 用于OT

  uint128_t tmp[2];
  random_uint128_t(tmp, 2);
  tmp[0] = tmp[0] | 1;  // 已确保LSB为1
  uint128_t delta = tmp[0];

  uint128_t constant[3];
  random_uint128_t(constant, 2);
  constant[2] = constant[1] ^ delta;  // gen方使用    constant[1]为eva方使用

  MITCCRH<8> mitccrh;  // 密钥生成和加密  8为Batch_size, schedule_key长度
  mitccrh.setS(tmp[1]);  // 秘钥生成start_point

  // 电路读取
  string operate;
  cin >> operate;

  string pth = fmt::format("{0}/yacl/io/circuit/data/{1}.txt",
                           std::filesystem::current_path().string(), operate);
  yacl::io::CircuitReader reader(pth);
  reader.ReadMeta();
  reader.ReadAllGates();
  circ_ = reader.StealCirc();

  // aes_128随机初始化输入值
  std::vector<uint128_t> inputs = {crypto::FastRandU128(),
                                   crypto::FastRandU128()};
  std::vector<uint128_t> result(1);
  // 其余情况
  // std::vector<uint64_t> inputs = {crypto::FastRandU64(),
  // crypto::FastRandU64()}; std::vector<uint64_t> result(1);

  // int2bool  还是得老老实实进行GB完整过程，主要目的是存储d[]
  // 用dynamic_bitset转化为二进制后，再进行混淆得到混淆值，后面的直接按电路顺序计算
  // 生成的table 存储 vector< vector(2)> > (num_gate) 存储时把gate_ID记录下来

  // aes_128
  dynamic_bitset<uint128_t> bi_val;
  // 其余情况
  // dynamic_bitset<uint64_t> bi_val;

  for (auto input : inputs) {
    bi_val.append(input);  // 直接转换为二进制  输入线路在前128位
  }

  // ***************GB阶段***************

  // 初始化
  gb_value.resize(circ_->nw);
  vector<vector<uint128_t>> table(circ_->ng, vector<uint128_t>(2));

  // 混淆过程
  int num_of_input_wires = 0;
  for (size_t i = 0; i < circ_->niv; ++i) {
    num_of_input_wires += circ_->niw[i];
  }

  random_uint128_t(gb_value.data(), num_of_input_wires);

  for (int i = 0; i < circ_->gates.size(); i++) {
    auto gate = circ_->gates[i];
    switch (gate.op) {
      case io::BFCircuit::Op::XOR: {
        const auto& iw0 = gb_value.operator[](gate.iw[0]);  // 取到具体值
        const auto& iw1 = gb_value.operator[](gate.iw[1]);
        gb_value[gate.ow[0]] = iw0 ^ iw1;
        break;
      }
      case io::BFCircuit::Op::AND: {
        const auto& iw0 = gb_value.operator[](gate.iw[0]);
        const auto& iw1 = gb_value.operator[](gate.iw[1]);
        gb_value[gate.ow[0]] = GBAND(iw0, iw0 ^ delta, iw1, iw1 ^ delta, delta,
                                     table[i].data(), &mitccrh);
        break;
      }
      case io::BFCircuit::Op::INV: {
        const auto& iw0 = gb_value.operator[](gate.iw[0]);
        gb_value[gate.ow[0]] = iw0 ^ constant[2];
        break;
      }
      case io::BFCircuit::Op::EQ: {
        gb_value[gate.ow[0]] = gate.iw[0];
        break;
      }
      case io::BFCircuit::Op::EQW: {
        const auto& iw0 = gb_value.operator[](gate.iw[0]);
        gb_value[gate.ow[0]] = iw0;
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

  /********   EN阶段    *********/

  wires_.resize(circ_->nw);
  // 前64位 直接置换  garbler
  for (int i = 0; i < circ_->niw[0]; i++) {
    wires_[i] = gb_value[i] ^ (select_mask[bi_val[i]] & delta);
  }

  /* ************暂时没看懂*********** */
  // 后64位 用OT evaluator 用iknp
  //   vector<array<uint128_t, 2>> send_blocks;
  //   vector<uint128_t> recv_blocks(num_ot);
  //   dynamic_bitset<uint128_t> choices(num_ot);
  //   for (int i = 64; i < 128; i++) {
  //     send_blocks.push_back({gb_value[i], gb_value[i] ^ delta});
  //     choices.push_back(bi_val[i]);
  //   }

  //   auto send = MakeOtSendStore(send_blocks);
  //   auto recv = MakeOtRecvStore(choices, recv_blocks);

  //   auto lctxs = yacl::link::test::SetupWorld(kWorldSize);
  //   std::vector<std::array<uint128_t, 2>> send_out(num_ot);
  //   std::vector<uint128_t> recv_out(num_ot);
  //   std::future<void> sender = std::async([&] {
  //     IknpOtExtSend(lctxs[0], recv, absl::MakeSpan(send_out), false);
  //   });  // 发送到base_ot.recv
  //   std::future<void> receiver = std::async([&] {
  //     IknpOtExtRecv(lctxs[1], send, choices, absl::MakeSpan(recv_out),
  //                   false);  // 从base_ot.send取
  //   });
  //   receiver.get();
  //   sender.get();

  /* ***********尝试使用base_OT*********** */

  // auto contexts = link::test::SetupWorld(kWorldSize);
  // vector<array<uint128_t, 2>> send_blocks;
  // vector<uint128_t> recv_blocks(num_ot);
  // dynamic_bitset<uint128_t> choices(num_ot);
  // for (int i = 64; i < 128; i++) {
  //   send_blocks.push_back({gb_value[i], gb_value[i] ^ delta});
  //   choices.push_back(bi_val[i]);
  // }

  // std::future<void> sender =
  //     std::async([&] { BaseOtSend(contexts[0],
  // absl::MakeSpan(send_blocks));
  //     });
  // std::future<void> receiver = std::async(
  //     [&] { BaseOtRecv(contexts[1], choices, absl::MakeSpan(recv_blocks));
  //     });
  // sender.get();
  // receiver.get();

  if (operate != "neg64" && operate != "zero_equal") {
    for (int i = circ_->niw[0]; i < circ_->niw[0] + circ_->niw[1]; i++) {
      wires_[i] = gb_value[i] ^ (select_mask[bi_val[i]] & delta);
    }
  }

  // 计算方进行计算 按拓扑顺序进行计算
  for (int i = 0; i < circ_->gates.size(); i++) {
    auto gate = circ_->gates[i];
    switch (gate.op) {
      case io::BFCircuit::Op::XOR: {
        const auto& iw0 = wires_.operator[](gate.iw[0]);  // 取到具体值
        const auto& iw1 = wires_.operator[](gate.iw[1]);
        wires_[gate.ow[0]] = iw0 ^ iw1;
        break;
      }
      case io::BFCircuit::Op::AND: {
        const auto& iw0 = wires_.operator[](gate.iw[0]);
        const auto& iw1 = wires_.operator[](gate.iw[1]);
        wires_[gate.ow[0]] = EVAND(iw0, iw1, table[i].data(), &mitccrh);
        break;
      }
      case io::BFCircuit::Op::INV: {
        const auto& iw0 = wires_.operator[](gate.iw[0]);
        wires_[gate.ow[0]] = iw0 ^ constant[1];
        break;
      }
      case io::BFCircuit::Op::EQ: {
        wires_[gate.ow[0]] = gate.iw[0];
        break;
      }
      case io::BFCircuit::Op::EQW: {
        const auto& iw0 = wires_.operator[](gate.iw[0]);
        wires_[gate.ow[0]] = iw0;
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

  // 识别输出线路 进行DE操作
  finalize(absl::MakeSpan(result));

  // 检查计算结果是否正确
  cout << inputs[0] << " " << inputs[1] << endl;
  if (operate == "adder64") {
    cout << inputs[0] + inputs[1] << endl;
  } else if (operate == "divide64") {
    cout << static_cast<int64_t>(inputs[0]) / static_cast<int64_t>(inputs[1])
         << endl;
  } else if (operate == "udivide64") {
    cout << inputs[0] / inputs[1] << endl;
  } else if (operate == "mult64") {
    cout << inputs[0] * inputs[1] << endl;
  } else if (operate == "neg64") {
    cout << -inputs[0] << endl;
  } else if (operate == "sub64") {
    cout << inputs[0] - inputs[1] << endl;
  } else if (operate == "aes_128") {
    cout << Aes128(ReverseBytes(inputs[0]), ReverseBytes(inputs[1])) << endl;
    result[0] = ReverseBytes(result[0]);
  } else {
    cout << "else" << endl;
  }

  cout << result[0] << endl;

  /* WHEN */
  //   PlainExecutor<uint64_t> exec;
  //   exec.LoadCircuitFile(io::BuiltinBFCircuit::Add64Path());
  //   exec.SetupInputs(absl::MakeSpan(inputs));  // En
  //   exec.Exec();
  //   exec.Finalize(absl::MakeSpan(result));

  /* THEN  验证计算结果 */

  return 0;
}

#include <algorithm>
#include <future>
#include <type_traits>
#include <vector>

// #include "absl/std::strings/escaping.h"
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
// #include "yacl/kernel/ot_kernel.h"
#include "yacl/kernel/type/ot_store_utils.h"
#include "yacl/link/context.h"
#include "yacl/link/factory.h"
#include "yacl/link/test_util.h"
#include "yacl/utils/circuit_executor.h"

namespace {
using uint128_t = __uint128_t;
}

const uint128_t all_one_uint128_t = ~static_cast<__uint128_t>(0);
const uint128_t select_mask[2] = {0, all_one_uint128_t};

std::shared_ptr<yacl::io::BFCircuit> circ_;
std::vector<uint128_t> wires_;
std::vector<uint128_t> gb_value;

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
  yacl::crypto::SymmetricCrypto enc(
      yacl::crypto::SymmetricCrypto::CryptoType::AES128_ECB, k);
  return enc.Encrypt(m);
}

uint128_t ReverseBytes(uint128_t x) {
  auto byte_view = yacl::ByteContainerView(&x, sizeof(x));
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
    yacl::dynamic_bitset<T> result(circ_->now[i]);
    for (size_t j = 0; j < circ_->now[i]; ++j) {
      int wire_index = index - circ_->now[i] + j;
      result[j] = getLSB(wires_[wire_index]) ^
                  getLSB(gb_value[wire_index]);  // 得到的是逆序的二进制值
                                                 // 对应的混淆电路计算为LSB ^ d
                                                 // 输出线路在后xx位
    }
    // std::cout << "输出：" << result.data() << std::endl;
    outputs[circ_->nov - i - 1] = *(uint128_t*)result.data();
    index -= circ_->now[i];
  }
}

int main(int argc, char* argv[]) {
  int FLAGS_rank = std::stoi(argv[1]);

  size_t world_size = 2;
  yacl::link::ContextDesc ctx_desc;

  for (size_t rank = 0; rank < world_size; rank++) {
    const auto id = fmt::format("id-{}", rank);
    const auto host = fmt::format("127.0.0.1:{}", 10086 + rank);
    ctx_desc.parties.push_back({id, host});
  }

  auto lctx = yacl::link::FactoryBrpc().CreateContext(ctx_desc, FLAGS_rank);
  lctx->ConnectToMesh();
  // auto lctxs = link::test::SetupWorld(2);

  // const size_t num_ot = 5000;
  // const auto ext_algorithm = yacl::crypto::OtKernel::ExtAlgorithm::Ferret;
  // OtSendStore ot_send(num_ot, OtStoreType::Compact);  // placeholder
  // OtRecvStore ot_recv(num_ot, OtStoreType::Compact);  // placeholder
  // OtKernel kernel0(OtKernel::Role::Sender, ext_algorithm);
  // OtKernel kernel1(OtKernel::Role::Receiver, ext_algorithm);

  // // WHEN
  // auto sender = std::async([&] {
  //   kernel0.init(lctxs[0]);
  //   kernel0.eval_cot_random_choice(lctxs[0], num_ot, &ot_send);
  // });
  // auto receiver = std::async([&] {
  //   kernel1.init(lctxs[1]);
  //   kernel1.eval_cot_random_choice(lctxs[1], num_ot, &ot_recv);
  // });

  // sender.get();
  // receiver.get();
  // std::cout << "OT delta :" << ot_send.GetDelta() << std::endl;

  // 参与方的设置，需要参照halfgate_gen/eva和sh_gen/eva   以下是一些用到的变量
  // constant[2]     0为全局delta   1为not门用到的public label
  // 秘钥相关   mitch  秘钥初始化start_point, shared_prg

  // const int kWorldSize = 2;

  uint128_t tmp[2];
  if (FLAGS_rank == 0) {
    random_uint128_t(tmp, 2);
    lctx->Send(1, yacl::ByteContainerView(tmp, sizeof(uint128_t) * 2), "tmp");
    std::cout << "tmpSend" << std::endl;
  } else {
    yacl::Buffer r = lctx->Recv(0, "tmp");
    const uint128_t* buffer_data = r.data<const uint128_t>();
    memcpy(tmp, buffer_data, sizeof(uint128_t) * 2);
    std::cout << "tmpRecv" << std::endl;
  }

  tmp[0] = tmp[0] | 1;       // 已确保LSB为1
  uint128_t delta = tmp[0];  // 统一全局Delta

  uint128_t constant[3];
  if (FLAGS_rank == 0) {
    random_uint128_t(constant, 2);
    lctx->Send(1, yacl::ByteContainerView(constant, sizeof(uint128_t) * 3),
               "constant");
    std::cout << "constantSend" << std::endl;
  } else {
    yacl::Buffer r = lctx->Recv(0, "constant");
    const uint128_t* buffer_data = r.data<const uint128_t>();
    memcpy(constant, buffer_data, sizeof(uint128_t) * 3);
    std::cout << "constantRecv" << std::endl;
  }

  constant[2] = constant[1] ^ delta;  // gen方使用    constant[1]为eva方使用

  MITCCRH<8> mitccrh;  // 密钥生成和加密  8为Batch_size, schedule_key长度
  mitccrh.setS(tmp[1]);  // 秘钥生成start_point

  // 电路读取
  std::string operate;
  std::cin >> operate;

  std::string pth =
      fmt::format("{0}/yacl/io/circuit/data/{1}.txt",
                  std::filesystem::current_path().string(), operate);
  yacl::io::CircuitReader reader(pth);
  reader.ReadMeta();
  reader.ReadAllGates();
  circ_ = reader.StealCirc();  // 指针

  // aes_128随机初始化输入值
  // std::vector<uint128_t> inputs = {crypto::FastRandU128(),
  //                                  crypto::FastRandU128()};
  // std::vector<uint128_t> result(1);
  // 其余情况
  uint64_t input = yacl::crypto::FastRandU64();
  std::cout << "input:" << input << std::endl;
  uint64_t input1;

  std::vector<uint64_t> result(1);

  // int2bool  还是得老老实实进行GB完整过程，主要目的是存储d[]
  // 用dynamic_bitset转化为二进制后，再进行混淆得到混淆值，后面的直接按电路顺序计算
  // 生成的table 存储 vector< vector(2)> > (num_gate) 存储时把gate_ID记录下来

  // aes_128
  // dynamic_bitset<uint128_t> bi_val;
  // 其余情况
  yacl::dynamic_bitset<uint64_t> bi_val;

  bi_val.append(input);  // 直接转换为二进制  输入线路在前64位

  // ***************GB阶段***************

  // 初始化
  gb_value.resize(circ_->nw);
  uint128_t table[circ_->ng][2];

  // 混淆过程
  int num_of_input_wires = 0;
  for (size_t i = 0; i < circ_->niv; ++i) {
    num_of_input_wires += circ_->niw[i];
    // break;
  }

  // random_uint128_t(gb_value.data(), circ_->niw[0]);
  random_uint128_t(gb_value.data(), num_of_input_wires);

  /********   EN阶段    *********/

  wires_.resize(circ_->nw);
  // 前64位 直接置换  garbler
  for (int i = 0; i < circ_->niw[0]; i++) {
    wires_[i] = gb_value[i] ^ (select_mask[bi_val[i]] & delta);
  }

  if (FLAGS_rank == 0) {
    lctx->Send(1,
               yacl::ByteContainerView(wires_.data(), sizeof(uint128_t) * 64),
               "garbleInput1");
    std::cout << "sendInput1" << std::endl;

  } else {
    yacl::Buffer r = lctx->Recv(0, "garbleInput1");

    const uint128_t* buffer_data = r.data<const uint128_t>();
    memcpy(wires_.data(), buffer_data, sizeof(uint128_t) * 64);
    std::cout << "recvInput1" << std::endl;
  }
  if (FLAGS_rank == 0) {
    lctx->Send(1, yacl::ByteContainerView(&input, sizeof(uint64_t)), "Input1");
    std::cout << "Input1OriginSend" << std::endl;

  } else {
    yacl::Buffer r = lctx->Recv(0, "Input1");

    const uint64_t* buffer_data = r.data<const uint64_t>();
    input1 = *buffer_data;
    std::cout << "Input1OriginRecv:" << input1 << std::endl;
  }
  // ************混淆方进行发送*********

  /* ************暂时没看懂*********** */
  // 后64位 用OT evaluator 用iknpsendTable
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

  // const int kWorldSize = 2;
  // auto contexts = link::test::SetupWorld(kWorldSize);

  // int num_ot = 64;

  // // WHEN

  // auto sender = std::async([&] { return BaseOtSend(contexts[0], num_ot); });
  // auto receiver =
  //     std::async([&] { return BaseOtRecv(contexts[1], choices, num_ot); });
  // auto send_blocks = sender.get();
  // auto recv_blocks = receiver.get();

  if (operate != "neg64" && operate != "zero_equal") {
    // const int kWorldSize = 2;
    // int num_ot = 128;

    // auto lctxs = link::test::SetupWorld(kWorldSize);  // setup network
    // auto base_ot = MockCots(128, delta);              // mock base ot
    // dynamic_bitset<uint128_t> choices;
    // choices.append(inputs[1]);  // 后64位全为0

    // // WHEN
    // std::vector<std::array<uint128_t, 2>> send_out(num_ot);
    // std::vector<uint128_t> recv_out(num_ot);
    // std::future<void> sender = std::async([&] {
    //   IknpOtExtSend(lctxs[0], base_ot.recv, absl::MakeSpan(send_out), false);
    // });  // 发送到base_ot.recv
    // std::future<void> receiver = std::async([&] {
    //   IknpOtExtRecv(lctxs[1], base_ot.send, choices,
    //   absl::MakeSpan(recv_out),
    //                 false);  // 从base_ot.send取
    // });
    // receiver.get();
    // sender.get();

    // for (int i = circ_->niw[0]; i < circ_->niw[0] + circ_->niw[1]; i++) {
    //   // gb_value[i] = send_out[i - 64][0];
    //   // wires_[i] = recv_out[i - 64];
    //   // if (send_out[i - 64][0] ^ delta == send_out[i - 64][1])
    //   //   std::cout << true << std::endl;

    //   wires_[i] = gb_value[i] ^ (select_mask[bi_val[i]] & delta);
    // }
    // 发送混淆值让 计算方 自己选
    if (FLAGS_rank == 0) {
      lctx->Send(
          1,
          yacl::ByteContainerView(gb_value.data() + 64, sizeof(uint128_t) * 64),
          "garbleInput2");
      std::cout << "sendInput2" << std::endl;

    } else {
      yacl::Buffer r = lctx->Recv(0, "garbleInput2");
      const uint128_t* buffer_data = r.data<const uint128_t>();
      for (int i = 0; i < circ_->niw[1]; i++) {
        // gb_value[i] = send_out[i - 64][0];
        // wires_[i] = recv_out[i - 64];
        // if (send_out[i - 64][0] ^ delta == send_out[i - 64][1])
        //   std::cout << true << std::endl;

        wires_[i + circ_->niw[0]] =
            buffer_data[i] ^ (select_mask[bi_val[i]] & delta);
      }
      std::cout << "recvInput2" << std::endl;
    }
  }
  std::cout << "输入线路值：";
  for (int i = 0; i < 64; i++) {
    std::cout << bi_val[i];
  }
  std::cout << std::endl;

  for (int i = 0; i < circ_->gates.size(); i++) {
    auto gate = circ_->gates[i];
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
        gb_value[gate.ow[0]] = GBAND(iw0, iw0 ^ delta, iw1, iw1 ^ delta, delta,
                                     table[i], &mitccrh);
        break;
      }
      case yacl::io::BFCircuit::Op::INV: {
        const auto& iw0 = gb_value.operator[](gate.iw[0]);
        gb_value[gate.ow[0]] = iw0 ^ constant[2];
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

  // 发送混淆表
  if (FLAGS_rank == 0) {
    lctx->Send(
        1, yacl::ByteContainerView(table, sizeof(uint128_t) * 2 * circ_->ng),
        "table");
    std::cout << "sendTable" << std::endl;
    // std::cout << "table0" << table[132][0];

  } else {
    yacl::Buffer r = lctx->Recv(0, "table");
    const uint128_t* buffer_data = r.data<const uint128_t>();
    int k = 0;
    for (int i = 0; i < circ_->ng; i++) {
      for (int j = 0; j < 2; j++) {
        table[i][j] = buffer_data[k];
        k++;
      }
    }

    std::cout << "recvTable" << std::endl;
    // std::cout << "table0" << table[132][0];
  }

  // 计算方进行计算 按拓扑顺序进行计算
  for (int i = 0; i < circ_->gates.size(); i++) {
    auto gate = circ_->gates[i];
    switch (gate.op) {
      case yacl::io::BFCircuit::Op::XOR: {
        const auto& iw0 = wires_.operator[](gate.iw[0]);  // 取到具体值
        const auto& iw1 = wires_.operator[](gate.iw[1]);
        wires_[gate.ow[0]] = iw0 ^ iw1;
        break;
      }
      case yacl::io::BFCircuit::Op::AND: {
        const auto& iw0 = wires_.operator[](gate.iw[0]);
        const auto& iw1 = wires_.operator[](gate.iw[1]);
        wires_[gate.ow[0]] = EVAND(iw0, iw1, table[i], &mitccrh);
        break;
      }
      case yacl::io::BFCircuit::Op::INV: {
        const auto& iw0 = wires_.operator[](gate.iw[0]);
        wires_[gate.ow[0]] = iw0 ^ constant[1];
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

  // 识别输出线路 进行DE操作
  // *********Finalize应该由谁来做，怎么做
  size_t index = wires_.size();
  int start = index - circ_->now[0];
  if (FLAGS_rank == 1) {
    lctx->Send(
        0,
        yacl::ByteContainerView(wires_.data() + start, sizeof(uint128_t) * 64),
        "output");
    std::cout << "sendOutput" << std::endl;
    // std::cout << "output:" << wires_[index - 1] << std::endl;

  } else {
    yacl::Buffer r = lctx->Recv(1, "output");
    const uint128_t* buffer_data = r.data<const uint128_t>();

    memcpy(wires_.data() + start, buffer_data, sizeof(uint128_t) * 64);
    // for (int i = 0; i < circ_->niw[1]; i++) {
    //   // gb_value[i] = send_out[i - 64][0];
    //   // wires_[i] = recv_out[i - 64];
    //   // if (send_out[i - 64][0] ^ delta == send_out[i - 64][1])
    //   //   std::cout << true << std::endl;

    //   wires_[i + circ_->niw[0]] =
    //       buffer_data[i] ^ (select_mask[bi_val[i]] & delta);
    // }
    std::cout << "recvOutput" << std::endl;
    // std::cout << "output:" << wires_[index - 1] << std::endl;
  }

  // 检查计算结果是否正确
  // std::cout << inputs[0] << " " << inputs[1] << std::endl;
  if (FLAGS_rank == 1) {
    std::cout << "明文计算结果：";
    if (operate == "adder64") {
      std::cout << input1 + input << std::endl;
    } else if (operate == "divide64") {
      std::cout << static_cast<int64_t>(input1) / static_cast<int64_t>(input)
                << std::endl;
    } else if (operate == "udivide64") {
      std::cout << input1 / input << std::endl;
    } else if (operate == "mult64") {
      std::cout << input1 * input << std::endl;
    } else if (operate == "neg64") {
      std::cout << -input1 << std::endl;
    } else if (operate == "sub64") {
      std::cout << input1 - input << std::endl;
    } else if (operate == "aes_128") {
      std::cout << Aes128(ReverseBytes(input1), ReverseBytes(input))
                << std::endl;
      result[0] = ReverseBytes(result[0]);
    } else {
      std::cout << "else" << std::endl;
    }
  } else {
    finalize(absl::MakeSpan(result));
    std::cout << "MPC结果：" << result[0] << std::endl;
  }

  /* WHEN */
  //   PlainExecutor<uint64_t> exec;
  //   exec.LoadCircuitFile(io::BuiltinBFCircuit::Add64Path());
  //   exec.SetupInputs(absl::MakeSpan(inputs));  // En
  //   exec.Exec();
  //   exec.Finalize(absl::MakeSpan(result));

  /* THEN  验证计算结果 */

  return 0;
}
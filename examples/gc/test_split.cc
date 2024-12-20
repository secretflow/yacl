#pragma once
#include <algorithm>
#include <future>
#include <type_traits>
#include <vector>

// #include "absl/std::strings/escaping.h"
#include "absl/types/span.h"
#include "examples/gc/evaluator.h"
#include "examples/gc/garbler.h"
#include "fmt/format.h"

using namespace std;
using namespace yacl;
namespace {
using uint128_t = __uint128_t;
}

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

// uint128_t GBAND(uint128_t LA0, uint128_t A1, uint128_t LB0, uint128_t B1,
//                 uint128_t delta, uint128_t* table, MITCCRH<8>* mitccrh) {
//   bool pa = getLSB(LA0);
//   bool pb = getLSB(LB0);

//   uint128_t HLA0, HA1, HLB0, HB1;
//   uint128_t tmp, W0;
//   uint128_t H[4];

//   H[0] = LA0;
//   H[1] = A1;
//   H[2] = LB0;
//   H[3] = B1;

//   mitccrh->hash<2, 2>(H);

//   HLA0 = H[0];
//   HA1 = H[1];
//   HLB0 = H[2];
//   HB1 = H[3];

//   table[0] = HLA0 ^ HA1;
//   table[0] = table[0] ^ (select_mask[pb] & delta);

//   W0 = HLA0;
//   W0 = W0 ^ (select_mask[pa] & table[0]);

//   tmp = HLB0 ^ HB1;
//   table[1] = tmp ^ LA0;

//   W0 = W0 ^ HLB0;
//   W0 = W0 ^ (select_mask[pb] & tmp);
//   return W0;
// }

// uint128_t EVAND(uint128_t A, uint128_t B, const uint128_t* table,
//                 MITCCRH<8>* mitccrh) {
//   uint128_t HA, HB, W;
//   int sa, sb;

//   sa = getLSB(A);
//   sb = getLSB(B);

//   uint128_t H[2];
//   H[0] = A;
//   H[1] = B;
//   mitccrh->hash<2, 1>(H);
//   HA = H[0];
//   HB = H[1];

//   W = HA ^ HB;
//   W = W ^ (select_mask[sa] & table[0]);
//   W = W ^ (select_mask[sb] & table[1]);
//   W = W ^ (select_mask[sb] & A);
//   return W;
// }

// template <typename T>
// void finalize(absl::Span<T> outputs) {
//   // YACL_ENFORCE(outputs.size() >= circ_->nov);

//   size_t index = wires_.size();

//   for (size_t i = 0; i < circ_->nov; ++i) {
//     yacl::dynamic_bitset<T> result(circ_->now[i]);
//     for (size_t j = 0; j < circ_->now[i]; ++j) {
//       int wire_index = index - circ_->now[i] + j;
//       result[j] = getLSB(wires_[wire_index]) ^
//                   getLSB(gb_value[wire_index]);  // 得到的是逆序的二进制值
//                                                  // 对应的混淆电路计算为LSB ^
//                                                  d
//                                                  // 输出线路在后xx位
//     }
//     // std::cout << "输出：" << result.data() << std::endl;
//     outputs[circ_->nov - i - 1] = *(uint128_t*)result.data();
//     index -= circ_->now[i];
//   }
// }

int main() {
  // 初始化
  Garbler* garbler = new Garbler();
  Evaluator* evaluator = new Evaluator();

  std::future<void> thread1 = std::async([&] { garbler->setup(); });
  std::future<void> thread2 = std::async([&] { evaluator->setup(); });
  thread1.get();
  thread2.get();

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

  // 输入值混淆
  thread1 = std::async([&] { garbler->inputProcess(*circ_); });
  thread2 = std::async([&] { evaluator->inputProcess(*circ_); });
  thread1.get();
  thread2.get();

  // for (int i = 0; i < circ_->gates.size(); i++) {
  //   auto gate = circ_->gates[i];
  //   switch (gate.op) {
  //     case yacl::io::BFCircuit::Op::XOR: {
  //       const auto& iw0 = gb_value.operator[](gate.iw[0]);  // 取到具体值
  //       const auto& iw1 = gb_value.operator[](gate.iw[1]);
  //       gb_value[gate.ow[0]] = iw0 ^ iw1;
  //       break;
  //     }
  //     case yacl::io::BFCircuit::Op::AND: {
  //       const auto& iw0 = gb_value.operator[](gate.iw[0]);
  //       const auto& iw1 = gb_value.operator[](gate.iw[1]);
  //       gb_value[gate.ow[0]] = GBAND(iw0, iw0 ^ delta, iw1, iw1 ^ delta,
  //       delta,
  //                                    table[i], &mitccrh);
  //       break;
  //     }
  //     case yacl::io::BFCircuit::Op::INV: {
  //       const auto& iw0 = gb_value.operator[](gate.iw[0]);
  //       gb_value[gate.ow[0]] = iw0 ^ constant[2];
  //       break;
  //     }
  //     case yacl::io::BFCircuit::Op::EQ: {
  //       gb_value[gate.ow[0]] = gate.iw[0];
  //       break;
  //     }
  //     case yacl::io::BFCircuit::Op::EQW: {
  //       const auto& iw0 = gb_value.operator[](gate.iw[0]);
  //       gb_value[gate.ow[0]] = iw0;
  //       break;
  //     }
  //     case yacl::io::BFCircuit::Op::MAND: { /* multiple ANDs */
  //       YACL_THROW("Unimplemented MAND gate");
  //       break;
  //     }
  //     default:
  //       YACL_THROW("Unknown Gate Type: {}", (int)gate.op);
  //   }
  // }

  // // 发送混淆表
  // if (FLAGS_rank == 0) {
  //   lctx->Send(
  //       1, yacl::ByteContainerView(table, sizeof(uint128_t) * 2 * circ_->ng),
  //       "table");
  //   std::cout << "sendTable" << std::endl;
  //   // std::cout << "table0" << table[132][0];

  // } else {
  //   yacl::Buffer r = lctx->Recv(0, "table");
  //   const uint128_t* buffer_data = r.data<const uint128_t>();
  //   int k = 0;
  //   for (int i = 0; i < circ_->ng; i++) {
  //     for (int j = 0; j < 2; j++) {
  //       table[i][j] = buffer_data[k];
  //       k++;
  //     }
  //   }

  //   std::cout << "recvTable" << std::endl;
  //   // std::cout << "table0" << table[132][0];
  // }

  // // 计算方进行计算 按拓扑顺序进行计算
  // for (int i = 0; i < circ_->gates.size(); i++) {
  //   auto gate = circ_->gates[i];
  //   switch (gate.op) {
  //     case yacl::io::BFCircuit::Op::XOR: {
  //       const auto& iw0 = wires_.operator[](gate.iw[0]);  // 取到具体值
  //       const auto& iw1 = wires_.operator[](gate.iw[1]);
  //       wires_[gate.ow[0]] = iw0 ^ iw1;
  //       break;
  //     }
  //     case yacl::io::BFCircuit::Op::AND: {
  //       const auto& iw0 = wires_.operator[](gate.iw[0]);
  //       const auto& iw1 = wires_.operator[](gate.iw[1]);
  //       wires_[gate.ow[0]] = EVAND(iw0, iw1, table[i], &mitccrh);
  //       break;
  //     }
  //     case yacl::io::BFCircuit::Op::INV: {
  //       const auto& iw0 = wires_.operator[](gate.iw[0]);
  //       wires_[gate.ow[0]] = iw0 ^ constant[1];
  //       break;
  //     }
  //     case yacl::io::BFCircuit::Op::EQ: {
  //       wires_[gate.ow[0]] = gate.iw[0];
  //       break;
  //     }
  //     case yacl::io::BFCircuit::Op::EQW: {
  //       const auto& iw0 = wires_.operator[](gate.iw[0]);
  //       wires_[gate.ow[0]] = iw0;
  //       break;
  //     }
  //     case yacl::io::BFCircuit::Op::MAND: { /* multiple ANDs */
  //       YACL_THROW("Unimplemented MAND gate");
  //       break;
  //     }
  //     default:
  //       YACL_THROW("Unknown Gate Type: {}", (int)gate.op);
  //   }
  // }

  // // 识别输出线路 进行DE操作
  // // *********Finalize应该由谁来做，怎么做
  // size_t index = wires_.size();
  // int start = index - circ_->now[0];
  // if (FLAGS_rank == 1) {
  //   lctx->Send(
  //       0,
  //       yacl::ByteContainerView(wires_.data() + start, sizeof(uint128_t) *
  //       64), "output");
  //   std::cout << "sendOutput" << std::endl;
  //   // std::cout << "output:" << wires_[index - 1] << std::endl;

  // } else {
  //   yacl::Buffer r = lctx->Recv(1, "output");
  //   const uint128_t* buffer_data = r.data<const uint128_t>();

  //   memcpy(wires_.data() + start, buffer_data, sizeof(uint128_t) * 64);
  //   // for (int i = 0; i < circ_->niw[1]; i++) {
  //   //   // gb_value[i] = send_out[i - 64][0];
  //   //   // wires_[i] = recv_out[i - 64];
  //   //   // if (send_out[i - 64][0] ^ delta == send_out[i - 64][1])
  //   //   //   std::cout << true << std::endl;

  //   //   wires_[i + circ_->niw[0]] =
  //   //       buffer_data[i] ^ (select_mask[bi_val[i]] & delta);
  //   // }
  //   std::cout << "recvOutput" << std::endl;
  //   // std::cout << "output:" << wires_[index - 1] << std::endl;
  // }

  // // 检查计算结果是否正确
  // // std::cout << inputs[0] << " " << inputs[1] << std::endl;
  // if (FLAGS_rank == 1) {
  //   std::cout << "明文计算结果：";
  //   if (operate == "adder64") {
  //     std::cout << input1 + input << std::endl;
  //   } else if (operate == "divide64") {
  //     std::cout << static_cast<int64_t>(input1) / static_cast<int64_t>(input)
  //               << std::endl;
  //   } else if (operate == "udivide64") {
  //     std::cout << input1 / input << std::endl;
  //   } else if (operate == "mult64") {
  //     std::cout << input1 * input << std::endl;
  //   } else if (operate == "neg64") {
  //     std::cout << -input1 << std::endl;
  //   } else if (operate == "sub64") {
  //     std::cout << input1 - input << std::endl;
  //   } else if (operate == "aes_128") {
  //     std::cout << Aes128(ReverseBytes(input1), ReverseBytes(input))
  //               << std::endl;
  //     result[0] = ReverseBytes(result[0]);
  //   } else {
  //     std::cout << "else" << std::endl;
  //   }
  // } else {
  //   finalize(absl::MakeSpan(result));
  //   std::cout << "MPC结果：" << result[0] << std::endl;
  // }

  // /* WHEN */
  // //   PlainExecutor<uint64_t> exec;
  // //   exec.LoadCircuitFile(io::BuiltinBFCircuit::Add64Path());
  // //   exec.SetupInputs(absl::MakeSpan(inputs));  // En
  // //   exec.Exec();
  // //   exec.Finalize(absl::MakeSpan(result));

  // /* THEN  验证计算结果 */

  // return 0;
}
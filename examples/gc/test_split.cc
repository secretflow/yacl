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
#include "yacl/kernel/ot_kernel.h"
#include "yacl/kernel/type/ot_store_utils.h"

using namespace std;
using namespace yacl;
using namespace yacl::crypto;
namespace {
using uint128_t = __uint128_t;
}

std::shared_ptr<yacl::io::BFCircuit> circ_;



inline uint128_t Aes128(uint128_t k, uint128_t m) {
  yacl::crypto::SymmetricCrypto enc(
      yacl::crypto::SymmetricCrypto::CryptoType::AES128_ECB, k);
  return enc.Encrypt(m);
}

int main() {
  // 初始化
  Garbler* garbler = new Garbler();
  Evaluator* evaluator = new Evaluator();

  std::future<void> thread1 = std::async([&] { garbler->setup(); });
  std::future<void> thread2 = std::async([&] { evaluator->setup(); });
  thread1.get();
  thread2.get();
  cout << "ROT:" << garbler -> ot_send.GetBlock(3, evaluator->ot_recv.GetChoice(3)) <<"  "  << evaluator->ot_recv.GetBlock(3) << endl; 
  
  // 电路读取
  // std::string operate;
  // cout << "输入进行的操作: ";
  // std::cin >> operate;

  // std::string pth =
  //     fmt::format("{0}/yacl/io/circuit/data/{1}.txt",
  //                 std::filesystem::current_path().string(), operate);
  std::string pth =
      fmt::format("{0}/yacl/io/circuit/data/{1}.txt",
                  std::filesystem::current_path().string(), "adder64");
  yacl::io::CircuitReader reader(pth);
  reader.ReadMeta();
  reader.ReadAllGates();
  circ_ = reader.StealCirc();  // 指针

  // 输入值混淆
  thread1 = std::async([&] { garbler->inputProcess(*circ_); });
  thread2 = std::async([&] { evaluator->inputProcess(*circ_); });
  thread1.get();
  thread2.get();
  

  // 混淆方对整个电路进行混淆, 并将混淆表发送给evaluator
  garbler->GB();
  garbler->sendTable();

  evaluator->recvTable();
  

  // // 计算方进行计算 按拓扑顺序进行计算
  evaluator->EV();

  // // evaluator发送计算结果 garbler进行DE操作
  evaluator->sendOutput();
  
  garbler->decode();
  

  return 0;
}
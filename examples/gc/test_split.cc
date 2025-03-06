#pragma once
#include <algorithm>
#include <future>
#include <type_traits>
#include <vector>

// #include "absl/std::strings/escaping.h"
#include "absl/types/span.h"

#include "examples/gc/aes_128_evaluator.h"
#include "examples/gc/aes_128_garbler.h"
#include "examples/gc/sha256_garbler.h"
#include "examples/gc/sha256_evaluator.h"
#include "fmt/format.h"
#include "yacl/kernel/ot_kernel.h"
#include "yacl/kernel/type/ot_store_utils.h"

using namespace std;
using namespace yacl;
using namespace yacl::crypto;
namespace {
using uint128_t = __uint128_t;
}






int main() {
  // 初始化
  std::shared_ptr<yacl::io::BFCircuit> circ_;
  // 初始化
  GarblerAES* garbler = new GarblerAES();
  EvaluatorAES * evaluator = new EvaluatorAES();

  std::future<void> thread1 = std::async([&] { garbler->setup(); });
  std::future<void> thread2 = std::async([&] { evaluator->setup(); });
  thread1.get();
  thread2.get();
  
  
  // 电路读取
  std::string pth =
      fmt::format("{0}/yacl/io/circuit/data/{1}.txt",
                  std::filesystem::current_path().string(), "aes_128");
  yacl::io::CircuitReader reader(pth);
  reader.ReadMeta();
  reader.ReadAllGates();
  circ_ = reader.StealCirc();  // 指针

  // 输入处理
  // garbler->inputProcess(*circ_);

  uint128_t key;
  uint128_t message;
  thread1 = std::async([&] { key = garbler->inputProcess(*circ_); });
  thread2 = std::async([&] { message = evaluator->inputProcess(*circ_); });
  thread1.get();
  thread2.get();

  // OT  
  thread1 = std::async([&] { evaluator -> onLineOT();});
  thread2 = std::async([&] { garbler -> onlineOT(); });
  thread1.get();
  thread2.get();
  

  // 混淆方对整个电路进行混淆, 并将混淆表发送给evaluator
  garbler->GB();
  garbler->sendTable();

  evaluator->recvTable();
  

  // // 计算方进行计算 按拓扑顺序进行计算
  evaluator->EV();

  // // // evaluator发送计算结果 garbler进行DE操作
  evaluator->sendOutput();
  
  uint128_t gc_result = garbler->decode();
  // auto aes = Aes128(ReverseBytes(key), ReverseBytes(message));
  // EXPECT_EQ(ReverseBytes(gc_result), aes);
  

  return 0;
}


#pragma once
#include "gtest/gtest.h"
#include <algorithm>
#include <future>
#include <type_traits>
#include <vector>

// #include "absl/std::strings/escaping.h"
#include "absl/types/span.h"


#include "examples/gc/sha256_garbler.h"
#include "examples/gc/sha256_evaluator.h"
#include "fmt/format.h"
#include "yacl/kernel/ot_kernel.h"
#include "yacl/kernel/type/ot_store_utils.h"





namespace examples::gc{

    





std::shared_ptr<yacl::io::BFCircuit> circ_;
TEST(GCTest, SHA256Test) {
  // 初始化
  GarblerSHA256* garbler = new GarblerSHA256();
  EvaluatorSHA256* evaluator = new EvaluatorSHA256();

  std::future<void> thread1 = std::async([&] { garbler->setup(); });
  std::future<void> thread2 = std::async([&] { evaluator->setup(); });
  thread1.get();
  thread2.get();
  
  
  // 电路读取
  std::string pth =
      fmt::format("{0}/yacl/io/circuit/data/{1}.txt",
                  std::filesystem::current_path().string(), "sha256");
  yacl::io::CircuitReader reader(pth);
  reader.ReadMeta();
  reader.ReadAllGates();
  circ_ = reader.StealCirc();  // 指针

  // 输入处理
  // garbler->inputProcess(*circ_);

    vector<uint8_t> sha256_result;
  thread1 = std::async([&] { sha256_result = garbler->inputProcess(*circ_); });
  thread2 = std::async([&] { evaluator->inputProcess(*circ_); });
  thread1.get();
  thread2.get();

  // // OT  **************因为SHA256场景中输入都在混淆方，所以不需要进行OT***************
  // thread1 = std::async([&] { evaluator -> onLineOT();});
  // thread2 = std::async([&] { garbler -> onlineOT(); });
  // thread1.get();
  // thread2.get();
  

  // 混淆方对整个电路进行混淆, 并将混淆表发送给evaluator
  garbler->GB();
  garbler->sendTable();

  evaluator->recvTable();
  

  // // 计算方进行计算 按拓扑顺序进行计算
  evaluator->EV();

  // // // evaluator发送计算结果 garbler进行DE操作
  evaluator->sendOutput();
  
  vector<uint8_t> gc_result = garbler->decode();

  EXPECT_EQ(sha256_result.size(), gc_result.size());
  EXPECT_TRUE(std::equal(gc_result.begin(), gc_result.end(), sha256_result.begin()));

}
}
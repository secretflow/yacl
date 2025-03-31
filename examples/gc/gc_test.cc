

#include <vector>

#include "examples/gc/aes_128_evaluator.h"
#include "examples/gc/aes_128_garbler.h"
#include "examples/gc/sha256_evaluator.h"
#include "examples/gc/sha256_garbler.h"
#include "fmt/format.h"
#include "gtest/gtest.h"

#include "yacl/crypto/block_cipher/symmetric_crypto.h"

namespace examples::gc {

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

TEST(GCTest, SHA256Test) {
  std::shared_ptr<yacl::io::BFCircuit> circ_;
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
  EXPECT_TRUE(
      std::equal(gc_result.begin(), gc_result.end(), sha256_result.begin()));
}

TEST(GCTest, AESTest) {
  std::shared_ptr<yacl::io::BFCircuit> circ_;
  // 初始化
  GarblerAES* garbler = new GarblerAES();
  EvaluatorAES* evaluator = new EvaluatorAES();

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
  thread1 = std::async([&] { evaluator->onLineOT(); });
  thread2 = std::async([&] { garbler->onlineOT(); });
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
  auto aes = Aes128(ReverseBytes(key), ReverseBytes(message));
  EXPECT_EQ(ReverseBytes(gc_result), aes);
}

}  // namespace examples::gc

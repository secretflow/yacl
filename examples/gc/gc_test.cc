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

#include <filesystem>
#include <future>
#include <vector>

#include "examples/gc/aes_128_evaluator.h"
#include "examples/gc/aes_128_garbler.h"
#include "examples/gc/sha256_evaluator.h"
#include "examples/gc/sha256_garbler.h"
#include "fmt/format.h"
#include "gtest/gtest.h"

#include "yacl/crypto/block_cipher/symmetric_crypto.h"

namespace examples::gc {

using namespace yacl;

inline uint128_t Aes128(uint128_t k, uint128_t m) {
  crypto::SymmetricCrypto enc(crypto::SymmetricCrypto::CryptoType::AES128_ECB,
                              k);
  return enc.Encrypt(m);
}

TEST(GCTest, SHA256Test) {
  std::shared_ptr<yacl::io::BFCircuit> circ_;

  GarblerSHA256* garbler = new GarblerSHA256();
  EvaluatorSHA256* evaluator = new EvaluatorSHA256();

  std::future<void> thread1 = std::async([&] { garbler->setup(); });
  std::future<void> thread2 = std::async([&] { evaluator->setup(); });
  thread1.get();
  thread2.get();

  std::string pth = fmt::format("yacl/io/circuit/data/{0}.txt", "sha256");
  yacl::io::CircuitReader reader(pth);
  reader.ReadMeta();
  reader.ReadAllGates();
  circ_ = reader.StealCirc();

  std::vector<uint8_t> sha256_result;
  thread1 = std::async([&] { sha256_result = garbler->inputProcess(*circ_); });
  thread2 = std::async([&] { evaluator->inputProcess(*circ_); });
  thread1.get();
  thread2.get();

  garbler->GB();
  garbler->sendTable();

  evaluator->recvTable();

  evaluator->EV();

  evaluator->sendOutput();

  std::vector<uint8_t> gc_result = garbler->decode();

  EXPECT_EQ(sha256_result.size(), gc_result.size());
  EXPECT_TRUE(
      std::equal(gc_result.begin(), gc_result.end(), sha256_result.begin()));
  delete garbler;
  delete evaluator;
}

TEST(GCTest, AESTest) {
  std::shared_ptr<yacl::io::BFCircuit> circ_;

  GarblerAES* garbler = new GarblerAES();
  EvaluatorAES* evaluator = new EvaluatorAES();

  std::future<void> thread1 = std::async([&] { garbler->setup(); });
  std::future<void> thread2 = std::async([&] { evaluator->setup(); });
  thread1.get();
  thread2.get();

  std::string pth = fmt::format("yacl/io/circuit/data/{0}.txt", "aes_128");
  yacl::io::CircuitReader reader(pth);
  reader.ReadMeta();
  reader.ReadAllGates();
  circ_ = reader.StealCirc();

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

  garbler->GB();
  garbler->sendTable();

  evaluator->recvTable();

  evaluator->EV();

  evaluator->sendOutput();

  uint128_t gc_result = garbler->decode();
  auto aes = Aes128(ReverseBytes(key), ReverseBytes(message));
  EXPECT_EQ(ReverseBytes(gc_result), aes);
  delete garbler;
  delete evaluator;
}

}  // namespace examples::gc

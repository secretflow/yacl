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
#include <fstream>
#include <future>
#include <vector>

#include "examples/gc/aes_128_evaluator.h"
#include "examples/gc/aes_128_garbler.h"
#include "fmt/format.h"

#include "yacl/crypto/block_cipher/symmetric_crypto.h"

int aes_garbler_send_bytes = 0;
int aes_evaluator_send_bytes = 0;
int aes_compute_time = 0;

void aes_performance() {
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

  for (int i = 0; i < 1; i++) {
    auto start1 = clock_start();
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

    [[maybe_unused]] uint128_t gc_result = garbler->decode();
    aes_compute_time += time_from(start1);
    aes_garbler_send_bytes += garbler->send_bytes;
    aes_evaluator_send_bytes += evaluator->send_bytes;
  }
  delete garbler;
  delete evaluator;
}

int main() {
  aes_performance();
  cout << "AES_performance:" << endl;
  std::cout << "Garbler send: " << aes_garbler_send_bytes << " bytes" << "  "
            << endl;
  std::cout << "Evaluator send: " << aes_evaluator_send_bytes << " bytes"
            << "  " << endl;
  cout << "Time for Computing: " << aes_compute_time << "us" << endl;
}

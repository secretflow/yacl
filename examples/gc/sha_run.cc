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
#include "examples/gc/sha256_evaluator.h"
#include "examples/gc/sha256_garbler.h"
#include "fmt/format.h"

#include "yacl/crypto/block_cipher/symmetric_crypto.h"

namespace yacl {
int sha_garbler_send_bytes = 0;
int sha_evaluator_send_bytes = 0;

int sha_compute_time = 0;

void sha_performance() {
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

  for (int i = 0; i < 1; i++) {
    std::vector<uint8_t> sha256_result;

    auto start1 = clock_start();
    sha256_result = garbler->inputProcess(*circ_);
    evaluator->inputProcess(*circ_);

    garbler->GB();
    garbler->sendTable();

    evaluator->recvTable();

    evaluator->EV();

    evaluator->sendOutput();

    std::vector<uint8_t> gc_result = garbler->decode();
    sha_compute_time += time_from(start1);
    sha_garbler_send_bytes += garbler->send_bytes;
    sha_evaluator_send_bytes += evaluator->send_bytes;
  }

  delete garbler;
  delete evaluator;
}
}  // namespace yacl

int main() {
  yacl::sha_performance();

  std::cout << "SHA_performance:" << std::endl;
  std::cout << "Garbler send: " << yacl::sha_garbler_send_bytes << " bytes"
            << "  " << std::endl;
  std::cout << "Evaluator send: " << yacl::sha_evaluator_send_bytes << " bytes"
            << "  " << std::endl;
  std::cout << "Time for Computing: " << yacl::sha_compute_time << "us"
            << std::endl;
  std::cout << std::endl;
}

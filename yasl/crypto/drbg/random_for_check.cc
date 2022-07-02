// Copyright 2019 Ant Group Co., Ltd.
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

#include <array>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

#include "yasl/crypto/drbg/ctr_drbg.h"
#include "yasl/crypto/ssl_hash.h"

namespace {
constexpr int kSingeLength = 125000;
constexpr int kTotalNum = 1000;
}  // namespace

int main(int argc, char **argv) {
  std::string file_name = fmt::format("random.bin");
  std::ofstream ofs;
  ofs.open(file_name, std::ios::out | std::ios::binary);

  for (size_t idx = 0; idx < kTotalNum; idx++) {
    yasl::crypto::CtrDrbg drbg;
    std::stringstream ss;
    std::string idx_str;

    for (size_t i = 0; i < kSingeLength; i += 1000) {
      auto random_buf = drbg.Generate(1024);
      std::array<uint8_t, 1024> random_buf2;
      for (size_t j = 0; j < 1024 / 32; ++j) {
        yasl::crypto::Sha256Hash sha256;
        std::string hash_data(32, '\0');
        std::memcpy(hash_data.data(), random_buf.data() + j * 32, 32);

        sha256.Update(hash_data);
        std::vector<uint8_t> hash_result = sha256.CumulativeHash();
        std::memcpy(random_buf2.data() + j * 32, hash_data.data(),
                    hash_result.size());
      }

      ofs.write(reinterpret_cast<const char *>(random_buf2.data()), 1000);
    }
  }
  ofs.flush();

  return 0;
}

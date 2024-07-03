// Copyright 2024 Guowei Ling.
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

#include "examples/hesm2/config.h"

#include "examples/hesm2/t1.h"
#include "examples/hesm2/t2.h"

namespace examples::hesm2 {

uint32_t GetSubBytesAsUint32(const yacl::Buffer& bytes, size_t start,
                             size_t end) {
  uint32_t result = 0;
  for (size_t i = start; i < end; ++i) {
    result = (result << 8) | bytes.data<uint8_t>()[i];
  }
  return result;
}

CuckooT1 t1_loaded(Jmax);
T2 t2_loaded(nullptr, false);

void InitializeConfig() {
  auto ec_group = yacl::crypto::EcGroupFactory::Instance().Create(
      "sm2", yacl::ArgLib = "openssl");

  // 检查是否成功创建
  if (!ec_group) {
    std::cerr << "Failed to create SM2 curve using OpenSSL" << std::endl;
    return;
  }
  // 检查文件是否存在，如果存在则从文件加载
  std::string filet1 = "cuckoo_t1.dat";
  std::ifstream ifs(filet1);
  if (ifs.good()) {
    t1_loaded.Deserialize(filet1);
    SPDLOG_INFO("t1_loaded from file: {}", filet1);
  } else {
    SPDLOG_INFO("t1_loaded generated and serialized to file:{} ", filet1);
    SPDLOG_INFO(
        "The process might be slow; you may need to wait a few minutes...");
    t1_loaded.InitializeEcGroup(std::move(ec_group));
    t1_loaded.Initialize();
    t1_loaded.Serialize(filet1);
  }

  auto ec_group_t2 = yacl::crypto::EcGroupFactory::Instance().Create(
      "sm2", yacl::ArgLib = "openssl");
  std::string filet2 = "t2.dat";
  std::ifstream ifst2(filet2);
  if (ifst2.good()) {
    t2_loaded.Deserialize(filet2);
    SPDLOG_INFO("t2_loaded from file: {}", filet2);
  } else {
    SPDLOG_INFO("t2_loaded generated and serialized to file:{} ", filet2);
    t2_loaded.InitializeEcGroup(std::move(ec_group_t2));
    t2_loaded.InitializeVector();
    t2_loaded.Serialize(filet2);
    t2_loaded.Deserialize(filet2);
  }
}

}  // namespace examples::hesm2
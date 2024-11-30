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

#pragma once

#include <tuple>
#include <utility>
#include <set>
#include <unordered_map>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <algorithm>

#include "yacl/crypto/block_cipher/symmetric_crypto.h"
#include "yacl/crypto/ecc/openssl/openssl_group.h"
#include "yacl/crypto/primitives/sse/TSet.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/io/rw/csv_reader.h"
#include "yacl/io/stream/file_io.h"
#include "yacl/math/mpint/mp_int.h"

namespace yacl::crypto::primitives::sse {

class SSE {
 public:
  SSE(int bucket_size = 8, int slot_size = 8, int lambda = 128,
      int n_lambda = 256,
      const std::string& filename =
          "/home/xbw/yacl/yacl/crypto/primitives/sse/test.csv");

  std::pair<
      std::vector<std::vector<yacl::crypto::primitives::sse::TSet::Record>>,
      std::string>
  EDBSetup();

  std::string getKt();
  std::tuple<
      std::map<std::string, std::string>,
      std::vector<std::vector<yacl::crypto::primitives::sse::TSet::Record>>,
      std::vector<yacl::crypto::EcPoint>>
  SaveEDB(const std::string& k_map_file = "/tmp/sse_test_data/K_map.bin",
          const std::string& tset_file = "/tmp/sse_test_data/TSet.bin",
          const std::string& xset_file = "/tmp/sse_test_data/XSet.bin");
  std::tuple<
      std::map<std::string, std::string>,
      std::vector<std::vector<yacl::crypto::primitives::sse::TSet::Record>>,
      std::vector<yacl::crypto::EcPoint>>
  LoadEDB(const std::string& k_map_file = "/tmp/sse_test_data/K_map.bin",
          const std::string& tset_file = "/tmp/sse_test_data/TSet.bin",
          const std::string& xset_file = "/tmp/sse_test_data/XSet.bin");

  std::vector<std::string> SearchProtocol(
      const std::vector<std::string>& keywords);

  ~SSE();

 private:
  bool isInXSet(const std::unique_ptr<yacl::crypto::EcGroup>& ec_group,
                const yacl::crypto::EcPoint& xtag,
                const std::vector<yacl::crypto::EcPoint>& XSet);
  void initialize(const std::string& filename);
  void processAndUpdateTAndXSet();

  std::tuple<std::vector<std::string>,
             std::vector<std::pair<std::string, std::string>>,
             std::unordered_map<std::string, std::vector<std::string>>>
  processAndSaveCSV(const std::string& file_path);
  uint128_t convert_to_uint128(const std::vector<uint8_t>& mac);
  std::string vectorToString(const std::vector<uint8_t>& vec);
  std::vector<std::string> fetchKeysByValue(
      const std::unordered_map<std::string, std::vector<std::string>>&
          reverseIndex,
      const std::string& value);

  std::vector<uint8_t> aes_ctr_encrypt(const std::vector<uint8_t>& plaintext,
                                       const uint128_t& key,
                                       const uint128_t& iv);
  std::vector<uint8_t> aes_ctr_decrypt(const std::vector<uint8_t>& ciphertext,
                                       const uint128_t& key,
                                       const uint128_t& iv);

  void SaveKeys(const std::map<std::string, std::string>& K_map,
                const std::string& file_path);
  void SaveTSet(
      const std::vector<
          std::vector<yacl::crypto::primitives::sse::TSet::Record>>& TSet,
      const std::string& file_path);
  void SaveXSet(const std::vector<yacl::crypto::EcPoint>& XSet,
                const std::string& file_path,
                const std::unique_ptr<yacl::crypto::EcGroup>& ec_group);
  std::map<std::string, std::string> LoadKeys(const std::string& file_path);
  std::vector<std::vector<yacl::crypto::primitives::sse::TSet::Record>>
  LoadTSet(const std::string& file_path);
  std::vector<yacl::crypto::EcPoint> LoadXSet(
      const std::string& file_path,
      const std::unique_ptr<yacl::crypto::EcGroup>& ec_group);

  // 其他私有成员
  std::vector<std::string> keywords_;
  std::vector<std::pair<std::string, std::string>> keyValuePairs_;
  std::unordered_map<std::string, std::vector<std::string>> reverseIndex_;
  std::map<std::string, std::string> K_map_;
  std::unique_ptr<yacl::crypto::EcGroup> ec_group_;
  std::unordered_map<std::string,
                     std::vector<std::pair<std::vector<uint8_t>, std::string>>>
      T_;
  std::vector<yacl::crypto::EcPoint> XSet_;
  std::vector<std::vector<yacl::crypto::primitives::sse::TSet::Record>> TSet_;

  TSet tset_;
};
}  // namespace yacl::crypto::primitives::sse

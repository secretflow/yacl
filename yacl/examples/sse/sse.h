// Copyright 2024 Li Zhihang.
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

#include <algorithm>
#include <filesystem>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include "yacl/crypto/block_cipher/symmetric_crypto.h"
#include "yacl/crypto/ecc/openssl/openssl_group.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/examples/sse/tset.h"
#include "yacl/io/rw/csv_reader.h"
#include "yacl/io/stream/file_io.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::sse {

class Sse {
 public:
  Sse(int bucket_size = 8, int slot_size = 8, int lambda = 128,
      int n_lambda = 256);

  std::pair<std::vector<std::vector<TSet::Record>>, std::string> EDBSetup();

  std::string GetKt();
  std::tuple<std::map<std::string, std::string>,
             std::vector<std::vector<TSet::Record>>,
             std::vector<yacl::crypto::EcPoint>>
  SaveEDB(const std::string& k_map_file = "/tmp/sse_test_data/K_map.bin",
          const std::string& tset_file = "/tmp/sse_test_data/TSet.bin",
          const std::string& xset_file = "/tmp/sse_test_data/XSet.bin");
  std::tuple<std::map<std::string, std::string>,
             std::vector<std::vector<TSet::Record>>,
             std::vector<yacl::crypto::EcPoint>>
  LoadEDB(const std::string& k_map_file = "/tmp/sse_test_data/K_map.bin",
          const std::string& tset_file = "/tmp/sse_test_data/TSet.bin",
          const std::string& xset_file = "/tmp/sse_test_data/XSet.bin");

  std::vector<std::string> SearchProtocol(
      const std::vector<std::string>& keywords);

  ~Sse();

 private:
  bool IsInXSet(const std::unique_ptr<yacl::crypto::EcGroup>& ec_group,
                const yacl::crypto::EcPoint& xtag,
                const std::vector<yacl::crypto::EcPoint>& XSet);
  void Initialize();
  void ProcessAndUpdateTAndXSet();

  std::tuple<std::vector<std::string>,
             std::vector<std::pair<std::string, std::string>>,
             std::unordered_map<std::string, std::vector<std::string>>>
  ProcessAndSaveCSV(const std::string& file_path);
  uint128_t ConvertToUint128(const std::vector<uint8_t>& mac);
  std::string VectorToString(const std::vector<uint8_t>& vec);
  std::vector<std::string> FetchKeysByValue(
      const std::unordered_map<std::string, std::vector<std::string>>&
          reverseIndex,
      const std::string& value);

  std::vector<uint8_t> AesCtrEncrypt(const std::vector<uint8_t>& plaintext,
                                     const uint128_t& key, const uint128_t& iv);
  std::vector<uint8_t> AesCtrDecrypt(const std::vector<uint8_t>& ciphertext,
                                     const uint128_t& key, const uint128_t& iv);

  void SaveKeys(const std::map<std::string, std::string>& K_map,
                const std::string& file_path);
  void SaveTSet(
      const std::vector<std::vector<TSet::Record>>& TSet,
      const std::string& file_path);
  void SaveXSet(const std::vector<yacl::crypto::EcPoint>& XSet,
                const std::string& file_path,
                const std::unique_ptr<yacl::crypto::EcGroup>& ec_group);
  std::map<std::string, std::string> LoadKeys(const std::string& file_path);
  std::vector<std::vector<TSet::Record>> LoadTSet(const std::string& file_path);
  std::vector<yacl::crypto::EcPoint> LoadXSet(
      const std::string& file_path,
      const std::unique_ptr<yacl::crypto::EcGroup>& ec_group);

  // 其他私有成员
  std::vector<std::string> keywords_;
  std::vector<std::pair<std::string, std::string>> keyValuePairs_;
  std::unordered_map<std::string, std::vector<std::string>> reverseIndex_;
  std::map<std::string, std::string> k_map_;
  std::unique_ptr<yacl::crypto::EcGroup> ec_group_;
  std::unordered_map<std::string,
                     std::vector<std::pair<std::vector<uint8_t>, std::string>>>
      T_;
  std::vector<yacl::crypto::EcPoint> XSet_;
  std::vector<std::vector<TSet::Record>> TSet_;

  TSet tset_;
};
}  // namespace examples::sse

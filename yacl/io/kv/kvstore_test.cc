// Copyright 2021 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstdio>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "gtest/gtest.h"

#include "yacl/crypto/tools/prg.h"
#include "yacl/io/kv/leveldb_kvstore.h"
#include "yacl/io/kv/memory_kvstore.h"

namespace yacl::io {

TEST(KVStore, memory_test) {
  std::unique_ptr<KVStore> memory_store(new MemoryKVStore());

  std::random_device rd;

  std::string key(16, '\0');
  std::string value(32, '\0');
  yacl::crypto::Prg<uint8_t> prg(rd());

  prg.Fill(absl::MakeSpan(&key[0], key.length()));
  prg.Fill(absl::MakeSpan(&value[0], value.size()));

  memory_store->Put(key, value);

  std::string value2;
  memory_store->Get(key, &value2);

  EXPECT_EQ(value, value2);
}

TEST(KVStore, leveldb_test) {
  std::unique_ptr<KVStore> leveldb_store(
      new LeveldbKVStore(true, "/tmp/leveldb_test"));

  std::random_device rd;

  std::string key(16, '\0');
  std::string value(32, '\0');
  yacl::crypto::Prg<uint8_t> prg(rd());

  prg.Fill(absl::MakeSpan(&key[0], key.length()));
  prg.Fill(absl::MakeSpan(&value[0], value.size()));

  leveldb_store->Put(key, value);

  std::string value2;
  leveldb_store->Get(key, &value2);

  EXPECT_EQ(value, value2);
}

TEST(KVStore, index_memory_test) {
  std::shared_ptr<KVStore> kv_store = std::make_shared<MemoryKVStore>();
  IndexStore index_store(kv_store);

  std::random_device rd;

  uint32_t key;
  std::string value(32, '\0');
  yacl::crypto::Prg<uint8_t> prg(rd());

  key = prg();
  prg.Fill(absl::MakeSpan(&value[0], value.size()));

  index_store.Put(key, value);

  std::string value2;
  index_store.Get(key, &value2);

  EXPECT_EQ(value, value2);
}

TEST(KVStore, index_leveldb_test) {
  std::shared_ptr<KVStore> kv_store = std::make_shared<LeveldbKVStore>(true);
  IndexStore index_store(kv_store);

  std::random_device rd;

  uint32_t key;
  std::string value(32, '\0');
  yacl::crypto::Prg<uint8_t> prg(rd());

  key = prg();
  prg.Fill(absl::MakeSpan(&value[0], value.size()));

  index_store.Put(key, value);

  std::string value2;
  index_store.Get(key, &value2);

  EXPECT_EQ(value, value2);
}

}  // namespace yacl::io

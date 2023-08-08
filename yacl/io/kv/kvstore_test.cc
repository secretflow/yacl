// Copyright (c) 2021 Ant Financial. All rights reserved.

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
      new LeveldbKVStore(false, std::tmpnam(nullptr)));

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

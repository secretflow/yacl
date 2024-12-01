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

#include "yacl/examples/primitives/sse/sse.h"

#include <gtest/gtest.h>

#include <unordered_set>

namespace yacl::examples::primitives::sse {

class SSETest : public ::testing::Test {
 protected:
  void SetUp() override {
    // 初始化SSE系统，使用默认参数
    sse_ = std::make_unique<SSE>(8,     // bucket_size
                                 8,     // slot_size
                                 128,   // lambda (安全参数)
                                 256);  // n_lambda

    // 设置EDB
    auto [tset, kt] = sse_->EDBSetup();
    EXPECT_FALSE(tset.empty());
    EXPECT_FALSE(kt.empty());
  }

  std::unique_ptr<SSE> sse_;
};

TEST_F(SSETest, BasicSearch) {
  std::vector<std::string> keyword = {"race=Black"};
  auto results = sse_->SearchProtocol(keyword);
  std::unordered_set<std::string> expected_results = {"ID_130162", "ID_130165"};
  EXPECT_EQ(results.size(), expected_results.size());
  std::unordered_set<std::string> actual_results(results.begin(),
                                                 results.end());
  EXPECT_EQ(actual_results, expected_results);
}

// 测试空关键词搜索
TEST_F(SSETest, EmptyKeywordSearch) {
  std::vector<std::string> keyword_empty = {};
  auto results = sse_->SearchProtocol(keyword_empty);
  EXPECT_TRUE(results.empty());
}

// 测试不存在的关键词搜索
TEST_F(SSETest, NonExistentKeywordSearch) {
  std::vector<std::string> non_existent = {"education=NonExistent"};
  auto results = sse_->SearchProtocol(non_existent);
  EXPECT_TRUE(results.empty());
}

//  测试两个关键词
TEST_F(SSETest, TwoKeywordsSearch) {
  std::vector<std::string> two_keywords = {"race=Black", "gender=Male"};
  auto results = sse_->SearchProtocol(two_keywords);
  std::unordered_set<std::string> expected_results = {"ID_130162", "ID_130165"};
  EXPECT_EQ(results.size(), expected_results.size());
  std::unordered_set<std::string> actual_results(results.begin(),
                                                 results.end());
  EXPECT_EQ(actual_results, expected_results);
}

// 测试三个关键词
TEST_F(SSETest, ThreeKeywordsSearch) {
  std::vector<std::string> three_keywords = {"race=Black", "gender=Male",
                                             "relationship=Husband"};
  auto results = sse_->SearchProtocol(three_keywords);
  std::unordered_set<std::string> expected_results = {"ID_130165"};
  EXPECT_EQ(results.size(), expected_results.size());
  std::unordered_set<std::string> actual_results(results.begin(),
                                                 results.end());
  EXPECT_EQ(actual_results, expected_results);
}

// 测试两个关键词，结果为空
TEST_F(SSETest, TwoKeywordsNotExistSearch) {
  std::vector<std::string> two_keywords_not_exist = {"race=Black",
                                                     "education=NonExistent"};
  auto results = sse_->SearchProtocol(two_keywords_not_exist);
  EXPECT_TRUE(results.empty());
}

// 测试多次搜索的一致性
TEST_F(SSETest, SearchConsistency) {
  std::vector<std::string> keyword = {"workclass=Private"};

  // 第一次搜索
  auto results1 = sse_->SearchProtocol(keyword);
  // 第二次搜索
  auto results2 = sse_->SearchProtocol(keyword);

  // 验证两次搜索结果一致
  EXPECT_EQ(results1.size(), results2.size());
  for (size_t i = 0; i < results1.size(); ++i) {
    EXPECT_EQ(results1[i], results2[i]);
  }
}

// 测试EDB的保存和加载
TEST_F(SSETest, SaveAndLoadEDB) {
  // 首先执行一次搜索并保存结果
  std::vector<std::string> keyword = {"education=Bachelors"};
  auto results_before = sse_->SearchProtocol(keyword);

  // 保存EDB到文件
  std::string test_dir = "/tmp/sse_test_data/";
  system(("mkdir -p " + test_dir).c_str());

  auto [k_map, tset, xset] = sse_->SaveEDB(
      test_dir + "K_map.bin", test_dir + "TSet.bin", test_dir + "XSet.bin");

  // 创建新的SSE实例并加载EDB
  auto new_sse = std::make_unique<SSE>();
  auto [loaded_k_map, loaded_tset, loaded_xset] = new_sse->LoadEDB(
      test_dir + "K_map.bin", test_dir + "TSet.bin", test_dir + "XSet.bin");

  // 使用加载后的实例执行相同的搜索
  auto results_after = new_sse->SearchProtocol(keyword);

  // 验证搜索结果一致性
  EXPECT_EQ(results_before.size(), results_after.size());
  for (size_t i = 0; i < results_before.size(); ++i) {
    EXPECT_EQ(results_before[i], results_after[i]);
  }
}

}  // namespace yacl::examples::primitives::sse

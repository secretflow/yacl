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

#include "yacl/examples/sse/sse.h"

#include <gtest/gtest.h>

#include <unordered_set>

#include "yacl/crypto/rand/rand.h"

namespace examples::sse {

class SseTest : public ::testing::Test {
 protected:
  void SetUp() override {
    sse_ = std::make_unique<Sse>(8,     // bucket_size
                                 8,     // slot_size
                                 128,   // lambda(security parameter)
                                 256);  // n_lambda

    auto [tset, kt] = sse_->EDBSetup();
    EXPECT_FALSE(tset.empty());
    EXPECT_FALSE(kt.empty());
  }

  std::unique_ptr<Sse> sse_;
};

TEST_F(SseTest, BasicSearch) {
  std::vector<std::string> keyword = {"race=Black"};
  auto results = sse_->SearchProtocol(keyword);
  std::unordered_set<std::string> expected_results = {"ID_130162", "ID_130165"};
  EXPECT_EQ(results.size(), expected_results.size());
  std::unordered_set<std::string> actual_results(results.begin(),
                                                 results.end());
  EXPECT_EQ(actual_results, expected_results);
}

TEST_F(SseTest, EmptyKeywordSearch) {
  std::vector<std::string> keyword_empty = {};
  auto results = sse_->SearchProtocol(keyword_empty);
  EXPECT_TRUE(results.empty());
}

TEST_F(SseTest, NonExistentKeywordSearch) {
  std::vector<std::string> non_existent = {"education=NonExistent"};
  auto results = sse_->SearchProtocol(non_existent);
  EXPECT_TRUE(results.empty());
}

TEST_F(SseTest, TwoKeywordsSearch) {
  std::vector<std::string> two_keywords = {"race=Black", "gender=Male"};
  auto results = sse_->SearchProtocol(two_keywords);
  std::unordered_set<std::string> expected_results = {"ID_130162", "ID_130165"};
  EXPECT_EQ(results.size(), expected_results.size());
  std::unordered_set<std::string> actual_results(results.begin(),
                                                 results.end());
  EXPECT_EQ(actual_results, expected_results);
}

TEST_F(SseTest, ThreeKeywordsSearch) {
  std::vector<std::string> three_keywords = {"race=Black", "gender=Male",
                                             "relationship=Husband"};
  auto results = sse_->SearchProtocol(three_keywords);
  std::unordered_set<std::string> expected_results = {"ID_130165"};
  EXPECT_EQ(results.size(), expected_results.size());
  std::unordered_set<std::string> actual_results(results.begin(),
                                                 results.end());
  EXPECT_EQ(actual_results, expected_results);
}

TEST_F(SseTest, TwoKeywordsNotExistSearch) {
  std::vector<std::string> two_keywords_not_exist = {"race=Black",
                                                     "education=NonExistent"};
  auto results = sse_->SearchProtocol(two_keywords_not_exist);
  EXPECT_TRUE(results.empty());
}

TEST_F(SseTest, SearchConsistency) {
  std::vector<std::string> keyword = {"workclass=Private"};

  auto results1 = sse_->SearchProtocol(keyword);
  auto results2 = sse_->SearchProtocol(keyword);

  EXPECT_EQ(results1.size(), results2.size());
  for (size_t i = 0; i < results1.size(); ++i) {
    EXPECT_EQ(results1[i], results2[i]);
  }
}

TEST_F(SseTest, SaveAndLoadEDB) {
  std::vector<std::string> keyword = {"education=Bachelors"};
  auto results_before = sse_->SearchProtocol(keyword);

  std::string test_dir = "/tmp/sse_test_data/";
  if (system(("mkdir -p " + test_dir).c_str()) != 0) {
    FAIL() << "Failed to create directory: " << test_dir;
  }

  sse_->SaveEDB(test_dir + "K_map.bin", test_dir + "TSet.bin",
                test_dir + "XSet.bin");

  auto new_sse = std::make_unique<Sse>();

  new_sse->LoadEDB(test_dir + "K_map.bin", test_dir + "TSet.bin",
                   test_dir + "XSet.bin");

  auto results_after = new_sse->SearchProtocol(keyword);

  EXPECT_EQ(results_before.size(), results_after.size());
  for (size_t i = 0; i < results_before.size(); ++i) {
    EXPECT_EQ(results_before[i], results_after[i]);
  }
}

}  // namespace examples::sse

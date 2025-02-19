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

#include "yacl/examples/sse/tset.h"

#include <gtest/gtest.h>

#include <memory>

namespace examples::sse {

class TSetTest : public ::testing::Test {
 protected:
  void SetUp() override {
    tset_ = std::make_unique<TSet>(2,     // bucket_size (b)
                                   3,     // slot_size (s)
                                   128);  // lambda
                                          //  256);  // n_lambda
  }
  std::unique_ptr<TSet> tset_;
};

TEST_F(TSetTest, Initialize) {
  EXPECT_EQ(tset_->GetTSet().size(), 2);
  EXPECT_EQ(tset_->GetTSet()[0].size(), 3);
  EXPECT_EQ(tset_->GetTSet()[0][0].label.size(), 128 / 8);
  EXPECT_EQ(tset_->GetTSet()[0][0].value.size(), 256 / 8 + 1);
  EXPECT_EQ(tset_->GetFree().size(), 2);
  EXPECT_EQ(tset_->GetFree()[0].size(), 3);
}

TEST_F(TSetTest, SetupAndGetTag) {
  std::unordered_map<std::string,
                     std::vector<std::pair<std::vector<uint8_t>, std::string>>>
      T = {
          {"keyword12",
           {{{11, 12, 13, 14, 15, 16, 17, 18, 19}, "value1"},
            {{21, 22, 23, 24, 25, 26, 27, 28, 29}, "value2"}}},
          {"keyword34",
           {{{31, 32, 33, 34, 35, 36, 37, 38, 39}, "value3"},
            {{41, 42, 43, 44, 45, 46, 47, 48, 49}, "value4"}}},
      };
  std::vector<std::string> keywords = {"keyword12", "keyword34"};

  auto Kt = tset_->TSetSetup(T, keywords);
  auto TSet = tset_->GetTSet();
  EXPECT_EQ(TSet.size(), 2);
  EXPECT_EQ(TSet[0].size(), 3);
  EXPECT_FALSE(Kt.empty());

  auto tag = tset_->TSetGetTag(Kt, "keyword12");
  EXPECT_EQ(tag.size(), 32);
}

// Test the complete retrieval flow
TEST_F(TSetTest, CompleteRetrievalFlow) {
  std::unordered_map<std::string,
                     std::vector<std::pair<std::vector<uint8_t>, std::string>>>
      T = {
          {"keyword12",
           {{{11, 12, 13, 14, 15, 16, 17, 18, 19}, "value1"},
            {{21, 22, 23, 24, 25, 26, 27, 28, 29}, "value2"}}},
          {"keyword34",
           {{{31, 32, 33, 34, 35, 36, 37, 38, 39}, "value3"},
            {{41, 42, 43, 44, 45, 46, 47, 48, 49}, "value4"}}},
      };
  std::vector<std::string> keywords = {"keyword12", "keyword34"};

  auto Kt = tset_->TSetSetup(T, keywords);
  auto TSet = tset_->GetTSet();

  std::string w = "keyword12";
  auto vector_stag = tset_->TSetGetTag(Kt, w);
  std::string stag = tset_->VectorToString(vector_stag);

  auto retrieved = tset_->TSetRetrieve(TSet, stag);

  EXPECT_EQ(retrieved.size(), 2);
  EXPECT_EQ(retrieved[0].first,
            std::vector<uint8_t>({11, 12, 13, 14, 15, 16, 17, 18, 19}));
  EXPECT_EQ(retrieved[0].second, "value1");
  EXPECT_EQ(retrieved[1].first,
            std::vector<uint8_t>({21, 22, 23, 24, 25, 26, 27, 28, 29}));
  EXPECT_EQ(retrieved[1].second, "value2");
}

}  // namespace examples::sse

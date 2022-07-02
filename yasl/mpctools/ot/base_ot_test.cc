#include "yasl/mpctools/ot/base_ot.h"

#include <future>
#include <thread>

#include "fmt/format.h"
#include "gtest/gtest.h"

#include "yasl/base/exception.h"
#include "yasl/crypto/utils.h"
#include "yasl/link/test_util.h"

namespace yasl {

struct TestParams {
  unsigned num_ot;
};

class BaseOtTest : public ::testing::TestWithParam<TestParams> {};

TEST_P(BaseOtTest, Works) {
  // GIVEN
  const int kWorldSize = 2;
  auto contexts = link::test::SetupWorld(kWorldSize);

  std::vector<std::array<Block, 2>> send_blocks;
  std::vector<Block> recv_blocks;

  auto params = GetParam();
  send_blocks.resize(params.num_ot);
  recv_blocks.resize(params.num_ot);

  // WHEN
  std::vector<bool> choices = CreateRandomChoices(params.num_ot);
  std::future<void> sender =
      std::async([&] { BaseOtSend(contexts[0], absl::MakeSpan(send_blocks)); });
  std::future<void> receiver = std::async(
      [&] { BaseOtRecv(contexts[1], choices, absl::MakeSpan(recv_blocks)); });
  sender.get();
  receiver.get();

  // THEN
  for (unsigned i = 0; i < params.num_ot; ++i) {
    unsigned idx = choices[i] ? 1 : 0;
    EXPECT_EQ(send_blocks[i][idx], recv_blocks[i]);
  }
}

INSTANTIATE_TEST_SUITE_P(Works_Instances, BaseOtTest,
                         testing::Values(TestParams{1},    //
                                         TestParams{128},  //
                                         TestParams{127},  //
                                         TestParams{233}   //
                                         ));

TEST(BaseOtEdgeTest, Test) {
  // GIVEN
  std::vector<std::array<Block, 2>> send_blocks;
  std::vector<Block> recv_blocks;
  std::vector<bool> choices;

  auto contexts = link::test::SetupWorld(2);

  // WHEN THEN
  ASSERT_THROW(BaseOtRecv(contexts[0], choices, absl::MakeSpan(recv_blocks)),
               ::yasl::Exception);
  ASSERT_THROW(BaseOtSend(contexts[1], absl::MakeSpan(send_blocks)),
               ::yasl::Exception);
}

}  // namespace yasl

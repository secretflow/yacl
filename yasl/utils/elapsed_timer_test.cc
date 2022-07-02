#include "yasl/utils/elapsed_timer.h"

#include <chrono>
#include <string>
#include <thread>

#include "gtest/gtest.h"

namespace yasl {

// 因为 sleep 函数本身不精确，允许 timer 实测值和预期值有一些误差
const static float kMarginPercent = 1.05;

int computeExpectedTimeInMs(int expect) {
  return static_cast<int>((expect == 0 ? 1 : expect) * kMarginPercent);
}

TEST(ElapsedTimerTest, zero) {
  ElapsedTimer timer;
  double cost_time_ms = timer.CountMs();
  EXPECT_LE(0, cost_time_ms);
  EXPECT_LE(cost_time_ms, computeExpectedTimeInMs(0));
}

TEST(ElapsedTimerTest, plus) {
  ElapsedTimer timer;
  int expect_cost_time_ms = 100;
  int relaxed_expect_cost_time_ms = computeExpectedTimeInMs(expect_cost_time_ms);
  std::this_thread::sleep_for(std::chrono::milliseconds(expect_cost_time_ms));
  double cost_time_ms = timer.CountMs();
  double cost_time_sec = timer.CountSec();
  EXPECT_LE(expect_cost_time_ms, cost_time_ms);
  EXPECT_LE(cost_time_ms, relaxed_expect_cost_time_ms);
  EXPECT_LE(expect_cost_time_ms / 1000.0, cost_time_sec);
  EXPECT_LE(cost_time_sec, (relaxed_expect_cost_time_ms) / 1000.0);

  timer.Pause();
  cost_time_ms = timer.CountMs();
  cost_time_sec = timer.CountSec();
  std::this_thread::sleep_for(std::chrono::milliseconds(expect_cost_time_ms));
  EXPECT_DOUBLE_EQ(cost_time_ms, timer.CountMs());
  EXPECT_DOUBLE_EQ(cost_time_sec, timer.CountSec());

  timer.Resume();
  std::this_thread::sleep_for(std::chrono::milliseconds(expect_cost_time_ms));
  expect_cost_time_ms *= 2;
  relaxed_expect_cost_time_ms = computeExpectedTimeInMs(expect_cost_time_ms);
  cost_time_ms = timer.CountMs();
  cost_time_sec = timer.CountSec();
  EXPECT_LE(expect_cost_time_ms, cost_time_ms);
  EXPECT_LE(cost_time_ms, relaxed_expect_cost_time_ms);
  EXPECT_LE(expect_cost_time_ms / 1000.0, cost_time_sec);
  EXPECT_LE(cost_time_sec, (relaxed_expect_cost_time_ms) / 1000.0);

  timer.Restart();
  expect_cost_time_ms = 100;
  relaxed_expect_cost_time_ms = computeExpectedTimeInMs(expect_cost_time_ms);
  std::this_thread::sleep_for(std::chrono::milliseconds(expect_cost_time_ms));
  cost_time_ms = timer.CountMs();
  cost_time_sec = timer.CountSec();
  EXPECT_LE(expect_cost_time_ms, cost_time_ms);
  EXPECT_LE(cost_time_ms, relaxed_expect_cost_time_ms);
  EXPECT_LE(expect_cost_time_ms / 1000.0, cost_time_sec);
  EXPECT_LE(cost_time_sec, (relaxed_expect_cost_time_ms) / 1000.0);

  timer.Pause();
  cost_time_ms = timer.CountMs();
  cost_time_sec = timer.CountSec();
  std::this_thread::sleep_for(std::chrono::milliseconds(expect_cost_time_ms));
  EXPECT_DOUBLE_EQ(cost_time_ms, timer.CountMs());
  EXPECT_DOUBLE_EQ(cost_time_sec, timer.CountSec());

  timer.Resume();
  std::this_thread::sleep_for(std::chrono::milliseconds(expect_cost_time_ms));
  expect_cost_time_ms *= 2;
  relaxed_expect_cost_time_ms = computeExpectedTimeInMs(expect_cost_time_ms);
  cost_time_ms = timer.CountMs();
  cost_time_sec = timer.CountSec();
  EXPECT_LE(expect_cost_time_ms, cost_time_ms);
  EXPECT_LE(cost_time_ms, relaxed_expect_cost_time_ms);
  EXPECT_LE(expect_cost_time_ms / 1000.0, cost_time_sec);
  EXPECT_LE(cost_time_sec, (relaxed_expect_cost_time_ms) / 1000.0);
}

}  // namespace yasl

// Copyright (c) 2020 Ant Financial Inc. All rights reserved.

#include "yacl/utils/thread_pool.h"

#include <atomic>
#include <thread>

#include "gtest/gtest.h"

namespace yacl {
namespace test {

constexpr static size_t kThreadPoolSize = 3;

namespace {
class Timer {
 public:
  Timer() { begin_point_ = std::chrono::steady_clock::now(); }

  double GetElapsedTimeInMs() const {
    auto end_point = std::chrono::steady_clock::now();
    double span = std::chrono::duration_cast<std::chrono::microseconds>(
                      end_point - begin_point_)
                      .count();
    return span / 1000.0;
  }

 private:
  std::chrono::steady_clock::time_point begin_point_;
};
}  // namespace

class ThreadPoolTest : public ::testing::Test {
 public:
  ThreadPoolTest() : thread_pool_(kThreadPoolSize) {}

 protected:
  ThreadPool thread_pool_;
};

TEST_F(ThreadPoolTest, InThreadPoolTest) {
  ASSERT_EQ(thread_pool_.NumThreads(), kThreadPoolSize);
  ASSERT_FALSE(thread_pool_.InThreadPool());

  auto caller_id = std::this_thread::get_id();
  auto ret = thread_pool_.Submit([&caller_id]() {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    return std::this_thread::get_id() == caller_id;
  });
  ASSERT_FALSE(ret.get());

  ret = thread_pool_.Submit([this]() { return thread_pool_.InThreadPool(); });
  ASSERT_TRUE(ret.get());
}

TEST_F(ThreadPoolTest, DISABLED_ParallelTest) {
  Timer timer;

  std::future<void> futures[kThreadPoolSize];
  for (auto& future : futures) {
    future = thread_pool_.Submit(
        []() { std::this_thread::sleep_for(std::chrono::milliseconds(100)); });
  }

  EXPECT_LT(timer.GetElapsedTimeInMs(), 80);
  for (auto& future : futures) {
    future.wait();
  }
  EXPECT_GE(timer.GetElapsedTimeInMs(), 100);
  EXPECT_LT(timer.GetElapsedTimeInMs(), 200);
}

TEST_F(ThreadPoolTest, MoreTasksTest) {
  std::atomic<int32_t> sum(0);

  std::future<void> futures[kThreadPoolSize * 10];
  for (auto& future : futures) {
    future = thread_pool_.Submit([&sum]() {
      for (int32_t i = 0; i < 10000; ++i) {
        ++sum;
      }
    });
  }

  // wait all
  for (auto& feature : futures) {
    feature.get();
  }

  EXPECT_EQ(sum.load(), 10000 * kThreadPoolSize * 10);
}

TEST_F(ThreadPoolTest, ParamsTest) {
  auto func1 = [](int a) { return a; };
  auto func2 = [](int a, long b) -> int { return a + b; };
  auto func3 = [](int a, int b, const uint32_t& c) -> int { return a + b + c; };

  std::vector<std::future<int>> futures;
  for (int i = 0; i < 600; i += 6) {
    futures.push_back(thread_pool_.Submit(func1, i));
    futures.push_back(thread_pool_.Submit(func2, i + 1, i + 2));
    futures.push_back(thread_pool_.Submit(func3, i + 3, i + 4, i + 5));
  }

  // get all
  int sum = 0;
  for (auto& feature : futures) {
    sum += feature.get();
  }

  EXPECT_EQ(sum, 600 * 599 / 2);  // 即 0..599 之和
}

TEST_F(ThreadPoolTest, ExceptionTest) {
  std::future<void> futures[7];
  futures[0] = thread_pool_.Submit([]() { throw RuntimeError(); });
  futures[1] = thread_pool_.Submit([]() { throw IoError(); });
  futures[2] = thread_pool_.Submit([]() { throw LogicError(); });
  futures[3] = thread_pool_.Submit([]() { throw std::exception(); });
  futures[4] = thread_pool_.Submit([]() { throw 1L; });
  futures[5] = thread_pool_.Submit([]() { throw "hello"; });
  futures[6] =
      thread_pool_.Submit([]() { throw std::string("is anybody here"); });

  // wait() always no throw
  for (auto& future : futures) {
    EXPECT_NO_THROW(future.wait());
  }

  EXPECT_THROW(futures[0].get(), RuntimeError);
  EXPECT_THROW(futures[1].get(), IoError);
  EXPECT_THROW(futures[2].get(), LogicError);
  EXPECT_THROW(futures[3].get(), std::exception);
  EXPECT_THROW(futures[4].get(), long);
  EXPECT_THROW(futures[5].get(), const char*);
  EXPECT_THROW(futures[6].get(), std::string);

  auto one_more_future =
      thread_pool_.Submit([]() { return "no throw, just return"; });
  EXPECT_NO_THROW(one_more_future.get());
}

}  // namespace test
}  // namespace yacl

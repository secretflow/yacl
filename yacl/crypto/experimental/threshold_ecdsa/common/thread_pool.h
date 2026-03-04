#pragma once

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <future>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace tecdsa {

class ThreadPool {
 public:
  explicit ThreadPool(size_t worker_count) {
    if (worker_count == 0) {
      throw std::invalid_argument("ThreadPool worker_count must be > 0");
    }

    workers_.reserve(worker_count);
    for (size_t i = 0; i < worker_count; ++i) {
      workers_.emplace_back([this]() { WorkerLoop(); });
    }
  }

  ~ThreadPool() {
    {
      std::lock_guard<std::mutex> lock(mu_);
      stop_ = true;
    }
    cv_.notify_all();
    for (std::thread& worker : workers_) {
      if (worker.joinable()) {
        worker.join();
      }
    }
  }

  ThreadPool(const ThreadPool&) = delete;
  ThreadPool& operator=(const ThreadPool&) = delete;
  ThreadPool(ThreadPool&&) = delete;
  ThreadPool& operator=(ThreadPool&&) = delete;

  template <typename Fn>
  auto Submit(Fn&& fn) -> std::future<std::invoke_result_t<Fn>> {
    using Result = std::invoke_result_t<Fn>;

    auto task = std::make_shared<std::packaged_task<Result()>>(std::forward<Fn>(fn));
    std::future<Result> future = task->get_future();
    {
      std::lock_guard<std::mutex> lock(mu_);
      if (stop_) {
        throw std::runtime_error("cannot submit task to stopped ThreadPool");
      }
      queue_.push_back([task]() { (*task)(); });
    }
    cv_.notify_one();
    return future;
  }

 private:
  void WorkerLoop() {
    while (true) {
      std::function<void()> task;
      {
        std::unique_lock<std::mutex> lock(mu_);
        cv_.wait(lock, [this]() { return stop_ || !queue_.empty(); });
        if (stop_ && queue_.empty()) {
          return;
        }
        task = std::move(queue_.front());
        queue_.pop_front();
      }
      task();
    }
  }

  std::vector<std::thread> workers_;
  std::deque<std::function<void()>> queue_;
  std::mutex mu_;
  std::condition_variable cv_;
  bool stop_ = false;
};

}  // namespace tecdsa

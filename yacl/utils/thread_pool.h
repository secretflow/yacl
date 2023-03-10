// Copyright 2019 Ant Group Co., Ltd.
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
//
// Brief: A simple thread pool

#pragma once

#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <type_traits>
#include <vector>

#include "yacl/base/exception.h"

namespace yacl {

class ThreadPool {
 public:
  ThreadPool();
  explicit ThreadPool(size_t num_threads);

  ThreadPool(const ThreadPool &) = delete;
  ThreadPool &operator=(const ThreadPool &) = delete;

  ~ThreadPool();

  static size_t DefaultNumThreads();

  size_t NumThreads() { return threads_.size(); }

  // Submit task
  // if the thread pool has idle thread, the task will run immediately,
  // otherwise the task will wait in a queue.
  template <class F, class... Args>
  auto Submit(F &&f, Args &&...args)
      -> std::future<typename std::invoke_result_t<F, Args...>>;

  // return true if the current (self) thread is a pooled thread
  bool InThreadPool() const;

  // get queue length.
  // don't need to lock mutex here, because length may be changed after the function
  // returned
  size_t GetQueueLength() const { return tasks_.size(); }

 private:
  void WorkLoop();

  // need to keep track of threads so we can join them
  std::vector<std::thread> threads_;
  // the task queue
  std::queue<std::function<void()>> tasks_;

  // synchronization
  std::mutex queue_mutex_;
  std::condition_variable condition_;
  bool stop_;
};

template <class F, class... Args>
auto ThreadPool::Submit(F &&f, Args &&...args)
    -> std::future<typename std::invoke_result_t<F, Args...>> {
  using return_type = typename std::invoke_result_t<F, Args...>;

  auto task = std::make_shared<std::packaged_task<return_type()>>(
      std::bind(std::forward<F>(f), std::forward<Args>(args)...));

  std::future<return_type> res = task->get_future();
  {
    std::unique_lock<std::mutex> lock(queue_mutex_);

    // don't allow enqueueing after stopping the pool
    YACL_ENFORCE(!stop_, "Submit on a stopped ThreadPool");

    tasks_.emplace([task]() { (*task)(); });
  }
  condition_.notify_one();
  return res;
}

}  // namespace yacl

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

#include "yacl/utils/thread_pool.h"

#include "spdlog/spdlog.h"

namespace yacl {

size_t ThreadPool::DefaultNumThreads() {
  auto num_threads = std::thread::hardware_concurrency();
  return num_threads;
}

ThreadPool::ThreadPool() : ThreadPool(DefaultNumThreads()) {}

// the constructor just launches some amount of workers
ThreadPool::ThreadPool(size_t num_threads) : stop_(false) {
  SPDLOG_INFO("Create a fixed thread pool with size {}", num_threads);
  YACL_ENFORCE(num_threads > 0, "num_threads must > 0");

  for (size_t i = 0; i < num_threads; ++i) {
    threads_.emplace_back(&ThreadPool::WorkLoop, this);
  }
}

void ThreadPool::WorkLoop() {
  while (true) {
    std::function<void()> task;

    {
      std::unique_lock<std::mutex> lock(this->queue_mutex_);
      this->condition_.wait(
          lock, [this] { return this->stop_ || !this->tasks_.empty(); });
      if (this->stop_ && this->tasks_.empty()) {
        return;
      }
      task = std::move(this->tasks_.front());
      this->tasks_.pop();
    }

    // note: the exception in task() will automatically catched by FUTURE object
    // and the exception will rethrow in caller thread on FUTURE.get() called.
    task();
  }
}

// the destructor joins all threads
ThreadPool::~ThreadPool() {
  {
    std::unique_lock<std::mutex> lock(queue_mutex_);
    stop_ = true;
  }

  condition_.notify_all();
  for (std::thread& worker : threads_) {
    worker.join();
  }
}

bool ThreadPool::InThreadPool() const {
  return std::any_of(threads_.begin(), threads_.end(),
                     [](const std::thread& thread) {
                       return thread.get_id() == std::this_thread::get_id();
                     });
}

}  // namespace yacl

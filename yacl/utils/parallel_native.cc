// Copyright (c) 2016 Facebook Inc.
#include <atomic>
#include <future>

#include "yacl/utils/parallel.h"
#include "yacl/utils/thread_pool.h"

namespace yacl {
namespace {
// used with _set_in_parallel_region to mark master thread
// as in parallel region while executing parallel primitives
thread_local bool in_parallel_region_ = false;

// thread number (task_id) set by parallel primitive
thread_local size_t thread_num_ = 0;

void _set_in_parallel_region(bool in_region) {
  in_parallel_region_ = in_region;
}

void _set_thread_num(size_t thread_num) { thread_num_ = thread_num; }

void _unset_thread_num() { thread_num_ = 0; }

const int NOT_SET = -1;
const int CONSUMED = -2;

// Number of threads set by the user
// NOT_SET -> positive value -> CONSUMED
// or
// NOT_SET -> CONSUMED
// Meaning:
//  - NOT_SET - pool not initialized, user value is not set
//  - positive value - pool not initialized, user value set
//  - CONSUMED - pool is initialized
std::atomic<int> num_intraop_threads{NOT_SET};

int _num_pool_threads(int nthreads) {
  if (nthreads == NOT_SET) {
    nthreads = intraop_default_num_threads();
  } else {
    YACL_ENFORCE(nthreads > 0);
  }
  // minus one because of the master thread
  return nthreads - 1;
}

ThreadPool& _get_intraop_pool() {
  static std::shared_ptr<ThreadPool> pool = std::make_shared<ThreadPool>(
      _num_pool_threads(num_intraop_threads.exchange(CONSUMED)));
  return *pool;
}

// RAII guard helps to support in_parallel_region() and get_thread_num() API.
struct ParallelRegionGuard {
  ParallelRegionGuard(int64_t task_id) {
    _set_thread_num(task_id);
    _set_in_parallel_region(true);
  }

  ~ParallelRegionGuard() {
    _set_in_parallel_region(false);
    _unset_thread_num();
  }
};

}  // namespace

namespace internal {

void _parallel_run(const int64_t begin, const int64_t end,
                   const int64_t grain_size,
                   const std::function<void(int64_t, int64_t, size_t)>& f) {
  size_t num_tasks;
  size_t chunk_size;
  std::tie(num_tasks, chunk_size) =
      internal::calc_num_tasks_and_chunk_size(begin, end, grain_size);

  auto task = [f, begin, end, chunk_size](size_t task_id) {
    int64_t local_start = begin + task_id * chunk_size;
    if (local_start < end) {
      int64_t local_end =
          std::min(end, static_cast<int64_t>(chunk_size + local_start));
      {
        ParallelRegionGuard guard(task_id);
        f(local_start, local_end, task_id);
      }
    }
  };

  // submit tasks
  std::vector<std::future<void>> futures;
  futures.reserve(num_tasks);
  for (size_t i = 1; i < num_tasks; ++i) {
    futures.push_back(_get_intraop_pool().Submit(task, i));
  }

  std::exception_ptr eptr;
  // Run the first task on the current thread directly.
  try {
    task(0);
  } catch (...) {
    eptr = std::current_exception();
  }

  // Wait for all tasks to finish.
  for (auto& future : futures) {
    // wait and throw exception.
    // if the task in thread pool throws an exception, the get() will rethrow it
    try {
      future.get();
    } catch (...) {
      // we catch exception here just to make sure all threads are finished
      // after parallel_for()/parallel_reduce() returned.
      eptr = std::current_exception();
    }
  }

  if (eptr) {
    std::rethrow_exception(eptr);
  }
}

}  // namespace internal

void init_num_threads() {}

void set_num_threads(int nthreads) {
  YACL_ENFORCE(nthreads > 0);
  int no_value = NOT_SET;
  if (!num_intraop_threads.compare_exchange_strong(no_value, nthreads)) {
    // num_intraop_threads either stores a positive integer or CONSUMED,
    // check that requested size is the same as the current one
    int stored_nthreads = num_intraop_threads.load();
    if (stored_nthreads <= 0) {
      // plus one because of master thread
      stored_nthreads = _get_intraop_pool().NumThreads() + 1;
    }
    if (stored_nthreads != nthreads) {
      YACL_ENFORCE(
          "Cannot set number of intraop threads "
          "after parallel work has started or after set_num_threads call "
          "when using native parallel backend");
    }
  }
}

int get_num_threads() {
  // not initializing pool unnecessarily,
  // because pool cannot be resized after initialization
  int nthreads = num_intraop_threads.load();
  if (nthreads > 0) {
    return nthreads;
  }
  if (nthreads == NOT_SET) {
    return intraop_default_num_threads();
  }
  YACL_ENFORCE(nthreads == CONSUMED);
  return _get_intraop_pool().NumThreads() + 1;
}

int get_thread_num() { return thread_num_; }

bool in_parallel_region() {
  return in_parallel_region_ ||
         (num_intraop_threads.load() == CONSUMED &&
          // Needed as intraop_launch() doesn't set in_parallel_region().
          _get_intraop_pool().InThreadPool());
}

}  // namespace yacl

// Copyright 2023 Ant Group Co., Ltd.
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

#pragma once

#include "yacl/base/exception.h"

namespace yacl {

inline int64_t divup(int64_t x, int64_t y) { return (x + y - 1) / y; }

// Called during new thread initialization
void init_num_threads();

// Sets the number of threads to be used in parallel region
void set_num_threads(int);

// Returns the number of threads used in parallel region
int get_num_threads();
int get_thread_id();
bool in_parallel_region();

// Returns number of intra-op threads used by default
int intraop_default_num_threads();

namespace internal {

inline std::tuple<size_t, size_t> calc_num_tasks_and_chunk_size(
    int64_t begin, int64_t end, int64_t grain_size) {
  if ((end - begin) < grain_size) {
    return std::make_tuple(1, std::max(static_cast<int64_t>(0), end - begin));
  }
  // Choose number of tasks based on grain size and number of threads.
  size_t chunk_size = divup((end - begin), get_num_threads());
  // Make sure each task is at least grain_size size.
  chunk_size = std::max(static_cast<size_t>(grain_size), chunk_size);
  size_t num_tasks = divup((end - begin), chunk_size);
  return std::make_tuple(num_tasks, chunk_size);
}

void _parallel_run(int64_t begin, int64_t end, int64_t grain_size,
                   const std::function<void(int64_t, int64_t, size_t)>& f);

}  // namespace internal

/*
parallel_for

begin: index at which to start applying user function

end: index at which to stop applying user function

grain_size: number of elements per chunk. impacts the degree of parallelization

f: user function applied in parallel to the chunks, signature:
  void f(int64_t begin, int64_t end)

Warning: parallel_for does NOT copy thread local
states from the current thread to the worker threads.
This means for example that Tensor operations CANNOT be used in the
body of your function, only data pointers.
*/
template <typename F>
inline void parallel_for(int64_t begin, int64_t end, int64_t grain_size,
                         F&& f) {
  YACL_ENFORCE(grain_size > 0);
  if (begin >= end) {
    return;
  }
  if ((end - begin) < grain_size || in_parallel_region()) {
    f(begin, end);
    return;
  }
  internal::_parallel_run(begin, end, grain_size,
                          [f](int64_t fstart, int64_t fend,
                              size_t /* unused */) { f(fstart, fend); });
}

inline void parallel_for(int64_t begin, int64_t end,
                         const std::function<void(int64_t, int64_t)>& f) {
  parallel_for(begin, end, 1, f);
}

/*
parallel_reduce

begin: index at which to start applying reduction

end: index at which to stop applying reduction

grain_size: number of elements per chunk. impacts number of elements in
intermediate results tensor and degree of parallelization.

reduce_f: function for reduction over a chunk.
combine_f: function to combine two partial results.

For example, you might have a tensor of 10000 entires and want to sum together
all the elements. Parallel_reduce with a grain_size of 2500 will then allocate
an intermediate result tensor with 4 elements. Then it will execute the function
"f" you provide and pass the beginning and end index of these chunks, so
0-2499, 2500-4999, etc. and the combination identity. It will then write out
the result from each of these chunks into the intermediate result tensor. After
that it'll reduce the partial results from each chunk into a single number using
the combination function sf and the identity ident. For a total summation this
would be "+" and 0 respectively. This is similar to tbb's approach [1], where
you need to provide a function to accumulate a subrange, a function to combine
two partial results and an identity.

Warning: parallel_reduce does NOT copy thread local
states from the current thread to the worker threads.
This means for example that Tensor operations CANNOT be used in the
body of your function, only data pointers.

[1] https://software.intel.com/en-us/node/506154
*/
template <class scalar_t, class F, class SF>
inline scalar_t parallel_reduce(const int64_t begin, const int64_t end,
                                const int64_t grain_size, const F& reduce_f,
                                const SF& combine_f) {
  YACL_ENFORCE(grain_size > 0);
  YACL_ENFORCE(begin < end, "begin={}, end={}", begin, end);

  if ((end - begin) < grain_size || in_parallel_region()) {
    return reduce_f(begin, end);
  }

  size_t num_tasks;
  size_t chunk_size;
  std::tie(num_tasks, chunk_size) =
      internal::calc_num_tasks_and_chunk_size(begin, end, grain_size);
  std::vector<scalar_t> results(num_tasks);
  internal::_parallel_run(begin, end, grain_size,
                          [&](int64_t fstart, int64_t fend, size_t task_id) {
                            results[task_id] = reduce_f(fstart, fend);
                          });
  auto result = results[0];
  for (size_t i = 1; i < results.size(); ++i) {
    result = combine_f(result, results[i]);
  }
  return result;
}

}  // namespace yacl

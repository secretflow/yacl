// Copyright (c) 2016 Facebook Inc.
#pragma once

#include <cstddef>
#include <exception>
#include <functional>
#include <tuple>
#include <vector>

#include "yacl/utils/parallel.h"

namespace yacl {
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

inline void parallel_for(int64_t begin, int64_t end, int64_t grain_size,
                         const std::function<void(int64_t, int64_t)>& f) {
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

template <class RES_T>
inline RES_T parallel_reduce(
    int64_t begin, int64_t end, int64_t grain_size,
    const std::function<RES_T(int64_t, int64_t)>& reduce_f,
    const std::function<RES_T(const RES_T&, const RES_T&)>& combine_f) {
  YACL_ENFORCE(grain_size > 0);
  YACL_ENFORCE(begin < end, "begin={}, end={}", begin, end);

  if ((end - begin) < grain_size || in_parallel_region()) {
    return reduce_f(begin, end);
  }

  size_t num_tasks;
  size_t chunk_size;
  std::tie(num_tasks, chunk_size) =
      internal::calc_num_tasks_and_chunk_size(begin, end, grain_size);
  std::vector<RES_T> results(num_tasks);
  RES_T* results_data = results.data();
  internal::_parallel_run(
      begin, end, grain_size,
      [&reduce_f, results_data](int64_t fstart, int64_t fend, size_t task_id) {
        results_data[task_id] = reduce_f(fstart, fend);
      });
  RES_T result = results[0];
  for (size_t i = 1; i < results.size(); ++i) {
    result = combine_f(result, results[i]);
  }
  return result;
}

}  // namespace yacl

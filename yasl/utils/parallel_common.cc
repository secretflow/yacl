// Copyright (c) 2016 Facebook Inc.
#include <sstream>

#include "yasl/utils/parallel.h"
#include "yasl/utils/thread_pool.h"

namespace yasl {
namespace {

size_t get_env_num_threads(const char* var_name, size_t def_value = 0) {
  try {
    if (auto* value = std::getenv(var_name)) {
      int nthreads = std::stoi(value);
      YASL_ENFORCE(nthreads > 0);
      return nthreads;
    }
  } catch (const std::exception& e) {
    YASL_ENFORCE("Invalid {} variable value: {}", var_name, e.what());
  }
  return def_value;
}

}  // namespace

int intraop_default_num_threads() {
  size_t nthreads = get_env_num_threads("OMP_NUM_THREADS", 0);
  if (nthreads == 0) {
    nthreads = ThreadPool::DefaultNumThreads();
  }
  return nthreads;
}

}  // namespace yasl

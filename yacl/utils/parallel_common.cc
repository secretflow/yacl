// Copyright (c) 2016 Facebook Inc.
#include <sstream>

#include "yacl/utils/parallel.h"
#include "yacl/utils/thread_pool.h"

namespace yacl {
namespace {

size_t get_env_num_threads(const char* var_name, size_t def_value = 0) {
  try {
    if (auto* value = std::getenv(var_name)) {
      int nthreads = std::stoi(value);
      YACL_ENFORCE(nthreads > 0);
      return nthreads;
    }
  } catch (const std::exception& e) {
    YACL_ENFORCE("Invalid {} variable value: {}", var_name, e.what());
  }
  return def_value;
}

}  // namespace

int intraop_default_num_threads() {
  size_t nthreads = get_env_num_threads("YACL_NUM_THREADS", 0);
  if (nthreads == 0) {
    nthreads = ThreadPool::DefaultNumThreads();
  }
  return nthreads;
}

}  // namespace yacl

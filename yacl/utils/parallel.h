// Copyright (c) 2016 Facebook Inc.
#pragma once

#include "yacl/base/exception.h"

namespace yacl {
namespace internal {
// This parameter is heuristically chosen to determine the minimum number of
// work that warrants parallelism. For example, when summing an array, it is
// deemed inefficient to parallelise over arrays shorter than 32768. Further,
// no parallel algorithm (such as parallel_reduce) should split work into
// smaller than GRAIN_SIZE chunks.
constexpr int64_t GRAIN_SIZE = 32768;
}  // namespace internal

inline int64_t divup(int64_t x, int64_t y) { return (x + y - 1) / y; }

// Called during new thread initialization
void init_num_threads();

// Sets the number of threads to be used in parallel region
void set_num_threads(int);

// Returns the number of threads used in parallel region
int get_num_threads();

// Returns the current thread number (starting from 0)
// in the current parallel region, or 0 in the sequential region
int get_thread_num();

// Checks whether the code runs in parallel region
bool in_parallel_region();

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
inline void parallel_for(int64_t begin, int64_t end, int64_t grain_size,
                         const std::function<void(int64_t, int64_t)>& f);

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
template <class RES_T>
inline RES_T parallel_reduce(
    int64_t begin, int64_t end, int64_t grain_size,
    const std::function<RES_T(int64_t, int64_t)>& reduce_f,
    const std::function<RES_T(const RES_T&, const RES_T&)>& combine_f);

// Returns number of intra-op threads used by default
int intraop_default_num_threads();

}  // namespace yacl

#include "yacl/utils/parallel_native.h"

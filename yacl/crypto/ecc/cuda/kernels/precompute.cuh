// Copyright 2025 Ant Group Co., Ltd.
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

#include <cuda_runtime.h>

#include "yacl/crypto/ecc/cuda/kernels/gpu_types.cuh"

namespace yacl::crypto::cuda {

// Fixed-base precomputation (Comb method)
constexpr int kFixedBaseWindowSize = 4;
constexpr int kNumWindows = (256 + kFixedBaseWindowSize - 1) / kFixedBaseWindowSize;
constexpr int kTableEntriesPerWindow = 1 << kFixedBaseWindowSize;
constexpr int kFixedBaseTableSize = kNumWindows * kTableEntriesPerWindow;

void copyTableToConstantMemory(const GpuAffinePoint* hostTable);

// wNAF for variable-base multiplication
constexpr int kVarBaseWindowSize = 4;
constexpr int kMaxWnafDigits = 256;
using WnafDigit = int8_t;
constexpr int kVarBaseTableSize = (1 << (kVarBaseWindowSize - 2));

__device__ int scalarToWnaf(const GpuScalar& scalar, WnafDigit* wnaf);
__device__ void buildVarBaseTable(const GpuJacobianPoint& P,
                                  GpuJacobianPoint* table);

// Double-base multiplication: s1 * G + s2 * P
struct DoubleBaseWnaf {
  WnafDigit wnaf1[kMaxWnafDigits + 1];
  WnafDigit wnaf2[kMaxWnafDigits + 1];
  int length;
};

__device__ void prepareDoubleBaseWnaf(const GpuScalar& s1, const GpuScalar& s2,
                                      DoubleBaseWnaf& result);

}  // namespace yacl::crypto::cuda

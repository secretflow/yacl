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

#include <cstdint>

namespace yacl::crypto::cuda {

// 256-bit field element in Montgomery form (4 x 64-bit limbs, little-endian)
struct GpuFieldElement {
  uint64_t limbs[4];
};

// 256-bit scalar (little-endian)
struct GpuScalar {
  uint64_t limbs[4];
};

// Affine point (x, y)
struct GpuAffinePoint {
  GpuFieldElement x;
  GpuFieldElement y;
};

// Jacobian point (X : Y : Z) where affine = (X/Z^2, Y/Z^3)
struct GpuJacobianPoint {
  GpuFieldElement X;
  GpuFieldElement Y;
  GpuFieldElement Z;
};

struct BatchConfig {
  int32_t batch_size;
  int32_t threads_per_block;
  int32_t use_shared_memory;
};

enum class CudaEccError {
  kSuccess = 0,
  kInvalidInput = 1,
  kCudaError = 2,
  kMemoryError = 3,
  kNotOnCurve = 4,
};

}  // namespace yacl::crypto::cuda

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

// Field element operations (all in Montgomery form)

__device__ void fpAdd(const GpuFieldElement& a, const GpuFieldElement& b,
                      GpuFieldElement& r);
__device__ void fpSub(const GpuFieldElement& a, const GpuFieldElement& b,
                      GpuFieldElement& r);
__device__ void fpNeg(const GpuFieldElement& a, GpuFieldElement& r);
__device__ void fpMul(const GpuFieldElement& a, const GpuFieldElement& b,
                      GpuFieldElement& r);
__device__ void fpSqr(const GpuFieldElement& a, GpuFieldElement& r);
__device__ void fpInv(const GpuFieldElement& a, GpuFieldElement& r);
__device__ void fpToMont(const GpuFieldElement& a, GpuFieldElement& r);
__device__ void fpFromMont(const GpuFieldElement& a, GpuFieldElement& r);
__device__ bool fpIsZero(const GpuFieldElement& a);
__device__ bool fpEqual(const GpuFieldElement& a, const GpuFieldElement& b);
__device__ void fpCopy(const GpuFieldElement& a, GpuFieldElement& r);
__device__ void fpSetZero(GpuFieldElement& r);
__device__ void fpSetOne(GpuFieldElement& r);
__device__ void fpDouble(const GpuFieldElement& a, GpuFieldElement& r);
__device__ void fpTriple(const GpuFieldElement& a, GpuFieldElement& r);
__device__ void fpHalve(const GpuFieldElement& a, GpuFieldElement& r);
__device__ uint64_t add256(const uint64_t* a, const uint64_t* b, uint64_t* r);
__device__ uint64_t sub256(const uint64_t* a, const uint64_t* b, uint64_t* r);

}  // namespace yacl::crypto::cuda

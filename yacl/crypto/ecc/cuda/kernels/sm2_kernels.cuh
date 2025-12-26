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

#include <functional>

#include "yacl/crypto/ecc/cuda/kernels/gpu_types.cuh"
#include "yacl/crypto/ecc/cuda/kernels/point_ops.cuh"
#include "yacl/crypto/ecc/cuda/kernels/precompute.cuh"

namespace yacl::crypto::cuda {

// CUDA context management
int cudaSm2Init(int deviceId = 0);
void cudaSm2Cleanup();
cudaStream_t cudaSm2GetStream();

// Register a cleanup callback to be invoked during cudaSm2Cleanup().
// Use this to register thread-local resources (e.g., pinned host buffers)
// that need explicit cleanup before CUDA runtime is destroyed.
void cudaSm2RegisterCleanup(std::function<void()> cleanup);

// Batch scalar multiplication kernels
__global__ void batchFixedBaseMulKernel(const GpuScalar* scalars,
                                        GpuAffinePoint* results, int32_t count);
__global__ void batchVarBaseMulKernel(const GpuAffinePoint* points,
                                      const GpuScalar* scalars,
                                      GpuAffinePoint* results, int32_t count);
__global__ void batchSameScalarMulKernel(const GpuAffinePoint* points,
                                         const GpuScalar* scalar,
                                         GpuAffinePoint* results,
                                         int32_t count);
__global__ void batchDoubleBaseMulKernel(const GpuScalar* s1,
                                         const GpuScalar* s2,
                                         const GpuAffinePoint* points,
                                         GpuAffinePoint* results,
                                         int32_t count);

// Batch point arithmetic kernels
__global__ void batchPointAddKernel(const GpuAffinePoint* p1s,
                                    const GpuAffinePoint* p2s,
                                    GpuAffinePoint* results, int32_t count);
__global__ void batchPointDoubleKernel(const GpuAffinePoint* points,
                                       GpuAffinePoint* results, int32_t count);
__global__ void batchPointNegateKernel(const GpuAffinePoint* points,
                                       GpuAffinePoint* results, int32_t count);
__global__ void batchIsOnCurveKernel(const GpuAffinePoint* points,
                                     int32_t* results, int32_t count);

// Host wrapper functions
CudaEccError batchMulBase(const void* hostScalars, void* hostResults,
                          int32_t count, cudaStream_t stream = 0);
CudaEccError batchMul(const void* hostPoints, const void* hostScalars,
                      void* hostResults, int32_t count,
                      cudaStream_t stream = 0);
CudaEccError batchMulSameScalar(const void* hostPoints, const void* hostScalar,
                                void* hostResults, int32_t count,
                                cudaStream_t stream = 0);
CudaEccError batchMulDoubleBase(const void* hostS1, const void* hostS2,
                                const void* hostPoints, void* hostResults,
                                int32_t count, cudaStream_t stream = 0);
CudaEccError batchAdd(const void* hostP1s, const void* hostP2s,
                      void* hostResults, int32_t count,
                      cudaStream_t stream = 0);
CudaEccError batchDouble(const void* hostPoints, void* hostResults,
                         int32_t count, cudaStream_t stream = 0);
CudaEccError batchHashAndMulFromSm3Digests(const void* hostDigests,
                                           const void* hostScalar,
                                           void* hostResults, int32_t count,
                                           cudaStream_t stream = 0);

// Debug/utility functions
extern "C" CudaEccError debugMontMul(int32_t* hostResults,
                                     cudaStream_t stream = 0);
extern "C" CudaEccError debugReadScalar(const void* hostScalar,
                                        uint64_t* hostResults,
                                        cudaStream_t stream = 0);
void cudaSm2Sync(cudaStream_t stream = 0);
const char* cudaSm2GetLastError();
bool isCudaAvailable();
void getGpuMemoryInfo(size_t* free, size_t* total);

}  // namespace yacl::crypto::cuda

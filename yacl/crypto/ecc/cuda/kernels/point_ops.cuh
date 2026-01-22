// Copyright 2025 SaladDay
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

#include "yacl/crypto/ecc/cuda/kernels/field_ops.cuh"
#include "yacl/crypto/ecc/cuda/kernels/gpu_types.cuh"

namespace yacl::crypto::cuda {

// Point operations in Jacobian coordinates

__device__ bool pointIsInfinity(const GpuJacobianPoint& p);
__device__ void pointSetInfinity(GpuJacobianPoint& p);
__device__ void pointCopy(const GpuJacobianPoint& p, GpuJacobianPoint& r);
__device__ void affineToJacobian(const GpuAffinePoint& a, GpuJacobianPoint& j);
__device__ void jacobianToAffine(const GpuJacobianPoint& j, GpuAffinePoint& a);
__device__ void pointDouble(const GpuJacobianPoint& P, GpuJacobianPoint& R);
__device__ void pointAdd(const GpuJacobianPoint& P, const GpuJacobianPoint& Q,
                         GpuJacobianPoint& R);
__device__ void pointAddMixed(const GpuJacobianPoint& P,
                              const GpuAffinePoint& Q, GpuJacobianPoint& R);
__device__ void pointNegate(const GpuJacobianPoint& P, GpuJacobianPoint& R);
__device__ void pointSub(const GpuJacobianPoint& P, const GpuJacobianPoint& Q,
                         GpuJacobianPoint& R);
__device__ bool pointEqual(const GpuJacobianPoint& P,
                           const GpuJacobianPoint& Q);
__device__ bool pointIsOnCurve(const GpuJacobianPoint& P);

}  // namespace yacl::crypto::cuda

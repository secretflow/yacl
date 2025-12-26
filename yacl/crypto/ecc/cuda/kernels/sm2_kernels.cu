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

#include <cuda_runtime.h>
#include <stdio.h>

#include <functional>
#include <mutex>
#include <vector>

#include "yacl/crypto/ecc/cuda/kernels/sm2_kernels.cuh"

namespace yacl::crypto::cuda {

// SM2 prime p (little-endian)
__constant__ const uint64_t kSm2Prime[4] = {
    0xFFFFFFFFFFFFFFFFULL,  // limbs[0]
    0xFFFFFFFF00000000ULL,  // limbs[1]
    0xFFFFFFFFFFFFFFFFULL,  // limbs[2]
    0xFFFFFFFEFFFFFFFFULL   // limbs[3]
};

// R^2 mod p = (2^256)^2 mod p
// Used for converting to Montgomery form
__constant__ const uint64_t kSm2R2[4] = {
    0x0000000200000003ULL, 0x00000002FFFFFFFFULL, 0x0000000100000001ULL,
    0x0000000400000002ULL};

// Montgomery parameter mu = -p^(-1) mod 2^64
__constant__ const uint64_t kSm2Mu = 0x0000000000000001ULL;

// R mod p = 2^256 mod p (1 in Montgomery form)
__constant__ const uint64_t kSm2RModP[4] = {
    0x0000000000000001ULL, 0x00000000FFFFFFFFULL, 0x0000000000000000ULL,
    0x0000000100000000ULL};

// SM2 curve parameter a = -3 mod p (normal form)
__constant__ const GpuFieldElement kSm2A = {
    {0xFFFFFFFFFFFFFFFCULL, 0xFFFFFFFF00000000ULL, 0xFFFFFFFFFFFFFFFFULL,
     0xFFFFFFFEFFFFFFFFULL}};

// SM2 curve parameter b (normal form)
// b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
__constant__ const GpuFieldElement kSm2B = {
    {0xDDBCBD414D940E93ULL, 0xF39789F515AB8F92ULL, 0x4D5A9E4BCF6509A7ULL,
     0x28E9FA9E9D9F5E34ULL}};

// Montgomery form constants: vMont = v * R mod p.
__constant__ const GpuFieldElement kSm2AMont = {
    {0xFFFFFFFFFFFFFFFCULL, 0xFFFFFFFC00000003ULL, 0xFFFFFFFFFFFFFFFFULL,
     0xFFFFFFFBFFFFFFFFULL}};
__constant__ const GpuFieldElement kSm2BMont = {
    {0x90D230632BC0DD42ULL, 0x71CF379AE9B537ABULL, 0x527981505EA51C3CULL,
     0x240FE188BA20E2C8ULL}};

// SM2 generator point G (affine coordinates, in normal form)
// Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
// Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
__constant__ const GpuAffinePoint kSm2Generator = {
    // x coordinate (normal form)
    {{0x715A4589334C74C7ULL, 0x8FE30BBFF2660BE1ULL, 0x5F9904466A39C994ULL,
      0x32C4AE2C1F198119ULL}},
    // y coordinate (normal form)
    {{0x02DF32E52139F0A0ULL, 0xD0A9877CC62A4740ULL, 0x59BDCEE36B692153ULL,
      0xBC3736A2F4F6779CULL}}};

// SM2 curve order n =
// 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
__constant__ const uint64_t kSm2Order[4] = {
    0x53BBF40939D54123ULL, 0x7203DF6B21C6052BULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFEFFFFFFFFULL};

// Precomputed generator table - use global memory instead of constant memory
// (constant memory is limited to 64KB)
__device__ GpuAffinePoint* g_generatorTable = nullptr;
static GpuAffinePoint* h_generatorTableDevice = nullptr;

static cudaStream_t g_stream = nullptr;
static bool g_initialized = false;
static int g_deviceId = -1;
static int g_refCount = 0;
static std::mutex g_mutex;

namespace {

struct Sm2DeviceWorkspace {
  GpuAffinePoint* points = nullptr;
  size_t points_capacity = 0;

  GpuAffinePoint* points2 = nullptr;
  size_t points2_capacity = 0;

  GpuScalar* scalars = nullptr;
  size_t scalars_capacity = 0;

  GpuScalar* scalars2 = nullptr;
  size_t scalars2_capacity = 0;

  GpuAffinePoint* results = nullptr;
  size_t results_capacity = 0;

  uint8_t* digests = nullptr;
  size_t digests_capacity = 0;  // bytes

  int32_t* error = nullptr;
  size_t error_capacity = 0;
};

// Thread-local workspace for device memory, avoiding global lock contention.
// Each thread has its own workspace to enable parallel batch operations.
thread_local Sm2DeviceWorkspace tl_workspace;

// Registry for thread-local workspace cleanup.
// When a thread first uses tl_workspace, it registers a cleanup callback.
// cudaSm2Cleanup() invokes all registered callbacks.
std::vector<std::function<void()>> g_workspace_cleanups;
std::mutex g_workspace_cleanups_mutex;
thread_local bool tl_workspace_registered = false;

void registerWorkspaceCleanup() {
  if (tl_workspace_registered) {
    return;
  }
  Sm2DeviceWorkspace* ws = &tl_workspace;
  std::lock_guard<std::mutex> lock(g_workspace_cleanups_mutex);
  g_workspace_cleanups.push_back([ws]() {
    if (ws->points != nullptr) {
      cudaFree(ws->points);
      ws->points = nullptr;
      ws->points_capacity = 0;
    }
    if (ws->points2 != nullptr) {
      cudaFree(ws->points2);
      ws->points2 = nullptr;
      ws->points2_capacity = 0;
    }
    if (ws->scalars != nullptr) {
      cudaFree(ws->scalars);
      ws->scalars = nullptr;
      ws->scalars_capacity = 0;
    }
    if (ws->scalars2 != nullptr) {
      cudaFree(ws->scalars2);
      ws->scalars2 = nullptr;
      ws->scalars2_capacity = 0;
    }
    if (ws->results != nullptr) {
      cudaFree(ws->results);
      ws->results = nullptr;
      ws->results_capacity = 0;
    }
    if (ws->digests != nullptr) {
      cudaFree(ws->digests);
      ws->digests = nullptr;
      ws->digests_capacity = 0;
    }
    if (ws->error != nullptr) {
      cudaFree(ws->error);
      ws->error = nullptr;
      ws->error_capacity = 0;
    }
  });
  tl_workspace_registered = true;
}

template <typename T>
cudaError_t ensureDeviceArray(T** ptr, size_t* capacity, size_t count) {
  if (*capacity >= count) {
    return cudaSuccess;
  }
  if (*ptr != nullptr) {
    cudaFree(*ptr);
    *ptr = nullptr;
    *capacity = 0;
  }
  cudaError_t err = cudaMalloc(ptr, count * sizeof(T));
  if (err != cudaSuccess) {
    *ptr = nullptr;
    *capacity = 0;
    return err;
  }
  *capacity = count;
  return cudaSuccess;
}

cudaError_t ensureDeviceBytes(uint8_t** ptr, size_t* capacity, size_t bytes) {
  if (*capacity >= bytes) {
    return cudaSuccess;
  }
  if (*ptr != nullptr) {
    cudaFree(*ptr);
    *ptr = nullptr;
    *capacity = 0;
  }
  cudaError_t err = cudaMalloc(ptr, bytes);
  if (err != cudaSuccess) {
    *ptr = nullptr;
    *capacity = 0;
    return err;
  }
  *capacity = bytes;
  return cudaSuccess;
}

void cleanupAllWorkspaces() {
  std::lock_guard<std::mutex> lock(g_workspace_cleanups_mutex);
  for (auto& cleanup : g_workspace_cleanups) {
    if (cleanup) {
      cleanup();
    }
  }
  g_workspace_cleanups.clear();
}

}  // namespace

static inline CudaEccError toCudaEccError(cudaError_t err) {
  if (err == cudaSuccess) {
    return CudaEccError::kSuccess;
  }
  if (err == cudaErrorMemoryAllocation) {
    return CudaEccError::kMemoryError;
  }
  if (err == cudaErrorInvalidValue) {
    return CudaEccError::kInvalidInput;
  }
  return CudaEccError::kCudaError;
}

int cudaSm2Init(int deviceId) {
  std::lock_guard<std::mutex> lock(g_mutex);
  if (g_initialized) {
    ++g_refCount;
    return g_deviceId;
  }

  cudaError_t err = cudaSetDevice(deviceId);
  if (err != cudaSuccess) {
    return -1;
  }

  err = cudaStreamCreate(&g_stream);
  if (err != cudaSuccess) {
    g_stream = nullptr;
    return -1;
  }

  g_deviceId = deviceId;
  g_initialized = true;
  g_refCount = 1;
  return deviceId;
}

void cudaSm2Cleanup() {
  std::lock_guard<std::mutex> lock(g_mutex);
  if (!g_initialized) {
    return;
  }
  --g_refCount;
  if (g_refCount > 0) {
    return;
  }

  if (g_stream != nullptr) {
    cudaStreamSynchronize(g_stream);
  }

  // Clean up all thread-local workspaces via registered callbacks.
  cleanupAllWorkspaces();

  if (h_generatorTableDevice != nullptr) {
    GpuAffinePoint* null_table = nullptr;
    const cudaError_t sym_err =
        cudaMemcpyToSymbol(g_generatorTable, &null_table, sizeof(null_table));
    if (sym_err == cudaSuccess) {
      cudaFree(h_generatorTableDevice);
      h_generatorTableDevice = nullptr;
    }
  }

  if (g_stream != nullptr) {
    cudaStreamDestroy(g_stream);
    g_stream = nullptr;
  }
  g_initialized = false;
  g_deviceId = -1;
  g_refCount = 0;
}

cudaStream_t cudaSm2GetStream() { return g_stream; }

void cudaSm2RegisterCleanup(std::function<void()> cleanup) {
  if (!cleanup) {
    return;
  }
  std::lock_guard<std::mutex> lock(g_workspace_cleanups_mutex);
  g_workspace_cleanups.push_back(std::move(cleanup));
}

void cudaSm2Sync(cudaStream_t stream) {
  if (stream == 0) {
    stream = g_stream;
  }
  cudaStreamSynchronize(stream);
}

bool isCudaAvailable() {
  int deviceCount = 0;
  cudaError_t err = cudaGetDeviceCount(&deviceCount);
  return (err == cudaSuccess && deviceCount > 0);
}

void getGpuMemoryInfo(size_t* free, size_t* total) {
  cudaMemGetInfo(free, total);
}

const char* cudaSm2GetLastError() {
  return cudaGetErrorString(cudaGetLastError());
}

// Montgomery multiplication using CIOS method

// 256-bit addition with carry: r = a + b, returns carry
__device__ __forceinline__ uint64_t add256(const uint64_t* a, const uint64_t* b,
                                           uint64_t* r) {
  uint64_t carry = 0;
  uint64_t sum0 = a[0] + b[0];
  carry = (sum0 < a[0]) ? 1 : 0;
  r[0] = sum0;

  uint64_t sum1 = a[1] + b[1];
  uint64_t c1 = (sum1 < a[1]) ? 1 : 0;
  uint64_t sum1c = sum1 + carry;
  uint64_t c1c = (sum1c < sum1) ? 1 : 0;
  r[1] = sum1c;
  carry = (c1 | c1c);

  uint64_t sum2 = a[2] + b[2];
  uint64_t c2 = (sum2 < a[2]) ? 1 : 0;
  uint64_t sum2c = sum2 + carry;
  uint64_t c2c = (sum2c < sum2) ? 1 : 0;
  r[2] = sum2c;
  carry = (c2 | c2c);

  uint64_t sum3 = a[3] + b[3];
  uint64_t c3 = (sum3 < a[3]) ? 1 : 0;
  uint64_t sum3c = sum3 + carry;
  uint64_t c3c = (sum3c < sum3) ? 1 : 0;
  r[3] = sum3c;
  carry = (c3 | c3c);

  return carry;
}

// 256-bit subtraction with borrow: r = a - b, returns borrow
__device__ __forceinline__ uint64_t sub256(const uint64_t* a, const uint64_t* b,
                                           uint64_t* r) {
  uint64_t borrow = 0;
  uint64_t tmp0 = a[0] - b[0];
  borrow = (a[0] < b[0]) ? 1 : 0;
  r[0] = tmp0;

  uint64_t tmp1 = a[1] - b[1] - borrow;
  borrow = borrow ? (a[1] <= b[1]) : (a[1] < b[1]);
  r[1] = tmp1;

  uint64_t tmp2 = a[2] - b[2] - borrow;
  borrow = borrow ? (a[2] <= b[2]) : (a[2] < b[2]);
  r[2] = tmp2;

  uint64_t tmp3 = a[3] - b[3] - borrow;
  borrow = borrow ? (a[3] <= b[3]) : (a[3] < b[3]);
  r[3] = tmp3;

  return borrow;
}

// Field element helper functions

__device__ void fpCopy(const GpuFieldElement& a, GpuFieldElement& r) {
  r.limbs[0] = a.limbs[0];
  r.limbs[1] = a.limbs[1];
  r.limbs[2] = a.limbs[2];
  r.limbs[3] = a.limbs[3];
}

__device__ void fpSetZero(GpuFieldElement& r) {
  r.limbs[0] = 0;
  r.limbs[1] = 0;
  r.limbs[2] = 0;
  r.limbs[3] = 0;
}

__device__ bool fpIsZero(const GpuFieldElement& a) {
  return (a.limbs[0] | a.limbs[1] | a.limbs[2] | a.limbs[3]) == 0;
}

__device__ bool fpEqual(const GpuFieldElement& a, const GpuFieldElement& b) {
  return (a.limbs[0] == b.limbs[0]) && (a.limbs[1] == b.limbs[1]) &&
         (a.limbs[2] == b.limbs[2]) && (a.limbs[3] == b.limbs[3]);
}

__device__ void fpSetOne(GpuFieldElement& r) {
  // 1 in Montgomery form = R mod p
  r.limbs[0] = kSm2RModP[0];
  r.limbs[1] = kSm2RModP[1];
  r.limbs[2] = kSm2RModP[2];
  r.limbs[3] = kSm2RModP[3];
}

__device__ void fpAdd(const GpuFieldElement& a, const GpuFieldElement& b,
                      GpuFieldElement& r) {
  uint64_t carry = add256(a.limbs, b.limbs, r.limbs);

  // If carry or r >= p, subtract p
  uint64_t tmp[4];
  uint64_t borrow = sub256(r.limbs, kSm2Prime, tmp);

  // Select r - p if no borrow, otherwise keep r
  bool select_sub = (carry != 0) || (borrow == 0);
  r.limbs[0] = select_sub ? tmp[0] : r.limbs[0];
  r.limbs[1] = select_sub ? tmp[1] : r.limbs[1];
  r.limbs[2] = select_sub ? tmp[2] : r.limbs[2];
  r.limbs[3] = select_sub ? tmp[3] : r.limbs[3];
}

__device__ void fpSub(const GpuFieldElement& a, const GpuFieldElement& b,
                      GpuFieldElement& r) {
  uint64_t borrow = sub256(a.limbs, b.limbs, r.limbs);

  // If borrow, add p
  if (borrow) {
    add256(r.limbs, kSm2Prime, r.limbs);
  }
}

__device__ void fpNeg(const GpuFieldElement& a, GpuFieldElement& r) {
  if (fpIsZero(a)) {
    fpSetZero(r);
  } else {
    sub256(kSm2Prime, a.limbs, r.limbs);
  }
}

__device__ void fpDouble(const GpuFieldElement& a, GpuFieldElement& r) {
  fpAdd(a, a, r);
}

__device__ void fpTriple(const GpuFieldElement& a, GpuFieldElement& r) {
  GpuFieldElement t;
  fpDouble(a, t);
  fpAdd(t, a, r);
}

// Point operation helper functions

__device__ bool pointIsInfinity(const GpuJacobianPoint& p) {
  return fpIsZero(p.Z);
}

__device__ void pointSetInfinity(GpuJacobianPoint& p) {
  fpSetOne(p.X);
  fpSetOne(p.Y);
  fpSetZero(p.Z);
}

__device__ void pointCopy(const GpuJacobianPoint& p, GpuJacobianPoint& r) {
  fpCopy(p.X, r.X);
  fpCopy(p.Y, r.Y);
  fpCopy(p.Z, r.Z);
}

__device__ void affineToJacobian(const GpuAffinePoint& a, GpuJacobianPoint& j) {
  // Point-at-infinity is encoded as (0, 0) in affine form.
  if (fpIsZero(a.x) && fpIsZero(a.y)) {
    pointSetInfinity(j);
    return;
  }
  fpCopy(a.x, j.X);
  fpCopy(a.y, j.Y);
  fpSetOne(j.Z);  // Z = 1 in Montgomery form
}

__device__ void pointNegate(const GpuJacobianPoint& P, GpuJacobianPoint& R) {
  fpCopy(P.X, R.X);
  fpNeg(P.Y, R.Y);
  fpCopy(P.Z, R.Z);
}

// Montgomery multiplication

__device__ __forceinline__ void mul64(uint64_t a, uint64_t b, uint64_t& lo,
                                      uint64_t& hi) {
  lo = a * b;
  hi = __umul64hi(a, b);
}

// Add (acc + lo + carry_lo) into out, and update carry = hi + carry_out.
// The carry is tracked as (carry_lo, carry_hi) where carry_hi is 0/1 and
// represents the extra 2^64.
__device__ __forceinline__ void addMulAcc(uint64_t acc, uint64_t lo,
                                          uint64_t hi, uint64_t carry_lo,
                                          uint64_t carry_hi, uint64_t& out,
                                          uint64_t& next_carry_lo,
                                          uint64_t& next_carry_hi) {
  uint64_t sum = acc + lo;
  uint64_t c1 = (sum < acc) ? 1 : 0;
  uint64_t sum2 = sum + carry_lo;
  uint64_t c2 = (sum2 < sum) ? 1 : 0;
  out = sum2;

  uint64_t carry_out = c1 + c2 + carry_hi;  // 0..3
  uint64_t tmp = hi + carry_out;
  next_carry_hi = (tmp < hi) ? 1 : 0;
  next_carry_lo = tmp;
}

// Propagate a 65-bit carry (carry_lo + carry_hi*2^64) into t[start..end].
__device__ __forceinline__ void addCarry(uint64_t* t, int start, int end,
                                         uint64_t carry_lo, uint64_t carry_hi) {
  uint64_t sum = t[start] + carry_lo;
  uint64_t carry = (sum < t[start]) ? 1 : 0;
  t[start] = sum;

  carry += carry_hi;  // 0..2
  for (int i = start + 1; carry != 0 && i <= end; ++i) {
    uint64_t s = t[i] + carry;
    carry = (s < t[i]) ? 1 : 0;
    t[i] = s;
  }
}

// Montgomery multiplication: r = a * b * R^(-1) mod p, where R = 2^256.
//
// NOTE: Keep this implementation correct-first. It is used by point arithmetic
// and scalar multiplication; subtle carry bugs can easily create invalid
// points.
__device__ void fpMul(const GpuFieldElement& a, const GpuFieldElement& b,
                      GpuFieldElement& r) {
  // Use a 2n+1 limb accumulator to avoid losing the top carry during reduction.
  uint64_t t[9] = {0};

  // t = a * b
  for (int i = 0; i < 4; ++i) {
    uint64_t carry_lo = 0;
    uint64_t carry_hi = 0;
    for (int j = 0; j < 4; ++j) {
      uint64_t lo, hi;
      mul64(a.limbs[i], b.limbs[j], lo, hi);
      addMulAcc(t[i + j], lo, hi, carry_lo, carry_hi, t[i + j], carry_lo,
                carry_hi);
    }
    addCarry(t, i + 4, 8, carry_lo, carry_hi);
  }

  // Montgomery reduction (CIOS)
  for (int i = 0; i < 4; ++i) {
    uint64_t m = t[i] * kSm2Mu;  // mu = -p^{-1} mod 2^64 (SM2: 1)
    uint64_t carry_lo = 0;
    uint64_t carry_hi = 0;
    for (int j = 0; j < 4; ++j) {
      uint64_t lo, hi;
      mul64(m, kSm2Prime[j], lo, hi);
      addMulAcc(t[i + j], lo, hi, carry_lo, carry_hi, t[i + j], carry_lo,
                carry_hi);
    }
    addCarry(t, i + 4, 8, carry_lo, carry_hi);
  }

  // Result is in t[4..7], with possible overflow in t[8].
  r.limbs[0] = t[4];
  r.limbs[1] = t[5];
  r.limbs[2] = t[6];
  r.limbs[3] = t[7];

  // Final reduction: if r >= p or we have overflow, subtract p.
  uint64_t tmp[4];
  uint64_t borrow = sub256(r.limbs, kSm2Prime, tmp);
  if (borrow == 0 || t[8] != 0) {
    r.limbs[0] = tmp[0];
    r.limbs[1] = tmp[1];
    r.limbs[2] = tmp[2];
    r.limbs[3] = tmp[3];
  }
}

// Montgomery squaring (optimized version of fpMul(a, a))
__device__ void fpSqr(const GpuFieldElement& a, GpuFieldElement& r) {
  // Optimized squaring with cached symmetric products.
  //
  // We keep the same row-wise accumulation (and carry boundaries) as fpMul,
  // but avoid redundant a[i]*a[j] multiplications by caching (i<=j) products
  // and reusing them for (j,i).
  uint64_t t[9] = {0};

  // t = a * a
  uint64_t plo[4][4];
  uint64_t phi[4][4];

  // Diagonal
  mul64(a.limbs[0], a.limbs[0], plo[0][0], phi[0][0]);
  mul64(a.limbs[1], a.limbs[1], plo[1][1], phi[1][1]);
  mul64(a.limbs[2], a.limbs[2], plo[2][2], phi[2][2]);
  mul64(a.limbs[3], a.limbs[3], plo[3][3], phi[3][3]);

  // Cross terms (fill symmetric entries).
  mul64(a.limbs[0], a.limbs[1], plo[0][1], phi[0][1]);
  plo[1][0] = plo[0][1];
  phi[1][0] = phi[0][1];

  mul64(a.limbs[0], a.limbs[2], plo[0][2], phi[0][2]);
  plo[2][0] = plo[0][2];
  phi[2][0] = phi[0][2];

  mul64(a.limbs[0], a.limbs[3], plo[0][3], phi[0][3]);
  plo[3][0] = plo[0][3];
  phi[3][0] = phi[0][3];

  mul64(a.limbs[1], a.limbs[2], plo[1][2], phi[1][2]);
  plo[2][1] = plo[1][2];
  phi[2][1] = phi[1][2];

  mul64(a.limbs[1], a.limbs[3], plo[1][3], phi[1][3]);
  plo[3][1] = plo[1][3];
  phi[3][1] = phi[1][3];

  mul64(a.limbs[2], a.limbs[3], plo[2][3], phi[2][3]);
  plo[3][2] = plo[2][3];
  phi[3][2] = phi[2][3];

#pragma unroll
  for (int i = 0; i < 4; ++i) {
    uint64_t carry_lo = 0;
    uint64_t carry_hi = 0;
#pragma unroll
    for (int j = 0; j < 4; ++j) {
      addMulAcc(t[i + j], plo[i][j], phi[i][j], carry_lo, carry_hi, t[i + j],
                carry_lo, carry_hi);
    }
    addCarry(t, i + 4, 8, carry_lo, carry_hi);
  }

  // Montgomery reduction (CIOS)
#pragma unroll
  for (int i = 0; i < 4; ++i) {
    uint64_t m = t[i] * kSm2Mu;  // mu = -p^{-1} mod 2^64 (SM2: 1)
    uint64_t carry_lo = 0;
    uint64_t carry_hi = 0;
#pragma unroll
    for (int j = 0; j < 4; ++j) {
      uint64_t lo, hi;
      mul64(m, kSm2Prime[j], lo, hi);
      addMulAcc(t[i + j], lo, hi, carry_lo, carry_hi, t[i + j], carry_lo,
                carry_hi);
    }
    addCarry(t, i + 4, 8, carry_lo, carry_hi);
  }

  // Result is in t[4..7], with possible overflow in t[8].
  r.limbs[0] = t[4];
  r.limbs[1] = t[5];
  r.limbs[2] = t[6];
  r.limbs[3] = t[7];

  // Final reduction: if r >= p or we have overflow, subtract p.
  uint64_t tmp[4];
  uint64_t borrow = sub256(r.limbs, kSm2Prime, tmp);
  if (borrow == 0 || t[8] != 0) {
    r.limbs[0] = tmp[0];
    r.limbs[1] = tmp[1];
    r.limbs[2] = tmp[2];
    r.limbs[3] = tmp[3];
  }
}

// Convert to Montgomery form: r = a * R mod p
__device__ __forceinline__ void fpToMont(const GpuFieldElement& a,
                                         GpuFieldElement& r) {
  GpuFieldElement r2 = {{kSm2R2[0], kSm2R2[1], kSm2R2[2], kSm2R2[3]}};
  fpMul(a, r2, r);
}

// Convert from Montgomery form: r = a * R^(-1) mod p
__device__ __forceinline__ void fpFromMont(const GpuFieldElement& a,
                                           GpuFieldElement& r) {
  GpuFieldElement one = {{1, 0, 0, 0}};
  fpMul(a, one, r);
}

// Convert affine point to Montgomery form
__device__ void affinePointToMont(const GpuAffinePoint& a, GpuAffinePoint& m) {
  fpToMont(a.x, m.x);
  fpToMont(a.y, m.y);
}

// Convert affine point from Montgomery form
__device__ void affinePointFromMont(const GpuAffinePoint& m,
                                    GpuAffinePoint& a) {
  fpFromMont(m.x, a.x);
  fpFromMont(m.y, a.y);
}

__device__ __forceinline__ uint32_t sm2PMinus2Bit(int bit) {
  // p - 2 = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFD
  constexpr uint64_t kExp0 = 0xFFFFFFFFFFFFFFFDULL;
  constexpr uint64_t kExp1 = 0xFFFFFFFF00000000ULL;
  constexpr uint64_t kExp2 = 0xFFFFFFFFFFFFFFFFULL;
  constexpr uint64_t kExp3 = 0xFFFFFFFEFFFFFFFFULL;

  const int limb = bit >> 6;
  const int offset = bit & 63;

  uint64_t v = 0;
  if (limb == 0) {
    v = kExp0;
  } else if (limb == 1) {
    v = kExp1;
  } else if (limb == 2) {
    v = kExp2;
  } else {
    v = kExp3;
  }
  return static_cast<uint32_t>((v >> offset) & 1ULL);
}

// Field inversion using Fermat's little theorem: a^(-1) = a^(p-2) mod p
__device__ void fpInv(const GpuFieldElement& a, GpuFieldElement& r) {
  // Sliding-window exponentiation (fixed exponent p-2).
  // p - 2 = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFD
  // TODO: Consider a faster constant-time inversion (e.g. dedicated addition
  // chain) if this becomes a performance bottleneck.
  constexpr int kWindowSize = 3;
  constexpr int kTableSize = 1 << (kWindowSize - 1);  // odd powers: 1..7

  // Precompute odd powers: a^(2*i+1), i=0..kTableSize-1.
  GpuFieldElement table[kTableSize];
  fpCopy(a, table[0]);

  GpuFieldElement a2;
  fpSqr(a, a2);
#pragma unroll
  for (int i = 1; i < kTableSize; ++i) {
    fpMul(table[i - 1], a2, table[i]);
  }

  GpuFieldElement result;
  fpSetOne(result);

  int i = 255;
  while (i >= 0) {
    if (sm2PMinus2Bit(i) == 0) {
      fpSqr(result, result);
      --i;
      continue;
    }

    int j = i - kWindowSize + 1;
    if (j < 0) j = 0;
    while (sm2PMinus2Bit(j) == 0) {
      ++j;
    }

    uint32_t window = 0;
    for (int k = i; k >= j; --k) {
      fpSqr(result, result);
      window = (window << 1) | sm2PMinus2Bit(k);
    }

    // window is odd and <= 2^kWindowSize - 1.
    fpMul(result, table[(window - 1) >> 1], result);
    i = j - 1;
  }

  fpCopy(result, r);
}

__device__ __forceinline__ uint32_t sm2PPlus1Over4Bit(int bit) {
  // (p + 1) / 4 (since p % 4 == 3):
  // 0x3FFFFFFFBFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC00000004000000000000000
  constexpr uint64_t kExp0 = 0x4000000000000000ULL;
  constexpr uint64_t kExp1 = 0xFFFFFFFFC0000000ULL;
  constexpr uint64_t kExp2 = 0xFFFFFFFFFFFFFFFFULL;
  constexpr uint64_t kExp3 = 0x3FFFFFFFBFFFFFFFULL;

  const int limb = bit >> 6;
  const int offset = bit & 63;

  uint64_t v = 0;
  if (limb == 0) {
    v = kExp0;
  } else if (limb == 1) {
    v = kExp1;
  } else if (limb == 2) {
    v = kExp2;
  } else {
    v = kExp3;
  }
  return static_cast<uint32_t>((v >> offset) & 1ULL);
}

// Field square root for SM2 prime field (p % 4 == 3).
// Returns true if a quadratic residue (including 0), and writes sqrt(a) to r.
__device__ __forceinline__ bool fpSqrt(const GpuFieldElement& a,
                                       GpuFieldElement& r) {
  if (fpIsZero(a)) {
    fpSetZero(r);
    return true;
  }

  // r = a^((p+1)/4)
  constexpr int kWindowSize = 3;
  constexpr int kTableSize = 1 << (kWindowSize - 1);  // odd powers: 1..7

  GpuFieldElement table[kTableSize];
  fpCopy(a, table[0]);

  GpuFieldElement a2;
  fpSqr(a, a2);
#pragma unroll
  for (int i = 1; i < kTableSize; ++i) {
    fpMul(table[i - 1], a2, table[i]);
  }

  GpuFieldElement result;
  fpSetOne(result);

  // (p+1)/4 is 254-bit, start from bit 253.
  int i = 253;
  while (i >= 0) {
    if (sm2PPlus1Over4Bit(i) == 0) {
      fpSqr(result, result);
      --i;
      continue;
    }

    int j = i - kWindowSize + 1;
    if (j < 0) j = 0;
    while (sm2PPlus1Over4Bit(j) == 0) {
      ++j;
    }

    uint32_t window = 0;
    for (int k = i; k >= j; --k) {
      fpSqr(result, result);
      window = (window << 1) | sm2PPlus1Over4Bit(k);
    }

    fpMul(result, table[(window - 1) >> 1], result);
    i = j - 1;
  }

  // Verify: r^2 == a.
  GpuFieldElement check;
  fpSqr(result, check);
  if (!fpEqual(check, a)) {
    return false;
  }

  fpCopy(result, r);
  return true;
}

// Halving: r = a / 2 mod p
__device__ __forceinline__ void fpHalve(const GpuFieldElement& a,
                                        GpuFieldElement& r) {
  uint64_t carry = 0;
  if (a.limbs[0] & 1) {
    // If a is odd, compute (a + p) / 2
    carry = add256(a.limbs, kSm2Prime, r.limbs);
  } else {
    fpCopy(a, r);
  }

  // Right shift by 1
  r.limbs[0] = (r.limbs[0] >> 1) | (r.limbs[1] << 63);
  r.limbs[1] = (r.limbs[1] >> 1) | (r.limbs[2] << 63);
  r.limbs[2] = (r.limbs[2] >> 1) | (r.limbs[3] << 63);
  r.limbs[3] = (r.limbs[3] >> 1) | (carry << 63);
}

// Point operations

__device__ void jacobianToAffine(const GpuJacobianPoint& j, GpuAffinePoint& a) {
  if (pointIsInfinity(j)) {
    fpSetZero(a.x);
    fpSetZero(a.y);
    return;
  }

  GpuFieldElement zInv, zInv2, zInv3;

  // zInv = Z^(-1)
  fpInv(j.Z, zInv);

  // zInv2 = Z^(-2)
  fpSqr(zInv, zInv2);

  // zInv3 = Z^(-3)
  fpMul(zInv2, zInv, zInv3);

  // x = X * Z^(-2)
  fpMul(j.X, zInv2, a.x);

  // y = Y * Z^(-3)
  fpMul(j.Y, zInv3, a.y);
}

template <int kBlockSize>
__device__ __forceinline__ void blockExclusiveProdScan(GpuFieldElement* data) {
  const int tid = threadIdx.x;

  // Upsweep
#pragma unroll
  for (int offset = 1; offset < kBlockSize; offset <<= 1) {
    const int idx = (tid + 1) * offset * 2 - 1;
    if (idx < kBlockSize) {
      GpuFieldElement tmp;
      fpMul(data[idx - offset], data[idx], tmp);
      fpCopy(tmp, data[idx]);
    }
    __syncthreads();
  }

  if (tid == 0) {
    fpSetOne(data[kBlockSize - 1]);
  }
  __syncthreads();

  // Downsweep
#pragma unroll
  for (int offset = kBlockSize >> 1; offset > 0; offset >>= 1) {
    const int idx = (tid + 1) * offset * 2 - 1;
    if (idx < kBlockSize) {
      GpuFieldElement t0, t1, tmp;
      fpCopy(data[idx - offset], t0);
      fpCopy(data[idx], t1);
      fpCopy(t1, data[idx - offset]);
      fpMul(t0, t1, tmp);
      fpCopy(tmp, data[idx]);
    }
    __syncthreads();
  }
}

template <int kBlockSize>
__device__ __forceinline__ void jacobianToAffineBatchInv(
    const GpuJacobianPoint& j, bool active, GpuAffinePoint& a,
    GpuFieldElement* sh_z, GpuFieldElement* sh_prefix, GpuFieldElement* sh_rev,
    GpuFieldElement* sh_inv_total) {
  const int tid = threadIdx.x;
  const int rev = kBlockSize - 1 - tid;

  const bool valid = active && !pointIsInfinity(j);

  GpuFieldElement one;
  fpSetOne(one);

  if (valid) {
    fpCopy(j.Z, sh_z[tid]);
  } else {
    fpCopy(one, sh_z[tid]);
  }
  __syncthreads();

  // prefix[i] = prod_{k < i} z[k]
  fpCopy(sh_z[tid], sh_prefix[tid]);
  __syncthreads();
  blockExclusiveProdScan<kBlockSize>(sh_prefix);

  // rev-prefix for suffix: rev-prefix[rev] = prod_{k < rev} z_rev[k]
  // suffix[i] = prod_{k > i} z[k] = rev-prefix[rev]
  fpCopy(sh_z[rev], sh_rev[tid]);
  __syncthreads();
  blockExclusiveProdScan<kBlockSize>(sh_rev);

  if (tid == 0) {
    GpuFieldElement total;
    fpMul(sh_prefix[kBlockSize - 1], sh_z[kBlockSize - 1], total);
    fpInv(total, *sh_inv_total);
  }
  __syncthreads();

  if (!valid) {
    fpSetZero(a.x);
    fpSetZero(a.y);
    return;
  }

  GpuFieldElement suffix;
  fpCopy(sh_rev[rev], suffix);

  GpuFieldElement prod, zInv, zInv2, zInv3;
  fpMul(sh_prefix[tid], suffix, prod);
  fpMul(prod, *sh_inv_total, zInv);

  fpSqr(zInv, zInv2);
  fpMul(zInv2, zInv, zInv3);

  fpMul(j.X, zInv2, a.x);
  fpMul(j.Y, zInv3, a.y);
}

// Point doubling in Jacobian coordinates
// Formula for a = -3 (SM2): optimized
__device__ void pointDouble(const GpuJacobianPoint& P, GpuJacobianPoint& R) {
  if (pointIsInfinity(P)) {
    pointSetInfinity(R);
    return;
  }

  // This is a well-known Jacobian doubling formula for short Weierstrass
  // curves with a = -3, written to avoid in-place hazards and keep the dataflow
  // explicit.
  GpuFieldElement a, b, c, d, e, f, z2, z4, tmp;

  // a = X^2
  fpSqr(P.X, a);

  // b = Y^2
  fpSqr(P.Y, b);

  // c = b^2 = Y^4
  fpSqr(b, c);

  // d = 2 * ((X + b)^2 - a - c)  (equivalent to 4*X*Y^2)
  fpAdd(P.X, b, d);
  fpSqr(d, d);
  fpSub(d, a, d);
  fpSub(d, c, d);
  fpDouble(d, d);

  // e = 3 * (a - z4) where z4 = Z^4  (since a_curve = -3)
  fpSqr(P.Z, z2);
  fpSqr(z2, z4);
  fpSub(a, z4, tmp);
  fpTriple(tmp, e);

  // f = e^2
  fpSqr(e, f);

  // X3 = f - 2*d
  fpDouble(d, tmp);
  fpSub(f, tmp, R.X);

  // Y3 = e*(d - X3) - 8*c
  fpSub(d, R.X, tmp);
  fpMul(e, tmp, R.Y);
  fpDouble(c, tmp);    // 2c
  fpDouble(tmp, tmp);  // 4c
  fpDouble(tmp, tmp);  // 8c
  fpSub(R.Y, tmp, R.Y);

  // Z3 = 2*Y*Z
  fpMul(P.Y, P.Z, R.Z);
  fpDouble(R.Z, R.Z);
}

// Point addition in Jacobian coordinates
__device__ void pointAdd(const GpuJacobianPoint& P, const GpuJacobianPoint& Q,
                         GpuJacobianPoint& R) {
  // Handle special cases
  if (pointIsInfinity(P)) {
    pointCopy(Q, R);
    return;
  }
  if (pointIsInfinity(Q)) {
    pointCopy(P, R);
    return;
  }

  GpuFieldElement z1z1, z2z2, u1, u2, s1, s2, h, i, j, rr, v;

  // Z1Z1 = Z1^2
  fpSqr(P.Z, z1z1);

  // Z2Z2 = Z2^2
  fpSqr(Q.Z, z2z2);

  // U1 = X1 * Z2Z2
  fpMul(P.X, z2z2, u1);

  // U2 = X2 * Z1Z1
  fpMul(Q.X, z1z1, u2);

  // S1 = Y1 * Z2 * Z2Z2
  fpMul(P.Y, Q.Z, s1);
  fpMul(s1, z2z2, s1);

  // S2 = Y2 * Z1 * Z1Z1
  fpMul(Q.Y, P.Z, s2);
  fpMul(s2, z1z1, s2);

  // H = U2 - U1
  fpSub(u2, u1, h);

  // Check if P == Q or P == -Q
  if (fpIsZero(h)) {
    GpuFieldElement sDiff;
    fpSub(s2, s1, sDiff);
    if (fpIsZero(sDiff)) {
      // P == Q, do doubling
      pointDouble(P, R);
      return;
    } else {
      // P == -Q, result is infinity
      pointSetInfinity(R);
      return;
    }
  }

  // I = (2*H)^2
  fpDouble(h, i);
  fpSqr(i, i);

  // J = H * I
  fpMul(h, i, j);

  // r = 2 * (S2 - S1)
  fpSub(s2, s1, rr);
  fpDouble(rr, rr);

  // V = U1 * I
  fpMul(u1, i, v);

  // X3 = r^2 - J - 2*V
  fpSqr(rr, R.X);
  fpSub(R.X, j, R.X);
  GpuFieldElement v2;
  fpDouble(v, v2);
  fpSub(R.X, v2, R.X);

  // Y3 = r * (V - X3) - 2 * S1 * J
  fpSub(v, R.X, R.Y);
  fpMul(rr, R.Y, R.Y);
  GpuFieldElement s1j;
  fpMul(s1, j, s1j);
  fpDouble(s1j, s1j);
  fpSub(R.Y, s1j, R.Y);

  // Z3 = ((Z1 + Z2)^2 - Z1Z1 - Z2Z2) * H
  fpAdd(P.Z, Q.Z, R.Z);
  fpSqr(R.Z, R.Z);
  fpSub(R.Z, z1z1, R.Z);
  fpSub(R.Z, z2z2, R.Z);
  fpMul(R.Z, h, R.Z);
}

// Mixed addition: Jacobian + Affine -> Jacobian
__device__ void pointAddMixed(const GpuJacobianPoint& P,
                              const GpuAffinePoint& Q, GpuJacobianPoint& R) {
  if (pointIsInfinity(P)) {
    affineToJacobian(Q, R);
    return;
  }

  GpuFieldElement z1z1, u2, s2, h, hh, i, j, rr, v;

  // Z1Z1 = Z1^2
  fpSqr(P.Z, z1z1);

  // U2 = X2 * Z1Z1 (U1 = X1 since Q.Z = 1)
  fpMul(Q.x, z1z1, u2);

  // S2 = Y2 * Z1 * Z1Z1 (S1 = Y1 since Q.Z = 1)
  fpMul(Q.y, P.Z, s2);
  fpMul(s2, z1z1, s2);

  // H = U2 - X1
  fpSub(u2, P.X, h);

  // Check if P == Q or P == -Q
  if (fpIsZero(h)) {
    GpuFieldElement sDiff;
    fpSub(s2, P.Y, sDiff);
    if (fpIsZero(sDiff)) {
      pointDouble(P, R);
      return;
    } else {
      pointSetInfinity(R);
      return;
    }
  }

  // HH = H^2
  fpSqr(h, hh);

  // I = 4 * HH
  fpDouble(hh, i);
  fpDouble(i, i);

  // J = H * I
  fpMul(h, i, j);

  // r = 2 * (S2 - Y1)
  fpSub(s2, P.Y, rr);
  fpDouble(rr, rr);

  // V = X1 * I
  fpMul(P.X, i, v);

  // X3 = r^2 - J - 2*V
  fpSqr(rr, R.X);
  fpSub(R.X, j, R.X);
  GpuFieldElement v2;
  fpDouble(v, v2);
  fpSub(R.X, v2, R.X);

  // Y3 = r * (V - X3) - 2 * Y1 * J
  fpSub(v, R.X, R.Y);
  fpMul(rr, R.Y, R.Y);
  GpuFieldElement y1j;
  fpMul(P.Y, j, y1j);
  fpDouble(y1j, y1j);
  fpSub(R.Y, y1j, R.Y);

  // Z3 = (Z1 + H)^2 - Z1Z1 - HH
  fpAdd(P.Z, h, R.Z);
  fpSqr(R.Z, R.Z);
  fpSub(R.Z, z1z1, R.Z);
  fpSub(R.Z, hh, R.Z);
}

// Point subtraction
__device__ void pointSub(const GpuJacobianPoint& P, const GpuJacobianPoint& Q,
                         GpuJacobianPoint& R) {
  GpuJacobianPoint negQ;
  pointNegate(Q, negQ);
  pointAdd(P, negQ, R);
}

// Check if point is on curve
__device__ bool pointIsOnCurve(const GpuJacobianPoint& P) {
  if (pointIsInfinity(P)) {
    return true;
  }

  // Convert to affine for easier check
  GpuAffinePoint a;
  jacobianToAffine(P, a);

  // Convert curve parameters to Montgomery form
  GpuFieldElement aMont, bMont;
  fpToMont(kSm2A, aMont);
  fpToMont(kSm2B, bMont);

  // Check: y^2 = x^3 + a*x + b (all in Montgomery form)
  GpuFieldElement lhs, rhs, t1, t2;

  // lhs = y^2
  fpSqr(a.y, lhs);

  // rhs = x^3
  fpSqr(a.x, t1);
  fpMul(t1, a.x, rhs);

  // rhs = x^3 + a*x
  fpMul(aMont, a.x, t2);
  fpAdd(rhs, t2, rhs);

  // rhs = x^3 + a*x + b
  fpAdd(rhs, bMont, rhs);

  return fpEqual(lhs, rhs);
}

// Check if two points are equal
__device__ bool pointEqual(const GpuJacobianPoint& P,
                           const GpuJacobianPoint& Q) {
  if (pointIsInfinity(P) && pointIsInfinity(Q)) {
    return true;
  }
  if (pointIsInfinity(P) || pointIsInfinity(Q)) {
    return false;
  }

  // Compare X1*Z2^2 == X2*Z1^2 and Y1*Z2^3 == Y2*Z1^3
  GpuFieldElement z1z1, z2z2, u1, u2, s1, s2;

  fpSqr(P.Z, z1z1);
  fpSqr(Q.Z, z2z2);

  fpMul(P.X, z2z2, u1);
  fpMul(Q.X, z1z1, u2);

  if (!fpEqual(u1, u2)) {
    return false;
  }

  fpMul(P.Y, Q.Z, s1);
  fpMul(s1, z2z2, s1);

  fpMul(Q.Y, P.Z, s2);
  fpMul(s2, z1z1, s2);

  return fpEqual(s1, s2);
}

// Scalar multiplication

__device__ int scalarToWnaf(const GpuScalar& scalar, WnafDigit* wnaf) {
  uint64_t k[5] = {scalar.limbs[0], scalar.limbs[1], scalar.limbs[2],
                   scalar.limbs[3], 0};

  const int w = kVarBaseWindowSize;
  const int64_t halfMod = 1 << (w - 1);  // 2^(w-1)
  const int64_t mod = 1 << w;            // 2^w

  int i = 0;

  while (k[0] != 0 || k[1] != 0 || k[2] != 0 || k[3] != 0 || k[4] != 0) {
    if (k[0] & 1) {
      // k is odd
      int64_t mods = k[0] & (mod - 1);
      if (mods >= halfMod) {
        mods -= mod;
      }
      wnaf[i] = (WnafDigit)mods;

      // k = k - mods (can be addition if mods < 0)
      if (mods > 0) {
        uint64_t borrow = 0;
        for (int j = 0; j < 5; j++) {
          uint64_t oldK = k[j];
          k[j] = k[j] - (j == 0 ? (uint64_t)mods : 0) - borrow;
          borrow = (k[j] > oldK) ? 1 : 0;
        }
      } else {
        uint64_t carry = 0;
        uint64_t add = (uint64_t)(-mods);
        for (int j = 0; j < 5; j++) {
          uint64_t oldK = k[j];
          k[j] = k[j] + (j == 0 ? add : 0) + carry;
          carry = (k[j] < oldK) ? 1 : 0;
        }
      }
    } else {
      wnaf[i] = 0;
    }

    // k = k / 2 (right shift)
    for (int j = 0; j < 4; j++) {
      k[j] = (k[j] >> 1) | (k[j + 1] << 63);
    }
    k[4] >>= 1;

    i++;
  }

  return i;
}

// Build variable-base table: table[i] = (2*i + 1) * P in Jacobian form.
__device__ void buildVarBaseTable(const GpuJacobianPoint& P,
                                  GpuJacobianPoint* table) {
  // table[0] = 1*P
  pointCopy(P, table[0]);

  // twoP = 2*P
  GpuJacobianPoint twoP;
  pointDouble(P, twoP);

  // table[i] = table[i-1] + 2P => 3P, 5P, ...
  for (int i = 1; i < kVarBaseTableSize; ++i) {
    pointAdd(table[i - 1], twoP, table[i]);
  }
}

__device__ void prepareDoubleBaseWnaf(const GpuScalar& s1, const GpuScalar& s2,
                                      DoubleBaseWnaf& result) {
  for (int i = 0; i < kMaxWnafDigits + 1; ++i) {
    result.wnaf1[i] = 0;
    result.wnaf2[i] = 0;
  }

  const int len1 = scalarToWnaf(s1, result.wnaf1);
  const int len2 = scalarToWnaf(s2, result.wnaf2);
  result.length = (len1 > len2) ? len1 : len2;
}

// Variable-base scalar multiplication using wNAF.
__device__ void scalarMulVarBase(const GpuAffinePoint& P, const GpuScalar& k,
                                 GpuJacobianPoint& R) {
  if ((k.limbs[0] | k.limbs[1] | k.limbs[2] | k.limbs[3]) == 0) {
    pointSetInfinity(R);
    return;
  }

  // Convert input point to Jacobian (Montgomery form).
  GpuJacobianPoint jacP;
  affineToJacobian(P, jacP);

  // Precompute odd multiples.
  GpuJacobianPoint table[kVarBaseTableSize];
  buildVarBaseTable(jacP, table);

  // Convert scalar to wNAF digits.
  WnafDigit wnaf[kMaxWnafDigits + 1] = {0};
  const int len = scalarToWnaf(k, wnaf);

  pointSetInfinity(R);

  GpuJacobianPoint tmp;
  for (int i = len - 1; i >= 0; --i) {
    pointDouble(R, tmp);
    pointCopy(tmp, R);

    const int d = static_cast<int>(wnaf[i]);
    if (d == 0) {
      continue;
    }

    const int abs_d = (d < 0) ? -d : d;
    const int idx = (abs_d - 1) >> 1;  // 1->0, 3->1, ...

    if (d > 0) {
      pointAdd(R, table[idx], tmp);
    } else {
      GpuJacobianPoint negQ;
      pointNegate(table[idx], negQ);
      pointAdd(R, negQ, tmp);
    }
    pointCopy(tmp, R);
  }
}

// Fixed-base scalar multiplication using precomputed table
__device__ void scalarMulFixedBase(const GpuScalar& k, GpuJacobianPoint& R) {
  pointSetInfinity(R);

  // If table is not initialized, fall back to variable-base multiplication.
  if (g_generatorTable == nullptr) {
    GpuAffinePoint genMont;
    affinePointToMont(kSm2Generator, genMont);
    scalarMulVarBase(genMont, k, R);
    return;
  }

  // k = sum window_i * 2^(i*w), where w = kFixedBaseWindowSize.
  for (int i = 0; i < kNumWindows; ++i) {
    const int bitPos = i * kFixedBaseWindowSize;
    const int limbIdx = bitPos / 64;
    const int bitOffset = bitPos % 64;

    // NOTE: kFixedBaseWindowSize divides 64, so the 4-bit window never crosses
    // limbs. Keep the branch-free form for speed and simplicity.
    const uint64_t window =
        (k.limbs[limbIdx] >> bitOffset) & ((1ULL << kFixedBaseWindowSize) - 1);
    if (window == 0) {
      continue;
    }

    const int tableIdx = i * kTableEntriesPerWindow + (int)window;
    GpuJacobianPoint tmp;
    pointAddMixed(R, g_generatorTable[tableIdx], tmp);
    pointCopy(tmp, R);
  }
}

// Debug kernels

__global__ void debugMontMulKernel(int32_t* results) {
  GpuFieldElement one_mont;
  fpSetOne(one_mont);

  GpuFieldElement mul_result;
  fpMul(one_mont, one_mont, mul_result);

  results[0] = fpEqual(one_mont, mul_result) ? 1 : 0;

  // Test 2: fpFromMont(fpToMont(x)) should equal x
  // Use a simple value: x = 2
  GpuFieldElement x = {{2, 0, 0, 0}};
  GpuFieldElement x_mont, x_back;
  fpToMont(x, x_mont);
  fpFromMont(x_mont, x_back);

  results[1] = fpEqual(x, x_back) ? 1 : 0;

  // Test 3: Verify R^2 mod p constant
  // fpMul(R^2, 1) should give R (since R^2 * R^(-1) = R)
  GpuFieldElement r2 = {{kSm2R2[0], kSm2R2[1], kSm2R2[2], kSm2R2[3]}};
  GpuFieldElement one_normal = {{1, 0, 0, 0}};
  GpuFieldElement r_result;
  fpMul(r2, one_normal, r_result);  // Should give R mod p

  GpuFieldElement r_expected = {
      {kSm2RModP[0], kSm2RModP[1], kSm2RModP[2], kSm2RModP[3]}};
  results[2] = fpEqual(r_expected, r_result) ? 1 : 0;

  // Store all 4 limbs of one_mont (results 3-10)
  results[3] = (int32_t)(one_mont.limbs[0] & 0xFFFFFFFF);
  results[4] = (int32_t)(one_mont.limbs[0] >> 32);
  results[5] = (int32_t)(one_mont.limbs[1] & 0xFFFFFFFF);
  results[6] = (int32_t)(one_mont.limbs[1] >> 32);
  results[7] = (int32_t)(one_mont.limbs[2] & 0xFFFFFFFF);
  results[8] = (int32_t)(one_mont.limbs[2] >> 32);
  results[9] = (int32_t)(one_mont.limbs[3] & 0xFFFFFFFF);
  results[10] = (int32_t)(one_mont.limbs[3] >> 32);

  // Store all 4 limbs of mul_result (results 11-18)
  results[11] = (int32_t)(mul_result.limbs[0] & 0xFFFFFFFF);
  results[12] = (int32_t)(mul_result.limbs[0] >> 32);
  results[13] = (int32_t)(mul_result.limbs[1] & 0xFFFFFFFF);
  results[14] = (int32_t)(mul_result.limbs[1] >> 32);
  results[15] = (int32_t)(mul_result.limbs[2] & 0xFFFFFFFF);
  results[16] = (int32_t)(mul_result.limbs[2] >> 32);
  results[17] = (int32_t)(mul_result.limbs[3] & 0xFFFFFFFF);
  results[18] = (int32_t)(mul_result.limbs[3] >> 32);

  // Store kSm2RModP for comparison (results 19-26)
  results[19] = (int32_t)(kSm2RModP[0] & 0xFFFFFFFF);
  results[20] = (int32_t)(kSm2RModP[0] >> 32);
  results[21] = (int32_t)(kSm2RModP[1] & 0xFFFFFFFF);
  results[22] = (int32_t)(kSm2RModP[1] >> 32);
  results[23] = (int32_t)(kSm2RModP[2] & 0xFFFFFFFF);
  results[24] = (int32_t)(kSm2RModP[2] >> 32);
  results[25] = (int32_t)(kSm2RModP[3] & 0xFFFFFFFF);
  results[26] = (int32_t)(kSm2RModP[3] >> 32);
}

extern "C" CudaEccError debugMontMul(int32_t* hostResults,
                                     cudaStream_t stream) {
  if (stream == 0) stream = g_stream;

  if (hostResults == nullptr || stream == nullptr) {
    return CudaEccError::kInvalidInput;
  }

  int32_t* devResults = nullptr;
  cudaError_t err = cudaMalloc(&devResults, 32 * sizeof(int32_t));
  if (err != cudaSuccess) return toCudaEccError(err);

  CudaEccError status = CudaEccError::kSuccess;

  do {
    err = cudaMemset(devResults, 0, 32 * sizeof(int32_t));
    if (err != cudaSuccess) {
      status = toCudaEccError(err);
      break;
    }

    debugMontMulKernel<<<1, 1, 0, stream>>>(devResults);
    err = cudaPeekAtLastError();
    if (err != cudaSuccess) {
      status = toCudaEccError(err);
      break;
    }

    err = cudaMemcpy(hostResults, devResults, 32 * sizeof(int32_t),
                     cudaMemcpyDeviceToHost);
    if (err != cudaSuccess) {
      status = toCudaEccError(err);
      break;
    }

    err = cudaStreamSynchronize(stream);
    if (err != cudaSuccess) {
      status = toCudaEccError(err);
      break;
    }
  } while (false);

  cudaFree(devResults);
  return status;
}

__global__ void debugReadScalarKernel(const GpuScalar* scalar,
                                      uint64_t* results) {
  if (blockIdx.x != 0 || threadIdx.x != 0) {
    return;
  }

  results[0] = scalar->limbs[0];
  results[1] = scalar->limbs[1];
  results[2] = scalar->limbs[2];
  results[3] = scalar->limbs[3];

  uint64_t pop = 0;
  pop += __popcll(scalar->limbs[0]);
  pop += __popcll(scalar->limbs[1]);
  pop += __popcll(scalar->limbs[2]);
  pop += __popcll(scalar->limbs[3]);
  results[4] = pop;

  int64_t msb = -1;
  for (int limb = 3; limb >= 0; --limb) {
    const uint64_t w = scalar->limbs[limb];
    if (w != 0) {
      msb = static_cast<int64_t>(limb) * 64 + (63 - __clzll(w));
      break;
    }
  }
  results[5] = static_cast<uint64_t>(msb);
}

extern "C" CudaEccError debugReadScalar(const void* hostScalar,
                                        uint64_t* hostResults,
                                        cudaStream_t stream) {
  if (stream == 0) stream = g_stream;

  if (hostScalar == nullptr || hostResults == nullptr || stream == nullptr) {
    return CudaEccError::kInvalidInput;
  }

  GpuScalar* devScalar = nullptr;
  uint64_t* devResults = nullptr;
  cudaError_t err = cudaMalloc(&devScalar, sizeof(GpuScalar));
  if (err != cudaSuccess) return toCudaEccError(err);
  err = cudaMalloc(&devResults, 6 * sizeof(uint64_t));
  if (err != cudaSuccess) {
    cudaFree(devScalar);
    return toCudaEccError(err);
  }

  CudaEccError status = CudaEccError::kSuccess;

  do {
    err = cudaMemcpyAsync(devScalar, hostScalar, sizeof(GpuScalar),
                          cudaMemcpyHostToDevice, stream);
    if (err != cudaSuccess) {
      status = toCudaEccError(err);
      break;
    }
    err = cudaMemsetAsync(devResults, 0, 6 * sizeof(uint64_t), stream);
    if (err != cudaSuccess) {
      status = toCudaEccError(err);
      break;
    }

    debugReadScalarKernel<<<1, 1, 0, stream>>>(devScalar, devResults);
    err = cudaPeekAtLastError();
    if (err != cudaSuccess) {
      status = toCudaEccError(err);
      break;
    }

    err = cudaMemcpyAsync(hostResults, devResults, 6 * sizeof(uint64_t),
                          cudaMemcpyDeviceToHost, stream);
    if (err != cudaSuccess) {
      status = toCudaEccError(err);
      break;
    }
    err = cudaStreamSynchronize(stream);
    if (err != cudaSuccess) {
      status = toCudaEccError(err);
      break;
    }
  } while (false);

  cudaFree(devScalar);
  cudaFree(devResults);

  return status;
}

// SM3 (fixed 32-byte message) and HashToCurve helpers

__device__ __forceinline__ uint32_t rotl32(uint32_t x, int n) {
  return (x << n) | (x >> (32 - n));
}

__device__ __forceinline__ uint32_t loadBe32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

__device__ __forceinline__ uint64_t loadBe64(const uint8_t* p) {
  return (static_cast<uint64_t>(loadBe32(p)) << 32) | loadBe32(p + 4);
}

__device__ __forceinline__ void storeBe32(uint8_t* out, uint32_t v) {
  out[0] = static_cast<uint8_t>(v >> 24);
  out[1] = static_cast<uint8_t>(v >> 16);
  out[2] = static_cast<uint8_t>(v >> 8);
  out[3] = static_cast<uint8_t>(v);
}

__device__ __forceinline__ uint32_t sm3P0(uint32_t x) {
  return x ^ rotl32(x, 9) ^ rotl32(x, 17);
}

__device__ __forceinline__ uint32_t sm3P1(uint32_t x) {
  return x ^ rotl32(x, 15) ^ rotl32(x, 23);
}

__device__ __forceinline__ uint32_t sm3FF(uint32_t x, uint32_t y, uint32_t z,
                                          int j) {
  if (j < 16) {
    return x ^ y ^ z;
  }
  return (x & y) | (x & z) | (y & z);
}

__device__ __forceinline__ uint32_t sm3GG(uint32_t x, uint32_t y, uint32_t z,
                                          int j) {
  if (j < 16) {
    return x ^ y ^ z;
  }
  return (x & y) | ((~x) & z);
}

// SM3 hash for exactly 32 bytes (single-block).
__device__ __forceinline__ void sm3Hash32(const uint8_t* msg32,
                                          uint8_t* digest32) {
  // Message words W[0..15].
  uint32_t W[68];
#pragma unroll
  for (int i = 0; i < 8; ++i) {
    W[i] = loadBe32(msg32 + i * 4);
  }
  W[8] = 0x80000000U;
#pragma unroll
  for (int i = 9; i <= 13; ++i) {
    W[i] = 0;
  }
  W[14] = 0;
  W[15] = 256;  // 32 bytes * 8 bits

  // Message expansion.
  for (int j = 16; j < 68; ++j) {
    const uint32_t x = W[j - 16] ^ W[j - 9] ^ rotl32(W[j - 3], 15);
    W[j] = sm3P1(x) ^ rotl32(W[j - 13], 7) ^ W[j - 6];
  }

  // W' = W[j] ^ W[j+4]
  uint32_t W1[64];
  for (int j = 0; j < 64; ++j) {
    W1[j] = W[j] ^ W[j + 4];
  }

  uint32_t A = 0x7380166FU;
  uint32_t B = 0x4914B2B9U;
  uint32_t C = 0x172442D7U;
  uint32_t D = 0xDA8A0600U;
  uint32_t E = 0xA96F30BCU;
  uint32_t F = 0x163138AAU;
  uint32_t G = 0xE38DEE4DU;
  uint32_t H = 0xB0FB0E4EU;

  for (int j = 0; j < 64; ++j) {
    const uint32_t Tj = (j < 16) ? 0x79CC4519U : 0x7A879D8AU;
    const uint32_t ss1 = rotl32(rotl32(A, 12) + E + rotl32(Tj, j & 31), 7);
    const uint32_t ss2 = ss1 ^ rotl32(A, 12);
    const uint32_t tt1 = sm3FF(A, B, C, j) + D + ss2 + W1[j];
    const uint32_t tt2 = sm3GG(E, F, G, j) + H + ss1 + W[j];
    D = C;
    C = rotl32(B, 9);
    B = A;
    A = tt1;
    H = G;
    G = rotl32(F, 19);
    F = E;
    E = sm3P0(tt2);
  }

  A ^= 0x7380166FU;
  B ^= 0x4914B2B9U;
  C ^= 0x172442D7U;
  D ^= 0xDA8A0600U;
  E ^= 0xA96F30BCU;
  F ^= 0x163138AAU;
  G ^= 0xE38DEE4DU;
  H ^= 0xB0FB0E4EU;

  storeBe32(digest32 + 0, A);
  storeBe32(digest32 + 4, B);
  storeBe32(digest32 + 8, C);
  storeBe32(digest32 + 12, D);
  storeBe32(digest32 + 16, E);
  storeBe32(digest32 + 20, F);
  storeBe32(digest32 + 24, G);
  storeBe32(digest32 + 28, H);
}

__device__ __forceinline__ void digestToSm2X(const uint8_t* digest,
                                             GpuFieldElement& x) {
  // Interpret digest as a big-endian 256-bit integer and reduce mod p.
  x.limbs[0] = loadBe64(digest + 24);
  x.limbs[1] = loadBe64(digest + 16);
  x.limbs[2] = loadBe64(digest + 8);
  x.limbs[3] = loadBe64(digest + 0);

  uint64_t tmp[4];
  const uint64_t borrow = sub256(x.limbs, kSm2Prime, tmp);
  if (borrow == 0) {
    x.limbs[0] = tmp[0];
    x.limbs[1] = tmp[1];
    x.limbs[2] = tmp[2];
    x.limbs[3] = tmp[3];
  }
}

__device__ __forceinline__ bool hashToCurveTryAndRehashSmFromDigest(
    const uint8_t* digest_in, GpuAffinePoint& pointMont) {
  uint8_t digest[32];
#pragma unroll
  for (int i = 0; i < 32; ++i) {
    digest[i] = digest_in[i];
  }

  constexpr int kMaxTries = 100;  // keep consistent with CPU guard
  for (int t = 0; t < kMaxTries; ++t) {
    GpuFieldElement xNorm;
    digestToSm2X(digest, xNorm);

    GpuFieldElement xMont;
    fpToMont(xNorm, xMont);

    // rhs = x^3 + a*x + b (all in Montgomery form)
    GpuFieldElement x2, x3, ax, rhs;
    fpSqr(xMont, x2);
    fpMul(x2, xMont, x3);
    fpMul(kSm2AMont, xMont, ax);
    fpAdd(x3, ax, rhs);
    fpAdd(rhs, kSm2BMont, rhs);

    GpuFieldElement yMont;
    if (fpSqrt(rhs, yMont)) {
      // Choose y with even LSB (ybit = 0).
      GpuFieldElement yNorm;
      fpFromMont(yMont, yNorm);
      if (yNorm.limbs[0] & 1ULL) {
        fpNeg(yMont, yMont);
      }

      fpCopy(xMont, pointMont.x);
      fpCopy(yMont, pointMont.y);
      return true;
    }

    uint8_t next[32];
    sm3Hash32(digest, next);
#pragma unroll
    for (int i = 0; i < 32; ++i) {
      digest[i] = next[i];
    }
  }

  return false;
}

// CUDA kernels

__global__ void batchFixedBaseMulKernel(const GpuScalar* scalars,
                                        GpuAffinePoint* results,
                                        int32_t count) {
  const int idx = blockIdx.x * blockDim.x + threadIdx.x;
  const bool active = (idx < count);

  GpuJacobianPoint jac;
  if (active) {
    scalarMulFixedBase(scalars[idx], jac);
  } else {
    pointSetInfinity(jac);
  }

  __shared__ GpuFieldElement sh_z[256];
  __shared__ GpuFieldElement sh_prefix[256];
  __shared__ GpuFieldElement sh_rev[256];
  __shared__ GpuFieldElement sh_inv_total;

  GpuAffinePoint affineResult;
  jacobianToAffineBatchInv<256>(jac, active, affineResult, sh_z, sh_prefix,
                                sh_rev, &sh_inv_total);

  if (active) {
    // Convert from Montgomery form to normal form for output
    affinePointFromMont(affineResult, results[idx]);
  }
}

__global__ void batchVarBaseMulKernel(const GpuAffinePoint* points,
                                      const GpuScalar* scalars,
                                      GpuAffinePoint* results, int32_t count) {
  const int idx = blockIdx.x * blockDim.x + threadIdx.x;
  const bool active = (idx < count);

  GpuAffinePoint pointMont;
  if (active) {
    // Convert input point from normal form to Montgomery form
    affinePointToMont(points[idx], pointMont);
  }

  GpuJacobianPoint jac;
  if (active) {
    scalarMulVarBase(pointMont, scalars[idx], jac);
  } else {
    pointSetInfinity(jac);
  }

  __shared__ GpuFieldElement sh_z[256];
  __shared__ GpuFieldElement sh_prefix[256];
  __shared__ GpuFieldElement sh_rev[256];
  __shared__ GpuFieldElement sh_inv_total;

  GpuAffinePoint affineResult;
  jacobianToAffineBatchInv<256>(jac, active, affineResult, sh_z, sh_prefix,
                                sh_rev, &sh_inv_total);

  if (active) {
    // Convert from Montgomery form to normal form for output
    affinePointFromMont(affineResult, results[idx]);
  }
}

__global__ void batchSameScalarMulKernel(const GpuAffinePoint* points,
                                         const GpuScalar* scalar,
                                         GpuAffinePoint* results,
                                         int32_t count) {
  const int idx = blockIdx.x * blockDim.x + threadIdx.x;
  const bool active = (idx < count);

  // Convert input point from normal form to Montgomery form
  GpuAffinePoint pointMont;
  if (active) {
    affinePointToMont(points[idx], pointMont);
  }

  GpuJacobianPoint jac;
  if (active) {
    scalarMulVarBase(pointMont, *scalar, jac);
  } else {
    pointSetInfinity(jac);
  }

  __shared__ GpuFieldElement sh_z[256];
  __shared__ GpuFieldElement sh_prefix[256];
  __shared__ GpuFieldElement sh_rev[256];
  __shared__ GpuFieldElement sh_inv_total;

  GpuAffinePoint affineResult;
  jacobianToAffineBatchInv<256>(jac, active, affineResult, sh_z, sh_prefix,
                                sh_rev, &sh_inv_total);

  if (active) {
    // Convert from Montgomery form to normal form for output
    affinePointFromMont(affineResult, results[idx]);
  }
}

__global__ void batchHashAndMulFromSm3DigestsKernel(const uint8_t* digests,
                                                    const GpuScalar* scalar,
                                                    GpuAffinePoint* results,
                                                    int32_t count,
                                                    int32_t* error_flag) {
  const int idx = blockIdx.x * blockDim.x + threadIdx.x;
  const bool active = (idx < count);

  bool ok = false;
  GpuJacobianPoint jac;

  if (active) {
    GpuAffinePoint hashPointMont;
    ok = hashToCurveTryAndRehashSmFromDigest(digests + idx * 32, hashPointMont);
    if (!ok) {
      if (error_flag != nullptr) {
        atomicExch(error_flag, 1);
      }
      pointSetInfinity(jac);
    } else {
      scalarMulVarBase(hashPointMont, *scalar, jac);
    }
  } else {
    pointSetInfinity(jac);
  }

  __shared__ GpuFieldElement sh_z[256];
  __shared__ GpuFieldElement sh_prefix[256];
  __shared__ GpuFieldElement sh_rev[256];
  __shared__ GpuFieldElement sh_inv_total;

  GpuAffinePoint affineResult;
  jacobianToAffineBatchInv<256>(jac, active && ok, affineResult, sh_z,
                                sh_prefix, sh_rev, &sh_inv_total);

  if (!active) {
    return;
  }
  if (!ok) {
    fpSetZero(results[idx].x);
    fpSetZero(results[idx].y);
    return;
  }
  affinePointFromMont(affineResult, results[idx]);
}

__global__ void batchPointAddKernel(const GpuAffinePoint* p1s,
                                    const GpuAffinePoint* p2s,
                                    GpuAffinePoint* results, int32_t count) {
  const int idx = blockIdx.x * blockDim.x + threadIdx.x;
  const bool active = (idx < count);

  // Convert input points from normal form to Montgomery form
  GpuAffinePoint p1Mont, p2Mont;
  if (active) {
    affinePointToMont(p1s[idx], p1Mont);
    affinePointToMont(p2s[idx], p2Mont);
  }

  GpuJacobianPoint jac1, jac2, jacR;
  if (active) {
    affineToJacobian(p1Mont, jac1);
    affineToJacobian(p2Mont, jac2);
    pointAdd(jac1, jac2, jacR);
  } else {
    pointSetInfinity(jacR);
  }

  __shared__ GpuFieldElement sh_z[256];
  __shared__ GpuFieldElement sh_prefix[256];
  __shared__ GpuFieldElement sh_rev[256];
  __shared__ GpuFieldElement sh_inv_total;

  GpuAffinePoint affineResult;
  jacobianToAffineBatchInv<256>(jacR, active, affineResult, sh_z, sh_prefix,
                                sh_rev, &sh_inv_total);

  if (active) {
    // Convert from Montgomery form to normal form for output
    affinePointFromMont(affineResult, results[idx]);
  }
}

__global__ void batchPointDoubleKernel(const GpuAffinePoint* points,
                                       GpuAffinePoint* results, int32_t count) {
  const int idx = blockIdx.x * blockDim.x + threadIdx.x;
  const bool active = (idx < count);

  // Convert input point from normal form to Montgomery form
  GpuAffinePoint pointMont;
  if (active) {
    affinePointToMont(points[idx], pointMont);
  }

  GpuJacobianPoint jac, jacR;
  if (active) {
    affineToJacobian(pointMont, jac);
    pointDouble(jac, jacR);
  } else {
    pointSetInfinity(jacR);
  }

  __shared__ GpuFieldElement sh_z[256];
  __shared__ GpuFieldElement sh_prefix[256];
  __shared__ GpuFieldElement sh_rev[256];
  __shared__ GpuFieldElement sh_inv_total;

  GpuAffinePoint affineResult;
  jacobianToAffineBatchInv<256>(jacR, active, affineResult, sh_z, sh_prefix,
                                sh_rev, &sh_inv_total);

  if (active) {
    // Convert from Montgomery form to normal form for output
    affinePointFromMont(affineResult, results[idx]);
  }
}

__global__ void batchPointNegateKernel(const GpuAffinePoint* points,
                                       GpuAffinePoint* results, int32_t count) {
  int idx = blockIdx.x * blockDim.x + threadIdx.x;
  if (idx >= count) return;

  // Convert input point from normal form to Montgomery form
  GpuAffinePoint pointMont;
  affinePointToMont(points[idx], pointMont);

  // Negate: x stays same, y becomes -y
  GpuAffinePoint resultMont;
  fpCopy(pointMont.x, resultMont.x);
  fpNeg(pointMont.y, resultMont.y);

  // Convert from Montgomery form to normal form for output
  affinePointFromMont(resultMont, results[idx]);
}

__global__ void batchIsOnCurveKernel(const GpuAffinePoint* points,
                                     int32_t* results, int32_t count) {
  int idx = blockIdx.x * blockDim.x + threadIdx.x;
  if (idx >= count) return;

  // Convert input point from normal form to Montgomery form
  GpuAffinePoint pointMont;
  affinePointToMont(points[idx], pointMont);

  GpuJacobianPoint jac;
  affineToJacobian(pointMont, jac);
  results[idx] = pointIsOnCurve(jac) ? 1 : 0;
}

__global__ void batchDoubleBaseMulKernel(const GpuScalar* s1,
                                         const GpuScalar* s2,
                                         const GpuAffinePoint* points,
                                         GpuAffinePoint* results,
                                         int32_t count) {
  const int idx = blockIdx.x * blockDim.x + threadIdx.x;
  const bool active = (idx < count);

  // Convert input point from normal form to Montgomery form
  GpuAffinePoint pointMont;
  if (active) {
    affinePointToMont(points[idx], pointMont);
  }

  GpuJacobianPoint jac1, jac2, jacR;
  if (active) {
    // Compute s1 * G
    scalarMulFixedBase(s1[idx], jac1);

    // Compute s2 * P
    scalarMulVarBase(pointMont, s2[idx], jac2);

    // R = s1*G + s2*P
    pointAdd(jac1, jac2, jacR);
  } else {
    pointSetInfinity(jacR);
  }

  __shared__ GpuFieldElement sh_z[256];
  __shared__ GpuFieldElement sh_prefix[256];
  __shared__ GpuFieldElement sh_rev[256];
  __shared__ GpuFieldElement sh_inv_total;

  GpuAffinePoint affineResult;
  jacobianToAffineBatchInv<256>(jacR, active, affineResult, sh_z, sh_prefix,
                                sh_rev, &sh_inv_total);

  if (active) {
    // Convert from Montgomery form to normal form for output
    affinePointFromMont(affineResult, results[idx]);
  }
}

// Host wrapper functions

CudaEccError batchMulBase(const void* hostScalars, void* hostResults,
                          int32_t count, cudaStream_t stream) {
  if (count <= 0 || hostScalars == nullptr || hostResults == nullptr) {
    return CudaEccError::kInvalidInput;
  }
  if (stream == 0) stream = g_stream;
  if (stream == nullptr) {
    return CudaEccError::kCudaError;
  }

  registerWorkspaceCleanup();

  cudaError_t err =
      ensureDeviceArray(&tl_workspace.scalars, &tl_workspace.scalars_capacity,
                        static_cast<size_t>(count));
  if (err != cudaSuccess) return toCudaEccError(err);
  err = ensureDeviceArray(&tl_workspace.results, &tl_workspace.results_capacity,
                          static_cast<size_t>(count));
  if (err != cudaSuccess) return toCudaEccError(err);

  const size_t scalarBytes = static_cast<size_t>(count) * sizeof(GpuScalar);
  const size_t pointBytes = static_cast<size_t>(count) * sizeof(GpuAffinePoint);

  err = cudaMemcpyAsync(tl_workspace.scalars, hostScalars, scalarBytes,
                        cudaMemcpyHostToDevice, stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  constexpr int kThreadsPerBlock = 256;
  const int numBlocks = (count + kThreadsPerBlock - 1) / kThreadsPerBlock;
  batchFixedBaseMulKernel<<<numBlocks, kThreadsPerBlock, 0, stream>>>(
      tl_workspace.scalars, tl_workspace.results, count);
  err = cudaPeekAtLastError();
  if (err != cudaSuccess) return toCudaEccError(err);

  err = cudaMemcpyAsync(hostResults, tl_workspace.results, pointBytes,
                        cudaMemcpyDeviceToHost, stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  err = cudaStreamSynchronize(stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  return CudaEccError::kSuccess;
}

CudaEccError batchMul(const void* hostPoints, const void* hostScalars,
                      void* hostResults, int32_t count, cudaStream_t stream) {
  if (count <= 0 || hostPoints == nullptr || hostScalars == nullptr ||
      hostResults == nullptr) {
    return CudaEccError::kInvalidInput;
  }
  if (stream == 0) stream = g_stream;
  if (stream == nullptr) {
    return CudaEccError::kCudaError;
  }

  registerWorkspaceCleanup();

  cudaError_t err =
      ensureDeviceArray(&tl_workspace.points, &tl_workspace.points_capacity,
                        static_cast<size_t>(count));
  if (err != cudaSuccess) return toCudaEccError(err);
  err = ensureDeviceArray(&tl_workspace.scalars, &tl_workspace.scalars_capacity,
                          static_cast<size_t>(count));
  if (err != cudaSuccess) return toCudaEccError(err);
  err = ensureDeviceArray(&tl_workspace.results, &tl_workspace.results_capacity,
                          static_cast<size_t>(count));
  if (err != cudaSuccess) return toCudaEccError(err);

  const size_t pointBytes = static_cast<size_t>(count) * sizeof(GpuAffinePoint);
  const size_t scalarBytes = static_cast<size_t>(count) * sizeof(GpuScalar);

  err = cudaMemcpyAsync(tl_workspace.points, hostPoints, pointBytes,
                        cudaMemcpyHostToDevice, stream);
  if (err != cudaSuccess) return toCudaEccError(err);
  err = cudaMemcpyAsync(tl_workspace.scalars, hostScalars, scalarBytes,
                        cudaMemcpyHostToDevice, stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  constexpr int kThreadsPerBlock = 256;
  const int numBlocks = (count + kThreadsPerBlock - 1) / kThreadsPerBlock;
  batchVarBaseMulKernel<<<numBlocks, kThreadsPerBlock, 0, stream>>>(
      tl_workspace.points, tl_workspace.scalars, tl_workspace.results, count);
  err = cudaPeekAtLastError();
  if (err != cudaSuccess) return toCudaEccError(err);

  err = cudaMemcpyAsync(hostResults, tl_workspace.results, pointBytes,
                        cudaMemcpyDeviceToHost, stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  err = cudaStreamSynchronize(stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  return CudaEccError::kSuccess;
}

CudaEccError batchMulSameScalar(const void* hostPoints, const void* hostScalar,
                                void* hostResults, int32_t count,
                                cudaStream_t stream) {
  if (count <= 0 || hostPoints == nullptr || hostScalar == nullptr ||
      hostResults == nullptr) {
    return CudaEccError::kInvalidInput;
  }
  if (stream == 0) stream = g_stream;
  if (stream == nullptr) {
    return CudaEccError::kCudaError;
  }

  registerWorkspaceCleanup();

  cudaError_t err =
      ensureDeviceArray(&tl_workspace.points, &tl_workspace.points_capacity,
                        static_cast<size_t>(count));
  if (err != cudaSuccess) return toCudaEccError(err);
  err = ensureDeviceArray(&tl_workspace.scalars, &tl_workspace.scalars_capacity,
                          1);
  if (err != cudaSuccess) return toCudaEccError(err);
  err = ensureDeviceArray(&tl_workspace.results, &tl_workspace.results_capacity,
                          static_cast<size_t>(count));
  if (err != cudaSuccess) return toCudaEccError(err);

  const size_t pointBytes = static_cast<size_t>(count) * sizeof(GpuAffinePoint);

  err = cudaMemcpyAsync(tl_workspace.points, hostPoints, pointBytes,
                        cudaMemcpyHostToDevice, stream);
  if (err != cudaSuccess) return toCudaEccError(err);
  err = cudaMemcpyAsync(tl_workspace.scalars, hostScalar, sizeof(GpuScalar),
                        cudaMemcpyHostToDevice, stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  constexpr int kThreadsPerBlock = 256;
  const int numBlocks = (count + kThreadsPerBlock - 1) / kThreadsPerBlock;
  batchSameScalarMulKernel<<<numBlocks, kThreadsPerBlock, 0, stream>>>(
      tl_workspace.points, tl_workspace.scalars, tl_workspace.results, count);
  err = cudaPeekAtLastError();
  if (err != cudaSuccess) return toCudaEccError(err);

  err = cudaMemcpyAsync(hostResults, tl_workspace.results, pointBytes,
                        cudaMemcpyDeviceToHost, stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  err = cudaStreamSynchronize(stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  return CudaEccError::kSuccess;
}

CudaEccError batchMulDoubleBase(const void* hostS1, const void* hostS2,
                                const void* hostPoints, void* hostResults,
                                int32_t count, cudaStream_t stream) {
  if (count <= 0 || hostS1 == nullptr || hostS2 == nullptr ||
      hostPoints == nullptr || hostResults == nullptr) {
    return CudaEccError::kInvalidInput;
  }
  if (stream == 0) stream = g_stream;
  if (stream == nullptr) {
    return CudaEccError::kCudaError;
  }

  registerWorkspaceCleanup();

  cudaError_t err =
      ensureDeviceArray(&tl_workspace.scalars, &tl_workspace.scalars_capacity,
                        static_cast<size_t>(count));
  if (err != cudaSuccess) return toCudaEccError(err);
  err =
      ensureDeviceArray(&tl_workspace.scalars2, &tl_workspace.scalars2_capacity,
                        static_cast<size_t>(count));
  if (err != cudaSuccess) return toCudaEccError(err);
  err = ensureDeviceArray(&tl_workspace.points, &tl_workspace.points_capacity,
                          static_cast<size_t>(count));
  if (err != cudaSuccess) return toCudaEccError(err);
  err = ensureDeviceArray(&tl_workspace.results, &tl_workspace.results_capacity,
                          static_cast<size_t>(count));
  if (err != cudaSuccess) return toCudaEccError(err);

  const size_t scalarBytes = static_cast<size_t>(count) * sizeof(GpuScalar);
  const size_t pointBytes = static_cast<size_t>(count) * sizeof(GpuAffinePoint);

  err = cudaMemcpyAsync(tl_workspace.scalars, hostS1, scalarBytes,
                        cudaMemcpyHostToDevice, stream);
  if (err != cudaSuccess) return toCudaEccError(err);
  err = cudaMemcpyAsync(tl_workspace.scalars2, hostS2, scalarBytes,
                        cudaMemcpyHostToDevice, stream);
  if (err != cudaSuccess) return toCudaEccError(err);
  err = cudaMemcpyAsync(tl_workspace.points, hostPoints, pointBytes,
                        cudaMemcpyHostToDevice, stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  constexpr int kThreadsPerBlock = 256;
  const int numBlocks = (count + kThreadsPerBlock - 1) / kThreadsPerBlock;
  batchDoubleBaseMulKernel<<<numBlocks, kThreadsPerBlock, 0, stream>>>(
      tl_workspace.scalars, tl_workspace.scalars2, tl_workspace.points,
      tl_workspace.results, count);
  err = cudaPeekAtLastError();
  if (err != cudaSuccess) return toCudaEccError(err);

  err = cudaMemcpyAsync(hostResults, tl_workspace.results, pointBytes,
                        cudaMemcpyDeviceToHost, stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  err = cudaStreamSynchronize(stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  return CudaEccError::kSuccess;
}

CudaEccError batchAdd(const void* hostP1s, const void* hostP2s,
                      void* hostResults, int32_t count, cudaStream_t stream) {
  if (count <= 0 || hostP1s == nullptr || hostP2s == nullptr ||
      hostResults == nullptr) {
    return CudaEccError::kInvalidInput;
  }
  if (stream == 0) stream = g_stream;
  if (stream == nullptr) {
    return CudaEccError::kCudaError;
  }

  registerWorkspaceCleanup();

  cudaError_t err =
      ensureDeviceArray(&tl_workspace.points, &tl_workspace.points_capacity,
                        static_cast<size_t>(count));
  if (err != cudaSuccess) return toCudaEccError(err);
  err = ensureDeviceArray(&tl_workspace.points2, &tl_workspace.points2_capacity,
                          static_cast<size_t>(count));
  if (err != cudaSuccess) return toCudaEccError(err);
  err = ensureDeviceArray(&tl_workspace.results, &tl_workspace.results_capacity,
                          static_cast<size_t>(count));
  if (err != cudaSuccess) return toCudaEccError(err);

  const size_t pointBytes = static_cast<size_t>(count) * sizeof(GpuAffinePoint);

  err = cudaMemcpyAsync(tl_workspace.points, hostP1s, pointBytes,
                        cudaMemcpyHostToDevice, stream);
  if (err != cudaSuccess) return toCudaEccError(err);
  err = cudaMemcpyAsync(tl_workspace.points2, hostP2s, pointBytes,
                        cudaMemcpyHostToDevice, stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  constexpr int kThreadsPerBlock = 256;
  const int numBlocks = (count + kThreadsPerBlock - 1) / kThreadsPerBlock;
  batchPointAddKernel<<<numBlocks, kThreadsPerBlock, 0, stream>>>(
      tl_workspace.points, tl_workspace.points2, tl_workspace.results, count);
  err = cudaPeekAtLastError();
  if (err != cudaSuccess) return toCudaEccError(err);

  err = cudaMemcpyAsync(hostResults, tl_workspace.results, pointBytes,
                        cudaMemcpyDeviceToHost, stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  err = cudaStreamSynchronize(stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  return CudaEccError::kSuccess;
}

CudaEccError batchDouble(const void* hostPoints, void* hostResults,
                         int32_t count, cudaStream_t stream) {
  if (count <= 0 || hostPoints == nullptr || hostResults == nullptr) {
    return CudaEccError::kInvalidInput;
  }
  if (stream == 0) stream = g_stream;
  if (stream == nullptr) {
    return CudaEccError::kCudaError;
  }

  registerWorkspaceCleanup();

  cudaError_t err =
      ensureDeviceArray(&tl_workspace.points, &tl_workspace.points_capacity,
                        static_cast<size_t>(count));
  if (err != cudaSuccess) return toCudaEccError(err);
  err = ensureDeviceArray(&tl_workspace.results, &tl_workspace.results_capacity,
                          static_cast<size_t>(count));
  if (err != cudaSuccess) return toCudaEccError(err);

  const size_t pointBytes = static_cast<size_t>(count) * sizeof(GpuAffinePoint);

  err = cudaMemcpyAsync(tl_workspace.points, hostPoints, pointBytes,
                        cudaMemcpyHostToDevice, stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  constexpr int kThreadsPerBlock = 256;
  const int numBlocks = (count + kThreadsPerBlock - 1) / kThreadsPerBlock;
  batchPointDoubleKernel<<<numBlocks, kThreadsPerBlock, 0, stream>>>(
      tl_workspace.points, tl_workspace.results, count);
  err = cudaPeekAtLastError();
  if (err != cudaSuccess) return toCudaEccError(err);

  err = cudaMemcpyAsync(hostResults, tl_workspace.results, pointBytes,
                        cudaMemcpyDeviceToHost, stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  err = cudaStreamSynchronize(stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  return CudaEccError::kSuccess;
}

CudaEccError batchHashAndMulFromSm3Digests(const void* hostDigests,
                                           const void* hostScalar,
                                           void* hostResults, int32_t count,
                                           cudaStream_t stream) {
  if (count <= 0 || hostDigests == nullptr || hostScalar == nullptr ||
      hostResults == nullptr) {
    return CudaEccError::kInvalidInput;
  }
  if (stream == 0) stream = g_stream;
  if (stream == nullptr) {
    return CudaEccError::kCudaError;
  }

  registerWorkspaceCleanup();

  const size_t digestBytes = static_cast<size_t>(count) * 32;
  const size_t pointBytes = static_cast<size_t>(count) * sizeof(GpuAffinePoint);

  cudaError_t err = ensureDeviceBytes(
      &tl_workspace.digests, &tl_workspace.digests_capacity, digestBytes);
  if (err != cudaSuccess) return toCudaEccError(err);
  err = ensureDeviceArray(&tl_workspace.scalars, &tl_workspace.scalars_capacity,
                          1);
  if (err != cudaSuccess) return toCudaEccError(err);
  err = ensureDeviceArray(&tl_workspace.results, &tl_workspace.results_capacity,
                          static_cast<size_t>(count));
  if (err != cudaSuccess) return toCudaEccError(err);
  err = ensureDeviceArray(&tl_workspace.error, &tl_workspace.error_capacity, 1);
  if (err != cudaSuccess) return toCudaEccError(err);

  err = cudaMemcpyAsync(tl_workspace.digests, hostDigests, digestBytes,
                        cudaMemcpyHostToDevice, stream);
  if (err != cudaSuccess) return toCudaEccError(err);
  err = cudaMemcpyAsync(tl_workspace.scalars, hostScalar, sizeof(GpuScalar),
                        cudaMemcpyHostToDevice, stream);
  if (err != cudaSuccess) return toCudaEccError(err);
  err = cudaMemsetAsync(tl_workspace.error, 0, sizeof(int32_t), stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  constexpr int kThreadsPerBlock = 256;
  const int numBlocks = (count + kThreadsPerBlock - 1) / kThreadsPerBlock;
  batchHashAndMulFromSm3DigestsKernel<<<numBlocks, kThreadsPerBlock, 0,
                                        stream>>>(
      tl_workspace.digests, tl_workspace.scalars, tl_workspace.results, count,
      tl_workspace.error);
  err = cudaPeekAtLastError();
  if (err != cudaSuccess) return toCudaEccError(err);

  err = cudaMemcpyAsync(hostResults, tl_workspace.results, pointBytes,
                        cudaMemcpyDeviceToHost, stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  int32_t hostError = 0;
  err = cudaMemcpyAsync(&hostError, tl_workspace.error, sizeof(int32_t),
                        cudaMemcpyDeviceToHost, stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  err = cudaStreamSynchronize(stream);
  if (err != cudaSuccess) return toCudaEccError(err);

  if (hostError != 0) {
    return CudaEccError::kNotOnCurve;
  }
  return CudaEccError::kSuccess;
}

void copyTableToConstantMemory(const GpuAffinePoint* hostTable) {
  if (hostTable == nullptr) {
    return;
  }

  std::lock_guard<std::mutex> lock(g_mutex);

  // Allocate global memory for the table
  bool allocated = false;
  if (h_generatorTableDevice == nullptr) {
    cudaError_t err = cudaMalloc(&h_generatorTableDevice,
                                 kFixedBaseTableSize * sizeof(GpuAffinePoint));
    if (err != cudaSuccess) {
      h_generatorTableDevice = nullptr;
      return;
    }
    allocated = true;
  }

  // Copy table to device global memory
  cudaError_t err = cudaMemcpy(h_generatorTableDevice, hostTable,
                               kFixedBaseTableSize * sizeof(GpuAffinePoint),
                               cudaMemcpyHostToDevice);
  if (err != cudaSuccess) {
    return;
  }

  // Update the device pointer
  err = cudaMemcpyToSymbol(g_generatorTable, &h_generatorTableDevice,
                           sizeof(GpuAffinePoint*));
  if (err != cudaSuccess) {
    if (allocated) {
      cudaFree(h_generatorTableDevice);
      h_generatorTableDevice = nullptr;
    }
    return;
  }
}

}  // namespace yacl::crypto::cuda

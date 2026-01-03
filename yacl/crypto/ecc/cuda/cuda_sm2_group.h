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
#include <memory>
#include <string>
#include <vector>

#include "absl/types/span.h"

#include "yacl/crypto/ecc/group_sketch.h"

namespace yacl::crypto::cuda {

// GPU-accelerated SM2 elliptic curve group.
// Single-point operations delegate to CPU (OpenSSL), batch operations use CUDA.
class CudaSm2Group : public EcGroupSketch {
 public:
  static std::unique_ptr<EcGroup> Create(const CurveMeta& meta);
  static bool IsSupported(const CurveMeta& meta);

  explicit CudaSm2Group(const CurveMeta& meta);
  ~CudaSm2Group() override;

  CudaSm2Group(const CudaSm2Group&) = delete;
  CudaSm2Group& operator=(const CudaSm2Group&) = delete;
  CudaSm2Group(CudaSm2Group&&) noexcept;
  CudaSm2Group& operator=(CudaSm2Group&&) noexcept;

  // EcGroup interface (single-point operations via CPU)
  std::string GetLibraryName() const override;

  MPInt GetCofactor() const override;
  MPInt GetField() const override;
  MPInt GetOrder() const override;
  EcPoint GetGenerator() const override;
  std::string ToString() const override;

  EcPoint Add(const EcPoint& p1, const EcPoint& p2) const override;
  void AddInplace(EcPoint* p1, const EcPoint& p2) const override;

  EcPoint Double(const EcPoint& p) const override;
  void DoubleInplace(EcPoint* p) const override;

  EcPoint Mul(const EcPoint& point, const MPInt& scalar) const override;
  void MulInplace(EcPoint* point, const MPInt& scalar) const override;

  EcPoint MulBase(const MPInt& scalar) const override;
  EcPoint MulDoubleBase(const MPInt& s1, const MPInt& s2,
                        const EcPoint& p2) const override;

  EcPoint Negate(const EcPoint& point) const override;
  void NegateInplace(EcPoint* point) const override;

  EcPoint CopyPoint(const EcPoint& point) const override;

  AffinePoint GetAffinePoint(const EcPoint& point) const override;

  uint64_t GetSerializeLength(PointOctetFormat format) const override;

  Buffer SerializePoint(const EcPoint& point,
                        PointOctetFormat format) const override;
  void SerializePoint(const EcPoint& point, PointOctetFormat format,
                      Buffer* buf) const override;
  void SerializePoint(const EcPoint& point, PointOctetFormat format,
                      uint8_t* buf, uint64_t buf_size) const override;
  EcPoint DeserializePoint(ByteContainerView buf,
                           PointOctetFormat format) const override;

  EcPoint HashToCurve(HashToCurveStrategy strategy, std::string_view str,
                      std::string_view dst) const override;

  yacl::math::MPInt HashToScalar(HashToCurveStrategy strategy,
                                 std::string_view str,
                                 std::string_view dst) const override;

  size_t HashPoint(const EcPoint& point) const override;
  bool PointEqual(const EcPoint& p1, const EcPoint& p2) const override;
  bool IsInCurveGroup(const EcPoint& point) const override;
  bool IsInfinity(const EcPoint& point) const override;

  // GPU-accelerated batch operations

  // results[i] = scalars[i] * points[i]
  void batchMul(absl::Span<const EcPoint> points,
                absl::Span<const MPInt> scalars,
                absl::Span<EcPoint> results) const;

  // results[i] = scalars[i] * G
  void batchMulBase(absl::Span<const MPInt> scalars,
                    absl::Span<EcPoint> results) const;

  // results[i] = scalar * points[i]
  void batchMulSameScalar(absl::Span<const EcPoint> points, const MPInt& scalar,
                          absl::Span<EcPoint> results) const;

  // results[i] = scalar * HashToCurve(inputs[i])
  void batchHashAndMul(HashToCurveStrategy strategy,
                       absl::Span<const std::string_view> inputs,
                       const MPInt& scalar, absl::Span<EcPoint> results) const;

  // results[i] = p1s[i] + p2s[i]
  void batchAdd(absl::Span<const EcPoint> p1s, absl::Span<const EcPoint> p2s,
                absl::Span<EcPoint> results) const;

  // results[i] = s1s[i] * G + s2s[i] * points[i]
  void batchMulDoubleBase(absl::Span<const MPInt> s1s,
                          absl::Span<const MPInt> s2s,
                          absl::Span<const EcPoint> points,
                          absl::Span<EcPoint> results) const;

  // Utility methods
  static bool isGpuAvailable();
  static int32_t getRecommendedBatchSize();
  static void getGpuMemoryInfo(size_t* free, size_t* total);

 private:
  // Host-side affine point in normal (non-Montgomery) form for CUDA kernels.
  // - Limb order is little-endian (x[0] is least significant 64 bits).
  // - Point-at-infinity is encoded as (0, 0).
  struct PackedAffinePoint {
    uint64_t x[4];
    uint64_t y[4];
  };

  void initCuda();
  void cleanupCuda();
  EcPoint toCpuPoint(const EcPoint& point) const;
  void convertToCudaPoint(const EcPoint& point, PackedAffinePoint* out) const;
  EcPoint convertFromCudaPoint(const PackedAffinePoint& p) const;
  void convertToCudaScalar(const MPInt& scalar, void* gpuScalar) const;

  std::shared_ptr<EcGroup> cpu_backend_;
  int cuda_device_id_;
  bool cuda_initialized_;
};

}  // namespace yacl::crypto::cuda

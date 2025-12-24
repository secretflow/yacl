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

#include "yacl/crypto/ecc/cuda/cuda_sm2_group.h"

#include <cstring>
#include <stdexcept>
#include <utility>

#include "yacl/crypto/ecc/cuda/kernels/sm2_kernels.cuh"
#include "yacl/crypto/ecc/ecc_spi.h"

namespace yacl::crypto::cuda {

namespace {

constexpr char kLibraryName[] = "CUDA_SM2";
constexpr int kDefaultDeviceId = 0;

// GPU point structure for data transfer (must match CUDA kernel types)
struct GpuPoint {
  uint64_t x[4];
  uint64_t y[4];
};

struct GpuScalarData {
  uint64_t limbs[4];
};

}  // namespace

std::unique_ptr<EcGroup> CudaSm2Group::Create(const CurveMeta& meta) {
  return std::make_unique<CudaSm2Group>(meta);
}

bool CudaSm2Group::IsSupported(const CurveMeta& meta) {
  if (meta.name != "SM2" && meta.name != "sm2") {
    return false;
  }
  return isGpuAvailable();
}

CudaSm2Group::CudaSm2Group(const CurveMeta& meta)
    : EcGroupSketch(meta), cuda_device_id_(-1), cuda_initialized_(false) {
  cpu_backend_ = EcGroupFactory::Instance().Create("sm2", ArgLib = "openssl");
  if (!cpu_backend_) {
    throw std::runtime_error("Failed to create OpenSSL SM2 backend");
  }

  // Initialize CUDA
  initCuda();
}

CudaSm2Group::~CudaSm2Group() {
  cleanupCuda();
}

CudaSm2Group::CudaSm2Group(CudaSm2Group&& other) noexcept
    : EcGroupSketch(std::move(other)),
      cpu_backend_(std::move(other.cpu_backend_)),
      cuda_device_id_(other.cuda_device_id_),
      cuda_initialized_(other.cuda_initialized_) {
  other.cuda_initialized_ = false;
  other.cuda_device_id_ = -1;
}

CudaSm2Group& CudaSm2Group::operator=(CudaSm2Group&& other) noexcept {
  if (this != &other) {
    cleanupCuda();
    EcGroupSketch::operator=(std::move(other));
    cpu_backend_ = std::move(other.cpu_backend_);
    cuda_device_id_ = other.cuda_device_id_;
    cuda_initialized_ = other.cuda_initialized_;
    other.cuda_initialized_ = false;
    other.cuda_device_id_ = -1;
  }
  return *this;
}

void CudaSm2Group::initCuda() {
  if (isGpuAvailable()) {
    cuda_device_id_ = cudaSm2Init(kDefaultDeviceId);
    cuda_initialized_ = (cuda_device_id_ >= 0);

    if (cuda_initialized_) {
      // Build fixed-base precomputation table for generator G
      const MPInt field = cpu_backend_->GetField();
      MPInt r(1);
      r <<= 256;
      r %= field;

      auto toMontField = [&](const MPInt& v) -> GpuFieldElement {
        MPInt mont = (v * r) % field;
        auto bytes = mont.ToMagBytes(Endian::little);
        GpuFieldElement out{};
        std::memset(out.limbs, 0, sizeof(out.limbs));
        std::memcpy(out.limbs, bytes.data(),
                    std::min(static_cast<size_t>(bytes.size()),
                             sizeof(out.limbs)));
        return out;
      };

      std::vector<GpuAffinePoint> hostTable(kFixedBaseTableSize);

      EcPoint base = cpu_backend_->GetGenerator();
      for (int i = 0; i < kNumWindows; ++i) {
        hostTable[i * kTableEntriesPerWindow + 0] = GpuAffinePoint{};

        EcPoint cur = base;
        for (int w = 1; w < kTableEntriesPerWindow; ++w) {
          const auto affine = cpu_backend_->GetAffinePoint(cur);
          hostTable[i * kTableEntriesPerWindow + w] = GpuAffinePoint{
              toMontField(affine.x),
              toMontField(affine.y),
          };
          cur = cpu_backend_->Add(cur, base);
        }

        for (int t = 0; t < kFixedBaseWindowSize; ++t) {
          base = cpu_backend_->Double(base);
        }
      }

      copyTableToConstantMemory(hostTable.data());
    }
  }
}

void CudaSm2Group::cleanupCuda() {
  if (cuda_initialized_) {
    cudaSm2Cleanup();
    cuda_initialized_ = false;
    cuda_device_id_ = -1;
  }
}

std::string CudaSm2Group::GetLibraryName() const {
  return kLibraryName;
}

MPInt CudaSm2Group::GetCofactor() const {
  return cpu_backend_->GetCofactor();
}

MPInt CudaSm2Group::GetField() const {
  return cpu_backend_->GetField();
}

MPInt CudaSm2Group::GetOrder() const {
  return cpu_backend_->GetOrder();
}

EcPoint CudaSm2Group::GetGenerator() const {
  return cpu_backend_->GetGenerator();
}

std::string CudaSm2Group::ToString() const {
  return fmt::format("CudaSm2Group (GPU-accelerated SM2, device={})",
                     cuda_device_id_);
}

EcPoint CudaSm2Group::Add(const EcPoint& p1, const EcPoint& p2) const {
  return cpu_backend_->Add(p1, p2);
}

void CudaSm2Group::AddInplace(EcPoint* p1, const EcPoint& p2) const {
  cpu_backend_->AddInplace(p1, p2);
}

EcPoint CudaSm2Group::Double(const EcPoint& p) const {
  return cpu_backend_->Double(p);
}

void CudaSm2Group::DoubleInplace(EcPoint* p) const {
  cpu_backend_->DoubleInplace(p);
}

EcPoint CudaSm2Group::Mul(const EcPoint& point, const MPInt& scalar) const {
  return cpu_backend_->Mul(point, scalar);
}

void CudaSm2Group::MulInplace(EcPoint* point, const MPInt& scalar) const {
  cpu_backend_->MulInplace(point, scalar);
}

EcPoint CudaSm2Group::MulBase(const MPInt& scalar) const {
  return cpu_backend_->MulBase(scalar);
}

EcPoint CudaSm2Group::MulDoubleBase(const MPInt& s1, const MPInt& s2,
                                    const EcPoint& p2) const {
  return cpu_backend_->MulDoubleBase(s1, s2, p2);
}

EcPoint CudaSm2Group::Negate(const EcPoint& point) const {
  return cpu_backend_->Negate(point);
}

void CudaSm2Group::NegateInplace(EcPoint* point) const {
  cpu_backend_->NegateInplace(point);
}

EcPoint CudaSm2Group::CopyPoint(const EcPoint& point) const {
  return cpu_backend_->CopyPoint(point);
}

AffinePoint CudaSm2Group::GetAffinePoint(const EcPoint& point) const {
  return cpu_backend_->GetAffinePoint(point);
}

uint64_t CudaSm2Group::GetSerializeLength(PointOctetFormat format) const {
  return cpu_backend_->GetSerializeLength(format);
}

Buffer CudaSm2Group::SerializePoint(const EcPoint& point,
                                    PointOctetFormat format) const {
  return cpu_backend_->SerializePoint(point, format);
}

void CudaSm2Group::SerializePoint(const EcPoint& point, PointOctetFormat format,
                                  Buffer* buf) const {
  cpu_backend_->SerializePoint(point, format, buf);
}

void CudaSm2Group::SerializePoint(const EcPoint& point, PointOctetFormat format,
                                  uint8_t* buf, uint64_t buf_size) const {
  cpu_backend_->SerializePoint(point, format, buf, buf_size);
}

EcPoint CudaSm2Group::DeserializePoint(ByteContainerView buf,
                                       PointOctetFormat format) const {
  return cpu_backend_->DeserializePoint(buf, format);
}

EcPoint CudaSm2Group::HashToCurve(HashToCurveStrategy strategy,
                                  std::string_view str,
                                  std::string_view dst) const {
  return cpu_backend_->HashToCurve(strategy, str, dst);
}

yacl::math::MPInt CudaSm2Group::HashToScalar(HashToCurveStrategy strategy,
                                             std::string_view str,
                                             std::string_view dst) const {
  return cpu_backend_->HashToScalar(strategy, str, dst);
}

size_t CudaSm2Group::HashPoint(const EcPoint& point) const {
  return cpu_backend_->HashPoint(point);
}

bool CudaSm2Group::PointEqual(const EcPoint& p1, const EcPoint& p2) const {
  return cpu_backend_->PointEqual(p1, p2);
}

bool CudaSm2Group::IsInCurveGroup(const EcPoint& point) const {
  return cpu_backend_->IsInCurveGroup(point);
}

bool CudaSm2Group::IsInfinity(const EcPoint& point) const {
  return cpu_backend_->IsInfinity(point);
}

void CudaSm2Group::convertToGpuPoint(const EcPoint& point,
                                     void* gpuPointRaw) const {
  auto* gpuPoint = static_cast<GpuPoint*>(gpuPointRaw);
  AffinePoint affine = cpu_backend_->GetAffinePoint(point);

  auto xBytes = affine.x.ToMagBytes(Endian::little);
  std::memset(gpuPoint->x, 0, sizeof(gpuPoint->x));
  std::memcpy(gpuPoint->x, xBytes.data(),
              std::min(static_cast<size_t>(xBytes.size()), sizeof(gpuPoint->x)));

  auto yBytes = affine.y.ToMagBytes(Endian::little);
  std::memset(gpuPoint->y, 0, sizeof(gpuPoint->y));
  std::memcpy(gpuPoint->y, yBytes.data(),
              std::min(static_cast<size_t>(yBytes.size()), sizeof(gpuPoint->y)));
}

EcPoint CudaSm2Group::convertFromGpuPoint(const void* gpuPointRaw) const {
  const auto* gpuPoint = static_cast<const GpuPoint*>(gpuPointRaw);

  std::vector<uint8_t> xBytes(reinterpret_cast<const uint8_t*>(gpuPoint->x),
                              reinterpret_cast<const uint8_t*>(gpuPoint->x) + 32);
  std::vector<uint8_t> yBytes(reinterpret_cast<const uint8_t*>(gpuPoint->y),
                              reinterpret_cast<const uint8_t*>(gpuPoint->y) + 32);

  MPInt x, y;
  x.FromMagBytes(xBytes, Endian::little);
  y.FromMagBytes(yBytes, Endian::little);

  // Point-at-infinity is encoded as (0, 0)
  if (x.IsZero() && y.IsZero()) {
    return cpu_backend_->MulBase(MPInt(0));
  }

  AffinePoint affine{x, y};
  return cpu_backend_->CopyPoint(EcPoint(affine));
}

void CudaSm2Group::convertToGpuScalar(const MPInt& scalar,
                                      void* gpuScalarRaw) const {
  auto* gpuScalar = static_cast<GpuScalarData*>(gpuScalarRaw);
  MPInt reduced = scalar.Mod(GetOrder());
  auto bytes = reduced.ToMagBytes(Endian::little);
  std::memset(gpuScalar->limbs, 0, sizeof(gpuScalar->limbs));
  std::memcpy(gpuScalar->limbs, bytes.data(),
              std::min(static_cast<size_t>(bytes.size()), sizeof(gpuScalar->limbs)));
}

void CudaSm2Group::batchMul(absl::Span<const EcPoint> points,
                            absl::Span<const MPInt> scalars,
                            absl::Span<EcPoint> results) const {
  YACL_ENFORCE(points.size() == scalars.size());
  YACL_ENFORCE(points.size() == results.size());

  if (!cuda_initialized_ || points.empty()) {
    for (size_t i = 0; i < points.size(); ++i) {
      results[i] = cpu_backend_->Mul(points[i], scalars[i]);
    }
    return;
  }

  int32_t count = static_cast<int32_t>(points.size());
  std::vector<GpuPoint> gpuPoints(count);
  std::vector<GpuScalarData> gpuScalars(count);
  std::vector<GpuPoint> gpuResults(count);

  for (int32_t i = 0; i < count; ++i) {
    convertToGpuPoint(points[i], &gpuPoints[i]);
    convertToGpuScalar(scalars[i], &gpuScalars[i]);
  }

  CudaEccError err = cuda::batchMul(gpuPoints.data(), gpuScalars.data(),
                                    gpuResults.data(), count);

  if (err != CudaEccError::kSuccess) {
    for (size_t i = 0; i < points.size(); ++i) {
      results[i] = cpu_backend_->Mul(points[i], scalars[i]);
    }
    return;
  }

  for (int32_t i = 0; i < count; ++i) {
    try {
      results[i] = convertFromGpuPoint(&gpuResults[i]);
    } catch (const std::exception&) {
      results[i] = cpu_backend_->Mul(points[i], scalars[i]);
    }
  }
}

void CudaSm2Group::batchMulBase(absl::Span<const MPInt> scalars,
                                absl::Span<EcPoint> results) const {
  YACL_ENFORCE(scalars.size() == results.size());

  if (!cuda_initialized_ || scalars.empty()) {
    for (size_t i = 0; i < scalars.size(); ++i) {
      results[i] = cpu_backend_->MulBase(scalars[i]);
    }
    return;
  }

  int32_t count = static_cast<int32_t>(scalars.size());

  std::vector<GpuScalarData> gpuScalars(count);
  std::vector<GpuPoint> gpuResults(count);

  for (int32_t i = 0; i < count; ++i) {
    convertToGpuScalar(scalars[i], &gpuScalars[i]);
  }

  CudaEccError err = cuda::batchMulBase(gpuScalars.data(),
                                        gpuResults.data(), count);

  if (err != CudaEccError::kSuccess) {
    for (size_t i = 0; i < scalars.size(); ++i) {
      results[i] = cpu_backend_->MulBase(scalars[i]);
    }
    return;
  }

  for (int32_t i = 0; i < count; ++i) {
    try {
      results[i] = convertFromGpuPoint(&gpuResults[i]);
    } catch (const std::exception&) {
      results[i] = cpu_backend_->MulBase(scalars[i]);
    }
  }
}

void CudaSm2Group::batchMulSameScalar(absl::Span<const EcPoint> points,
                                      const MPInt& scalar,
                                      absl::Span<EcPoint> results) const {
  YACL_ENFORCE(points.size() == results.size());

  if (!cuda_initialized_ || points.empty()) {
    for (size_t i = 0; i < points.size(); ++i) {
      results[i] = cpu_backend_->Mul(points[i], scalar);
    }
    return;
  }

  int32_t count = static_cast<int32_t>(points.size());

  std::vector<GpuPoint> gpuPoints(count);
  GpuScalarData gpuScalar;
  std::vector<GpuPoint> gpuResults(count);

  for (int32_t i = 0; i < count; ++i) {
    convertToGpuPoint(points[i], &gpuPoints[i]);
  }
  convertToGpuScalar(scalar, &gpuScalar);

  CudaEccError err = cuda::batchMulSameScalar(gpuPoints.data(), &gpuScalar,
                                              gpuResults.data(), count);

  if (err != CudaEccError::kSuccess) {
    for (size_t i = 0; i < points.size(); ++i) {
      results[i] = cpu_backend_->Mul(points[i], scalar);
    }
    return;
  }

  for (int32_t i = 0; i < count; ++i) {
    try {
      results[i] = convertFromGpuPoint(&gpuResults[i]);
    } catch (const std::exception&) {
      results[i] = cpu_backend_->Mul(points[i], scalar);
    }
  }
}

void CudaSm2Group::batchHashAndMul(HashToCurveStrategy strategy,
                                   absl::Span<const std::string_view> inputs,
                                   const MPInt& scalar,
                                   absl::Span<EcPoint> results) const {
  YACL_ENFORCE(inputs.size() == results.size());

  // HashToCurve on CPU, then batch multiplication on GPU
  std::vector<EcPoint> hashedPoints(inputs.size());
  for (size_t i = 0; i < inputs.size(); ++i) {
    hashedPoints[i] = cpu_backend_->HashToCurve(strategy, inputs[i], "");
  }
  batchMulSameScalar(hashedPoints, scalar, results);
}

void CudaSm2Group::batchAdd(absl::Span<const EcPoint> p1s,
                            absl::Span<const EcPoint> p2s,
                            absl::Span<EcPoint> results) const {
  YACL_ENFORCE(p1s.size() == p2s.size());
  YACL_ENFORCE(p1s.size() == results.size());

  if (!cuda_initialized_ || p1s.empty()) {
    for (size_t i = 0; i < p1s.size(); ++i) {
      results[i] = cpu_backend_->Add(p1s[i], p2s[i]);
    }
    return;
  }

  int32_t count = static_cast<int32_t>(p1s.size());

  std::vector<GpuPoint> gpuP1s(count);
  std::vector<GpuPoint> gpuP2s(count);
  std::vector<GpuPoint> gpuResults(count);

  for (int32_t i = 0; i < count; ++i) {
    convertToGpuPoint(p1s[i], &gpuP1s[i]);
    convertToGpuPoint(p2s[i], &gpuP2s[i]);
  }

  CudaEccError err = cuda::batchAdd(gpuP1s.data(), gpuP2s.data(),
                                    gpuResults.data(), count);

  if (err != CudaEccError::kSuccess) {
    for (size_t i = 0; i < p1s.size(); ++i) {
      results[i] = cpu_backend_->Add(p1s[i], p2s[i]);
    }
    return;
  }

  for (int32_t i = 0; i < count; ++i) {
    try {
      results[i] = convertFromGpuPoint(&gpuResults[i]);
    } catch (const std::exception&) {
      results[i] = cpu_backend_->Add(p1s[i], p2s[i]);
    }
  }
}

void CudaSm2Group::batchMulDoubleBase(absl::Span<const MPInt> s1s,
                                      absl::Span<const MPInt> s2s,
                                      absl::Span<const EcPoint> points,
                                      absl::Span<EcPoint> results) const {
  YACL_ENFORCE(s1s.size() == s2s.size());
  YACL_ENFORCE(s1s.size() == points.size());
  YACL_ENFORCE(s1s.size() == results.size());

  if (!cuda_initialized_ || s1s.empty()) {
    for (size_t i = 0; i < s1s.size(); ++i) {
      results[i] = cpu_backend_->MulDoubleBase(s1s[i], s2s[i], points[i]);
    }
    return;
  }

  int32_t count = static_cast<int32_t>(s1s.size());

  std::vector<GpuScalarData> gpuS1(count);
  std::vector<GpuScalarData> gpuS2(count);
  std::vector<GpuPoint> gpuPoints(count);
  std::vector<GpuPoint> gpuResults(count);

  for (int32_t i = 0; i < count; ++i) {
    convertToGpuScalar(s1s[i], &gpuS1[i]);
    convertToGpuScalar(s2s[i], &gpuS2[i]);
    convertToGpuPoint(points[i], &gpuPoints[i]);
  }

  CudaEccError err =
      cuda::batchMulDoubleBase(gpuS1.data(), gpuS2.data(), gpuPoints.data(),
                               gpuResults.data(), count);

  if (err != CudaEccError::kSuccess) {
    for (size_t i = 0; i < s1s.size(); ++i) {
      results[i] = cpu_backend_->MulDoubleBase(s1s[i], s2s[i], points[i]);
    }
    return;
  }

  for (int32_t i = 0; i < count; ++i) {
    try {
      results[i] = convertFromGpuPoint(&gpuResults[i]);
    } catch (const std::exception&) {
      results[i] = cpu_backend_->MulDoubleBase(s1s[i], s2s[i], points[i]);
    }
  }
}

bool CudaSm2Group::isGpuAvailable() {
  return isCudaAvailable();
}

int32_t CudaSm2Group::getRecommendedBatchSize() {
  return 4096;
}

void CudaSm2Group::getGpuMemoryInfo(size_t* free, size_t* total) {
  cuda::getGpuMemoryInfo(free, total);
}

}  // namespace yacl::crypto::cuda

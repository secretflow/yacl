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

#include "yacl/crypto/ecc/cuda/cuda_sm2_group.h"

#include <condition_variable>
#include <cstring>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "spdlog/spdlog.h"

#include "yacl/crypto/ecc/cuda/kernels/sm2_kernels.cuh"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/openssl_wrappers.h"
#include "yacl/utils/parallel.h"

namespace yacl::crypto::cuda {

namespace {

constexpr char kLibraryName[] = "CUDA_SM2";
constexpr int kDefaultDeviceId = 0;

inline bool ShouldCheckCudaPointValidity(int32_t idx, int32_t count) {
#ifdef NDEBUG
  (void)idx;
  (void)count;
  return false;
#else
  constexpr int32_t kMaxFullCheck = 4096;
  constexpr int32_t kEdgeChecks = 16;
  constexpr int32_t kStride = 4096;
  if (count <= kMaxFullCheck) {
    return true;
  }
  return idx < kEdgeChecks || idx >= count - kEdgeChecks ||
         (idx % kStride) == 0;
#endif
}
constexpr size_t kSm2FieldBytes = 32;

void WarnCudaFallback(std::string_view op, CudaEccError err, int32_t count) {
  SPDLOG_WARN("CudaSm2Group: {} failed (err={}, count={}), fallback to CPU", op,
              static_cast<int>(err), count);
}

struct GpuScalarData {
  uint64_t limbs[4];
};

const MPInt& Sm2FieldP() {
  static const MPInt p(
      "0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
  return p;
}

const MPInt& Sm2CurveB() {
  static const MPInt b(
      "0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93");
  return b;
}

class Sm3OneShot {
 public:
  Sm3OneShot() : ctx_(EVP_MD_CTX_new()) { YACL_ENFORCE(ctx_ != nullptr); }

  void Digest(std::string_view data, uint8_t out[kSm2FieldBytes]) {
    unsigned int out_len = 0;
    OSSL_RET_1(EVP_MD_CTX_reset(ctx_.get()));
    OSSL_RET_1(EVP_DigestInit_ex(ctx_.get(), EVP_sm3(), nullptr));
    OSSL_RET_1(EVP_DigestUpdate(ctx_.get(), data.data(), data.size()));
    OSSL_RET_1(EVP_DigestFinal_ex(ctx_.get(), out, &out_len));
    YACL_ENFORCE(out_len == kSm2FieldBytes);
  }

 private:
  openssl::UniqueMdCtx ctx_;
};

template <typename T>
class PinnedHostBuffer {
 public:
  PinnedHostBuffer() = default;
  PinnedHostBuffer(const PinnedHostBuffer&) = delete;
  PinnedHostBuffer& operator=(const PinnedHostBuffer&) = delete;

  ~PinnedHostBuffer() { Reset(); }

  T* data() { return state_->ptr; }
  const T* data() const { return state_->ptr; }
  size_t capacity() const { return state_->capacity; }

  bool Ensure(size_t count) {
    if (count <= state_->capacity) {
      return true;
    }
    Reset();
    void* p = nullptr;
    const cudaError_t err = cudaMallocHost(&p, count * sizeof(T));
    if (err != cudaSuccess) {
      return false;
    }
    state_->ptr = static_cast<T*>(p);
    state_->capacity = count;

    // Register cleanup callback on first successful allocation.
    // This ensures the buffer is freed before CUDA runtime shutdown.
    if (!registered_) {
      std::weak_ptr<State> weak = state_;
      cuda::cudaSm2RegisterCleanup([weak]() {
        auto state = weak.lock();
        if (!state) {
          return;
        }
        if (state->ptr != nullptr) {
          cudaFreeHost(state->ptr);
          state->ptr = nullptr;
          state->capacity = 0;
        }
      });
      registered_ = true;
    }
    return true;
  }

  void Reset() {
    if (state_->ptr != nullptr) {
      cudaFreeHost(state_->ptr);
      state_->ptr = nullptr;
      state_->capacity = 0;
    }
  }

 private:
  struct State {
    T* ptr = nullptr;
    size_t capacity = 0;
  };

  std::shared_ptr<State> state_ = std::make_shared<State>();
  bool registered_ = false;
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

CudaSm2Group::~CudaSm2Group() { cleanupCuda(); }

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
        GpuFieldElement out{};
        mont.ToBytes(reinterpret_cast<unsigned char*>(out.limbs),
                     kSm2FieldBytes, Endian::little);
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

std::string CudaSm2Group::GetLibraryName() const { return kLibraryName; }

MPInt CudaSm2Group::GetCofactor() const { return cpu_backend_->GetCofactor(); }

MPInt CudaSm2Group::GetField() const { return cpu_backend_->GetField(); }

MPInt CudaSm2Group::GetOrder() const { return cpu_backend_->GetOrder(); }

EcPoint CudaSm2Group::GetGenerator() const {
  return cpu_backend_->GetGenerator();
}

std::string CudaSm2Group::ToString() const {
  return fmt::format("CudaSm2Group (GPU-accelerated SM2, device={})",
                     cuda_device_id_);
}

EcPoint CudaSm2Group::Add(const EcPoint& p1, const EcPoint& p2) const {
  return cpu_backend_->Add(toCpuPoint(p1), toCpuPoint(p2));
}

void CudaSm2Group::AddInplace(EcPoint* p1, const EcPoint& p2) const {
  YACL_ENFORCE(p1 != nullptr);
  if (!std::holds_alternative<AnyPtr>(*p1)) {
    *p1 = toCpuPoint(*p1);
  }
  cpu_backend_->AddInplace(p1, toCpuPoint(p2));
}

EcPoint CudaSm2Group::Double(const EcPoint& p) const {
  return cpu_backend_->Double(toCpuPoint(p));
}

void CudaSm2Group::DoubleInplace(EcPoint* p) const {
  YACL_ENFORCE(p != nullptr);
  if (!std::holds_alternative<AnyPtr>(*p)) {
    *p = toCpuPoint(*p);
  }
  cpu_backend_->DoubleInplace(p);
}

EcPoint CudaSm2Group::Mul(const EcPoint& point, const MPInt& scalar) const {
  return cpu_backend_->Mul(toCpuPoint(point), scalar);
}

void CudaSm2Group::MulInplace(EcPoint* point, const MPInt& scalar) const {
  YACL_ENFORCE(point != nullptr);
  if (!std::holds_alternative<AnyPtr>(*point)) {
    *point = toCpuPoint(*point);
  }
  cpu_backend_->MulInplace(point, scalar);
}

EcPoint CudaSm2Group::MulBase(const MPInt& scalar) const {
  return cpu_backend_->MulBase(scalar);
}

EcPoint CudaSm2Group::MulDoubleBase(const MPInt& s1, const MPInt& s2,
                                    const EcPoint& p2) const {
  return cpu_backend_->MulDoubleBase(s1, s2, toCpuPoint(p2));
}

EcPoint CudaSm2Group::Negate(const EcPoint& point) const {
  return cpu_backend_->Negate(toCpuPoint(point));
}

void CudaSm2Group::NegateInplace(EcPoint* point) const {
  YACL_ENFORCE(point != nullptr);
  if (!std::holds_alternative<AnyPtr>(*point)) {
    *point = toCpuPoint(*point);
  }
  cpu_backend_->NegateInplace(point);
}

EcPoint CudaSm2Group::CopyPoint(const EcPoint& point) const {
  return cpu_backend_->CopyPoint(point);
}

AffinePoint CudaSm2Group::GetAffinePoint(const EcPoint& point) const {
  if (std::holds_alternative<AffinePoint>(point)) {
    return std::get<AffinePoint>(point);
  }
  return cpu_backend_->GetAffinePoint(point);
}

uint64_t CudaSm2Group::GetSerializeLength(PointOctetFormat format) const {
  return cpu_backend_->GetSerializeLength(format);
}

Buffer CudaSm2Group::SerializePoint(const EcPoint& point,
                                    PointOctetFormat format) const {
  Buffer buf;
  SerializePoint(point, format, &buf);
  return buf;
}

void CudaSm2Group::SerializePoint(const EcPoint& point, PointOctetFormat format,
                                  Buffer* buf) const {
  YACL_ENFORCE(buf != nullptr);
  if (!std::holds_alternative<AffinePoint>(point)) {
    cpu_backend_->SerializePoint(point, format, buf);
    return;
  }

  const auto& ap = std::get<AffinePoint>(point);
  if (ap.x.IsZero() && ap.y.IsZero()) {
    buf->resize(1);
    buf->data<uint8_t>()[0] = 0x00;
    return;
  }

  enum class SerMode : uint8_t {
    kCompressed = 0,
    kUncompressed = 1,
    kHybrid = 2,
  };

  SerMode mode;
  switch (format) {
    case PointOctetFormat::X962Uncompressed:
      mode = SerMode::kUncompressed;
      break;
    case PointOctetFormat::X962Hybrid:
      mode = SerMode::kHybrid;
      break;
    default:
      mode = SerMode::kCompressed;
      break;
  }

  if (mode == SerMode::kCompressed) {
    buf->resize(1 + kSm2FieldBytes);
    uint8_t* out = buf->data<uint8_t>();
    out[0] = ap.y.IsOdd() ? 0x03 : 0x02;
    ap.x.ToBytes(out + 1, kSm2FieldBytes, Endian::big);
    return;
  }

  buf->resize(1 + 2 * kSm2FieldBytes);
  uint8_t* out = buf->data<uint8_t>();
  if (mode == SerMode::kUncompressed) {
    out[0] = 0x04;
  } else {
    out[0] = ap.y.IsOdd() ? 0x07 : 0x06;
  }
  ap.x.ToBytes(out + 1, kSm2FieldBytes, Endian::big);
  ap.y.ToBytes(out + 1 + kSm2FieldBytes, kSm2FieldBytes, Endian::big);
}

void CudaSm2Group::SerializePoint(const EcPoint& point, PointOctetFormat format,
                                  uint8_t* buf, uint64_t buf_size) const {
  if (!std::holds_alternative<AffinePoint>(point)) {
    cpu_backend_->SerializePoint(point, format, buf, buf_size);
    return;
  }
  Buffer tmp;
  SerializePoint(point, format, &tmp);
  const uint64_t tmp_size = static_cast<uint64_t>(tmp.size());
  YACL_ENFORCE(buf_size >= tmp_size, "buf size is small than needed {}",
               tmp_size);
  std::memcpy(buf, tmp.data<uint8_t>(), tmp.size());
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
  if (!std::holds_alternative<AffinePoint>(point)) {
    return cpu_backend_->HashPoint(point);
  }

  const auto& ap = std::get<AffinePoint>(point);
  if (ap.x.IsZero() && ap.y.IsZero()) {
    return 0;
  }

  const size_t len = (ap.x.BitCount() + 7) / 8;
  if (len == 0) {
    return std::hash<std::string_view>{}({}) + ap.y.IsOdd();
  }

  YACL_ENFORCE(len <= kSm2FieldBytes);
  unsigned char buf[kSm2FieldBytes];
  ap.x.ToMagBytes(buf, len, Endian::little);
  return std::hash<std::string_view>{}(
             {reinterpret_cast<const char*>(buf), len}) +
         ap.y.IsOdd();
}

bool CudaSm2Group::PointEqual(const EcPoint& p1, const EcPoint& p2) const {
  if (std::holds_alternative<AnyPtr>(p1) &&
      std::holds_alternative<AnyPtr>(p2)) {
    return cpu_backend_->PointEqual(p1, p2);
  }
  const auto a1 = GetAffinePoint(p1);
  const auto a2 = GetAffinePoint(p2);
  return a1 == a2;
}

bool CudaSm2Group::IsInCurveGroup(const EcPoint& point) const {
  if (!std::holds_alternative<AffinePoint>(point)) {
    return cpu_backend_->IsInCurveGroup(point);
  }

  const auto& ap = std::get<AffinePoint>(point);
  if (ap.x.IsZero() && ap.y.IsZero()) {
    return true;
  }
  if (ap.x.IsNegative() || ap.y.IsNegative()) {
    return false;
  }
  if (ap.x >= Sm2FieldP() || ap.y >= Sm2FieldP()) {
    return false;
  }

  const MPInt p = Sm2FieldP();
  const MPInt a = p - 3;
  const MPInt x = ap.x % p;
  const MPInt y = ap.y % p;

  const MPInt y2 = (y * y) % p;
  const MPInt x2 = (x * x) % p;
  const MPInt x3 = (x2 * x) % p;
  const MPInt rhs = (x3 + (a * x) + Sm2CurveB()) % p;
  return y2 == rhs;
}

bool CudaSm2Group::IsInfinity(const EcPoint& point) const {
  if (!std::holds_alternative<AffinePoint>(point)) {
    return cpu_backend_->IsInfinity(point);
  }
  const auto& ap = std::get<AffinePoint>(point);
  return ap.x.IsZero() && ap.y.IsZero();
}

EcPoint CudaSm2Group::toCpuPoint(const EcPoint& point) const {
  if (std::holds_alternative<AnyPtr>(point)) {
    return point;
  }
  if (std::holds_alternative<AffinePoint>(point)) {
    const auto& ap = std::get<AffinePoint>(point);
    if (ap.x.IsZero() && ap.y.IsZero()) {
      return cpu_backend_->MulBase(MPInt(0));
    }
  }
  return cpu_backend_->CopyPoint(point);
}

void CudaSm2Group::convertToCudaPoint(const EcPoint& point,
                                      PackedAffinePoint* out) const {
  YACL_ENFORCE(out != nullptr);
  AffinePoint affine;
  if (std::holds_alternative<AffinePoint>(point)) {
    affine = std::get<AffinePoint>(point);
  } else {
    affine = cpu_backend_->GetAffinePoint(point);
  }

  affine.x.ToBytes(reinterpret_cast<unsigned char*>(out->x), kSm2FieldBytes,
                   Endian::little);
  affine.y.ToBytes(reinterpret_cast<unsigned char*>(out->y), kSm2FieldBytes,
                   Endian::little);
}

EcPoint CudaSm2Group::convertFromCudaPoint(const PackedAffinePoint& p) const {
  MPInt x, y;
  x.FromMagBytes(yacl::ByteContainerView(p.x, kSm2FieldBytes), Endian::little);
  y.FromMagBytes(yacl::ByteContainerView(p.y, kSm2FieldBytes), Endian::little);

  // Point-at-infinity is encoded as (0, 0).
  if (x.IsZero() && y.IsZero()) {
    return EcPoint(AffinePoint{});
  }

  return EcPoint(AffinePoint{x, y});
}

void CudaSm2Group::convertToCudaScalar(const MPInt& scalar,
                                       void* gpuScalarRaw) const {
  auto* gpuScalar = static_cast<GpuScalarData*>(gpuScalarRaw);
  MPInt reduced = scalar.Mod(GetOrder());
  reduced.ToBytes(reinterpret_cast<unsigned char*>(gpuScalar->limbs),
                  kSm2FieldBytes, Endian::little);
}

void CudaSm2Group::batchMul(absl::Span<const EcPoint> points,
                            absl::Span<const MPInt> scalars,
                            absl::Span<EcPoint> results) const {
  YACL_ENFORCE(points.size() == scalars.size());
  YACL_ENFORCE(points.size() == results.size());

  if (!cuda_initialized_ || points.empty()) {
    for (size_t i = 0; i < points.size(); ++i) {
      results[i] = cpu_backend_->Mul(toCpuPoint(points[i]), scalars[i]);
    }
    return;
  }

  YACL_ENFORCE(points.size() <=
               static_cast<size_t>(std::numeric_limits<int32_t>::max()));
  int32_t count = static_cast<int32_t>(points.size());
  std::vector<PackedAffinePoint> gpuPoints(count);
  std::vector<GpuScalarData> gpuScalars(count);
  std::vector<PackedAffinePoint> gpuResults(count);

  for (int32_t i = 0; i < count; ++i) {
    convertToCudaPoint(points[i], &gpuPoints[i]);
    convertToCudaScalar(scalars[i], &gpuScalars[i]);
  }

  CudaEccError err = cuda::batchMul(gpuPoints.data(), gpuScalars.data(),
                                    gpuResults.data(), count);

  if (err != CudaEccError::kSuccess) {
    WarnCudaFallback("batchMul", err, count);
    for (size_t i = 0; i < points.size(); ++i) {
      results[i] = cpu_backend_->Mul(toCpuPoint(points[i]), scalars[i]);
    }
    return;
  }

  for (int32_t i = 0; i < count; ++i) {
    results[i] = convertFromCudaPoint(gpuResults[i]);
    if (ShouldCheckCudaPointValidity(i, count)) {
      WEAK_ENFORCE(IsInCurveGroup(results[i]),
                   "CudaSm2Group: batchMul produced invalid point at idx={}",
                   i);
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

  YACL_ENFORCE(scalars.size() <=
               static_cast<size_t>(std::numeric_limits<int32_t>::max()));
  int32_t count = static_cast<int32_t>(scalars.size());

  std::vector<GpuScalarData> gpuScalars(count);
  std::vector<PackedAffinePoint> gpuResults(count);

  for (int32_t i = 0; i < count; ++i) {
    convertToCudaScalar(scalars[i], &gpuScalars[i]);
  }

  CudaEccError err =
      cuda::batchMulBase(gpuScalars.data(), gpuResults.data(), count);

  if (err != CudaEccError::kSuccess) {
    WarnCudaFallback("batchMulBase", err, count);
    for (size_t i = 0; i < scalars.size(); ++i) {
      results[i] = cpu_backend_->MulBase(scalars[i]);
    }
    return;
  }

  for (int32_t i = 0; i < count; ++i) {
    results[i] = convertFromCudaPoint(gpuResults[i]);
    if (ShouldCheckCudaPointValidity(i, count)) {
      WEAK_ENFORCE(
          IsInCurveGroup(results[i]),
          "CudaSm2Group: batchMulBase produced invalid point at idx={}", i);
    }
  }
}

void CudaSm2Group::batchMulSameScalar(absl::Span<const EcPoint> points,
                                      const MPInt& scalar,
                                      absl::Span<EcPoint> results) const {
  YACL_ENFORCE(points.size() == results.size());

  if (!cuda_initialized_ || points.empty()) {
    for (size_t i = 0; i < points.size(); ++i) {
      results[i] = cpu_backend_->Mul(toCpuPoint(points[i]), scalar);
    }
    return;
  }

  YACL_ENFORCE(points.size() <=
               static_cast<size_t>(std::numeric_limits<int32_t>::max()));
  int32_t count = static_cast<int32_t>(points.size());

  std::vector<PackedAffinePoint> gpuPoints(count);
  GpuScalarData gpuScalar;
  std::vector<PackedAffinePoint> gpuResults(count);

  for (int32_t i = 0; i < count; ++i) {
    convertToCudaPoint(points[i], &gpuPoints[i]);
  }
  convertToCudaScalar(scalar, &gpuScalar);

  CudaEccError err = cuda::batchMulSameScalar(gpuPoints.data(), &gpuScalar,
                                              gpuResults.data(), count);

  if (err != CudaEccError::kSuccess) {
    WarnCudaFallback("batchMulSameScalar", err, count);
    for (size_t i = 0; i < points.size(); ++i) {
      results[i] = cpu_backend_->Mul(toCpuPoint(points[i]), scalar);
    }
    return;
  }

  for (int32_t i = 0; i < count; ++i) {
    results[i] = convertFromCudaPoint(gpuResults[i]);
    if (ShouldCheckCudaPointValidity(i, count)) {
      WEAK_ENFORCE(IsInCurveGroup(results[i]),
                   "CudaSm2Group: batchMulSameScalar produced invalid point at "
                   "idx={}",
                   i);
    }
  }
}

void CudaSm2Group::batchHashAndMul(HashToCurveStrategy strategy,
                                   absl::Span<const std::string_view> inputs,
                                   const MPInt& scalar,
                                   absl::Span<EcPoint> results) const {
  YACL_ENFORCE(inputs.size() == results.size());

  auto cpuFallback = [&]() {
    std::vector<EcPoint> hashedPoints(inputs.size());
    for (size_t i = 0; i < inputs.size(); ++i) {
      hashedPoints[i] = cpu_backend_->HashToCurve(strategy, inputs[i], "");
    }
    batchMulSameScalar(hashedPoints, scalar, results);
  };

  if (!cuda_initialized_ || inputs.empty() ||
      strategy != HashToCurveStrategy::TryAndRehash_SM) {
    cpuFallback();
    return;
  }

  YACL_ENFORCE(inputs.size() <=
               static_cast<size_t>(std::numeric_limits<int32_t>::max()));
  const int32_t count = static_cast<int32_t>(inputs.size());

  GpuScalarData gpuScalar;
  convertToCudaScalar(scalar, &gpuScalar);

  CudaEccError last_gpu_err = CudaEccError::kSuccess;
  auto runGpuNonPipelined = [&]() -> bool {
    thread_local PinnedHostBuffer<uint8_t> digests_buf;
    thread_local PinnedHostBuffer<PackedAffinePoint> results_buf;

    const bool pinned_ok =
        digests_buf.Ensure(static_cast<size_t>(count) * kSm2FieldBytes) &&
        results_buf.Ensure(static_cast<size_t>(count));

    if (!pinned_ok) {
      // Fallback to pageable host memory if pinned allocation fails.
      std::vector<uint8_t> digests(static_cast<size_t>(count) * kSm2FieldBytes);
      std::vector<PackedAffinePoint> gpuResults(count);
      yacl::parallel_for(
          0, count, getRecommendedBatchSize(), [&](int64_t begin, int64_t end) {
            thread_local Sm3OneShot hasher;
            for (int64_t i = begin; i < end; ++i) {
              hasher.Digest(
                  inputs[static_cast<size_t>(i)],
                  digests.data() + static_cast<size_t>(i) * kSm2FieldBytes);
            }
          });

      const CudaEccError err = cuda::batchHashAndMulFromSm3Digests(
          digests.data(), &gpuScalar, gpuResults.data(), count);
      if (err != CudaEccError::kSuccess) {
        last_gpu_err = err;
        return false;
      }

      yacl::parallel_for(
          0, count, getRecommendedBatchSize(), [&](int64_t begin, int64_t end) {
            for (int64_t i = begin; i < end; ++i) {
              const auto idx = static_cast<size_t>(i);
              results[idx] = convertFromCudaPoint(gpuResults[idx]);
              if (ShouldCheckCudaPointValidity(static_cast<int32_t>(idx),
                                               count)) {
                WEAK_ENFORCE(
                    IsInCurveGroup(results[idx]),
                    "CudaSm2Group: batchHashAndMul produced invalid point at "
                    "idx={}",
                    idx);
              }
            }
          });
      return true;
    }

    uint8_t* digests = digests_buf.data();
    PackedAffinePoint* gpuResults = results_buf.data();

    yacl::parallel_for(
        0, count, getRecommendedBatchSize(), [&](int64_t begin, int64_t end) {
          thread_local Sm3OneShot hasher;
          for (int64_t i = begin; i < end; ++i) {
            hasher.Digest(inputs[static_cast<size_t>(i)],
                          digests + static_cast<size_t>(i) * kSm2FieldBytes);
          }
        });

    const CudaEccError err = cuda::batchHashAndMulFromSm3Digests(
        digests, &gpuScalar, gpuResults, count);
    if (err != CudaEccError::kSuccess) {
      last_gpu_err = err;
      return false;
    }

    yacl::parallel_for(
        0, count, getRecommendedBatchSize(), [&](int64_t begin, int64_t end) {
          for (int64_t i = begin; i < end; ++i) {
            const auto idx = static_cast<size_t>(i);
            results[idx] = convertFromCudaPoint(gpuResults[idx]);
            if (ShouldCheckCudaPointValidity(static_cast<int32_t>(idx),
                                             count)) {
              WEAK_ENFORCE(IsInCurveGroup(results[idx]),
                           "CudaSm2Group: batchHashAndMul produced invalid "
                           "point at idx={}",
                           idx);
            }
          }
        });
    return true;
  };

  // Pipelined path (double-buffering) for large batches.
  constexpr int32_t kChunkSize = 131072;  // 128K
  const bool enable_pipeline = (count >= 2 * kChunkSize);

  if (!enable_pipeline) {
    if (!runGpuNonPipelined()) {
      WarnCudaFallback("batchHashAndMul", last_gpu_err, count);
      cpuFallback();
    }
    return;
  }

  struct PipelineSlot {
    PinnedHostBuffer<uint8_t> digests;
    PinnedHostBuffer<PackedAffinePoint> results;
    std::vector<uint8_t> digests_vec;
    std::vector<PackedAffinePoint> results_vec;
    bool use_pinned = true;

    bool Ensure(int32_t n, bool prefer_pinned) {
      use_pinned = prefer_pinned &&
                   digests.Ensure(static_cast<size_t>(n) * kSm2FieldBytes) &&
                   results.Ensure(static_cast<size_t>(n));
      if (use_pinned) {
        return true;
      }

      digests_vec.resize(static_cast<size_t>(n) * kSm2FieldBytes);
      results_vec.resize(static_cast<size_t>(n));
      return true;
    }

    uint8_t* DigestsData() {
      return use_pinned ? digests.data() : digests_vec.data();
    }
    PackedAffinePoint* ResultsData() {
      return use_pinned ? results.data() : results_vec.data();
    }
  };

  thread_local PipelineSlot slots[2];

  struct SlotState {
    int32_t offset = 0;
    int32_t n = 0;
    bool digests_ready = false;
    bool results_ready = false;
    CudaEccError status = CudaEccError::kSuccess;
  };

  SlotState state[2];
  std::mutex mu;
  std::condition_variable cv;
  bool stop = false;

  const int32_t num_chunks = (count + kChunkSize - 1) / kChunkSize;

  std::thread gpu_worker([&]() {
    cudaSetDevice(cuda_device_id_);
    for (int32_t chunk = 0; chunk < num_chunks; ++chunk) {
      const int slot = chunk & 1;

      std::unique_lock<std::mutex> lock(mu);
      cv.wait(lock, [&] { return stop || state[slot].digests_ready; });
      if (stop) {
        return;
      }

      const int32_t n = state[slot].n;
      state[slot].digests_ready = false;
      lock.unlock();

      const CudaEccError st = cuda::batchHashAndMulFromSm3Digests(
          slots[slot].DigestsData(), &gpuScalar, slots[slot].ResultsData(), n);

      lock.lock();
      state[slot].status = st;
      state[slot].results_ready = true;
      if (st != CudaEccError::kSuccess) {
        stop = true;
      }
      lock.unlock();
      cv.notify_all();

      if (st != CudaEccError::kSuccess) {
        return;
      }
    }
  });

  auto convertChunk = [&](int slot) {
    const int32_t off = state[slot].offset;
    const int32_t n = state[slot].n;
    auto* gpuResults = slots[slot].ResultsData();

    yacl::parallel_for(
        0, n, getRecommendedBatchSize(), [&](int64_t begin, int64_t end) {
          for (int64_t i = begin; i < end; ++i) {
            const auto idx = static_cast<size_t>(i);
            const size_t out_idx = static_cast<size_t>(off) + idx;
            results[out_idx] = convertFromCudaPoint(gpuResults[idx]);
            if (ShouldCheckCudaPointValidity(static_cast<int32_t>(out_idx),
                                             count)) {
              WEAK_ENFORCE(IsInCurveGroup(results[out_idx]),
                           "CudaSm2Group: batchHashAndMul produced invalid "
                           "point at idx={}",
                           out_idx);
            }
          }
        });
  };

  bool prefer_pinned = true;

  for (int32_t chunk = 0; chunk < num_chunks; ++chunk) {
    const int slot = chunk & 1;
    const int32_t off = chunk * kChunkSize;
    const int32_t n = std::min(kChunkSize, count - off);

    if (!slots[slot].Ensure(n, prefer_pinned)) {
      {
        std::lock_guard<std::mutex> lock(mu);
        stop = true;
      }
      cv.notify_all();
      break;
    }
    if (!slots[slot].use_pinned) {
      prefer_pinned = false;
    }

    // Prepare digests for this chunk.
    uint8_t* digests = slots[slot].DigestsData();
    yacl::parallel_for(off, off + n, getRecommendedBatchSize(),
                       [&](int64_t begin, int64_t end) {
                         thread_local Sm3OneShot hasher;
                         for (int64_t i = begin; i < end; ++i) {
                           const auto local = static_cast<size_t>(i - off);
                           hasher.Digest(inputs[static_cast<size_t>(i)],
                                         digests + local * kSm2FieldBytes);
                         }
                       });

    {
      std::lock_guard<std::mutex> lock(mu);
      state[slot].offset = off;
      state[slot].n = n;
      state[slot].status = CudaEccError::kSuccess;
      state[slot].results_ready = false;
      state[slot].digests_ready = true;
    }
    cv.notify_all();

    // Consume previous chunk's results.
    if (chunk > 0) {
      const int prev_slot = (chunk - 1) & 1;
      std::unique_lock<std::mutex> lock(mu);
      cv.wait(lock, [&] { return stop || state[prev_slot].results_ready; });
      if (stop) {
        lock.unlock();
        break;
      }
      const CudaEccError st = state[prev_slot].status;
      state[prev_slot].results_ready = false;
      lock.unlock();

      if (st != CudaEccError::kSuccess) {
        {
          std::lock_guard<std::mutex> guard(mu);
          stop = true;
        }
        cv.notify_all();
        break;
      }
      convertChunk(prev_slot);
    }
  }

  // Consume last chunk's results.
  const int last_slot = (num_chunks - 1) & 1;
  {
    std::unique_lock<std::mutex> lock(mu);
    cv.wait(lock, [&] { return stop || state[last_slot].results_ready; });
    if (stop) {
      lock.unlock();
      gpu_worker.join();
      if (!runGpuNonPipelined()) {
        WarnCudaFallback("batchHashAndMul", last_gpu_err, count);
        cpuFallback();
      }
      return;
    }
    const CudaEccError st = state[last_slot].status;
    state[last_slot].results_ready = false;
    lock.unlock();

    if (st != CudaEccError::kSuccess) {
      std::lock_guard<std::mutex> guard(mu);
      stop = true;
    } else {
      convertChunk(last_slot);
    }
  }

  gpu_worker.join();

  if (stop) {
    if (!runGpuNonPipelined()) {
      WarnCudaFallback("batchHashAndMul", last_gpu_err, count);
      cpuFallback();
    }
    return;
  }
}

void CudaSm2Group::batchAdd(absl::Span<const EcPoint> p1s,
                            absl::Span<const EcPoint> p2s,
                            absl::Span<EcPoint> results) const {
  YACL_ENFORCE(p1s.size() == p2s.size());
  YACL_ENFORCE(p1s.size() == results.size());

  if (!cuda_initialized_ || p1s.empty()) {
    for (size_t i = 0; i < p1s.size(); ++i) {
      results[i] = cpu_backend_->Add(toCpuPoint(p1s[i]), toCpuPoint(p2s[i]));
    }
    return;
  }

  YACL_ENFORCE(p1s.size() <=
               static_cast<size_t>(std::numeric_limits<int32_t>::max()));
  int32_t count = static_cast<int32_t>(p1s.size());

  std::vector<PackedAffinePoint> gpuP1s(count);
  std::vector<PackedAffinePoint> gpuP2s(count);
  std::vector<PackedAffinePoint> gpuResults(count);

  for (int32_t i = 0; i < count; ++i) {
    convertToCudaPoint(p1s[i], &gpuP1s[i]);
    convertToCudaPoint(p2s[i], &gpuP2s[i]);
  }

  CudaEccError err =
      cuda::batchAdd(gpuP1s.data(), gpuP2s.data(), gpuResults.data(), count);

  if (err != CudaEccError::kSuccess) {
    WarnCudaFallback("batchAdd", err, count);
    for (size_t i = 0; i < p1s.size(); ++i) {
      results[i] = cpu_backend_->Add(toCpuPoint(p1s[i]), toCpuPoint(p2s[i]));
    }
    return;
  }

  for (int32_t i = 0; i < count; ++i) {
    results[i] = convertFromCudaPoint(gpuResults[i]);
    if (ShouldCheckCudaPointValidity(i, count)) {
      WEAK_ENFORCE(IsInCurveGroup(results[i]),
                   "CudaSm2Group: batchAdd produced invalid point at idx={}",
                   i);
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
      results[i] =
          cpu_backend_->MulDoubleBase(s1s[i], s2s[i], toCpuPoint(points[i]));
    }
    return;
  }

  YACL_ENFORCE(s1s.size() <=
               static_cast<size_t>(std::numeric_limits<int32_t>::max()));
  int32_t count = static_cast<int32_t>(s1s.size());

  std::vector<GpuScalarData> gpuS1(count);
  std::vector<GpuScalarData> gpuS2(count);
  std::vector<PackedAffinePoint> gpuPoints(count);
  std::vector<PackedAffinePoint> gpuResults(count);

  for (int32_t i = 0; i < count; ++i) {
    convertToCudaScalar(s1s[i], &gpuS1[i]);
    convertToCudaScalar(s2s[i], &gpuS2[i]);
    convertToCudaPoint(points[i], &gpuPoints[i]);
  }

  CudaEccError err = cuda::batchMulDoubleBase(
      gpuS1.data(), gpuS2.data(), gpuPoints.data(), gpuResults.data(), count);

  if (err != CudaEccError::kSuccess) {
    WarnCudaFallback("batchMulDoubleBase", err, count);
    for (size_t i = 0; i < s1s.size(); ++i) {
      results[i] =
          cpu_backend_->MulDoubleBase(s1s[i], s2s[i], toCpuPoint(points[i]));
    }
    return;
  }

  for (int32_t i = 0; i < count; ++i) {
    results[i] = convertFromCudaPoint(gpuResults[i]);
    if (ShouldCheckCudaPointValidity(i, count)) {
      WEAK_ENFORCE(IsInCurveGroup(results[i]),
                   "CudaSm2Group: batchMulDoubleBase produced invalid point at "
                   "idx={}",
                   i);
    }
  }
}

bool CudaSm2Group::isGpuAvailable() { return isCudaAvailable(); }

int32_t CudaSm2Group::getRecommendedBatchSize() { return 4096; }

void CudaSm2Group::getGpuMemoryInfo(size_t* free, size_t* total) {
  cuda::getGpuMemoryInfo(free, total);
}

}  // namespace yacl::crypto::cuda

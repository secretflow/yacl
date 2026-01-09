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

#include <cstring>
#include <vector>

#include "gtest/gtest.h"

#include "yacl/crypto/ecc/cuda/cuda_sm2_group.h"
#include "yacl/crypto/ecc/cuda/kernels/sm2_kernels.cuh"
#include "yacl/crypto/ecc/ecc_spi.h"

namespace yacl::crypto::cuda {
namespace {

class CudaSm2Test : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    if (!CudaSm2Group::isGpuAvailable()) {
      return;
    }
    cuda_ec_ = EcGroupFactory::Instance().Create("sm2", ArgLib = "CUDA_SM2");
    cpu_ec_ = EcGroupFactory::Instance().Create("sm2", ArgLib = "openssl");
  }

  MPInt randomScalar() {
    MPInt s;
    MPInt::RandomLtN(cpu_ec_->GetOrder(), &s);
    return s;
  }

  EcPoint randomPoint() { return cpu_ec_->MulBase(randomScalar()); }

  void SetUp() override {
    if (!CudaSm2Group::isGpuAvailable()) {
      GTEST_SKIP() << "CUDA is not available, skipping GPU tests";
    }

    ASSERT_NE(cuda_ec_, nullptr);
    ASSERT_NE(cpu_ec_, nullptr);
  }

  static std::shared_ptr<EcGroup> cuda_ec_;
  static std::shared_ptr<EcGroup> cpu_ec_;
};

std::shared_ptr<EcGroup> CudaSm2Test::cuda_ec_ = nullptr;
std::shared_ptr<EcGroup> CudaSm2Test::cpu_ec_ = nullptr;

TEST_F(CudaSm2Test, LibraryName) {
  EXPECT_EQ(cuda_ec_->GetLibraryName(), "CUDA_SM2");
}

TEST_F(CudaSm2Test, DebugMontgomeryMul) {
  int32_t results[32] = {0};
  auto err = debugMontMul(results, 0);
  ASSERT_EQ(err, CudaEccError::kSuccess);

  EXPECT_EQ(results[0], 1) << "fpMul(1,1) != 1";
  EXPECT_EQ(results[1], 1) << "fpFromMont(fpToMont(2)) != 2";
  EXPECT_EQ(results[2], 1) << "fpMul(R^2, 1) != R";
}

TEST_F(CudaSm2Test, DebugReadScalar) {
  GpuScalar s{};
  auto bytes = MPInt(2).ToBytes(/*byte_len=*/32, Endian::little);
  std::memcpy(s.limbs, bytes.data(), bytes.size());

  uint64_t results[6] = {0};
  const auto err = debugReadScalar(&s, results, 0);
  ASSERT_EQ(err, CudaEccError::kSuccess);

  EXPECT_EQ(results[0], 2);
  EXPECT_EQ(results[1], 0);
  EXPECT_EQ(results[2], 0);
  EXPECT_EQ(results[3], 0);
  EXPECT_EQ(results[4], 1);                        // popcount
  EXPECT_EQ(static_cast<int64_t>(results[5]), 1);  // msb index
}

TEST_F(CudaSm2Test, GetCurveParams) {
  EXPECT_EQ(cuda_ec_->GetOrder(), cpu_ec_->GetOrder());
  EXPECT_EQ(cuda_ec_->GetField(), cpu_ec_->GetField());
  EXPECT_EQ(cuda_ec_->GetCofactor(), cpu_ec_->GetCofactor());
}

TEST_F(CudaSm2Test, SinglePointMulBase) {
  auto scalar = randomScalar();

  auto cuda_result = cuda_ec_->MulBase(scalar);
  auto cpu_result = cpu_ec_->MulBase(scalar);

  EXPECT_TRUE(cuda_ec_->PointEqual(cuda_result, cpu_result));
}

TEST_F(CudaSm2Test, SinglePointMul) {
  auto point = randomPoint();
  auto scalar = randomScalar();

  auto cuda_result = cuda_ec_->Mul(point, scalar);
  auto cpu_result = cpu_ec_->Mul(point, scalar);

  EXPECT_TRUE(cuda_ec_->PointEqual(cuda_result, cpu_result));
}

TEST_F(CudaSm2Test, SinglePointAdd) {
  auto p1 = randomPoint();
  auto p2 = randomPoint();

  auto cuda_result = cuda_ec_->Add(p1, p2);
  auto cpu_result = cpu_ec_->Add(p1, p2);

  EXPECT_TRUE(cuda_ec_->PointEqual(cuda_result, cpu_result));
}

TEST_F(CudaSm2Test, BatchMulBase) {
  const int count = 100;

  std::vector<MPInt> scalars(count);
  for (int i = 0; i < count; ++i) {
    scalars[i] = randomScalar();
  }

  std::vector<EcPoint> cuda_results(count);
  auto* cuda_group = dynamic_cast<CudaSm2Group*>(cuda_ec_.get());
  cuda_group->batchMulBase(scalars, absl::MakeSpan(cuda_results));

  for (int i = 0; i < count; ++i) {
    auto cpu_result = cpu_ec_->MulBase(scalars[i]);
    EXPECT_TRUE(cuda_ec_->PointEqual(cuda_results[i], cpu_result))
        << "Mismatch at index " << i;
  }
}

TEST_F(CudaSm2Test, BatchMulDoubleBase) {
  const int count = 100;

  std::vector<MPInt> s1s(count);
  std::vector<MPInt> s2s(count);
  std::vector<EcPoint> points(count);
  for (int i = 0; i < count; ++i) {
    s1s[i] = randomScalar();
    s2s[i] = randomScalar();
    points[i] = randomPoint();
  }

  std::vector<EcPoint> cuda_results(count);
  auto* cuda_group = dynamic_cast<CudaSm2Group*>(cuda_ec_.get());
  cuda_group->batchMulDoubleBase(s1s, s2s, points,
                                 absl::MakeSpan(cuda_results));

  for (int i = 0; i < count; ++i) {
    const auto cpu_result = cpu_ec_->MulDoubleBase(s1s[i], s2s[i], points[i]);
    EXPECT_TRUE(cuda_ec_->PointEqual(cuda_results[i], cpu_result))
        << "Mismatch at index " << i;
  }
}

TEST_F(CudaSm2Test, RawMulGeneratorScalar2) {
  auto toGpuField = [](const MPInt& v) -> GpuFieldElement {
    GpuFieldElement f{};
    auto bytes = v.ToBytes(/*byte_len=*/32, Endian::little);
    std::memcpy(f.limbs, bytes.data(), bytes.size());
    return f;
  };

  auto toGpuScalar = [](const MPInt& scalar) -> GpuScalar {
    GpuScalar s{};
    auto bytes = scalar.ToBytes(/*byte_len=*/32, Endian::little);
    std::memcpy(s.limbs, bytes.data(), bytes.size());
    return s;
  };

  auto toAffine = [](const GpuAffinePoint& p) -> AffinePoint {
    MPInt x, y;
    x.FromMagBytes({reinterpret_cast<const uint8_t*>(p.x.limbs), 32},
                   Endian::little);
    y.FromMagBytes({reinterpret_cast<const uint8_t*>(p.y.limbs), 32},
                   Endian::little);
    return {x, y};
  };

  const auto gen = cpu_ec_->GetGenerator();
  const auto gen_affine = cpu_ec_->GetAffinePoint(gen);
  const GpuAffinePoint in{toGpuField(gen_affine.x), toGpuField(gen_affine.y)};

  const auto scalar = MPInt(2);
  const auto gpuScalar = toGpuScalar(scalar);
  GpuAffinePoint out{};
  const auto err =
      cuda::batchMul(&in, &gpuScalar, &out, /*count=*/1, /*stream=*/0);
  ASSERT_EQ(err, CudaEccError::kSuccess);

  const auto affine = toAffine(out);
  EcPoint got;
  ASSERT_NO_THROW(got = cpu_ec_->CopyPoint(EcPoint(affine)));

  const auto expected = cpu_ec_->MulBase(scalar);
  EXPECT_TRUE(cpu_ec_->PointEqual(got, expected));
}

TEST_F(CudaSm2Test, RawMulBaseSmallScalars) {
  auto toGpuScalar = [](const MPInt& scalar) -> GpuScalar {
    GpuScalar s{};
    auto bytes = scalar.ToBytes(/*byte_len=*/32, Endian::little);
    std::memcpy(s.limbs, bytes.data(), bytes.size());
    return s;
  };

  auto toAffine = [](const GpuAffinePoint& p) -> AffinePoint {
    MPInt x, y;
    x.FromMagBytes({reinterpret_cast<const uint8_t*>(p.x.limbs), 32},
                   Endian::little);
    y.FromMagBytes({reinterpret_cast<const uint8_t*>(p.y.limbs), 32},
                   Endian::little);
    return {x, y};
  };

  for (const MPInt scalar :
       {MPInt(1), MPInt(2), MPInt(3), MPInt(5), MPInt(7)}) {
    SCOPED_TRACE(std::string("scalar=") + scalar.ToHexString());
    const auto expected = cpu_ec_->MulBase(scalar);

    const auto gpuScalar = toGpuScalar(scalar);
    GpuAffinePoint gpuOut{};
    const auto err =
        cuda::batchMulBase(&gpuScalar, &gpuOut, /*count=*/1, /*stream=*/0);
    ASSERT_EQ(err, CudaEccError::kSuccess);

    const auto affine = toAffine(gpuOut);
    SCOPED_TRACE(std::string("gpu.x=") + affine.x.ToHexString());
    SCOPED_TRACE(std::string("gpu.y=") + affine.y.ToHexString());
    EcPoint got;
    ASSERT_NO_THROW(got = cpu_ec_->CopyPoint(EcPoint(affine)));
    EXPECT_TRUE(cpu_ec_->PointEqual(got, expected))
        << "Mismatch for scalar=" << scalar.ToHexString();
  }
}

TEST_F(CudaSm2Test, RawAddDoubleGenerator) {
  auto toGpuField = [](const MPInt& v) -> GpuFieldElement {
    GpuFieldElement f{};
    auto bytes = v.ToBytes(/*byte_len=*/32, Endian::little);
    std::memcpy(f.limbs, bytes.data(), bytes.size());
    return f;
  };

  auto toAffine = [](const GpuAffinePoint& p) -> AffinePoint {
    MPInt x, y;
    x.FromMagBytes({reinterpret_cast<const uint8_t*>(p.x.limbs), 32},
                   Endian::little);
    y.FromMagBytes({reinterpret_cast<const uint8_t*>(p.y.limbs), 32},
                   Endian::little);
    return {x, y};
  };

  const auto gen = cpu_ec_->GetGenerator();
  const auto gen_affine = cpu_ec_->GetAffinePoint(gen);

  const GpuAffinePoint in{
      toGpuField(gen_affine.x),
      toGpuField(gen_affine.y),
  };

  GpuAffinePoint out{};
  const auto err = cuda::batchAdd(&in, &in, &out, /*count=*/1, /*stream=*/0);
  ASSERT_EQ(err, CudaEccError::kSuccess);

  const auto affine = toAffine(out);
  EcPoint got;
  ASSERT_NO_THROW(got = cpu_ec_->CopyPoint(EcPoint(affine)));

  const auto expected = cpu_ec_->Double(gen);
  EXPECT_TRUE(cpu_ec_->PointEqual(got, expected));
}

TEST_F(CudaSm2Test, RawDoubleGenerator) {
  auto toGpuField = [](const MPInt& v) -> GpuFieldElement {
    GpuFieldElement f{};
    auto bytes = v.ToBytes(/*byte_len=*/32, Endian::little);
    std::memcpy(f.limbs, bytes.data(), bytes.size());
    return f;
  };

  auto toAffine = [](const GpuAffinePoint& p) -> AffinePoint {
    MPInt x, y;
    x.FromMagBytes({reinterpret_cast<const uint8_t*>(p.x.limbs), 32},
                   Endian::little);
    y.FromMagBytes({reinterpret_cast<const uint8_t*>(p.y.limbs), 32},
                   Endian::little);
    return {x, y};
  };

  const auto gen = cpu_ec_->GetGenerator();
  const auto gen_affine = cpu_ec_->GetAffinePoint(gen);
  const GpuAffinePoint in{toGpuField(gen_affine.x), toGpuField(gen_affine.y)};

  GpuAffinePoint out{};
  const auto err = cuda::batchDouble(&in, &out, /*count=*/1, /*stream=*/0);
  ASSERT_EQ(err, CudaEccError::kSuccess);

  const auto affine = toAffine(out);
  EcPoint got;
  ASSERT_NO_THROW(got = cpu_ec_->CopyPoint(EcPoint(affine)));

  const auto expected = cpu_ec_->Double(gen);
  EXPECT_TRUE(cpu_ec_->PointEqual(got, expected));
}

TEST_F(CudaSm2Test, BatchMul) {
  const int count = 100;

  std::vector<EcPoint> points(count);
  std::vector<MPInt> scalars(count);
  for (int i = 0; i < count; ++i) {
    points[i] = randomPoint();
    scalars[i] = randomScalar();
  }

  std::vector<EcPoint> cuda_results(count);
  auto* cuda_group = dynamic_cast<CudaSm2Group*>(cuda_ec_.get());
  cuda_group->batchMul(points, scalars, absl::MakeSpan(cuda_results));

  for (int i = 0; i < count; ++i) {
    auto cpu_result = cpu_ec_->Mul(points[i], scalars[i]);
    EXPECT_TRUE(cuda_ec_->PointEqual(cuda_results[i], cpu_result))
        << "Mismatch at index " << i;
  }
}

TEST_F(CudaSm2Test, BatchMulSameScalar) {
  const int count = 100;
  auto scalar = randomScalar();

  std::vector<EcPoint> points(count);
  for (int i = 0; i < count; ++i) {
    points[i] = randomPoint();
  }

  std::vector<EcPoint> cuda_results(count);
  auto* cuda_group = dynamic_cast<CudaSm2Group*>(cuda_ec_.get());
  cuda_group->batchMulSameScalar(points, scalar, absl::MakeSpan(cuda_results));

  for (int i = 0; i < count; ++i) {
    auto cpu_result = cpu_ec_->Mul(points[i], scalar);
    EXPECT_TRUE(cuda_ec_->PointEqual(cuda_results[i], cpu_result))
        << "Mismatch at index " << i;
  }
}

TEST_F(CudaSm2Test, BatchAdd) {
  const int count = 100;

  std::vector<EcPoint> p1s(count);
  std::vector<EcPoint> p2s(count);
  for (int i = 0; i < count; ++i) {
    p1s[i] = randomPoint();
    p2s[i] = randomPoint();
  }

  std::vector<EcPoint> cuda_results(count);
  auto* cuda_group = dynamic_cast<CudaSm2Group*>(cuda_ec_.get());
  cuda_group->batchAdd(p1s, p2s, absl::MakeSpan(cuda_results));

  for (int i = 0; i < count; ++i) {
    auto cpu_result = cpu_ec_->Add(p1s[i], p2s[i]);
    EXPECT_TRUE(cuda_ec_->PointEqual(cuda_results[i], cpu_result))
        << "Mismatch at index " << i;
  }
}

TEST_F(CudaSm2Test, BatchHashAndMul) {
  const int count = 50;
  auto scalar = randomScalar();

  std::vector<std::string> inputs(count);
  std::vector<std::string_view> input_views(count);
  for (int i = 0; i < count; ++i) {
    inputs[i] = "test_input_" + std::to_string(i);
    input_views[i] = inputs[i];
  }

  std::vector<EcPoint> cuda_results(count);
  auto* cuda_group = dynamic_cast<CudaSm2Group*>(cuda_ec_.get());
  cuda_group->batchHashAndMul(HashToCurveStrategy::TryAndRehash_SM, input_views,
                              scalar, absl::MakeSpan(cuda_results));

  for (int i = 0; i < count; ++i) {
    auto hashed = cpu_ec_->HashToCurve(HashToCurveStrategy::TryAndRehash_SM,
                                       inputs[i], "");
    auto cpu_result = cpu_ec_->Mul(hashed, scalar);
    EXPECT_TRUE(cuda_ec_->PointEqual(cuda_results[i], cpu_result))
        << "Mismatch at index " << i;
  }
}

TEST_F(CudaSm2Test, EdgeCases) {
  MPInt zero(0);
  auto result = cuda_ec_->MulBase(zero);
  EXPECT_TRUE(cuda_ec_->IsInfinity(result));

  MPInt one(1);
  auto gen = cuda_ec_->GetGenerator();
  result = cuda_ec_->MulBase(one);
  EXPECT_TRUE(cuda_ec_->PointEqual(result, gen));

  auto point = randomPoint();
  auto neg_point = cuda_ec_->Negate(point);
  result = cuda_ec_->Add(point, neg_point);
  EXPECT_TRUE(cuda_ec_->IsInfinity(result));
}

TEST_F(CudaSm2Test, Serialization) {
  auto point = randomPoint();
  auto serialized =
      cuda_ec_->SerializePoint(point, PointOctetFormat::X962Uncompressed);
  auto deserialized = cuda_ec_->DeserializePoint(
      serialized, PointOctetFormat::X962Uncompressed);
  EXPECT_TRUE(cuda_ec_->PointEqual(point, deserialized));

  // Batch outputs are represented as AffinePoint; ensure serialization works.
  auto* cuda_group = dynamic_cast<CudaSm2Group*>(cuda_ec_.get());
  std::vector<MPInt> scalars{randomScalar()};
  std::vector<EcPoint> batch_points(1);
  cuda_group->batchMulBase(scalars, absl::MakeSpan(batch_points));

  auto serialized2 = cuda_ec_->SerializePoint(
      batch_points[0], PointOctetFormat::X962Uncompressed);
  auto deserialized2 = cuda_ec_->DeserializePoint(
      serialized2, PointOctetFormat::X962Uncompressed);
  EXPECT_TRUE(cuda_ec_->PointEqual(batch_points[0], deserialized2));
}

}  // namespace
}  // namespace yacl::crypto::cuda

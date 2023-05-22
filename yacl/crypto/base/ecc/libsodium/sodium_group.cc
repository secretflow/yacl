// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "yacl/crypto/base/ecc/libsodium/sodium_group.h"

#include <functional>
#include <mutex>
#include <string_view>
#include <utility>

#include "fmt/format.h"

#include "yacl/crypto/base/ecc/ec_point.h"

namespace yacl::crypto::sodium {

SodiumGroup::SodiumGroup(CurveMeta meta, CurveParam param)
    : EcGroupSketch(std::move(meta)), param_(std::move(param)) {}

MPInt SodiumGroup::GetCofactor() const { return param_.h; }

MPInt SodiumGroup::GetField() const { return param_.p; }

MPInt SodiumGroup::GetOrder() const { return param_.n; }

std::string SodiumGroup::ToString() const {
  return fmt::format("Curve {} from {}", GetCurveName(), GetLibraryName());
}

EcPoint SodiumGroup::CopyPoint(const EcPoint& point) const { return point; }

Buffer SodiumGroup::SerializePoint(const EcPoint& point,
                                   PointOctetFormat format) const {
  YACL_ENFORCE(format == PointOctetFormat::Autonomous,
               "{} only support Autonomous format, given={}", GetLibraryName(),
               (int)format);
  Buffer buf(Cast(point), 32);
  return buf;
}

void SodiumGroup::SerializePoint(const EcPoint& point, PointOctetFormat format,
                                 Buffer* buf) const {
  *buf = SerializePoint(point, format);
}

EcPoint SodiumGroup::DeserializePoint(ByteContainerView buf,
                                      PointOctetFormat format) const {
  EcPoint p(std::in_place_type<Array32>);
  std::memcpy(Cast(p), buf.data(), 32);
  return p;
}

EcPoint SodiumGroup::HashToCurve(HashToCurveStrategy strategy,
                                 std::string_view str) const {
  YACL_THROW("not impl");
}

size_t SodiumGroup::HashPoint(const EcPoint& point) const {
  auto* p = Cast(point);
  return std::hash<std::string_view>()({(char*)p, 32});
}

bool SodiumGroup::PointEqual(const EcPoint& p1, const EcPoint& p2) const {
  return std::get<Array32>(p1) == std::get<Array32>(p2);
}

const unsigned char* SodiumGroup::Cast(const EcPoint& p) const {
  return std::get<Array32>(p).data();
}

unsigned char* SodiumGroup::Cast(EcPoint& p) const {
  return std::get<Array32>(p).data();
}

}  // namespace yacl::crypto::sodium

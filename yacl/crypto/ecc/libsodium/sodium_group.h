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

#pragma once

#include <cstring>
#include <utility>

#include "yacl/base/buffer.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/group_sketch.h"
#include "yacl/crypto/ecc/libsodium/sodium_private.h"

namespace yacl::crypto::sodium {

struct CurveParam {
  MPInt p;
  MPInt n;
  MPInt h;

#if __cplusplus >= 202002L
#else
  CurveParam() = default;
#endif
};

class SodiumGroup : public EcGroupSketch {
 public:
  explicit SodiumGroup(CurveMeta meta, CurveParam param);
  std::string GetLibraryName() const override;

  MPInt GetCofactor() const override;
  MPInt GetField() const override;
  MPInt GetOrder() const override;
  std::string ToString() const override;

  EcPoint CopyPoint(const EcPoint& point) const override;

  uint64_t GetSerializeLength(PointOctetFormat format) const override;

  Buffer SerializePoint(const EcPoint& point,
                        PointOctetFormat format) const override;
  void SerializePoint(const EcPoint& point, PointOctetFormat format,
                      Buffer* buf) const override;
  void SerializePoint(const EcPoint& point, PointOctetFormat format,
                      uint8_t* buf, uint64_t buf_size) const override;
  EcPoint DeserializePoint(ByteContainerView buf,
                           PointOctetFormat format) const override;

  EcPoint HashToCurve(HashToCurveStrategy strategy,
                      std::string_view str) const override;

  size_t HashPoint(const EcPoint& point) const override;
  bool PointEqual(const EcPoint& p1, const EcPoint& p2) const override;

 protected:
  static const ge25519_p3* CastP3(const EcPoint& p);
  static ge25519_p3* CastP3(EcPoint& p);

  CurveParam param_;
};

}  // namespace yacl::crypto::sodium

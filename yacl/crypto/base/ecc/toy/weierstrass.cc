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

#include "yacl/crypto/base/ecc/toy/weierstrass.h"

namespace yacl::crypto::toy {

static const AffinePoint kInfPoint = AffinePoint(MPInt(0), MPInt(0));
static const EcPoint kInfEcPoint = kInfPoint;

std::string ToyWeierstrassGroup::ToString() {
  return fmt::format("{} ==> y^2 = x^3 + {}x + {} (mod {})", GetCurveName(),
                     params_.A, params_.B, params_.p);
}

AffinePoint ToyWeierstrassGroup::Add(const AffinePoint &p1,
                                     const AffinePoint &p2) const {
  if (IsInfinity(p1)) {
    return p2;
  }

  if (IsInfinity(p2)) {
    return p1;
  }

  if (p1.x == p2.x && p1.y != p2.y) {
    return kInfPoint;
  }

  MPInt lambda(0, params_.p.BitCount());
  if (p1.x == p2.x) {
    // p1 == p2, double it
    auto tmp = p1.x.Pow(2);
    tmp.MulInplace(3);
    tmp += params_.A;
    MPInt::MulMod(tmp, p1.y.Mul(2).InvertMod(params_.p), params_.p, &lambda);
  } else {
    // As you can see, InvertMod() is very slow.
    // If we do things using projective coordinates, it turns out that we don't
    // need to compute any inverses at all (we do increase the number of modular
    // additions and multiplications we need, however the time involved there is
    // much less than doing a single modular inversion, and so it is a win).
    MPInt::MulMod(p2.y - p1.y,
                  (p2.x.SubMod(p1.x, params_.p)).InvertMod(params_.p),
                  params_.p, &lambda);
  }

  auto x3 = lambda.Pow(2).SubMod(p1.x + p2.x, params_.p);
  auto y3 = (lambda * (p1.x - x3)).SubMod(p1.y, params_.p);
  return {x3, y3};
}

EcPoint ToyWeierstrassGroup::Add(const EcPoint &p1, const EcPoint &p2) const {
  const auto &op1 = std::get<AffinePoint>(p1);
  const auto &op2 = std::get<AffinePoint>(p2);
  return Add(op1, op2);
}

EcPoint ToyWeierstrassGroup::Mul(const EcPoint &point,
                                 const MPInt &scalar) const {
  const auto &op = std::get<AffinePoint>(point);

  if (IsInfinity(op)) {
    return kInfEcPoint;
  }

  if ((scalar % params_.n).IsZero()) {
    return kInfEcPoint;
  }

  AffinePoint base = op;
  MPInt exp = scalar.Abs();

  auto res = MPInt::SlowCustomPow<AffinePoint>(
      kInfPoint, base, exp,
      [this](AffinePoint *a, const AffinePoint &b) { *a = Add(*a, b); });

  if (scalar.IsNegative()) {
    return Negate(res);
  } else {
    return res;
  }
}

EcPoint ToyWeierstrassGroup::Negate(const EcPoint &point) const {
  const auto &op = std::get<AffinePoint>(point);
  if (IsInfinity(op)) {
    return point;
  }
  return AffinePoint(op.x, params_.p - op.y);
}

Buffer ToyWeierstrassGroup::SerializePoint(const EcPoint &point,
                                           PointOctetFormat format) const {
  YACL_ENFORCE(format == PointOctetFormat::Autonomous,
               "Toy lib do not support {} format", (int)format);
  const auto &op = std::get<AffinePoint>(point);
  return op.Serialize();
}

void ToyWeierstrassGroup::SerializePoint(const EcPoint &point,
                                         PointOctetFormat format,
                                         Buffer *buf) const {
  YACL_ENFORCE(format == PointOctetFormat::Autonomous,
               "Toy lib do not support {} format", (int)format);
  *buf = SerializePoint(point, format);
}

EcPoint ToyWeierstrassGroup::DeserializePoint(ByteContainerView buf,
                                              PointOctetFormat format) const {
  YACL_ENFORCE(format == PointOctetFormat::Autonomous,
               "Toy lib do not support {} format", (int)format);
  AffinePoint op;
  op.Deserialize(buf);
  return op;
}

EcPoint ToyWeierstrassGroup::HashToCurve(HashToCurveStrategy strategy,
                                         std::string_view str) const {
  YACL_THROW("not impl");
}

bool ToyWeierstrassGroup::PointEqual(const EcPoint &p1,
                                     const EcPoint &p2) const {
  return std::get<AffinePoint>(p1) == std::get<AffinePoint>(p2);
}

bool ToyWeierstrassGroup::IsInCurveGroup(const EcPoint &point) const {
  const auto &p = std::get<AffinePoint>(point);
  return IsInfinity(p) ||
         ((p.y.Pow(2) - p.x.Pow(3) - params_.A * p.x - params_.B) % params_.p)
             .IsZero();
}

bool ToyWeierstrassGroup::IsInfinity(const EcPoint &point) const {
  return IsInfinity(std::get<AffinePoint>(point));
}

bool ToyWeierstrassGroup::IsInfinity(const AffinePoint &p) const {
  return p.x.IsZero() && p.y.IsZero();
}

}  // namespace yacl::crypto::toy

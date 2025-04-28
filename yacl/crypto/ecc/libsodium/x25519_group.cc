// Copyright 2024 Ant Group Co., Ltd.
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

#include "yacl/crypto/ecc/libsodium/x25519_group.h"

#include "sodium/crypto_scalarmult_curve25519.h"

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/ecc/hash_to_curve/curve25519.h"
#include "yacl/crypto/hash/hash_utils.h"

namespace yacl::crypto::sodium {

X25519Group::X25519Group(const CurveMeta& meta, const CurveParam& param)
    : SodiumGroup(meta, param) {}

EcPoint X25519Group::GetGenerator() const { YACL_THROW("not implemented"); }

EcPoint X25519Group::Add(const EcPoint&, const EcPoint&) const {
  YACL_THROW("not implemented");
}

void X25519Group::AddInplace(EcPoint*, const EcPoint&) const {
  YACL_THROW("not implemented");
}

EcPoint X25519Group::Sub(const EcPoint&, const EcPoint&) const {
  YACL_THROW("not implemented");
}

void X25519Group::SubInplace(EcPoint*, const EcPoint&) const {
  YACL_THROW("not implemented");
}

EcPoint X25519Group::Double(const EcPoint&) const {
  YACL_THROW("not implemented");
}

void X25519Group::DoubleInplace(EcPoint*) const {
  YACL_THROW("not implemented");
}

EcPoint X25519Group::MulBase(const MPInt& scalar) const {
  Array32 buf;
  memset(buf.data(), 0, sizeof(buf));
  scalar.Mod(param_.n).ToMagBytes(buf.data(), buf.size(), Endian::little);

  EcPoint r(std::in_place_type<Array32>);
  YACL_ENFORCE(0 ==
               crypto_scalarmult_curve25519_base(CastString(r), buf.data()));
  return r;
}

EcPoint X25519Group::Mul(const EcPoint& point, const MPInt& scalar) const {
  Array32 buf;
  memset(buf.data(), 0, sizeof(buf));
  scalar.Mod(param_.n).ToMagBytes(buf.data(), buf.size(), Endian::little);

  EcPoint r(std::in_place_type<Array32>);
  YACL_ENFORCE(0 == crypto_scalarmult_curve25519(CastString(r), buf.data(),
                                                 CastString(point)));

  return r;
}

void X25519Group::MulInplace(EcPoint* point, const MPInt& scalar) const {
  Array32 buf;
  memset(buf.data(), 0, sizeof(buf));
  scalar.ToMagBytes(buf.data(), buf.size(), Endian::little);

  YACL_ENFORCE(0 == crypto_scalarmult_curve25519(CastString(*point), buf.data(),
                                                 CastString(*point)));
}

EcPoint X25519Group::MulDoubleBase(const MPInt&, const MPInt&,
                                   const EcPoint&) const {
  YACL_THROW("not implemented");
}

EcPoint X25519Group::Negate(const EcPoint&) const {
  YACL_THROW("not implemented");
}

void X25519Group::NegateInplace(EcPoint*) const {
  YACL_THROW("not implemented");
}

AffinePoint X25519Group::GetAffinePoint(const EcPoint&) const {
  YACL_THROW("not implemented");
}

bool X25519Group::IsInCurveGroup(const EcPoint&) const {
  YACL_THROW("not implemented");
}

bool X25519Group::IsInfinity(const EcPoint&) const {
  YACL_THROW("not implemented");
}

uint64_t X25519Group::GetSerializeLength(PointOctetFormat format) const {
  switch (format) {
    case PointOctetFormat::Autonomous:
    case PointOctetFormat::Uncompressed:
      return 32;
    default:
      YACL_THROW("{} only support Uncompressed format, given={}",
                 GetLibraryName(), static_cast<int>(format));
  }
}

Buffer X25519Group::SerializePoint(const EcPoint& point,
                                   PointOctetFormat format) const {
  switch (format) {
    case PointOctetFormat::Autonomous:
    case PointOctetFormat::Uncompressed: {
      Buffer buf(32);
      memcpy(buf.data(), CastString(point), 32);
      return buf;
    }
    default:
      YACL_THROW("{} only support Uncompressed format, given={}",
                 GetLibraryName(), static_cast<int>(format));
  }
}

void X25519Group::SerializePoint(const EcPoint& point, PointOctetFormat format,
                                 Buffer* buf) const {
  *buf = SerializePoint(point, format);
}

void X25519Group::SerializePoint(const EcPoint& point, PointOctetFormat format,
                                 uint8_t* buf, uint64_t buf_size) const {
  switch (format) {
    case PointOctetFormat::Autonomous:
    case PointOctetFormat::Uncompressed: {
      YACL_ENFORCE(buf_size >= 32, "buf size is smaller than needed 32");
      memcpy(buf, CastString(point), 32);
      break;
    }
    default:
      YACL_THROW("{} only support Uncompressed format, given={}",
                 GetLibraryName(), static_cast<int>(format));
  }
}

EcPoint X25519Group::DeserializePoint(ByteContainerView buf,
                                      PointOctetFormat format) const {
  switch (format) {
    case PointOctetFormat::Autonomous:
    case PointOctetFormat::Uncompressed: {
      YACL_ENFORCE(buf.size() == 32, "buf size not equal to 32");
      EcPoint p(std::in_place_type<Array32>);
      memcpy(CastString(p), buf.data(), buf.size());
      return p;
    }
    default:
      YACL_THROW("{} only support Uncompressed format, given={}",
                 GetLibraryName(), static_cast<int>(format));
  }
}

EcPoint X25519Group::HashToCurve(HashToCurveStrategy strategy,
                                 std::string_view input) const {
  switch (strategy) {
    case HashToCurveStrategy::Autonomous:
    case HashToCurveStrategy::HashAsPointX_SHA2:
      return yacl::crypto::Sha256(input);
    case HashToCurveStrategy::SHA512_ELL2_RO_: {
      const std::string dst =
          "QUUX-V01-CS02-with-curve25519_XMD:SHA-512_ELL2_RO_";
      EcPoint p = HashToCurveCurve25519(input, dst);
      return p;
    }
    case HashToCurveStrategy::SHA512_ELL2_NU_: {
      // TODO: implement corresponding methods for supporting corresponding test
      const std::string dst =
          "QUUX-V01-CS02-with-curve25519_XMD:SHA-512_ELL2_NU_";
      EcPoint p = EncodeToCurveCurve25519(input, dst);
      return p;
    }
    default:
      YACL_THROW("hash to curve strategy {} not supported",
                 static_cast<int>(strategy));
  }
}

const unsigned char* X25519Group::CastString(const EcPoint& p) {
  YACL_ENFORCE(std::holds_alternative<Array32>(p),
               "Illegal EcPoint, expected Array32, real={}", p.index());
  return std::get<Array32>(p).data();
}

unsigned char* X25519Group::CastString(EcPoint& p) {
  YACL_ENFORCE(std::holds_alternative<Array32>(p),
               "Illegal EcPoint, expected Array32, real={}", p.index());
  return std::get<Array32>(p).data();
}

}  // namespace yacl::crypto::sodium

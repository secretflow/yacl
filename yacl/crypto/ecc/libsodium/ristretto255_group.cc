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

#include "yacl/crypto/ecc/libsodium/ristretto255_group.h"

#include <cstring>
#include <utility>

#include "sodium/crypto_core_ristretto255.h"
#include "sodium/crypto_scalarmult_ristretto255.h"

#include "yacl/crypto/ecc/hash_to_curve/ristretto255.h"
#include "yacl/crypto/hash/ssl_hash.h"

namespace yacl::crypto::sodium {

namespace {

constexpr size_t kPointBytes = crypto_core_ristretto255_BYTES;
constexpr size_t kScalarBytes = crypto_core_ristretto255_SCALARBYTES;
constexpr size_t kHashBytes = crypto_core_ristretto255_HASHBYTES;

}  // namespace

Ristretto255Group::Ristretto255Group(const CurveMeta& meta,
                                     const CurveParam& param)
    : SodiumGroup(meta, param) {
  static_assert(kPointBytes == 32);
  static_assert(kScalarBytes == 32);
  static_assert(kHashBytes == 64);

  g_ = MulBase(1_mp);
  inf_ = EcPoint(std::in_place_type<Array32>);
  std::memset(CastBytes(inf_), 0, kPointBytes);
}

bool Ristretto255Group::MpIntToScalar(const MPInt& mp,
                                      unsigned char* buf) const {
  auto s = mp.Mod(param_.n);
  s.ToBytes(buf, kScalarBytes, Endian::little);
  return s.IsPositive();
}

const unsigned char* Ristretto255Group::CastBytes(const EcPoint& p) {
  return std::get<Array32>(p).data();
}

unsigned char* Ristretto255Group::CastBytes(EcPoint& p) {
  return std::get<Array32>(p).data();
}

EcPoint Ristretto255Group::GetGenerator() const { return g_; }

EcPoint Ristretto255Group::Add(const EcPoint& p1, const EcPoint& p2) const {
  EcPoint r(std::in_place_type<Array32>);
  int ret = crypto_core_ristretto255_add(CastBytes(r), CastBytes(p1),
                                         CastBytes(p2));
  YACL_ENFORCE(ret == 0, "ristretto255_add failed: invalid point");
  return r;
}

void Ristretto255Group::AddInplace(EcPoint* p1, const EcPoint& p2) const {
  Array32 temp;
  int ret = crypto_core_ristretto255_add(temp.data(), CastBytes(*p1),
                                         CastBytes(p2));
  YACL_ENFORCE(ret == 0, "ristretto255_add failed: invalid point");
  std::memcpy(CastBytes(*p1), temp.data(), kPointBytes);
}

EcPoint Ristretto255Group::Sub(const EcPoint& p1, const EcPoint& p2) const {
  EcPoint r(std::in_place_type<Array32>);
  int ret = crypto_core_ristretto255_sub(CastBytes(r), CastBytes(p1),
                                         CastBytes(p2));
  YACL_ENFORCE(ret == 0, "ristretto255_sub failed: invalid point");
  return r;
}

void Ristretto255Group::SubInplace(EcPoint* p1, const EcPoint& p2) const {
  Array32 temp;
  int ret = crypto_core_ristretto255_sub(temp.data(), CastBytes(*p1),
                                         CastBytes(p2));
  YACL_ENFORCE(ret == 0, "ristretto255_sub failed: invalid point");
  std::memcpy(CastBytes(*p1), temp.data(), kPointBytes);
}

EcPoint Ristretto255Group::Double(const EcPoint& p) const {
  return Add(p, p);
}

void Ristretto255Group::DoubleInplace(EcPoint* p) const {
  Array32 temp;
  int ret = crypto_core_ristretto255_add(temp.data(), CastBytes(*p),
                                         CastBytes(*p));
  YACL_ENFORCE(ret == 0, "ristretto255_add failed: invalid point");
  std::memcpy(CastBytes(*p), temp.data(), kPointBytes);
}

EcPoint Ristretto255Group::MulBase(const MPInt& scalar) const {
  unsigned char s[kScalarBytes];
  MpIntToScalar(scalar, s);

  EcPoint r(std::in_place_type<Array32>);
  int ret = crypto_scalarmult_ristretto255_base(CastBytes(r), s);
  if (ret != 0) {
    std::memcpy(CastBytes(r), CastBytes(inf_), kPointBytes);
  }
  return r;
}

EcPoint Ristretto255Group::Mul(const EcPoint& point,
                               const MPInt& scalar) const {
  if (IsInfinity(point)) {
    return inf_;
  }

  unsigned char s[kScalarBytes];
  MpIntToScalar(scalar, s);

  EcPoint r(std::in_place_type<Array32>);
  int ret = crypto_scalarmult_ristretto255(CastBytes(r), s, CastBytes(point));
  if (ret != 0) {
    std::memcpy(CastBytes(r), CastBytes(inf_), kPointBytes);
  }
  return r;
}

void Ristretto255Group::MulInplace(EcPoint* point, const MPInt& scalar) const {
  if (IsInfinity(*point)) {
    return;
  }

  unsigned char s[kScalarBytes];
  MpIntToScalar(scalar, s);

  Array32 temp;
  int ret = crypto_scalarmult_ristretto255(temp.data(), s, CastBytes(*point));
  if (ret != 0) {
    std::memcpy(CastBytes(*point), CastBytes(inf_), kPointBytes);
  } else {
    std::memcpy(CastBytes(*point), temp.data(), kPointBytes);
  }
}

EcPoint Ristretto255Group::MulDoubleBase(const MPInt& s1, const MPInt& s2,
                                         const EcPoint& p2) const {
  auto r = MulBase(s1);
  AddInplace(&r, Mul(p2, s2));
  return r;
}

EcPoint Ristretto255Group::Negate(const EcPoint& point) const {
  if (IsInfinity(point)) {
    return point;
  }
  return Sub(inf_, point);
}

void Ristretto255Group::NegateInplace(EcPoint* point) const {
  if (IsInfinity(*point)) {
    return;
  }
  Array32 temp;
  int ret = crypto_core_ristretto255_sub(temp.data(), CastBytes(inf_),
                                         CastBytes(*point));
  YACL_ENFORCE(ret == 0, "ristretto255_sub failed");
  std::memcpy(CastBytes(*point), temp.data(), kPointBytes);
}

AffinePoint Ristretto255Group::GetAffinePoint(const EcPoint& point) const {
  const unsigned char* bytes = CastBytes(point);
  MPInt x(0, 256);
  x.FromMagBytes({bytes, kPointBytes}, Endian::little);
  return {x, 0_mp};
}

bool Ristretto255Group::IsInCurveGroup(const EcPoint& point) const {
  return IsInfinity(point) ||
         crypto_core_ristretto255_is_valid_point(CastBytes(point)) == 1;
}

bool Ristretto255Group::IsInfinity(const EcPoint& point) const {
  const unsigned char* bytes = CastBytes(point);
  for (size_t i = 0; i < kPointBytes; ++i) {
    if (bytes[i] != 0) {
      return false;
    }
  }
  return true;
}

EcPoint Ristretto255Group::CopyPoint(const EcPoint& point) const {
  EcPoint r(std::in_place_type<Array32>);
  std::memcpy(CastBytes(r), CastBytes(point), kPointBytes);
  return r;
}

size_t Ristretto255Group::HashPoint(const EcPoint& point) const {
  const unsigned char* bytes = CastBytes(point);
  size_t hash = 0;
  for (size_t i = 0; i < kPointBytes; ++i) {
    hash ^= static_cast<size_t>(bytes[i]) << ((i % sizeof(size_t)) * 8);
  }
  return hash;
}

bool Ristretto255Group::PointEqual(const EcPoint& p1, const EcPoint& p2) const {
  return std::memcmp(CastBytes(p1), CastBytes(p2), kPointBytes) == 0;
}

uint64_t Ristretto255Group::GetSerializeLength(
    PointOctetFormat /* format */) const {
  return kPointBytes;
}

Buffer Ristretto255Group::SerializePoint(const EcPoint& point,
                                         PointOctetFormat format) const {
  Buffer buf(kPointBytes);
  SerializePoint(point, format, buf.data<uint8_t>(), kPointBytes);
  return buf;
}

void Ristretto255Group::SerializePoint(const EcPoint& point,
                                       PointOctetFormat format,
                                       Buffer* buf) const {
  buf->resize(kPointBytes);
  SerializePoint(point, format, buf->data<uint8_t>(), kPointBytes);
}

void Ristretto255Group::SerializePoint(const EcPoint& point,
                                       PointOctetFormat /* format */,
                                       uint8_t* buf, uint64_t buf_size) const {
  YACL_ENFORCE(buf_size >= kPointBytes,
               "Buffer too small for Ristretto255 point serialization");
  std::memcpy(buf, CastBytes(point), kPointBytes);
}

EcPoint Ristretto255Group::DeserializePoint(ByteContainerView buf,
                                            PointOctetFormat /* format */) const {
  YACL_ENFORCE(buf.size() >= kPointBytes,
               "Buffer too small for Ristretto255 point deserialization");

  EcPoint p(std::in_place_type<Array32>);
  std::memcpy(CastBytes(p), buf.data(), kPointBytes);

  // Validate the point
  YACL_ENFORCE(IsInCurveGroup(p), "Invalid Ristretto255 point encoding");
  return p;
}

EcPoint Ristretto255Group::HashToCurve(HashToCurveStrategy strategy,
                                       std::string_view str,
                                       std::string_view dst) const {
  switch (strategy) {
    case HashToCurveStrategy::SHA512_R255_RO_: {
      std::string dst_s = dst.empty()
          ? "QUUX-V01-CS02-with-ristretto255_XMD:SHA-512_R255MAP_RO_"
          : std::string(dst);
      return yacl::HashToCurveRistretto255(str, dst_s);
    }
    case HashToCurveStrategy::SHA512_R255_NU_: {
      std::string dst_s = dst.empty()
          ? "QUUX-V01-CS02-with-ristretto255_XMD:SHA-512_R255MAP_NU_"
          : std::string(dst);
      return yacl::EncodeToCurveRistretto255(str, dst_s);
    }
    case HashToCurveStrategy::Autonomous:
    default:
      break;
  }

  // Autonomous: SHA-512(dst || str) + ristretto255_from_hash
  std::string input;
  input.reserve(dst.size() + str.size());
  input.append(dst);
  input.append(str);

  SslHash sha512(HashAlgorithm::SHA512);
  sha512.Update(input);
  auto hash = sha512.CumulativeHash();

  EcPoint r(std::in_place_type<Array32>);
  crypto_core_ristretto255_from_hash(CastBytes(r), hash.data());
  return r;
}

yacl::math::MPInt Ristretto255Group::HashToScalar(
    HashToCurveStrategy strategy, std::string_view str,
    std::string_view dst) const {
  if (strategy == HashToCurveStrategy::Ristretto255_SHA512_) {
    std::string dst_s = dst.empty()
        ? "QUUX-V01-CS02-with-ristretto255_XMD:SHA-512_R255MAP_"
        : std::string(dst);
    return yacl::HashToScalarRistretto255(str, dst_s);
  }

  // Autonomous: SHA-512(dst || str) + scalar_reduce
  std::string input;
  input.reserve(dst.size() + str.size());
  input.append(dst);
  input.append(str);

  SslHash sha512(HashAlgorithm::SHA512);
  sha512.Update(input);
  auto hash = sha512.CumulativeHash();

  unsigned char scalar[kScalarBytes];
  crypto_core_ristretto255_scalar_reduce(scalar, hash.data());

  MPInt result(0, 256);
  result.FromMagBytes({scalar, kScalarBytes}, Endian::little);
  return result;
}

}  // namespace yacl::crypto::sodium

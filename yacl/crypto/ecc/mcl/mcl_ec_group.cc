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

#include "yacl/crypto/ecc/mcl/mcl_ec_group.h"

#include "yacl/crypto/ecc/mcl/mcl_util.h"
#include "yacl/crypto/hash/blake3.h"
#include "yacl/crypto/pairing/factory/mcl_pairing_header.h"

namespace yacl::crypto {

template <typename Fp_, typename Zn_>
MclGroupT<Fp_, Zn_>::MclGroupT(const CurveMeta& meta, int mcl_curve_type,
                               const EcPoint& generator, bool const_time_mul)
    : EcGroupSketch(meta),
      mcl_curve_type_(mcl_curve_type),
      const_time_(const_time_mul) {
  order_ = Mpz2Mp(Zn_::BaseFp::getOp().mp);
  // Note that order of extension field != field's Modulus, so it's
  // meaningless for high-level computation.
  field_p_ = Mpz2Mp(Fp_::BaseFp::getOp().mp);
  generator_ = generator;
}

template <typename Fp_, typename Zn_>
std::string MclGroupT<Fp_, Zn_>::GetLibraryName() const {
  return kLibName;
}

template <typename Fp_, typename Zn_>
MPInt MclGroupT<Fp_, Zn_>::GetCofactor() const {
  YACL_ENFORCE(mcl_curve_type_ >= MCL_EC_BEGIN, "Not impl!");
  return 1_mp;
}

template <typename Fp_, typename Zn_>
MPInt MclGroupT<Fp_, Zn_>::GetField() const {
  return field_p_;
}

template <typename Fp_, typename Zn_>
MPInt MclGroupT<Fp_, Zn_>::GetOrder() const {
  return order_;
}

template <typename Fp_, typename Zn_>
EcPoint MclGroupT<Fp_, Zn_>::GetGenerator() const {
  return generator_;
}

template <typename Fp_, typename Zn_>
std::string MclGroupT<Fp_, Zn_>::ToString() const {
  return GetCurveName();
}

template <typename Fp_, typename Zn_>
EcPoint MclGroupT<Fp_, Zn_>::Add(const EcPoint& p1, const EcPoint& p2) const {
  auto ret = MakeShared<Ec>();
  Ec::add(*CastAny<Ec>(ret), *CastAny<Ec>(p1), *CastAny<Ec>(p2));
  return ret;
}

template <typename Fp_, typename Zn_>
void MclGroupT<Fp_, Zn_>::AddInplace(EcPoint* p1, const EcPoint& p2) const {
  Ec::add(*CastAny<Ec>(p1), *CastAny<Ec>(p1), *CastAny<Ec>(p2));
}

template <typename Fp_, typename Zn_>
EcPoint MclGroupT<Fp_, Zn_>::Double(const EcPoint& p) const {
  auto ret = MakeShared<Ec>();
  Ec::dbl(*CastAny<Ec>(ret), *CastAny<Ec>(p));
  return ret;
}

template <typename Fp_, typename Zn_>
void MclGroupT<Fp_, Zn_>::DoubleInplace(EcPoint* p) const {
  Ec::dbl(*CastAny<Ec>(p), *CastAny<Ec>(p));
}

template <typename Fp_, typename Zn_>
EcPoint MclGroupT<Fp_, Zn_>::MulBase(const MPInt& scalar) const {
  auto ret = MakeShared<Ec>();
  if (!const_time_) {
    Ec::mul(*CastAny<Ec>(ret), *CastAny<Ec>(GetGenerator()),
            Mp2Mpz(scalar % order_));
  } else {
    Ec::mulCT(*CastAny<Ec>(ret), *CastAny<Ec>(GetGenerator()),
              Mp2Mpz(scalar % order_));
  }
  return ret;
}

template <typename Fp_, typename Zn_>
EcPoint MclGroupT<Fp_, Zn_>::Mul(const EcPoint& point,
                                 const MPInt& scalar) const {
  auto ret = MakeShared<Ec>();
  if (!const_time_) {
    Ec::mul(*CastAny<Ec>(ret), *CastAny<Ec>(point), Mp2Mpz(scalar % order_));
  } else {
    Ec::mulCT(*CastAny<Ec>(ret), *CastAny<Ec>(point), Mp2Mpz(scalar % order_));
  }
  return ret;
}

template <typename Fp_, typename Zn_>
void MclGroupT<Fp_, Zn_>::MulInplace(EcPoint* point,
                                     const MPInt& scalar) const {
  if (!const_time_) {
    Ec::mul(*CastAny<Ec>(point), *CastAny<Ec>(point), Mp2Mpz(scalar % order_));
  } else {
    Ec::mulCT(*CastAny<Ec>(point), *CastAny<Ec>(point),
              Mp2Mpz(scalar % order_));
  }
}

template <typename Fp_, typename Zn_>
EcPoint MclGroupT<Fp_, Zn_>::MulDoubleBase(const MPInt& s1, const MPInt& s2,
                                           const EcPoint& p2) const {
  auto ret = MakeShared<Ec>();
  auto scalar1 = Mp2Mpz(s1 % order_);
  Fr ps1;
  ps1.setMpz(scalar1);

  auto scalar2 = Mp2Mpz(s2 % order_);
  Fr ps2;
  ps2.setMpz(scalar2);

  Ec ecs[] = {*CastAny<Ec>(GetGenerator()), *CastAny<Ec>(p2)};
  Fr frs[] = {ps1, ps2};
  Ec::mulVecMT(*CastAny<Ec>(ret), ecs, frs, 2, 2);
  return ret;
}

template <typename Fp_, typename Zn_>
EcPoint MclGroupT<Fp_, Zn_>::Negate(const EcPoint& point) const {
  auto ret = MakeShared<Ec>();
  Ec::neg(*CastAny<Ec>(ret), *CastAny<Ec>(point));
  return ret;
}

template <typename Fp_, typename Zn_>
void MclGroupT<Fp_, Zn_>::NegateInplace(EcPoint* point) const {
  Ec::neg(*CastAny<Ec>(point), *CastAny<Ec>(point));
}

template <typename Fp_, typename Zn_>
EcPoint MclGroupT<Fp_, Zn_>::CopyPoint(const EcPoint& point) const {
  if (std::holds_alternative<AnyPtr>(point)) {
    auto ret = MakeShared<Ec>();
    *CastAny<Ec>(ret) = *CastAny<Ec>(point);
    return ret;
  }

  if (std::holds_alternative<AffinePoint>(point)) {
    auto p = std::get<AffinePoint>(point);
    return GetMclPoint(p);
  }

  YACL_THROW("Unsupported EcPoint type {}", point.index());
}

template <typename Fp_, typename Zn_>
AnyPtr MclGroupT<Fp_, Zn_>::GetMclPoint(const AffinePoint& p) const {
  const int size = Fp_::getByteSize();
  auto point = MakeShared<Ec>();

  Fp_ x;
  auto buf_x = p.x.ToBytes(size, Endian::little);
  x.deserialize(buf_x.data(), buf_x.size());
  Fp_ y;
  auto buf_y = p.y.ToBytes(size, Endian::little);
  y.deserialize(buf_y.data(), buf_y.size());
  CastAny<Ec>(point)->set(x, y);
  return point;
}

template <typename Fp_, typename Zn_>
uint64_t MclGroupT<Fp_, Zn_>::GetSerializeLength(
    PointOctetFormat format) const {
  if (mcl_curve_type_ == MCL_BLS12_381 &&
      (format == PointOctetFormat::ZCash_BLS12_381 ||
       format == PointOctetFormat::Autonomous)) {
    return Ec::getSerializedByteSize();
  }

  switch (format) {
    case PointOctetFormat::X962Uncompressed:
    case PointOctetFormat::X962Hybrid: {
      // 1 more byte for being compatible with x962 format
      return Fp_::getByteSize() * 2 + 1;
    }
    case PointOctetFormat::Autonomous:
    case PointOctetFormat::X962Compressed: {
      return Fp_::getByteSize() + 1;
    }
    default:
      YACL_THROW("Not supported serialize format for standard curve in {}",
                 kLibName);
  }
}

template <typename Fp_, typename Zn_>
Buffer MclGroupT<Fp_, Zn_>::SerializePoint(const EcPoint& point,
                                           PointOctetFormat format) const {
  Buffer buf;
  SerializePoint(point, format, &buf);
  return buf;
}

template <typename Fp_, typename Zn_>
void MclGroupT<Fp_, Zn_>::SerializePoint(const EcPoint& point,
                                         PointOctetFormat format,
                                         Buffer* buf) const {
  auto len = GetSerializeLength(format);
  buf->resize(len);
  SerializePoint(point, format, buf->data<uint8_t>(), buf->size());
}

// Compressed Serialization Process:
// IoEcCompY Mode
// 	1-bit y prepresentation of elliptic curve
// 	"2 <x>" ; compressed for even y
// 	"3 <x>" ; compressed for odd y
// IoSerialize Mode
//   if isMSBserialize(): // p is not full bit
//      size = Fp::getByteSize()
//      use MSB of array of x for 1-bit y for prime p where (p % 8 != 0)
//      [0] ; infinity
//      <x> ; for even y
//      <x>|1 ; for odd y ; |1 means set MSB of x
//   else:// x962 compressed format
//      size = Fp::getByteSize() + 1
//      [0] ; infinity
//      2 <x> ; for even y
//      3 <x> ; for odd y
template <typename Fp_, typename Zn_>
void MclGroupT<Fp_, Zn_>::SerializePoint(const EcPoint& point,
                                         PointOctetFormat format, uint8_t* buf,
                                         uint64_t buf_size) const {
  auto len = GetSerializeLength(format);
  YACL_ENFORCE(buf_size >= len, "buf size is small than needed {}", len);

  const Ec& p = *CastAny<Ec>(point);
  int write_bits = 0;

  if (mcl_curve_type_ == MCL_BLS12_381) {
    // pairing curve MCL_BLS12_381, use ZCash_BLS12_381 serialization mode,
    // which is Big Endian.
    switch (format) {
      case PointOctetFormat::Autonomous:
      case PointOctetFormat::ZCash_BLS12_381: {
        write_bits = p.serialize(buf, len, mcl::IoMode::IoSerialize);
        YACL_ENFORCE(len == static_cast<uint64_t>(write_bits),
                     "Serialize error!");
        break;
      }
      default:
        YACL_THROW("Not supported serialize format for pairing curve in {}",
                   kLibName);
    }
    return;
  }

  switch (format) {
    case PointOctetFormat::X962Uncompressed: {
      // for ANSI X9.62 uncompressed format
      buf[0] = 0x04;
      // mcl uncompressed serialization is only x||y, not z=0x04||x||y
      write_bits =
          p.serialize(buf + 1, len - 1, mcl::IoMode::IoEcAffineSerialize);
      YACL_ENFORCE(len == static_cast<uint64_t>(write_bits + 1),
                   "Serialize error!");
      break;
    }
    case PointOctetFormat::X962Hybrid: {
      // for ANSI X9.62 hybrid format
      Ec ecp = Ec(p);
      // Check is normalized for affine coordinates
      if (!ecp.isNormalized()) {
        ecp.normalize();
      }
      buf[0] = (ecp.y.isOdd() ? 7 : 6);
      write_bits =
          ecp.serialize(buf + 1, len - 1, mcl::IoMode::IoEcAffineSerialize);
      YACL_ENFORCE(len == static_cast<uint64_t>(write_bits + 1),
                   "Serialize error!");
      break;
    }
    case PointOctetFormat::Autonomous:
    case PointOctetFormat::X962Compressed: {
      if (p.isZero()) {
        std::memset(buf + write_bits, 0, len);
        write_bits = len;
      } else {
        Ec ecp = Ec(p);
        // Check is normalized for affine coordinates
        if (!ecp.isNormalized()) {
          ecp.normalize();
        }
        buf[0] = ecp.y.isOdd() ? 3 : 2;
        write_bits =
            ecp.x.serialize(buf + 1, buf_size - 1, mcl::IoMode::IoSerialize);
        YACL_ENFORCE(len == static_cast<uint64_t>(write_bits + 1),
                     "Serialize error!");
      }
      break;
    }
    default:
      YACL_THROW("Not supported serialize format for curve in {}", kLibName);
  }
  if (buf_size > len) {
    std::memset(buf + write_bits, 0, buf_size - write_bits);
  }
}

template <typename Fp_, typename Zn_>
EcPoint MclGroupT<Fp_, Zn_>::DeserializePoint(ByteContainerView buf,
                                              PointOctetFormat format) const {
  const auto len = GetSerializeLength(format);
  YACL_ENFORCE(buf.size() >= len);
  auto ret = MakeShared<Ec>();

  if (mcl_curve_type_ == MCL_BLS12_381) {
    // pairing curve MCL_BLS12_381, use ZCash_BLS12_381 serialization mode,
    // which is Big Endian.
    switch (format) {
      case PointOctetFormat::Autonomous:
      case PointOctetFormat::ZCash_BLS12_381: {
        CastAny<Ec>(ret)->deserialize(buf.cbegin(), len,
                                      mcl::IoMode::IoSerialize);
        break;
      }
      default:
        YACL_THROW("Not supported deserialize format for pairing curve in {}",
                   kLibName);
    }
    return ret;
  }

  switch (format) {
    case PointOctetFormat::X962Uncompressed:
      YACL_ENFORCE(buf[0] == 0x04);
      CastAny<Ec>(ret)->deserialize(buf.cbegin() + 1, len - 1,
                                    mcl::IoMode::IoEcAffineSerialize);
      break;
    case PointOctetFormat::X962Hybrid:
      YACL_ENFORCE(buf[0] == 0x06 || buf[0] == 0x07);
      CastAny<Ec>(ret)->deserialize(buf.cbegin() + 1, len - 1,
                                    mcl::IoMode::IoEcAffineSerialize);
      break;
    case PointOctetFormat::Autonomous:
    case PointOctetFormat::X962Compressed: {
      auto* p = CastAny<Ec>(ret);
      p->z = 1;
      if (mcl::bint::isZeroN(buf.cbegin(), len)) {
        p->clear();
      } else {
        bool isYodd = buf[0] == 3;
        p->x.deserialize(buf.cbegin() + 1, len - 1, mcl::IoMode::IoSerialize);
        YACL_ENFORCE(Ec::getYfromX(p->y, p->x, isYodd));
      }
      break;
    }
    default:
      YACL_THROW("Not supported deserialize format for standard curve in {}",
                 kLibName);
  }

  return ret;
}

template <typename Fp_, typename Zn_>
EcPoint MclGroupT<Fp_, Zn_>::HashToStdCurve(HashToCurveStrategy strategy,
                                            std::string_view str) const {
  YACL_ENFORCE(mcl_curve_type_ >= MCL_EC_BEGIN && mcl_curve_type_ <= MCL_EC_END,
               "This curve doesn't support hash to curve!");

  auto ret = MakeShared<Ec>();
  const auto bits = Fp::BaseFp::getOp().mp.getBitSize();
  HashAlgorithm hash_algorithm;
  switch (strategy) {
    case HashToCurveStrategy::TryAndIncrement_SHA2:
      if (bits <= 224) {
        hash_algorithm = HashAlgorithm::SHA224;
      } else if (bits <= 256) {
        hash_algorithm = HashAlgorithm::SHA256;
      } else if (bits <= 384) {
        hash_algorithm = HashAlgorithm::SHA384;
      } else {
        hash_algorithm = HashAlgorithm::SHA512;
      }
      break;
    case HashToCurveStrategy::TryAndIncrement_SHA3:
      YACL_THROW("Mcl lib do not support TryAndRehash_SHA3 strategy now");
      break;
    case HashToCurveStrategy::TryAndIncrement_SM:
      hash_algorithm = HashAlgorithm::SM3;
      break;
    case HashToCurveStrategy::TryAndIncrement_BLAKE3:
    case HashToCurveStrategy::Autonomous:
      hash_algorithm = HashAlgorithm::BLAKE3;
      break;
    default:
      YACL_THROW("Mcl lib only support TryAndIncrement strategy now. select={}",
                 (int)strategy);
  }
  std::vector<uint8_t> buf;
  if (hash_algorithm != HashAlgorithm::BLAKE3) {
    buf = SslHash(hash_algorithm).Update(str).CumulativeHash();
  } else {
    buf = Blake3Hash((bits + 7) / 8).Update(str).CumulativeHash();
  }

  Fp p;
  p.deserialize(buf.data(), buf.size());
  mcl::ec::tryAndIncMapTo(*CastAny<Ec>(ret), p);
  return ret;
}

template <typename Fp_, typename Zn_>
EcPoint MclGroupT<Fp_, Zn_>::HashToCurve(HashToCurveStrategy strategy,
                                         std::string_view str) const {
  if (mcl_curve_type_ <= MCL_BN_P256) {
    YACL_ENFORCE(HashToCurveStrategy::TryAndIncrement_SHA2 == strategy ||
                     HashToCurveStrategy::Autonomous == strategy,
                 "libmcl only support hash strategy TryAndIncrement_SHA2 for "
                 "pairing curve!");
    YACL_ENFORCE(hash_to_pairing_curve_func_ != nullptr,
                 "No Hash to curve function provided!");
    auto ret = MakeShared<Ec>();
    hash_to_pairing_curve_func_(*CastAny<Ec>(ret), std::string(str));
    return ret;
  } else {
    return HashToStdCurve(strategy, str);
  }
}

// PointEqual 1013ns
// this 3027 ns
// TODO: slow!
template <typename Fp_, typename Zn_>
size_t MclGroupT<Fp_, Zn_>::HashPoint(const EcPoint& point) const {
  Ec ecp = Ec(*CastAny<Ec>(point));
  // Check is normalized for affine coordinates
  if (!ecp.isNormalized()) {
    ecp.normalize();
  }
  return size_t(*(ecp.x.getUnit())) + ecp.y.isOdd();
}

template <typename Fp_, typename Zn_>
bool MclGroupT<Fp_, Zn_>::PointEqual(const EcPoint& p1,
                                     const EcPoint& p2) const {
  return *CastAny<Ec>(p1) == *CastAny<Ec>(p2);
}

template <typename Fp_, typename Zn_>
bool MclGroupT<Fp_, Zn_>::IsInCurveGroup(const EcPoint& point) const {
  return CastAny<Ec>(point)->isValid();
}

template <typename Fp_, typename Zn_>
bool MclGroupT<Fp_, Zn_>::IsInfinity(const EcPoint& point) const {
  return CastAny<Ec>(point)->isZero();
}

template <typename Fp_, typename Zn_>
void MclGroupT<Fp_, Zn_>::SetConstTimeMul(bool const_time_mul) {
  const_time_ = const_time_mul;
}

template <typename Fp_, typename Zn_>
AffinePoint MclGroupT<Fp_, Zn_>::GetAffinePoint(const EcPoint& point) const {
  const int size = Fp_::getByteSize();
  if (IsInfinity(point)) {
    return {};
  }
  Ec ecp = Ec(*CastAny<Ec>(point));
  // Check is normalized for affine coordinates
  if (!ecp.isNormalized()) {
    ecp.normalize();
  }

  AffinePoint ret;
  Buffer x(size);
  ecp.x.serialize(x.data(), x.size());
  ret.x.FromMagBytes(x, Endian::little);
  Buffer y(size);
  ecp.y.serialize(y.data(), y.size());
  ret.y.FromMagBytes(y, Endian::little);
  return ret;
}

// ===================================================================
// Instantiate standard curve class from template (for template link)
// ===================================================================
#define TEMPLATE_GROUP_INSTANCE(bitsize)                  \
  template class MclGroupT<mcl::FpT<mcl::FpTag, bitsize>, \
                           mcl::FpT<mcl::ZnTag, bitsize>>;

TEMPLATE_GROUP_INSTANCE(160);
TEMPLATE_GROUP_INSTANCE(192);
TEMPLATE_GROUP_INSTANCE(224);
TEMPLATE_GROUP_INSTANCE(256);
TEMPLATE_GROUP_INSTANCE(384);

#define TEMPLATE_NIST_INSTANCE(bitsize)                         \
  template class MclGroupT<mcl::FpT<local::NISTFpTag, bitsize>, \
                           mcl::FpT<local::NISTZnTag, bitsize>>;

TEMPLATE_NIST_INSTANCE(192)
TEMPLATE_NIST_INSTANCE(224)
TEMPLATE_NIST_INSTANCE(256)

// ===============================================================
// Instantiate Pairing Curve class from template
// ===============================================================

#define TEMPLATE_CURVE_INSTANCE(curve_name)                           \
  template class MclGroupT<mcl::curve_name::Fp, mcl::curve_name::Fr>; \
  template class MclGroupT<mcl::curve_name::Fp2, mcl::curve_name::Fr>;

// Pairing Classes
TEMPLATE_CURVE_INSTANCE(bls12);
TEMPLATE_CURVE_INSTANCE(bnsnark);

#ifdef MCL_ALL_PAIRING_FOR_YACL
TEMPLATE_CURVE_INSTANCE(bn254);
TEMPLATE_CURVE_INSTANCE(bn382m);
TEMPLATE_CURVE_INSTANCE(bn382r);
TEMPLATE_CURVE_INSTANCE(bn462);
TEMPLATE_CURVE_INSTANCE(bn160);
TEMPLATE_CURVE_INSTANCE(bls123);
TEMPLATE_CURVE_INSTANCE(bls124);
TEMPLATE_CURVE_INSTANCE(bn256);
#endif

}  // namespace yacl::crypto

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

#include "mcl/ec.hpp"

#include "yacl/crypto/ecc/group_sketch.h"
#include "yacl/crypto/hash/ssl_hash.h"

// hmcl = herumi_mcl
namespace yacl::crypto {

const std::string kLibName = "libmcl";

class MclEGFactory {
 public:
  static std::unique_ptr<EcGroup> Create(const CurveMeta& meta);
  static bool IsSupported(const CurveMeta& meta);
};

// Warning! Ecc group in libmcl only support one instance at the same
// moment.
template <typename Fp_, typename Zn_>
class MclGroupT : public EcGroupSketch {
 public:
  using Ec = mcl::EcT<Fp_>;
  using Fr = Zn_;
  using Fp = Fp_;
  using BaseFp = typename Fp::BaseFp;

  std::string GetLibraryName() const override;
  // 1_mp for G1 only field
  MPInt GetCofactor() const override;
  // Warning! If it's an extension field, then its field will be 0. Cause
  // order(number of elements) of extension field != field's Modulus, so it's
  // meaningless for high-level computation.
  MPInt GetField() const override;
  MPInt GetOrder() const override;
  EcPoint GetGenerator() const override;
  std::string ToString() const override;

  EcPoint Add(const EcPoint& p1, const EcPoint& p2) const override;
  void AddInplace(EcPoint* p1, const EcPoint& p2) const override;
  EcPoint Double(const EcPoint& p) const override;
  void DoubleInplace(EcPoint* p) const override;

  EcPoint MulBase(const MPInt& scalar) const override;
  EcPoint Mul(const EcPoint& point, const MPInt& scalar) const override;
  void MulInplace(EcPoint* point, const MPInt& scalar) const override;
  EcPoint MulDoubleBase(const MPInt& s1, const MPInt& s2,
                        const EcPoint& p2) const override;

  EcPoint Negate(const EcPoint& point) const override;
  void NegateInplace(EcPoint* point) const override;

  EcPoint CopyPoint(const EcPoint& point) const override;
  AffinePoint GetAffinePoint(const EcPoint& point) const override;
  // AffinePoint -> Ec(MclPoint)
  AnyPtr GetMclPoint(const AffinePoint& p) const;

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
  bool IsInCurveGroup(const EcPoint& point) const override;
  bool IsInfinity(const EcPoint& point) const override;

  void SetConstTimeMul(bool const_time_mul);

 private:
  explicit MclGroupT(const CurveMeta& meta, int mcl_curve_type,
                     const EcPoint& generator, bool const_time_mul = false);

  // For standard hash to curve
  EcPoint HashToStdCurve(HashToCurveStrategy strategy,
                         std::string_view str) const;
  // For pairing hash to curve
  using HashToPairingCurveFunc = std::function<void(Ec&, const std::string&)>;

  int mcl_curve_type_;
  MPInt order_;
  MPInt field_p_;
  EcPoint generator_;
  bool const_time_ = true;
  HashToPairingCurveFunc hash_to_pairing_curve_func_;

  friend class MclEGFactory;
  friend class MclPGFactory;
};

// ===============================================================
// Alias for standard curve class from template
// ===============================================================
#define MCL_CURVE_SECP_ALIAS(curve_name, bitsize) \
  using Mcl##curve_name =                         \
      MclGroupT<mcl::FpT<mcl::FpTag, bitsize>, mcl::FpT<mcl::ZnTag, bitsize>>;

#define MCL_CURVE_SECPK1_ALIAS(bitsize) \
  MCL_CURVE_SECP_ALIAS(Secp##bitsize##k1, bitsize);

MCL_CURVE_SECPK1_ALIAS(160);
MCL_CURVE_SECPK1_ALIAS(192);
MCL_CURVE_SECPK1_ALIAS(224);
MCL_CURVE_SECPK1_ALIAS(256);

#define MCL_CURVE_SECPR1_ALIAS(bitsize) \
  MCL_CURVE_SECP_ALIAS(Secp##bitsize##r1, bitsize);

MCL_CURVE_SECPR1_ALIAS(384);  // SECP384R1 is same as NIST_P384

namespace local {
// Related, see mcl::ZnTag & mcl::FpTag
// For ecc curve multi instances.
struct NISTFpTag;
struct NISTZnTag;
}  // namespace local

#define MCL_CURVE_NIST_ALIAS(bitsize)                                      \
  using MclNistP##bitsize = MclGroupT<mcl::FpT<local::NISTFpTag, bitsize>, \
                                      mcl::FpT<local::NISTZnTag, bitsize>>;

MCL_CURVE_NIST_ALIAS(192)
MCL_CURVE_NIST_ALIAS(224)
MCL_CURVE_NIST_ALIAS(256)

}  // namespace yacl::crypto

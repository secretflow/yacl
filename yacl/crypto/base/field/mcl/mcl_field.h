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

#include "mcl/fp.hpp"
#include "mcl/fp_tower.hpp"

#include "yacl/crypto/base/ecc/mcl/pairing_header.h"
#include "yacl/crypto/base/field/field_spi.h"

namespace yacl::crypto::hmcl {

using yacl::math::MPInt;

// class `MclField` have specific template parameters from libmcl,
// checker `is_supported_mcl_field` helps avoid misuse of class `MclField`
template <typename T, size_t degree>
struct is_supported_mcl_field {
  static constexpr bool value = false;
};

// Support template params check in template class `MclField`
// ! NOT suggest use DECLARE_SUPPORT.
//  Developers should be aware of the specific field type `T` from libmcl and
//  the field extension degree of `T` if use macro DECLARE_SUPPORT.
#define DECLARE_SUPPORT(T, degree)           \
  template <>                                \
  struct is_supported_mcl_field<T, degree> { \
    static constexpr bool value = true;      \
  };

template <typename T_, size_t degree_>
class MclField : public Field {
 private:
  //  Only declared field from libmcl could be instantiated in this class.
  template <
      typename = std::enable_if_t<is_supported_mcl_field<T_, degree_>::value>>
  MclField() {}

 public:
  using T = T_;

  std::string GetLibraryName() const override;
  std::string GetFieldName() const override;
  int64_t GetExtensionDegree() const override;
  // Note that pairing GT field's order is enabled(!=0) and != p^12, since it's
  // actually a sub-field belong to field Fp^12
  MPInt GetOrder() const override;

  bool IsOne(const FElement& x) const override;
  bool IsZero(const FElement& x) const override;
  bool Equal(const FElement& x, const FElement& y) const override;

  FElement Rand() const override;

  // univariate input
  void SetOne(FElement* x) const override;
  FElement MakeOne() const override;
  void SetZero(FElement* x) const override;
  FElement MakeZero() const override;
  FElement MakeInstance() const override;
  FElement FromInt64(int64_t i) const override;
  FElement Copy(const FElement& x) const override;

  FElement Neg(const FElement& x) const override;
  FElement Sqr(const FElement& x) const override;
  FElement Inv(const FElement& x) const override;

  // bivariate inputs
  FElement Add(const FElement& x, const FElement& y) const override;
  void AddInplace(FElement* x, const FElement& y) const override;

  FElement Sub(const FElement& x, const FElement& y) const override;
  void SubInplace(FElement* x, const FElement& y) const override;

  FElement Mul(const FElement& x, const FElement& y) const override;
  void MulInplace(FElement* x, const FElement& y) const override;

  FElement Div(const FElement& x, const FElement& y) const override;
  void DivInplace(FElement* x, const FElement& y) const override;

  FElement Pow(const FElement& x, const MPInt& y) const override;
  void PowInplace(FElement* x, const MPInt& y) const override;

  // serialize
  std::string ToString(const FElement& x) const override;
  FElement FromString(const std::string& x) const override;
  std::string ToDecString(const FElement& x) const override;
  FElement FromDecString(const std::string& x) const override;
  std::string ToHexString(const FElement& x) const override;
  FElement FromHexString(const std::string& x) const override;
  Buffer Serialize(const FElement& x) const override;
  FElement Deserialize(ByteContainerView buffer) const override;

 public:
  explicit MclField(const MPInt& order, bool is_sub_field);
  // xi_a is used for Fp2::mul_xi(), where xi = xi_a + i and i^2 = -1, see
  // Fp::init(int xi_a, ...)
  explicit MclField(const MPInt& base_prime_p,
                    mcl::fp::Mode mode = mcl::fp::FP_AUTO, int xi_a = 1);

 private:
  MPInt order_;
  bool is_sub_field_;
};

DECLARE_SUPPORT(mcl::bls12::GT, 12);

#ifdef MCL_FIELD_YACL_TEST
DECLARE_SUPPORT(mcl::FpT<>, 1);
typedef mcl::FpT<mcl::FpTag, 256> fqt256;
DECLARE_SUPPORT(fqt256, 1);
DECLARE_SUPPORT(mcl::Fp2T<mcl::FpT<>>, 2);
DECLARE_SUPPORT(mcl::Fp6T<mcl::FpT<>>, 6);
DECLARE_SUPPORT(mcl::Fp12T<mcl::FpT<>>, 12);
#endif

#ifdef MCL_ALL_PAIRING_FOR_YACL
DECLARE_SUPPORT(mcl::bn254::GT, 12);
DECLARE_SUPPORT(mcl::bn382m::GT, 12);
DECLARE_SUPPORT(mcl::bn382r::GT, 12);
DECLARE_SUPPORT(mcl::bn462::GT, 12);
DECLARE_SUPPORT(mcl::bnsnark::GT, 12);
DECLARE_SUPPORT(mcl::bn160::GT, 12);
DECLARE_SUPPORT(mcl::bls123::GT, 12);
DECLARE_SUPPORT(mcl::bls124::GT, 12);
DECLARE_SUPPORT(mcl::bn256::GT, 12);
#endif

}  // namespace yacl::crypto::hmcl

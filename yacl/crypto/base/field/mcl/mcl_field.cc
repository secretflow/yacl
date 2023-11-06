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

#include "yacl/crypto/base/field/mcl/mcl_field.h"

#include "mcl/fp_tower.hpp"
#include "mcl/op.hpp"
#include "mcl_field.h"

#include "yacl/crypto/base/ecc/mcl/mcl_util.h"
#include "yacl/crypto/base/ecc/mcl/pairing_header.h"

namespace yacl::crypto::hmcl {

template <typename T_, size_t degree_>
std::string MclField<T_, degree_>::GetLibraryName() const {
  return "libmcl";
}

template <typename T_, size_t degree_>
std::string MclField<T_, degree_>::GetFieldName() const {
  return fmt::format("<MclField F_p^{}>", degree_,
                     Mpz2Mp(T_::BaseFp::getOp().mp));
}

template <typename T_, size_t degree_>
int64_t MclField<T_, degree_>::GetExtensionDegree() const {
  return degree_;
}

template <typename T_, size_t degree_>
MPInt MclField<T_, degree_>::GetOrder() const {
  return order_;
}

template <typename T_, size_t degree_>
bool MclField<T_, degree_>::IsOne(const FElement& x) const {
  return CastAny<T_>(x)->isOne();
}

template <typename T_, size_t degree_>
bool MclField<T_, degree_>::IsZero(const FElement& x) const {
  return CastAny<T_>(x)->isZero();
}

template <typename T_, size_t degree_>
bool MclField<T_, degree_>::Equal(const FElement& x, const FElement& y) const {
  return *CastAny<T_>(x) == *CastAny<T_>(y);
}

template <typename T_, size_t degree_>
FElement MclField<T_, degree_>::Rand() const {
  using BaseFp = typename T_::BaseFp;
  const auto per_size = (BaseFp::getOp().mp.getBitSize() + 7) / 8;

  auto ret = MakeShared<T_>();
  Buffer buf(per_size * degree_);
  BaseFp p;
  for (uint64_t i = 0; i < degree_; i++) {
    p.setByCSPRNG();
    p.serialize(buf.data<uint8_t>() + i * per_size, per_size);
  }

  CastAny<T_>(ret)->deserialize(buf.data<uint8_t>(), buf.size());
  return ret;
}

template <typename T_, size_t degree_>
void MclField<T_, degree_>::SetOne(FElement* x) const {
  auto* p = std::get<AnyPtr>(*x).get<T>();
  if (!p->isOne() && degree_ == 1) {
    *p = 1;
  } else {
    p->clear();
    *(p->getFp0()) = 1;
  }
}

template <typename T_, size_t degree_>
FElement MclField<T_, degree_>::MakeOne() const {
  return FromInt64(1);
}

template <typename T_, size_t degree_>
void MclField<T_, degree_>::SetZero(FElement* x) const {
  auto* p = std::get<AnyPtr>(*x).get<T>();
  if (!p->isOne() && degree_ == 0) {
    *p = 0;
  } else {
    p->clear();
    *(p->getFp0()) = 0;
  }
}

template <typename T_, size_t degree_>
FElement MclField<T_, degree_>::MakeZero() const {
  return MakeShared<T_>(0);
}

template <typename T_, size_t degree_>
FElement MclField<T_, degree_>::MakeInstance() const {
  return MakeShared<T_>(0);
}

template <typename T_, size_t degree_>
FElement MclField<T_, degree_>::FromInt64(int64_t i) const {
  return MakeShared<T_>(i);
}

template <typename T_, size_t degree_>
FElement MclField<T_, degree_>::Copy(const FElement& x) const {
  auto ret = MakeShared<T_>();
  *CastAny<T_>(ret) = *CastAny<T_>(x);
  return ret;
}

template <typename T_, size_t degree_>
FElement MclField<T_, degree_>::Neg(const FElement& x) const {
  auto ret = MakeShared<T_>();
  T_::neg(*CastAny<T_>(ret), *CastAny<T_>(x));
  return ret;
}

template <typename T_, size_t degree_>
FElement MclField<T_, degree_>::Sqr(const FElement& x) const {
  auto ret = MakeShared<T_>();
  T_::sqr(*CastAny<T_>(ret), *CastAny<T_>(x));
  return ret;
}

template <typename T_, size_t degree_>
FElement MclField<T_, degree_>::Inv(const FElement& x) const {
  auto ret = MakeShared<T_>();
  T_::inv(*CastAny<T_>(ret), *CastAny<T_>(x));
  return ret;
}

template <typename T_, size_t degree_>
FElement MclField<T_, degree_>::Add(const FElement& x,
                                    const FElement& y) const {
  auto ret = MakeShared<T_>();
  T_::add(*CastAny<T_>(ret), *CastAny<T_>(x), *CastAny<T_>(y));
  return ret;
}

template <typename T_, size_t degree_>
void MclField<T_, degree_>::AddInplace(FElement* x, const FElement& y) const {
  T_::add(*CastAny<T_>(*x), *CastAny<T_>(x), *CastAny<T_>(y));
}

template <typename T_, size_t degree_>
FElement MclField<T_, degree_>::Sub(const FElement& x,
                                    const FElement& y) const {
  auto ret = MakeShared<T_>();
  T_::sub(*CastAny<T_>(ret), *CastAny<T_>(x), *CastAny<T_>(y));
  return ret;
}

template <typename T_, size_t degree_>
void MclField<T_, degree_>::SubInplace(FElement* x, const FElement& y) const {
  T_::sub(*CastAny<T_>(*x), *CastAny<T_>(x), *CastAny<T_>(y));
}

template <typename T_, size_t degree_>
FElement MclField<T_, degree_>::Mul(const FElement& x,
                                    const FElement& y) const {
  auto ret = MakeShared<T_>();
  T_::mul(*CastAny<T_>(ret), *CastAny<T_>(x), *CastAny<T_>(y));
  return ret;
}

template <typename T_, size_t degree_>
void MclField<T_, degree_>::MulInplace(FElement* x, const FElement& y) const {
  T_::mul(*CastAny<T_>(*x), *CastAny<T_>(x), *CastAny<T_>(y));
}

template <typename T_, size_t degree_>
FElement MclField<T_, degree_>::Div(const FElement& x,
                                    const FElement& y) const {
  auto ret = MakeShared<T_>();
  T_::div(*CastAny<T_>(ret), *CastAny<T_>(x), *CastAny<T_>(y));
  return ret;
}

template <typename T_, size_t degree_>
void MclField<T_, degree_>::DivInplace(FElement* x, const FElement& y) const {
  T_::div(*CastAny<T_>(*x), *CastAny<T_>(x), *CastAny<T_>(y));
}

template <typename T_, size_t degree_>
FElement MclField<T_, degree_>::Pow(const FElement& x, const MPInt& y) const {
  auto ret = MakeShared<T_>();
  T_::pow(*CastAny<T_>(ret), *CastAny<T_>(x), Mp2Mpz(y));
  return ret;
}

template <typename T_, size_t degree_>
void MclField<T_, degree_>::PowInplace(FElement* x, const MPInt& y) const {
  T_::pow(*CastAny<T_>(*x), *CastAny<T_>(x), Mp2Mpz(y));
}

template <typename T_, size_t degree_>
std::string MclField<T_, degree_>::ToString(const FElement& x) const {
  return ToDecString(x);
}

template <typename T_, size_t degree_>
FElement MclField<T_, degree_>::FromString(const std::string& x) const {
  return FromDecString(x);
}

template <typename T_, size_t degree_>
std::string MclField<T_, degree_>::ToDecString(const FElement& x) const {
  return CastAny<T_>(x)->getStr(mcl::IoDec);
}

template <typename T_, size_t degree_>
FElement MclField<T_, degree_>::FromDecString(const std::string& x) const {
  auto ret = MakeShared<T_>();
  CastAny<T_>(ret)->setStr(x, mcl::IoDec);
  return ret;
}

template <typename T_, size_t degree_>
std::string MclField<T_, degree_>::ToHexString(const FElement& x) const {
  return CastAny<T_>(x)->getStr(mcl::IoHex);
}

template <typename T_, size_t degree_>
FElement MclField<T_, degree_>::FromHexString(const std::string& x) const {
  auto ret = MakeShared<T_>();
  CastAny<T_>(ret)->setStr(x, mcl::IoHex);
  return ret;
}

template <typename T_, size_t degree_>
Buffer MclField<T_, degree_>::Serialize(const FElement& x) const {
  Buffer buf(sizeof(T_));
  auto size = CastAny<T_>(x)->serialize(buf.data(), buf.size());
  buf.resize(size);
  return buf;
}

template <typename T_, size_t degree_>
FElement MclField<T_, degree_>::Deserialize(ByteContainerView buffer) const {
  auto ret = MakeShared<T_>();
  CastAny<T_>(ret)->deserialize(buffer.data(), buffer.size());
  return ret;
}

template <typename T_, size_t degree_>
MclField<T_, degree_>::MclField(const MPInt& order, bool is_sub_field) {
  order_ = order;
  is_sub_field_ = is_sub_field;
  // if is_sub_field_ == true, we should provide specific (not zero) order.
  YACL_ENFORCE(is_sub_field_ && !order_.IsZero(),
               "Should provide specific (not zero) order for subfield!");
}

template <typename T_, size_t degree_>
MclField<T_, degree_>::MclField(const MPInt& base_prime_p, mcl::fp::Mode mode,
                                int xi_a) {
  auto base_p = Mp2Mpz(base_prime_p);
  if (degree_ == 1) {
    T_::BaseFp::init(base_p, mode);
    order_ = base_prime_p;
  } else {
    // init for extension mcl field Fp^{2,6,12}
    // xi_a is used for Fp2::mul_xi(), where xi = xi_a + i and i^2 = -1
    // if xi_a = 0 then asm functions for Fp2 are not generated.
    T_::BaseFp::init(xi_a, base_p, mode);
    mcl::Fp2T<typename T_::BaseFp>::init();
    order_ = 0_mp;
  }
}

// ===============================================================
//  Instantiate Field for test
// ===============================================================
#ifdef MCL_FIELD_YACL_TEST
template class MclField<mcl::FpT<>, 1>;
template class MclField<mcl::FpT<mcl::FpTag, 256>, 1>;
template class MclField<mcl::Fp2T<mcl::FpT<>>, 2>;
template class MclField<mcl::Fp6T<mcl::FpT<>>, 6>;
template class MclField<mcl::Fp12T<mcl::FpT<>>, 12>;
#endif

// ===============================================================
//  Instantiate Pairing Curve Field from template
// ===============================================================
template class MclField<mcl::bls12::GT, 12>;

#ifdef MCL_ALL_PAIRING_FOR_YACL
template class MclField<mcl::bn254::GT, 12>;
template class MclField<mcl::bn382m::GT, 12>;
template class MclField<mcl::bn382r::GT, 12>;
template class MclField<mcl::bn462::GT, 12>;
template class MclField<mcl::bnsnark::GT, 12>;
template class MclField<mcl::bn160::GT, 12>;
template class MclField<mcl::bls123::GT, 12>;
template class MclField<mcl::bls124::GT, 12>;
template class MclField<mcl::bn256::GT, 12>;
#endif

}  // namespace yacl::crypto::hmcl

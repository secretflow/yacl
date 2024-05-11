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

#include "yacl/math/galois_field/factory/mcl_factory.h"

#include "mcl/fp_tower.hpp"
#include "mcl/op.hpp"

#include "yacl/crypto/ecc/mcl/mcl_util.h"
#include "yacl/crypto/pairing/factory/mcl_pairing_header.h"

namespace yacl::math {

REGISTER_GF_LIBRARY(kMclLib, 200, MclFieldFactory::Check,
                    MclFieldFactory::Create);

struct MclFieldMeta {
  std::string field_name;
  // Specified by ArgDegree
  uint64_t degree;
  // Specified by ArgMaxBitSize
  uint64_t max_bit_size;

  bool IsEquivalent(const MclFieldMeta& rhs) const {
    return std::tie(field_name, degree, max_bit_size) ==
           std::tie(rhs.field_name, rhs.degree, rhs.max_bit_size);
  }
  MclFieldMeta(std::string field_name, uint64_t degree, uint64_t max_bit_size) {
    this->field_name = field_name;
    this->degree = degree;
    this->max_bit_size = max_bit_size;
  }
};

const std::vector<MclFieldMeta> kMclFieldMetas = {
    {kPrimeField, 1, 256},      {kPrimeField, 1, 512},
    {kExtensionField, 2, 512},  {kExtensionField, 6, 512},
    {kExtensionField, 12, 512},
};

std::unique_ptr<GaloisField> MclFieldFactory::Create(
    const std::string& field_name, const SpiArgs& args) {
  auto mod = args.GetRequired(ArgMod);
  auto degree = args.GetOrDefault(ArgDegree, 1);
  auto maxBitSize = args.GetOrDefault(ArgMaxBitSize, 512);
  auto it = kMclFieldMetas.cbegin();
  for (; it != kMclFieldMetas.cend(); it++) {
    if (it->IsEquivalent({field_name, degree, maxBitSize})) {
      break;
    }
  }
  YACL_ENFORCE(it != kMclFieldMetas.cend());

  switch (it->degree) {
    case 1:
      if (maxBitSize == 256) {
        return std::unique_ptr<GaloisField>(
            new MclField<mcl::FpT<mcl::FpTag, 256>, 1>(mod));
      } else if (maxBitSize == 512) {
        return std::unique_ptr<GaloisField>(
            new MclField<mcl::FpT<mcl::FpTag, 512>, 1>(mod));
      } else {
        YACL_THROW("Unsupported parameter: maxBitSize = {}", maxBitSize);
      }
    case 2:
      return std::unique_ptr<GaloisField>(
          new MclField<mcl::Fp2T<mcl::FpT<mcl::FpTag, 512>>, 2>(mod));
    case 6:
      return std::unique_ptr<GaloisField>(
          new MclField<mcl::Fp6T<mcl::FpT<mcl::FpTag, 512>>, 6>(mod));
    case 12:
      return std::unique_ptr<GaloisField>(
          new MclField<mcl::Fp12T<mcl::FpT<mcl::FpTag, 512>>, 12>(mod));
    default:
      YACL_THROW("Not supported Field by {}", kMclLib);
  }
}

bool MclFieldFactory::Check(const std::string& field_name,
                            const SpiArgs& args) {
  uint64_t degree;
  if (field_name == kPrimeField) {
    degree = args.GetOrDefault(ArgDegree, 1);
  } else {
    degree = args.GetRequired(ArgDegree);
  }

  auto maxBitSize = args.GetOrDefault(ArgMaxBitSize, 512);
  MclFieldMeta meta = {field_name, degree, maxBitSize};
  for (auto it : kMclFieldMetas) {
    if (meta.IsEquivalent(it)) {
      return true;
    }
  }
  return false;
}

namespace ch = yacl::math;

#define BASE_FP_SIZE ((T::BaseFp::getOp().mp.getBitSize() + 7) / 8)

template <typename T, size_t degree>
std::string MclField<T, degree>::GetLibraryName() const {
  return kMclLib;
}

template <typename T, size_t degree>
std::string MclField<T, degree>::GetFieldName() const {
  return degree == 1 ? kPrimeField : kExtensionField;
}

template <typename T, size_t degree>
uint64_t MclField<T, degree>::GetExtensionDegree() const {
  return degree;
}

template <typename T, size_t degree>
MPInt MclField<T, degree>::GetOrder() const {
  return order_;
}

template <typename T, size_t degree>
MPInt MclField<T, degree>::GetMulGroupOrder() const {
  return order_mul_;
}

template <typename T, size_t degree>
MPInt MclField<T, degree>::GetAddGroupOrder() const {
  return order_add_;
}

template <typename T, size_t degree>
MPInt MclField<T, degree>::GetBaseFieldOrder() const {
  return crypto::Mpz2Mp(T::BaseFp::getOp().mp);
}

template <typename T, size_t degree>
Item MclField<T, degree>::GetIdentityZero() const {
  return T(0);
}

template <typename T, size_t degree>
Item MclField<T, degree>::GetIdentityOne() const {
  return T(1);
}

template <typename T, size_t degree>
inline bool MclField<T, degree>::IsIdentityOne(const T& x) const {
  return x.isOne();
}

template <typename T, size_t degree>
bool MclField<T, degree>::IsIdentityZero(const T& x) const {
  return x.isZero();
}

template <typename T, size_t degree>
bool MclField<T, degree>::IsInField(const T&) const {
  // Cause only valid element could be managed by class T, so element in class T
  // is always valid.
  return true;
}

template <typename T, size_t degree>
bool MclField<T, degree>::Equal(const T& x, const T& y) const {
  return x == y;
}

template <typename T, size_t degree>
T MclField<T, degree>::Neg(const T& x) const {
  T ret;
  T::neg(ret, x);
  return ret;
}

template <typename T, size_t degree>
void MclField<T, degree>::NegInplace(T* x) const {
  T::neg(*x, *x);
}

template <typename T, size_t degree>
T MclField<T, degree>::Inv(const T& x) const {
  T ret;
  T::inv(ret, x);
  return ret;
}

template <typename T, size_t degree>
void MclField<T, degree>::InvInplace(T* x) const {
  T::inv(*x, *x);
}

template <typename T, size_t degree>
T MclField<T, degree>::Add(const T& x, const T& y) const {
  return x + y;
}

template <typename T, size_t degree>
void MclField<T, degree>::AddInplace(T* x, const T& y) const {
  T::add(*x, *x, y);
}

template <typename T, size_t degree>
T MclField<T, degree>::Sub(const T& x, const T& y) const {
  return x - y;
}

template <typename T, size_t degree>
void MclField<T, degree>::SubInplace(T* x, const T& y) const {
  T::sub(*x, *x, y);
}

template <typename T, size_t degree>
T MclField<T, degree>::Mul(const T& x, const T& y) const {
  return x * y;
}

template <typename T, size_t degree>
void MclField<T, degree>::MulInplace(T* x, const T& y) const {
  T::mul(*x, *x, y);
}

template <typename T, size_t degree>
T MclField<T, degree>::Div(const T& x, const T& y) const {
  return x / y;
}

template <typename T, size_t degree>
void MclField<T, degree>::DivInplace(T* x, const T& y) const {
  T::div(*x, *x, y);
}

template <typename T, size_t degree>
T MclField<T, degree>::Pow(const T& x, const MPInt& y) const {
  T ret;
  T::pow(ret, x, crypto::Mp2Mpz(y));
  return ret;
}

template <typename T, size_t degree>
void MclField<T, degree>::PowInplace(T* x, const MPInt& y) const {
  T::pow(*x, *x, crypto::Mp2Mpz(y));
}

template <typename T, size_t degree>
T MclField<T, degree>::RandomT() const {
  const auto per_size = BASE_FP_SIZE;

  T ret;
  Buffer buf(per_size * degree);
  typename T::BaseFp p;
  for (uint64_t i = 0; i < degree; i++) {
    p.setByCSPRNG();
    p.serialize(buf.data<uint8_t>() + i * per_size, per_size);
  }

  ret.deserialize(buf.data<uint8_t>(), buf.size());
  return ret;
}

template <typename T, size_t degree>
T MclField<T, degree>::DeepCopy(const T& x) const {
  return x;
}

template <typename T, size_t degree>
std::string MclField<T, degree>::ToString(const T& x) const {
  return x.getStr(mcl::IoDec);
}

template <typename T, size_t degree>
size_t MclField<T, degree>::Serialize(const T& x, uint8_t* buf,
                                      size_t buf_len) const {
  if (buf == nullptr) {
    return BASE_FP_SIZE * degree;
  }
  YACL_ENFORCE(BASE_FP_SIZE * degree <= buf_len);
  auto sz = x.serialize(buf, buf_len);
  return sz;
}

template <typename T, size_t degree>
T MclField<T, degree>::DeserializeT(ByteContainerView buffer) const {
  T ret;
  ret.deserialize(buffer.data(), buffer.size());
  return ret;
}

template <typename T, size_t degree>
MclField<T, degree>::MclField(const MPInt& order, Type field_type) {
  switch (field_type) {
    case Type::Add: {
      order_ = 0_mp;
      order_mul_ = 0_mp;
      order_add_ = order;
      break;
    }
    case Type::Mul: {
      order_ = 0_mp;
      order_mul_ = order;
      order_add_ = 0_mp;
      break;
    }
    default: {
      order_ = order;
      order_mul_ = order - 1_mp;
      order_add_ = order_;
    }
  }
}

template <typename T, size_t degree>
MclField<T, degree>::MclField(const MPInt& base_prime_p, mcl::fp::Mode mode,
                              int xi_a) {
  auto base_p = crypto::Mp2Mpz(base_prime_p);
  if (degree == 1) {
    T::BaseFp::init(base_p, mode);
    order_ = base_prime_p;
    order_mul_ = order_ - 1_mp;
    order_add_ = order_;
  } else {
    // init for extension mcl field Fp^{2,6,12}
    // xi_a is used for Fp2::mul_xi(), where xi = xi_a + i and i^2 = -1
    // if xi_a = 0 then asm functions for Fp2 are not generated.
    T::BaseFp::init(xi_a, base_p, mode);
    mcl::Fp2T<typename T::BaseFp>::init();
    order_ = 0_mp;
    order_mul_ = order_;
    order_add_ = order_;
  }
}

// ===============================================================
//  Instantiate Field for test
// ===============================================================
template class MclField<DefaultFp, 1>;
template class MclField<FpWithSize256, 1>;
template class MclField<DefaultFp2, 2>;
template class MclField<DefaultFp6, 6>;
template class MclField<DefaultFp12, 12>;

// ===============================================================
//  Instantiate Pairing Curve Field from template
// ===============================================================
// Declare class instances for Pairing Curve
template class MclField<mcl::bls12::GT, 12>;
template class MclField<mcl::bnsnark::GT, 12>;

// ONLY for test, not recommended to use in production
#ifdef MCL_ALL_PAIRING_FOR_YACL
template class MclField<mcl::bn254::GT, 12>;
template class MclField<mcl::bn382m::GT, 12>;
template class MclField<mcl::bn382r::GT, 12>;
template class MclField<mcl::bn462::GT, 12>;
template class MclField<mcl::bn160::GT, 12>;
template class MclField<mcl::bls123::GT, 12>;
template class MclField<mcl::bls124::GT, 12>;
template class MclField<mcl::bn256::GT, 12>;
#endif

}  // namespace yacl::math

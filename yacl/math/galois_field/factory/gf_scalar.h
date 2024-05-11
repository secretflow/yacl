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

#include <cstdint>

#include "yacl/math/galois_field/factory/gf_spi.h"
#include "yacl/utils/parallel.h"
#include "yacl/utils/spi/sketch/scalar_define.h"
#include "yacl/utils/spi/sketch/scalar_tools.h"

namespace yacl::math {

// Scalar means that Lib based on this class can only process one data at a
// time, but each method can be called concurrently.
// Scalar 表示基于此类实现的库一次只能处理一个数据，但是每个接口都能被并发调用
template <typename T>
class GFScalarSketch : public GaloisField {
 public:
  // if x is scalar, returns bool
  // if x is vectored, returns std::vector<bool>
  virtual bool IsIdentityOne(const T& x) const = 0;
  virtual bool IsIdentityZero(const T& x) const = 0;
  virtual bool IsInField(const T& x) const = 0;

  virtual bool Equal(const T& x, const T& y) const = 0;

  //==================================//
  //   operations defined on field    //
  //==================================//

  // get the additive inverse −a for all elements in set
  virtual T Neg(const T& x) const = 0;
  virtual void NegInplace(T* x) const = 0;

  // get the multiplicative inverse 1/b for every nonzero element in set
  virtual T Inv(const T& x) const = 0;
  virtual void InvInplace(T* x) const = 0;

  virtual T Add(const T& x, const T& y) const = 0;
  virtual void AddInplace(T* x, const T& y) const = 0;

  virtual T Sub(const T& x, const T& y) const = 0;
  virtual void SubInplace(T* x, const T& y) const = 0;

  virtual T Mul(const T& x, const T& y) const = 0;
  virtual void MulInplace(T* x, const T& y) const = 0;

  virtual T Div(const T& x, const T& y) const = 0;
  virtual void DivInplace(T* x, const T& y) const = 0;

  virtual T Pow(const T& x, const MPInt& y) const = 0;
  virtual void PowInplace(T* x, const MPInt& y) const = 0;

  // scalar version: return a random scalar element
  virtual T RandomT() const = 0;

  //==================================//
  //   operations defined on field    //
  //==================================//

  virtual T DeepCopy(const T& x) const = 0;

  // To human-readable string
  virtual std::string ToString(const T& x) const = 0;

  // serialize field element(s) to already allocated buffer.
  // if buf is nullptr, then calc serialize size only
  // @return: the actual size of serialized buffer
  virtual size_t Serialize(const T& x, uint8_t* buf, size_t buf_len) const = 0;

  virtual T DeserializeT(ByteContainerView buffer) const = 0;

 private:
  // if x is scalar, returns bool
  // if x is vectored, returns std::vector<bool>
  DefineBoolUnaryFunc(IsIdentityOne);
  DefineBoolUnaryFunc(IsIdentityZero);
  DefineBoolUnaryFunc(IsInField);

  bool Equal(const Item& x, const Item& y) const override {
    switch (x, y) {
      case OperandType::Scalar2Scalar: {
        return Equal(x.As<T>(), y.As<T>());
      }
      case OperandType::Vector2Vector: {
        auto xsp = x.AsSpan<T>();
        auto ysp = y.AsSpan<T>();
        if (xsp.length() != ysp.length()) {
          return false;
        }

        std::atomic<bool> res = true;
        yacl::parallel_for(0, xsp.length(), [&](int64_t beg, int64_t end) {
          for (int64_t i = beg; i < end; ++i) {
            if (!res) {
              return;
            }

            if (!Equal(xsp[i], ysp[i])) {
              res.store(false);
              return;
            }
          }
        });
        return res.load();
      }
      case OperandType::Scalar2Vector:
      case OperandType::Vector2Scalar:
        return false;
    }
    YACL_THROW("Bug: please add more case branch");
  }

  //================================//
  //   operations defined on set    //
  //================================//

  // get the additive inverse −a for all elements in set
  DefineUnaryFunc(Neg);
  DefineUnaryInplaceFunc(NegInplace);

  // get the multiplicative inverse 1/b for every nonzero element in set
  DefineUnaryFunc(Inv);
  DefineUnaryInplaceFunc(InvInplace);

  DefineBinaryFunc(Add);
  DefineBinaryInplaceFunc(AddInplace);

  DefineBinaryFunc(Sub);
  DefineBinaryInplaceFunc(SubInplace);

  DefineBinaryFunc(Mul);
  DefineBinaryInplaceFunc(MulInplace);

  DefineBinaryFunc(Div);
  DefineBinaryInplaceFunc(DivInplace);

  Item Pow(const Item& x, const MPInt& y) const override {
    CallUnaryFunc(Pow, T, x, y);
  }

  void PowInplace(Item* x, const MPInt& y) const override {
    CallUnaryInplaceFunc(PowInplace, T, x, y);
  }

  Item Random() const override { return RandomT(); }

  Item Random(size_t count) const override {
    std::vector<T> res(count);
    yacl::parallel_for(0, count, [&](int64_t beg, int64_t end) {
      for (int64_t i = beg; i < end; ++i) {
        res[i] = RandomT();
      }
    });
    return Item::Take(std::move(res));
  }

  //================================//
  //              I/O               //
  //================================//

  DefineUnaryFunc(DeepCopy);

  // To human-readable string
  std::string ToString(const Item& x) const override {
    if (x.IsArray()) {
      auto xsp = x.AsSpan<T>();
      std::string res = "[";
      if (!xsp.empty()) {
        std::string str = ToString(xsp[0]);
        res.reserve(str.size() * xsp.length() * 1.1);
        res += str;
      }

      for (size_t i = 1; i < xsp.length(); ++i) {
        res += ", ";
        res += ToString(xsp[i]);
      }
      res += "]";
      return res;
    } else {
      return ToString(x.As<T>());
    }
  }

  Buffer Serialize(const Item& x) const override {
    return ScalarSketchTools::Serialize<T>(this, x);
  }

  // serialize field element(s) to already allocated buffer.
  // if buf is nullptr, then calc approximate serialize size only
  // @return: the actual size of serialized buffer
  size_t Serialize(const Item& x, uint8_t* buf, size_t buf_len) const override {
    return ScalarSketchTools::Serialize<T>(this, x, buf, buf_len);
  }

  Item Deserialize(ByteContainerView buffer) const override {
    msgpack::object_handle msg = msgpack::unpack(
        reinterpret_cast<const char*>(buffer.data()), buffer.size());

    auto obj = msg.get();
    switch (obj.type) {
      case msgpack::type::STR:
        // scalar case
        return DeserializeT({obj.via.str.ptr, obj.via.str.size});
      case msgpack::type::ARRAY: {
        // vector case
        std::vector<T> res;
        res.resize(obj.via.array.size);
        yacl::parallel_for(
            0, obj.via.array.size, [&](int64_t beg, int64_t end) {
              for (int64_t i = beg; i < end; ++i) {
                auto str_obj = obj.via.array.ptr[i];
                YACL_ENFORCE(str_obj.type == msgpack::type::STR,
                             "Deserialize: illegal format");
                res[i] =
                    DeserializeT({str_obj.via.str.ptr, str_obj.via.str.size});
              }
            });
        return Item::Take(std::move(res));
      }
      default:
        YACL_THROW("Deserialize: unexpected type");
    }
  }
};

}  // namespace yacl::math

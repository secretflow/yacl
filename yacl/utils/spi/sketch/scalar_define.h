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

#pragma once

#include "yacl/utils/spi/sketch/scalar_call.h"

// From:
//   virtual Item FuncName(const Item& x) const = 0;
// To:
//   virtual bool FuncName(const T& x) const = 0;
#define DefineBoolUnaryFunc(FuncName)                                     \
  Item FuncName(const Item& x) const override {                           \
    if (x.IsArray()) {                                                    \
      auto xsp = x.AsSpan<T>();                                           \
      /* std::vector<bool> cannot write in parallel */                    \
      std::vector<uint8_t> res;                                           \
      res.resize(xsp.length());                                           \
      yacl::parallel_for(0, xsp.length(), [&](int64_t beg, int64_t end) { \
        for (int64_t i = beg; i < end; ++i) {                             \
          res[i] = FuncName(xsp[i]);                                      \
        }                                                                 \
      });                                                                 \
      /* convert std::vector<uint8_t> to std::vector<bool> */             \
      std::vector<bool> bv;                                               \
      bv.resize(res.size());                                              \
      std::copy(res.begin(), res.end(), bv.begin());                      \
      return Item::Take(std::move(bv));                                   \
    } else {                                                              \
      return FuncName(x.As<T>());                                         \
    }                                                                     \
  }

// From:
//   virtual Item FuncName(const Item& x) const = 0;
// To:
//   virtual T FuncName(const T& x) const = 0;
#define DefineUnaryFunc(FuncName) \
  Item FuncName(const Item& x) const override { CallUnaryFunc(FuncName, T, x); }

// From:
//   virtual void FuncName(Item* x) const = 0;
// To:
//   virtual void FuncName(T* x) const = 0;
#define DefineUnaryInplaceFunc(FuncName)  \
  void FuncName(Item* x) const override { \
    CallUnaryInplaceFunc(FuncName, T, x); \
  }

// From:
//   virtual Item FuncName(const Item& x, const Item& y) const = 0;
// To:
//   virtual T FuncName(const T& x, const T& y) const = 0;
#define DefineBinaryFunc(FuncName)                             \
  Item FuncName(const Item& x, const Item& y) const override { \
    CallBinaryFunc(FuncName, T, T);                            \
  }

// From:
//   virtual void FuncName(Item* x, const Item& y) const = 0;
// To:
//   virtual void FuncName(T* x, const T& y) const = 0;
#define DefineBinaryInplaceFunc(FuncName)                \
  void FuncName(Item* x, const Item& y) const override { \
    CallBinaryInplaceFunc(FuncName, T, T);               \
  }

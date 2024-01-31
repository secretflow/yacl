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

// Who are using those macros?
// - galois field SPI (YACL)
// - HE SPI (HEU)

// Call:
//   virtual T FuncName(const T& x) const = 0;
//   virtual T FuncName(const T& x, ...) const = 0;
#define CallUnaryFunc(FuncName, T, x, ...)                                    \
  do {                                                                        \
    using RES_T = decltype(FuncName(std::declval<const T>(), ##__VA_ARGS__)); \
                                                                              \
    if (x.IsArray()) {                                                        \
      auto xsp = x.AsSpan<T>();                                               \
      std::vector<RES_T> res;                                                 \
      res.resize(xsp.length());                                               \
      yacl::parallel_for(0, xsp.length(), [&](int64_t beg, int64_t end) {     \
        for (int64_t i = beg; i < end; ++i) {                                 \
          res[i] = FuncName(xsp[i], ##__VA_ARGS__);                           \
        }                                                                     \
      });                                                                     \
      return Item::Take(std::move(res));                                      \
    } else {                                                                  \
      return FuncName(x.As<T>(), ##__VA_ARGS__);                              \
    }                                                                         \
  } while (0)

// Call:
//   virtual void FuncName(T* x) const = 0;
//   virtual void FuncName(T* x, ...) const = 0;
#define CallUnaryInplaceFunc(FuncName, T, x, ...)                         \
  do {                                                                    \
    if (x->IsArray()) {                                                   \
      auto xsp = x->AsSpan<T>();                                          \
      yacl::parallel_for(0, xsp.length(), [&](int64_t beg, int64_t end) { \
        for (int64_t i = beg; i < end; ++i) {                             \
          FuncName(&xsp[i], ##__VA_ARGS__);                               \
        }                                                                 \
      });                                                                 \
    } else {                                                              \
      FuncName(x->As<T*>(), ##__VA_ARGS__);                               \
    }                                                                     \
  } while (0)

// Call:
//   virtual T FuncName(const TX& x, const TY& y) const = 0;
#define CallBinaryFunc(FuncName, TX, TY)                                      \
  do {                                                                        \
    using RES_T = decltype(FuncName(std::declval<const TX>(),                 \
                                    std::declval<const TY>()));               \
                                                                              \
    switch (x, y) {                                                           \
      case yacl::OperandType::Scalar2Scalar: {                                \
        return FuncName(x.As<TX>(), y.As<TY>());                              \
      }                                                                       \
      case yacl::OperandType::Vector2Vector: {                                \
        auto xsp = x.AsSpan<TX>();                                            \
        auto ysp = y.AsSpan<TY>();                                            \
        YACL_ENFORCE_EQ(                                                      \
            xsp.length(), ysp.length(),                                       \
            "operands must have the same length, x.len={}, y.len={}",         \
            xsp.length(), ysp.length());                                      \
                                                                              \
        std::vector<RES_T> res;                                               \
        res.resize(xsp.length());                                             \
        yacl::parallel_for(0, xsp.length(), [&](int64_t beg, int64_t end) {   \
          for (int64_t i = beg; i < end; ++i) {                               \
            res[i] = FuncName(xsp[i], ysp[i]);                                \
          }                                                                   \
        });                                                                   \
        return Item::Take(std::move(res));                                    \
      }                                                                       \
      default:                                                                \
        YACL_THROW("Scalar sketch method [{}] doesn't support broadcast now", \
                   #FuncName);                                                \
    }                                                                         \
  } while (0)

// Call:
//   virtual void FuncName(TX* x, const TY& y) const = 0;
#define CallBinaryInplaceFunc(FuncName, TX, TY)                               \
  do {                                                                        \
    switch (*x, y) {                                                          \
      case yacl::OperandType::Scalar2Scalar: {                                \
        FuncName(x->As<TX*>(), y.As<TY>());                                   \
        return;                                                               \
      }                                                                       \
      case yacl::OperandType::Vector2Vector: {                                \
        auto xsp = x->AsSpan<TX>();                                           \
        auto ysp = y.AsSpan<TY>();                                            \
        YACL_ENFORCE_EQ(                                                      \
            xsp.length(), ysp.length(),                                       \
            "operands must have the same length, x.len={}, y.len={}",         \
            xsp.length(), ysp.length());                                      \
        yacl::parallel_for(0, xsp.length(), [&](int64_t beg, int64_t end) {   \
          for (int64_t i = beg; i < end; ++i) {                               \
            FuncName(&xsp[i], ysp[i]);                                        \
          }                                                                   \
        });                                                                   \
        return;                                                               \
      }                                                                       \
      default:                                                                \
        YACL_THROW("Scalar sketch method [{}] doesn't support broadcast now", \
                   #FuncName);                                                \
    }                                                                         \
  } while (0)

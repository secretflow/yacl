// Copyright 2022 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <array>
#include <exception>

#include "absl/debugging/stacktrace.h"
#include "absl/debugging/symbolize.h"
#include "absl/strings/str_join.h"
#include "absl/types/span.h"
#include "fmt/format.h"

template <>
struct fmt::formatter<absl::Span<const int64_t>> {
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx) {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(absl::Span<const int64_t> number, FormatContext& ctx) {
    return fmt::format_to(ctx.out(), "{}", absl::StrJoin(number, "x"));
  }
};

template <>
struct fmt::formatter<std::vector<int64_t>> {
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx) {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const std::vector<int64_t>& number, FormatContext& ctx) {
    return fmt::format_to(ctx.out(), "{}", absl::StrJoin(number, "x"));
  }
};

namespace yacl {
namespace internal {

const int kMaxStackTraceDep = 16;

#if __cplusplus >= 202002L
template <typename... Args>
inline std::string Format(fmt::format_string<Args...> f, Args&&... args) {
  return fmt::format(f, std::forward<Args>(args)...);
}
#else
template <typename... Args>
inline std::string Format(Args&&... args) {
  return fmt::format(std::forward<Args>(args)...);
}
#endif

// Trick to make Format works with empty arguments.
#if __cplusplus >= 202002L
#else
template <>
#endif
inline std::string Format() { return ""; }

}  // namespace internal

// NOTE: Currently we are using STL exception tree.
//   |- exception
//       |- logic_error
//       |- runtime_error
//           |- io_error
class Exception : public std::exception {
 public:
  Exception() = default;
  explicit Exception(std::string msg) : msg_(std::move(msg)) {}
  explicit Exception(const char* msg) : msg_(msg) {}
  explicit Exception(std::string msg, void** stacks, int dep,
                     bool append_stack_to_msg = false) {
    for (int i = 0; i < dep; ++i) {
      std::array<char, 2048> tmp;
      const char* symbol = "(unknown)";
      if (absl::Symbolize(stacks[i], tmp.data(), tmp.size())) {
        symbol = tmp.data();
      }
      stack_trace_.append(fmt::format("#{} {}+{}\n", i, symbol, stacks[i]));
    }

    if (append_stack_to_msg) {
      msg_ = fmt::format("{}\nStacktrace:\n{}", msg, stack_trace_);
    } else {
      msg_ = std::move(msg);
    }
  }
  const char* what() const noexcept override { return msg_.c_str(); }

  const std::string& stack_trace() const noexcept { return stack_trace_; }

 private:
  std::string msg_;
  std::string stack_trace_;
};

class RuntimeError : public Exception {
  using Exception::Exception;
};

class LogicError : public Exception {
  using Exception::Exception;
};

class NotImplementedError : public Exception {
  using Exception::Exception;
};

class IoError : public RuntimeError {
  using RuntimeError::RuntimeError;
};

class ArgumentError : public RuntimeError {
  using RuntimeError::RuntimeError;
};

class InvalidFormat : public IoError {
  using IoError::IoError;
};

class LinkAborted : public IoError {
  using IoError::IoError;
};

class NetworkError : public IoError {
  using IoError::IoError;
};

class LinkError : public NetworkError {
 public:
  LinkError() = delete;
  explicit LinkError(const std::string& msg, int code, int http_code = 0)
      : NetworkError(msg), code_(code), http_code_(http_code) {}
  explicit LinkError(const std::string& msg, void** stacks, int dep, int code,
                     int http_code = 0)
      : NetworkError(msg, stacks, dep), code_(code), http_code_(http_code) {}

  int code() const noexcept { return code_; }
  int http_code() const noexcept { return http_code_; }

 private:
  int code_;
  int http_code_;
};

#define YACL_ERROR_MSG(...) \
  fmt::format("[{}:{}] {}", __FILE__, __LINE__, fmt::format(__VA_ARGS__))

using stacktrace_t = std::array<void*, ::yacl::internal::kMaxStackTraceDep>;

// add absl::InitializeSymbolizer to main function to get
// human-readable names stack trace
//
// Example:
// int main(int argc, char *argv[]) {
//   absl::InitializeSymbolizer(argv[0]);
//   ...
// }

std::string GetStacktraceString();

#define YACL_THROW_HELPER(ExceptionName, AppendStack, ...)                     \
  do {                                                                         \
    ::yacl::stacktrace_t __stacks__;                                           \
    int __dep__ = absl::GetStackTrace(__stacks__.data(),                       \
                                      ::yacl::internal::kMaxStackTraceDep, 0); \
    throw ExceptionName(YACL_ERROR_MSG(__VA_ARGS__), __stacks__.data(),        \
                        __dep__, AppendStack);                                 \
  } while (false)

#define YACL_THROW(...) \
  YACL_THROW_HELPER(::yacl::RuntimeError, false, __VA_ARGS__)

#define YACL_THROW_WITH_STACK(...) \
  YACL_THROW_HELPER(::yacl::RuntimeError, true, __VA_ARGS__)

#define YACL_THROW_LOGIC_ERROR(...) \
  YACL_THROW_HELPER(::yacl::LogicError, false, __VA_ARGS__)

#define YACL_THROW_IO_ERROR(...) \
  YACL_THROW_HELPER(::yacl::IoError, false, __VA_ARGS__)

#define YACL_THROW_LINK_ABORTED(...) \
  YACL_THROW_HELPER(::yacl::LinkAborted, false, __VA_ARGS__)

#define YACL_THROW_NETWORK_ERROR(...) \
  YACL_THROW_HELPER(::yacl::NetworkError, false, __VA_ARGS__)

#define YACL_THROW_LINK_ERROR(code, http_code, ...) \
  YACL_THROW_HELPER(::yacl::LinkError, false, __VA_ARGS__)

#define YACL_THROW_INVALID_FORMAT(...) \
  YACL_THROW_HELPER(::yacl::InvalidFormat, false, __VA_ARGS__)

#define YACL_THROW_ARGUMENT_ERROR(...) \
  YACL_THROW_HELPER(::yacl::ArgumentError, false, __VA_ARGS__)

// For Status.
#define CHECK_OR_THROW(statement) \
  do {                            \
    auto __s__ = (statement);     \
    if (!__s__.IsOk()) {          \
      YACL_THROW(__s__.Msg());    \
    }                             \
  } while (false)

// For StatusOr from Asylo.
#define ASSIGN_OR_THROW(lhs, rexpr)      \
  do {                                   \
    auto __s__ = (rexpr);                \
    if (!__s__.IsOk()) {                 \
      YACL_THROW(__s__.status().Msg());  \
    }                                    \
    lhs = std::move(__s__).ValueOrDie(); \
  } while (false)

//------------------------------------------------------
// ENFORCE
// https://github.com/facebookincubator/gloo/blob/master/gloo/common/logging.h

/**
 * Copyright (c) 2017-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

class EnforceNotMet : public Exception {
 public:
  EnforceNotMet(const char* file, int line, const char* condition,
                const std::string& msg)
      : Exception(fmt::format("[Enforce fail at {}:{}] {}. {}", file, line,
                              condition, msg)) {}
  EnforceNotMet(const char* file, int line, const char* condition,
                const std::string& msg, void** stacks, int dep)
      : Exception(fmt::format("[Enforce fail at {}:{}] {}. {}", file, line,
                              condition, msg),
                  stacks, dep, true) {}
};

// If you don't want to print stacktrace in error message, use
// "YACL_ENFORCE_THAT" instead.
#define YACL_ENFORCE(condition, ...)                                     \
  do {                                                                   \
    if (!(condition)) {                                                  \
      ::yacl::stacktrace_t __stacks__;                                   \
      const int __dep__ = absl::GetStackTrace(                           \
          __stacks__.data(), ::yacl::internal::kMaxStackTraceDep, 0);    \
      throw ::yacl::EnforceNotMet(__FILE__, __LINE__, #condition,        \
                                  ::yacl::internal::Format(__VA_ARGS__), \
                                  __stacks__.data(), __dep__);           \
    }                                                                    \
  } while (false)

/**
 * Rich logging messages
 *
 * YACL_ENFORCE_THAT can be used with one of the "checker functions" that
 * capture input argument values and add it to the exception message. E.g.
 * `YACL_ENFORCE_THAT(Equals(foo(x), bar(y)), "Optional additional message")`
 * would evaluate both foo and bar only once and if the results are not equal -
 * include them in the exception message.
 *
 * Some of the basic checker functions like Equals or Greater are already
 * defined below. Other header might define customized checkers by adding
 * functions to yacl::enforce_detail namespace. For example:
 *
 *   namespace yacl { namespace enforce_detail {
 *   inline EnforceFailMessage IsVector(const vector<TIndex>& shape) {
 *     if (shape.size() == 1) { return EnforceOK(); }
 *     return fmt::format("Shape {} is not a vector", shape);
 *   }
 *   }}
 *
 * With further usages like `YACL_ENFORCE_THAT(IsVector(Input(0).dims()))`
 *
 * Convenient wrappers for binary operations like YACL_ENFORCE_EQ are provided
 * too. Please use them instead of CHECK_EQ and friends for failures in
 * user-provided input.
 */

namespace enforce_detail {

struct EnforceOK {};

class EnforceFailMessage {
 public:
  constexpr /* implicit */ EnforceFailMessage(EnforceOK) : msg_(nullptr) {}

  EnforceFailMessage(EnforceFailMessage&&) = default;
  EnforceFailMessage(const EnforceFailMessage&) = delete;
  EnforceFailMessage& operator=(EnforceFailMessage&&) = delete;
  EnforceFailMessage& operator=(const EnforceFailMessage&) = delete;

  /* implicit */ EnforceFailMessage(std::string&& msg) {
    msg_ = new std::string(std::move(msg));
  }

  ~EnforceFailMessage() { Free(); }

  inline bool Bad() const { return msg_ != nullptr; }

  std::string GetMessageAndFree(std::string&& extra) {
    std::string r;
    if (extra.empty()) {
      r = std::move(*msg_);
    } else {
      r = fmt::format("{}.{}", *msg_, extra);
    }
    Free();
    return r;
  }

 private:
  void Free() {
    delete msg_;
    msg_ = nullptr;
  }

  std::string* msg_;
};

#define BINARY_COMP_HELPER(name, op)                         \
  template <typename T1, typename T2>                        \
  inline EnforceFailMessage name(const T1& x, const T2& y) { \
    if (x op y) {                                            \
      return EnforceOK();                                    \
    }                                                        \
    return fmt::format("{} vs {}", x, y);                    \
  }
BINARY_COMP_HELPER(Equals, ==)
BINARY_COMP_HELPER(NotEquals, !=)
BINARY_COMP_HELPER(Greater, >)
BINARY_COMP_HELPER(GreaterEquals, >=)
BINARY_COMP_HELPER(Less, <)
BINARY_COMP_HELPER(LessEquals, <=)
#undef BINARY_COMP_HELPER

#define YACL_ENFORCE_THAT_IMPL(condition, expr, ...)                     \
  do {                                                                   \
    ::yacl::enforce_detail::EnforceFailMessage _r_(condition);           \
    if (_r_.Bad()) {                                                     \
      throw ::yacl::EnforceNotMet(                                       \
          __FILE__, __LINE__, expr,                                      \
          _r_.GetMessageAndFree(::yacl::internal::Format(__VA_ARGS__))); \
    }                                                                    \
  } while (false)
}  // namespace enforce_detail

#define YACL_ENFORCE_THAT(condition, ...) \
  YACL_ENFORCE_THAT_IMPL((condition), #condition, __VA_ARGS__)

#define YACL_ENFORCE_EQ(x, y, ...)                                 \
  YACL_ENFORCE_THAT_IMPL(::yacl::enforce_detail::Equals((x), (y)), \
                         #x " == " #y, __VA_ARGS__)
#define YACL_ENFORCE_NE(x, y, ...)                                    \
  YACL_ENFORCE_THAT_IMPL(::yacl::enforce_detail::NotEquals((x), (y)), \
                         #x " != " #y, __VA_ARGS__)
#define YACL_ENFORCE_LE(x, y, ...)                                     \
  YACL_ENFORCE_THAT_IMPL(::yacl::enforce_detail::LessEquals((x), (y)), \
                         #x " <= " #y, __VA_ARGS__)
#define YACL_ENFORCE_LT(x, y, ...)                                            \
  YACL_ENFORCE_THAT_IMPL(::yacl::enforce_detail::Less((x), (y)), #x " < " #y, \
                         __VA_ARGS__)
#define YACL_ENFORCE_GE(x, y, ...)                                        \
  YACL_ENFORCE_THAT_IMPL(::yacl::enforce_detail::GreaterEquals((x), (y)), \
                         #x " >= " #y, __VA_ARGS__)
#define YACL_ENFORCE_GT(x, y, ...)                                  \
  YACL_ENFORCE_THAT_IMPL(::yacl::enforce_detail::Greater((x), (y)), \
                         #x " > " #y, __VA_ARGS__)

template <typename T, std::enable_if_t<std::is_pointer<T>::value, int> = 0>
T CheckNotNull(T t) {
  YACL_ENFORCE(t != nullptr);
  return t;
}

#ifdef NDEBUG
#define WEAK_ENFORCE(condition, ...) ((void)0)
#else
#define WEAK_ENFORCE(condition, ...) YACL_ENFORCE(condition, __VA_ARGS__)
#endif

}  // namespace yacl

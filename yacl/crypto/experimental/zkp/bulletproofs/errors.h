// Copyright 2025 @yangjucai.
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

#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/str_join.h"

#include "yacl/base/exception.h"

namespace examples::zkp {

// Forward declarations for conversion constructors
class R1CSError;
class MPCError;

// Represents an error in proof creation, verification, or parsing.
class ProofError : public std::runtime_error {
 public:
  enum class Code {
    VerificationError,
    FormatError,
    WrongNumBlindingFactors,
    InvalidBitsize,
    InvalidAggregation,
    InvalidGeneratorsLength,
    InvalidInputLength,
    ProvingError,
    WrongNumBitCommitments,
    WrongNumPolyCommitments,
    WrongNumProofShares,
    MalformedProofShares,
    MaliciousDealer
  };

  explicit ProofError(Code type, const std::string& msg = "")
      : std::runtime_error(GetErrorMessage(type, msg)),
        code_(type),
        msg_(msg) {}

  // Conversion from MPCError
  ProofError(const MPCError& mpc_error);

  Code GetCode() const { return code_; }

 private:
  static std::string GetErrorMessage(Code type, const std::string& msg);

  Code code_;
  std::string msg_;  // Store optional message
};

class MPCError : public std::runtime_error {
 public:
  enum class Code {
    MaliciousDealer,
    InvalidBitsize,
    InvalidAggregation,
    InvalidGeneratorsLength,
    WrongNumBitCommitments,
    WrongNumPolyCommitments,
    WrongNumProofShares,
    MalformedProofShares
  };

  explicit MPCError(Code type, const std::string& msg = "")
      : std::runtime_error(GetErrorMessage(type, msg)),
        code_(type),
        msg_(msg) {}

  Code GetCode() const { return code_; }

 private:
  static std::string GetErrorMessage(Code type, const std::string& msg);

  Code code_;
  std::string msg_;
};

class R1CSError : public std::runtime_error {
 public:
  enum class Code {
    InvalidGeneratorsLength,
    FormatError,
    VerificationError,
    MissingAssignment,
    GadgetError,
    NotImplemented,
  };

  explicit R1CSError(Code type, const std::string& msg = "")
      : std::runtime_error(GetErrorMessage(type, msg)),
        code_(type),
        msg_(msg) {}

  R1CSError(const ProofError& proof_error);

  Code GetCode() const { return code_; }

 private:
  static std::string GetErrorMessage(Code type, const std::string& msg);

  Code code_;
  std::string msg_;
};

// Result type for operations that can fail
// Generic Result<T> template for non-void types
template <typename T, typename E = ProofError>
class Result {
 private:
  std::optional<T> value_;
  std::optional<E> error_;

  // Private constructors
  explicit Result(const T& value) : value_(value), error_(std::nullopt) {}
  explicit Result(T&& value) : value_(std::move(value)), error_(std::nullopt) {}
  explicit Result(E error) : value_(std::nullopt), error_(std::move(error)) {}

 public:
  Result() = delete;

  static Result<T, E> Ok(const T& value) { return Result<T, E>(value); }
  static Result<T, E> Ok(T&& value) { return Result<T, E>(std::move(value)); }
  static Result<T, E> Err(E error) { return Result<T, E>(std::move(error)); }

  bool IsOk() const { return value_.has_value(); }
  bool IsErr() const { return error_.has_value(); }

  const T& Value() const& {
    YACL_ENFORCE(IsOk(), "Called Value() on an Err result");
    return *value_;
  }

  T& Value() & {
    YACL_ENFORCE(IsOk(), "Called Value() on an Err result");
    return *value_;
  }

  T&& TakeValue() && {
    YACL_ENFORCE(IsOk(), "Called TakeValue() on an Err result");
    return std::move(*value_);
  }

  const E& Error() const {
    YACL_ENFORCE(IsErr(), "Called Error() on an Ok result");
    return *error_;
  }
};

// Template specialization for Result<void, E>
template <typename E>
class Result<void, E> {
 private:
  std::optional<E> error_;

  Result() : error_(std::nullopt) {}
  explicit Result(E error) : error_(std::move(error)) {}

 public:
  static Result<void, E> Ok() { return Result<void, E>(); }
  static Result<void, E> Err(E error) {
    return Result<void, E>(std::move(error));
  }

  bool IsOk() const { return !error_.has_value(); }
  bool IsErr() const { return error_.has_value(); }

  const E& Error() const {
    YACL_ENFORCE(IsErr(), "Called Error() on an Ok result");
    return *error_;
  }
};

}  // namespace examples::zkp
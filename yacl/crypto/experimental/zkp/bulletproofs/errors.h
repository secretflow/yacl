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
#include <variant>
#include <vector>

namespace examples::zkp {

// Represents an error in proof creation, verification, or parsing.
class ProofError : public std::runtime_error {
 public:
  enum class ErrorType {
    // This error occurs when a proof failed to verify.
    VerificationError,
    // This error occurs when the proof encoding is malformed.
    FormatError,
    // This error occurs during proving if the number of blinding
    // factors does not match the number of values.
    WrongNumBlindingFactors,
    // This error occurs when attempting to create a proof with
    // bitsize other than 8, 16, 32, or 64.
    InvalidBitsize,
    // This error occurs when attempting to create an aggregated
    // proof with non-power-of-two aggregation size.
    InvalidAggregation,
    // This error occurs when there are insufficient generators for the proof.
    InvalidGeneratorsLength,
    // This error occurs when inputs are the incorrect length for the proof.
    InvalidInputLength,
    // This error results from an internal error during proving.
    ProvingError
  };

  explicit ProofError(ErrorType type, const std::string& msg = "")
      : std::runtime_error(GetErrorMessage(type, msg)), type_(type) {}

  ErrorType GetType() const { return type_; }

 private:
  static std::string GetErrorMessage(ErrorType type, const std::string& msg) {
    switch (type) {
      case ErrorType::VerificationError:
        return "Proof verification failed.";
      case ErrorType::FormatError:
        return "Proof data could not be parsed.";
      case ErrorType::WrongNumBlindingFactors:
        return "Wrong number of blinding factors supplied.";
      case ErrorType::InvalidBitsize:
        return "Invalid bitsize, must have n = 8,16,32,64.";
      case ErrorType::InvalidAggregation:
        return "Invalid aggregation size, m must be a power of 2.";
      case ErrorType::InvalidGeneratorsLength:
        return "Invalid generators size, too few generators for proof";
      case ErrorType::InvalidInputLength:
        return "Invalid input size, incorrect input length for proof";
      case ErrorType::ProvingError:
        return "Internal error during proof creation: " + msg;
    }
    return "Unknown error";
  }

  ErrorType type_;
};

// Result type for operations that can fail
template <typename T = void>
class Result {
 public:
  // Construct a successful result
  static Result<T> Ok(const T& value) { return Result<T>(value); }

  static Result<T> Ok(T&& value) { return Result<T>(std::move(value)); }

  // Construct an error result
  static Result<T> Err(const ProofError& error) { return Result<T>(error); }

  // Check if result is successful
  bool IsOk() const { return !error_.has_value(); }

  // Get the value (must check IsOk() first)
  const T& Value() const {
    if (!IsOk()) {
      throw std::runtime_error("Attempted to get value from error result");
    }
    return value_;
  }

  T&& TakeValue() && {
    if (!IsOk()) {
      throw std::runtime_error("Attempted to take value from error result");
    }
    return std::move(value_);
  }

  // Get the error (must check !IsOk() first)
  const ProofError& Error() const {
    if (IsOk()) {
      throw std::runtime_error("Attempted to get error from successful result");
    }
    return *error_;
  }

 private:
  explicit Result(const T& value) : value_(value) {}
  explicit Result(T&& value) : value_(std::move(value)) {}
  explicit Result(const ProofError& error) : error_(error) {}

  T value_;
  std::optional<ProofError> error_;
};

// Specialization for void
template <>
class Result<void> {
 public:
  static Result<void> Ok() { return Result<void>(); }

  static Result<void> Err(const ProofError& error) {
    return Result<void>(error);
  }

  bool IsOk() const { return !error_.has_value(); }

  const ProofError& Error() const {
    if (IsOk()) {
      throw std::runtime_error("Attempted to get error from successful result");
    }
    return *error_;
  }

 private:
  Result() = default;
  explicit Result(const ProofError& error) : error_(error) {}

  std::optional<ProofError> error_;
};

}  // namespace examples::zkp
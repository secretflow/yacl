// Copyright 2023 Ant Group Co., Ltd.
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

#include <unordered_set>
#include <vector>

#include "yacl/link/link.pb.h"

namespace yacl::link {

struct RetryOptions {
  static constexpr uint32_t kDefaultMaxRetryCount = 3;
  static constexpr uint32_t kDefaultRetryInterval = 1000;
  static constexpr uint32_t kDefaultRetryIncrement = 2000;
  static constexpr uint32_t kDefaultMaxRetryInterval = 10000;

  // max retry count
  uint32_t max_retry;
  // at first retry interval
  uint32_t retry_interval_ms;
  // the amount of time to increase between retries
  uint32_t retry_interval_incr_ms;
  // the max interval between retries
  uint32_t max_retry_interval_ms;
  // retry on these error codes, if empty, retry on all codes
  std::unordered_set<uint32_t> error_codes;
  // retry on these http codes, if empty, retry on all http codes
  std::unordered_set<uint32_t> http_codes;
  // do aggressive retry
  bool aggressive_retry;

  RetryOptions()
      : max_retry(kDefaultMaxRetryCount),
        retry_interval_ms(kDefaultRetryInterval),
        retry_interval_incr_ms(kDefaultRetryIncrement),
        max_retry_interval_ms(kDefaultMaxRetryInterval),
        aggressive_retry(true) {}

  RetryOptions(const RetryOptions&) = default;

  RetryOptions(const RetryOptionsProto& pb) {
    max_retry = pb.max_retry() ? pb.max_retry() : kDefaultMaxRetryCount;
    retry_interval_ms =
        pb.retry_interval_ms() ? pb.retry_interval_ms() : kDefaultRetryInterval;
    retry_interval_incr_ms = pb.retry_interval_incr_ms()
                                 ? pb.retry_interval_ms()
                                 : kDefaultRetryIncrement;
    max_retry_interval_ms = pb.max_retry_interval_ms()
                                ? pb.max_retry_interval_ms()
                                : kDefaultMaxRetryInterval;
    std::for_each(pb.error_codes().begin(), pb.error_codes().end(),
                  [this](const auto& codes) { error_codes.insert(codes); });
    std::for_each(pb.http_codes().begin(), pb.http_codes().end(),
                  [this](const auto& codes) { http_codes.insert(codes); });
    aggressive_retry = pb.aggressive_retry();
  }
};

}  // namespace yacl::link

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

#include <memory>

#include "brpc/retry_policy.h"

namespace yacl::link::transport {

class DefaultBrpcRetryPolicy : public brpc::RetryPolicy {
 public:
  explicit DefaultBrpcRetryPolicy(uint32_t retry_interval_ms,
                                  bool aggressive_retry)
      : retry_interval_us_(retry_interval_ms * 1000),
        aggressive_retry_(aggressive_retry) {}

  virtual bool OnRpcSuccess(const brpc::Controller* cntl) const;

  // From brpc::RetryPolicy
  bool DoRetry(const brpc::Controller* cntl) const final;

 protected:
  // for bthread_usleep
  const uint32_t retry_interval_us_;
  bool aggressive_retry_ = true;
};

}  // namespace yacl::link::transport

// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "yacl/link/transport/default_brpc_retry_policy.h"

#include "bthread/bthread.h"
#include "spdlog/spdlog.h"

namespace yacl::link::transport {

void LogHttpDetail(const brpc::Controller* cntl) {
  const auto& response_header = cntl->http_response();
  std::string str_header;
  for (auto it = response_header.HeaderBegin();
       it != response_header.HeaderEnd(); ++it) {
    str_header += fmt::format("[{}]:[{}];", it->first, it->second);
  }
  SPDLOG_INFO(
      "cntl ErrorCode '{}', http status code '{}', response header "
      "'{}', error msg '{}'",
      cntl->ErrorCode(), cntl->http_response().status_code(), str_header,
      cntl->ErrorText());
}

bool DefaultBrpcRetryPolicy::OnRpcSuccess(
    const brpc::Controller* /* cntl */) const {
  SPDLOG_DEBUG("rpc success, no retry.");
  return false;
}

// From brpc::RetryPolicy
bool DefaultBrpcRetryPolicy::DoRetry(const brpc::Controller* cntl) const {
  if (cntl->ErrorCode() == 0) {
    // successful RPC, check response header
    return OnRpcSuccess(cntl);
  } else if (cntl->ErrorCode() == ECONNREFUSED ||
             cntl->ErrorCode() == ECONNRESET) {
    // if a lot of parallel job and each of which may send a lot of async
    // request, the remote (gateway) may reset the connection, this branch
    // tries to handle this by sleep a little bit.
    SPDLOG_INFO("socket error, sleep={}us and retry", retry_interval_us_);
    bthread_usleep(retry_interval_us_);
    return true;
  } else if (cntl->ErrorCode() == brpc::EHTTP &&
             cntl->http_response().status_code() ==
                 brpc::HTTP_STATUS_BAD_GATEWAY) {
    // rejected by peer gateway, do retry.
    LogHttpDetail(cntl);
    SPDLOG_INFO("rejected by remote gateway, sleep={}us and retry",
                retry_interval_us_);
    bthread_usleep(retry_interval_us_);
    return true;
  } else if (cntl->ErrorCode() == brpc::ERPCTIMEDOUT ||
             cntl->ErrorCode() == ECANCELED) {
    // do not retry on ERPCTIMEDOUT / ECANCELED, otherwise brpc will trigger
    // assert.
    // https://github.com/apache/brpc/blob/1.0.0-rc02/src/brpc/controller.cpp#L625
    SPDLOG_INFO(
        "not retry for reached rcp timeout, ErrorCode '{}', error msg '{}'",
        cntl->ErrorCode(), cntl->ErrorText());
    return false;
  } else if (aggressive_retry_) {
    LogHttpDetail(cntl);
    SPDLOG_INFO("aggressive retry, sleep={}us and retry", retry_interval_us_);
    bthread_usleep(retry_interval_us_);

    return true;
  }

  // leave others to brpc::DefaultRetryPolicy()
  return brpc::DefaultRetryPolicy()->DoRetry(cntl);
}

}  // namespace yacl::link::transport

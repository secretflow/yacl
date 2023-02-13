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

#include "yacl/link/trace.h"

#include <mutex>

#include "absl/strings/escaping.h"
#include "spdlog/sinks/rotating_file_sink.h"

#include "yacl/base/exception.h"

namespace yacl::link {
namespace {

const char* kLoggerName = "logger";
const char* kLoggerPath = "trace.log";

const size_t kDefaultMaxLogFileSize = 500 * 1024 * 1024;
const size_t kDefaultMaxLogFileCount = 3;

}  // namespace

std::shared_ptr<TraceLogger> TraceLogger::logger_;

void TraceLogger::SetLogger(std::shared_ptr<TraceLogger> l) {
  YACL_ENFORCE(!logger_, "do not setup logger more then once");
  logger_ = std::move(l);
}

void TraceLogger::LinkTrace(std::string_view event, std::string_view tag,
                            std::string_view content) {
#ifdef ENABLE_LINK_TRACE
  static std::once_flag gInitTrace;
  std::call_once(gInitTrace, []() {
    if (!logger_) {
      // setup default logger
      SetLogger(std::make_shared<DefaultLogger>());
    }
  });
#endif

  if (logger_) {
    logger_->LinkTraceImpl(event, tag, content);
  }
}

DefaultLogger::DefaultLogger() {
  spdlog::rotating_logger_mt(kLoggerName, kLoggerPath, kDefaultMaxLogFileSize,
                             kDefaultMaxLogFileCount);
  logger_ = spdlog::get(kLoggerName);
}

void DefaultLogger::LinkTraceImpl(std::string_view event, std::string_view tag,
                                  std::string_view content) {
  // trace this action anyway.
  SPDLOG_DEBUG("[LINK] key={},tag={}", event, tag);

  // write to link file trace if enabled.
  if (logger_) {
    SPDLOG_LOGGER_INFO(logger_, "[link] key={},tag={},value={}", event, tag,
                       absl::BytesToHexString(content));
  }
}

}  // namespace yacl::link

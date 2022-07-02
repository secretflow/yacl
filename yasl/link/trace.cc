#include "yasl/link/trace.h"

#include <mutex>

#include "absl/strings/escaping.h"
#include "spdlog/sinks/rotating_file_sink.h"

#include "yasl/base/exception.h"

namespace yasl::link {
namespace {

const char* kLoggerName = "logger";
const char* kLoggerPath = "trace.log";

const size_t kDefaultMaxLogFileSize = 500 * 1024 * 1024;
const size_t kDefaultMaxLogFileCount = 3;

}  // namespace

std::shared_ptr<TraceLogger> TraceLogger::logger_;

void TraceLogger::SetLogger(std::shared_ptr<TraceLogger> l) {
  YASL_ENFORCE(!logger_, "do not setup logger more then once");
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
  SPDLOG_TRACE("[LINK] key={},tag={}", event, tag);

  // write to link file trace if enabled.
  if (logger_) {
    SPDLOG_LOGGER_INFO(logger_, "[link] key={},tag={},value={}", event, tag,
                       absl::BytesToHexString(content));
  }
}

}  // namespace yasl::link

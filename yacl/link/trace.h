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

// TODO(jint) move me to somewhere else.

#pragma once

#include <string_view>

#include "spdlog/spdlog.h"

namespace yacl::link {

// Link trace is use to track inter-party communication.
//
// Note: MPC programs are communication-intensive, so trace communication will
// cause severe performance degradation and take a huge amount of disk space.
class TraceLogger {
 public:
  virtual ~TraceLogger() = default;
  TraceLogger() = default;
  ;

  static void SetLogger(std::shared_ptr<TraceLogger>);

  static void LinkTrace(std::string_view event, std::string_view tag,
                        std::string_view content);

 private:
  static std::shared_ptr<TraceLogger> logger_;

 protected:
  virtual void LinkTraceImpl(std::string_view event, std::string_view tag,
                             std::string_view content) = 0;
};

class DefaultLogger : public TraceLogger {
 public:
  DefaultLogger();

 private:
  void LinkTraceImpl(std::string_view event, std::string_view tag,
                     std::string_view content) override;

  std::shared_ptr<spdlog::logger> logger_;
};

}  // namespace yacl::link

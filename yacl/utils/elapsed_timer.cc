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

#include "yacl/utils/elapsed_timer.h"

namespace yacl {

ElapsedTimer::ElapsedTimer() : ElapsedTimer(true) {}

ElapsedTimer::ElapsedTimer(bool start_timer) {
  if (start_timer) {
    Restart();
  } else {
    paused_ = true;
    time_elapsed_us_ = 0;
  }
}

void ElapsedTimer::Restart() {
  paused_ = false;
  time_elapsed_us_ = 0;
  begin_point_ = std::chrono::steady_clock::now();
}

double ElapsedTimer::CountMs() const {
  if (paused_) {
    return time_elapsed_us_ / 1000.0;
  }

  auto end_point = std::chrono::steady_clock::now();
  double span = std::chrono::duration_cast<std::chrono::microseconds>(
                    end_point - begin_point_)
                    .count();
  return (span + time_elapsed_us_) / 1000.0;
}

double ElapsedTimer::CountSec() const { return CountMs() / 1000; }

void ElapsedTimer::Pause() {
  if (paused_) {
    return;
  }

  auto end_point = std::chrono::steady_clock::now();
  double span = std::chrono::duration_cast<std::chrono::microseconds>(
                    end_point - begin_point_)
                    .count();
  time_elapsed_us_ += span;
  paused_ = true;
}

void ElapsedTimer::Resume() {
  if (!paused_) {
    return;
  }

  paused_ = false;
  begin_point_ = std::chrono::steady_clock::now();
}

}  // namespace yacl

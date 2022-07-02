#pragma once

#include <chrono>

namespace yasl {
class ElapsedTimer {
 public:
  /**
   * create and start timer
   */
  ElapsedTimer();
  explicit ElapsedTimer(bool start_timer);

  double CountMs() const;
  double CountSec() const;

  void Restart();
  void Pause();
  void Resume();

 private:
  std::chrono::steady_clock::time_point begin_point_;
  double time_elapsed_us_;
  bool paused_;
};

}  // namespace yasl

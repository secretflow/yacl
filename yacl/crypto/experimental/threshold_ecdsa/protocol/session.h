#pragma once

#include <chrono>
#include <string>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/types.h"

namespace tecdsa {

enum class SessionStatus {
  kRunning = 0,
  kCompleted = 1,
  kAborted = 2,
  kTimedOut = 3,
};

class Session {
 public:
  Session(Bytes session_id,
          PartyIndex self_id,
          std::chrono::milliseconds timeout);
  virtual ~Session() = default;

  const Bytes& session_id() const;
  PartyIndex self_id() const;

  SessionStatus status() const;
  bool IsTerminal() const;
  const std::string& abort_reason() const;

  bool PollTimeout(std::chrono::steady_clock::time_point now =
                       std::chrono::steady_clock::now());

 protected:
  bool ValidateSessionBinding(const Bytes& msg_session_id,
                              PartyIndex to,
                              std::string* error) const;

  void Touch(std::chrono::steady_clock::time_point now =
                 std::chrono::steady_clock::now());
  void Abort(const std::string& reason);
  void Complete();

 private:
  Bytes session_id_;
  PartyIndex self_id_;
  std::chrono::milliseconds timeout_;
  std::chrono::steady_clock::time_point last_activity_;

  SessionStatus status_ = SessionStatus::kRunning;
  std::string abort_reason_;
};

}  // namespace tecdsa

#include "yacl/crypto/experimental/threshold_ecdsa/protocol/session.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"

#include <stdexcept>
#include <utility>

#include "yacl/crypto/experimental/threshold_ecdsa/net/envelope.h"

namespace tecdsa {

Session::Session(Bytes session_id,
                 PartyIndex self_id,
                 std::chrono::milliseconds timeout)
    : session_id_(std::move(session_id)),
      self_id_(self_id),
      timeout_(timeout),
      last_activity_(std::chrono::steady_clock::now()) {
  if (session_id_.empty()) {
    TECDSA_THROW_ARGUMENT("Session ID must not be empty");
  }
  if (self_id_ == 0) {
    TECDSA_THROW_ARGUMENT("self_id must be non-zero");
  }
  if (timeout_.count() <= 0) {
    TECDSA_THROW_ARGUMENT("timeout must be positive");
  }
}

const Bytes& Session::session_id() const {
  return session_id_;
}

PartyIndex Session::self_id() const {
  return self_id_;
}

SessionStatus Session::status() const {
  return status_;
}

bool Session::IsTerminal() const {
  return status_ == SessionStatus::kCompleted ||
         status_ == SessionStatus::kAborted ||
         status_ == SessionStatus::kTimedOut;
}

const std::string& Session::abort_reason() const {
  return abort_reason_;
}

bool Session::PollTimeout(std::chrono::steady_clock::time_point now) {
  if (IsTerminal()) {
    return status_ == SessionStatus::kTimedOut;
  }

  if (now - last_activity_ > timeout_) {
    status_ = SessionStatus::kTimedOut;
    abort_reason_ = "session timed out";
    return true;
  }
  return false;
}

bool Session::ValidateSessionBinding(const Bytes& msg_session_id,
                                     PartyIndex to,
                                     std::string* error) const {
  if (msg_session_id != session_id_) {
    if (error != nullptr) {
      *error = "session_id mismatch";
    }
    return false;
  }

  if (to != self_id_ && to != kBroadcastPartyId) {
    if (error != nullptr) {
      *error = "message recipient mismatch";
    }
    return false;
  }

  return true;
}

void Session::Touch(std::chrono::steady_clock::time_point now) {
  last_activity_ = now;
}

void Session::Abort(const std::string& reason) {
  if (IsTerminal()) {
    return;
  }
  status_ = SessionStatus::kAborted;
  abort_reason_ = reason;
}

void Session::Complete() {
  if (IsTerminal()) {
    return;
  }
  status_ = SessionStatus::kCompleted;
  abort_reason_.clear();
}

}  // namespace tecdsa

#pragma once

#include <cstdint>
#include <span>

#include "yacl/crypto/experimental/threshold_ecdsa/common/bytes.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/types.h"

namespace tecdsa {

constexpr PartyIndex kBroadcastPartyId = 0;

struct Envelope {
  Bytes session_id;
  PartyIndex from = 0;
  PartyIndex to = 0;
  uint32_t type = 0;
  Bytes payload;
};

Bytes EncodeEnvelope(const Envelope& envelope);
Envelope DecodeEnvelope(std::span<const uint8_t> encoded,
                        size_t max_session_id_len = 32,
                        size_t max_payload_len = 1 << 20);

}  // namespace tecdsa

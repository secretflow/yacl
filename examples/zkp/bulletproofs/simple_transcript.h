// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::zkp {

// --- SimpleTranscript Implementation --- //

class SimpleTranscript {
 public:
  // Constants used for domain separation
  static constexpr uint8_t PROTOCOL_LABEL[] = "dom-sep";
  static constexpr uint8_t APP_LABEL[] = "bulletproof-ipa";

  // Constructor: Initialize with a domain separation label
  explicit SimpleTranscript(yacl::ByteContainerView initial_label) {
    hasher_.Reset();

    // Add protocol label domain separation (mimics Merlin's behavior)
    AbsorbU64(sizeof(PROTOCOL_LABEL) - 1);  // Length of label (no null)
    hasher_.Update(
        yacl::ByteContainerView(PROTOCOL_LABEL, sizeof(PROTOCOL_LABEL) - 1));

    // Add app label domain separation
    AbsorbU64(sizeof(APP_LABEL) - 1);
    hasher_.Update(yacl::ByteContainerView(APP_LABEL, sizeof(APP_LABEL) - 1));

    // Add the initial label
    AbsorbU64(initial_label.size());
    hasher_.Update(initial_label);
  }

  // Absorb data into the transcript state with a label
  void Absorb(yacl::ByteContainerView label, yacl::ByteContainerView data) {
    // Add a special "absorb" label (like Merlin does with "dom-sep")
    static const uint8_t ABSORB_LABEL[] = "absorb";
    AbsorbU64(sizeof(ABSORB_LABEL) - 1);
    hasher_.Update(
        yacl::ByteContainerView(ABSORB_LABEL, sizeof(ABSORB_LABEL) - 1));

    // Include the label and its length
    AbsorbU64(label.size());
    hasher_.Update(label);

    // Include the data and its length
    AbsorbU64(data.size());
    hasher_.Update(data);
  }

  // Squeeze bytes from the transcript state with a label
  yacl::Buffer Squeeze(yacl::ByteContainerView label) {
    // Add a special "squeeze" label (like Merlin does with "dom-sep")
    static const uint8_t SQUEEZE_LABEL[] = "squeeze";

    // Get the current hash state
    auto current_state = hasher_.CumulativeHash();

    // Create a new hasher for generating the digest
    yacl::crypto::Sha256Hash temp_hasher;
    temp_hasher.Reset();
    // Feed it the current state first
    temp_hasher.Update(yacl::ByteContainerView(current_state));

    // Add squeeze domain separation
    uint8_t squeeze_len_bytes[8];
    uint64_t squeeze_len = sizeof(SQUEEZE_LABEL) - 1;
    for (int i = 0; i < 8; ++i) {
      squeeze_len_bytes[i] = (squeeze_len >> (i * 8)) & 0xFF;
    }
    temp_hasher.Update(
        yacl::ByteContainerView(squeeze_len_bytes, sizeof(squeeze_len_bytes)));
    temp_hasher.Update(
        yacl::ByteContainerView(SQUEEZE_LABEL, sizeof(SQUEEZE_LABEL) - 1));

    // Add the label
    uint8_t label_len_bytes[8];
    uint64_t label_len = label.size();
    for (int i = 0; i < 8; ++i) {
      label_len_bytes[i] = (label_len >> (i * 8)) & 0xFF;
    }
    temp_hasher.Update(
        yacl::ByteContainerView(label_len_bytes, sizeof(label_len_bytes)));
    temp_hasher.Update(label);

    // Get digest from the temporary state
    std::vector<uint8_t> digest_vec = temp_hasher.CumulativeHash();
    yacl::Buffer digest(std::move(digest_vec));

    // Update the main state with the same data (but don't reset)
    AbsorbU64(sizeof(SQUEEZE_LABEL) - 1);
    hasher_.Update(
        yacl::ByteContainerView(SQUEEZE_LABEL, sizeof(SQUEEZE_LABEL) - 1));
    AbsorbU64(label.size());
    hasher_.Update(label);

    // Also absorb the output (like Merlin does for re-keying)
    AbsorbU64(digest.size());
    hasher_.Update(digest);

    return digest;
  }

  // Convenience function to squeeze and convert to MPInt mod order
  yacl::math::MPInt Challenge(yacl::ByteContainerView label,
                              const yacl::math::MPInt& order) {
    // Loop until we get a valid challenge (non-zero)
    // This matches Merlin's behavior in scalar_from_bytes_mod_order_wide
    while (true) {
      yacl::Buffer bytes = Squeeze(label);
      yacl::math::MPInt result;
      // Use little-endian consistent with Dalek/Merlin
      result.FromMagBytes(bytes, yacl::Endian::little);
      result %= order;
      if (!result.IsZero()) {  // Ensure challenge is not zero
        return result;
      }
      // If zero, absorb a dummy byte and try again
      static const uint8_t RETRY_BYTE[] = {0x52};  // 'R' as a byte array
      Absorb(label, yacl::ByteContainerView(RETRY_BYTE, sizeof(RETRY_BYTE)));
    }
  }

 private:
  // Helper to absorb a 64-bit unsigned integer as little-endian bytes
  void AbsorbU64(uint64_t value) {
    uint8_t bytes[8];
    for (int i = 0; i < 8; ++i) {
      bytes[i] = (value >> (i * 8)) & 0xFF;
    }
    hasher_.Update(yacl::ByteContainerView(bytes, sizeof(bytes)));
  }

  yacl::crypto::Sha256Hash hasher_;
};

}  // namespace examples::zkp
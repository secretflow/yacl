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

#pragma once

#include <memory>
#include <vector>

#include "absl/types/span.h"

#include "yacl/crypto/base/aes/aes_intrinsics.h"
#include "yacl/crypto/primitives/ot/ot_store.h"
#include "yacl/link/link.h"

namespace yacl::crypto {

inline constexpr int kKkrtWidth = 4;  // KKRT width
using KkrtRow = std::array<uint128_t, kKkrtWidth>;

// KKRT OT Extension Implementation
//
// This implementation bases on KKRT OTE, for more theoretical details, see
// https://eprint.iacr.org/2016/799.pdf (Charpter 2).
//
//             (1-out-of-2)    (1-out-of-n)
//              +---------+    +---------+
//              |   ROT   | => |   ROT   |
//              +---------+    +---------+
//              num = t        num = n
//              len = n        len = kappa
//
//  > t: computation security parameter * kKkrtWidth (128 * 4 = 512 for example)
//
// Security assumptions:
//  *. correlation-robust hash function, for more details about its
//  implementation, see `yacl/crypto-tools/random_permutation.h`
//
// NOTE
//  * OT Extension sender requires receiver base ot context.
//  * OT Extension receiver requires sender base ot context.
//

// In KKRT Oblivious PRF, the sender gets a group of PRFs(pseudo random
// function) where each PRF can evaluate any input. The receiver get evaluated
// results for its input numbers.

class IGroupPRF {
 public:
  virtual ~IGroupPRF() = default;

  virtual uint128_t Eval(size_t group_idx, uint128_t input) = 0;
  virtual void Eval(size_t group_idx, uint128_t input, uint8_t* buf,
                    size_t bufsize) = 0;

  virtual size_t Size() const = 0;
};

// In KKRT. The sender get a list of PRFs where each PRF is able to
// evaluate any input, i.e. get a list of PRFs.
//
// Reference: https://eprint.iacr.org/2016/799.pdf (Charpter 2)
//
// Main difference from IKNP:
// - `pseudo random code(PRC)` vs `repetition code (REPEAT)`
// - N-Choose-One : Two-Choose-One
//
// Summary:
//   In IKNP: Sender receives q_j = t_j ^ (REPEAT(r_j) & s), where r_j is
//   expanded from one bit to 128 repeated bits. Receiver gets t_j.
//
//   In KKRT: sender receives q_j = t_j ^ (PRC(r_j) & s), where r_j is a random
//   128 bit input and is expanded to 512 random bits with a random oracle.
//   Receiver gets t_j (Note `t_j = q_j ^ (PRC(r_j) & s))`) which can be view as
//   an evaluated result for an exactly input r = r_j.
//   Sender gets a PRF (Note Enc(r) = q_j ^ (PRC(r_j) & s) since sender
//   knows `s` & `q_j`) which can evaluate any input.
//
// Communication costs:
//   NK, N for number of OPRF instances, K for IKNP width, which is now 512
//   (proved to guarantee 128 bit hamming-distance). Since we are using
//   optimizations from `https://eprint.iacr.org/2013/552.pdf (Protocol 52)`, so
//   it is `NK` instead of `2NK`.
//
// Q: Why are kkrt named as `OT Extension` instead of `OPRF`?
// A: For N-Choose-One Random OT extension, we usually can support N to 2^128.
// Hence for sender you usually get a PRF which can generate random N outputs
// lazily (like yield in python which can create a generator) instead of
// allocate a `2^128` vector (which is impossible due to memory requirements).
// Nowadays, OT Extension are actually same as OPRF for `N-Choose-One` settings
// if N is big enough.
//
// TODO(shuyan.ycf):
//   - Abstract IKNP core with customizable width & coding method, rewrite IKNP
//     as repetition codes and KKRT as pseudo random codes.
//   - This function requires base ot width to 512 now. Let us cut this to 128
//     by implicitly calling IKNP inside KKRT.

std::unique_ptr<IGroupPRF> KkrtOtExtSend(
    const std::shared_ptr<link::Context>& ctx,
    const std::shared_ptr<OtRecvStore>& base_ot, size_t num_ot);

void KkrtOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                   const std::shared_ptr<OtSendStore>& base_ot,
                   absl::Span<const uint128_t> choices,
                   absl::Span<uint128_t> recv_blocks);

class KkrtOtExtSender {
 public:
  KkrtOtExtSender() = default;

  void Init(const std::shared_ptr<link::Context>& ctx,
            const std::shared_ptr<OtRecvStore>& base_ot, uint64_t num_ot);

  void RecvCorrection(const std::shared_ptr<link::Context>& ctx,
                      uint64_t recv_count);

  void RecvCorrection(const std::shared_ptr<link::Context>& ctx);
  void SetCorrection(const yacl::Buffer& recvceived_correction,
                     uint64_t recv_count);

  void Encode(uint64_t ot_idx, uint128_t input, void* dest, uint64_t dest_ize);

  std::shared_ptr<IGroupPRF> GetOprf() { return oprf_; }

  uint64_t GetBatchSize() const { return batch_size_; }
  void SetBatchSize(uint64_t batch_size) { batch_size_ = batch_size; }

 private:
  std::shared_ptr<IGroupPRF> oprf_;
  uint64_t batch_size_ = 128;
  uint64_t correction_idx_ = 0;
};

class KkrtOtExtReceiver {
 public:
  KkrtOtExtReceiver() = default;

  void Init(const std::shared_ptr<link::Context>& ctx,
            const std::shared_ptr<OtSendStore>& base_ot, uint64_t num_ot);

  void Encode(uint64_t ot_idx, absl::Span<const uint128_t> inputs,
              absl::Span<uint8_t> dest_encode);
  void Encode(uint64_t ot_idx, uint128_t input,
              absl::Span<uint8_t> dest_encode);
  void ZeroEncode(uint64_t ot_idx);

  void SendCorrection(const std::shared_ptr<link::Context>& ctx,
                      uint64_t send_count);
  yacl::Buffer ShiftCorrection(uint64_t send_count);

  uint64_t GetBatchSize() const { return batch_size_; }
  void SetBatchSize(uint64_t batch_size) { batch_size_ = batch_size; }

 private:
  std::vector<KkrtRow> T_;
  std::vector<KkrtRow> U_;

  uint64_t batch_size_ = 128;
  uint64_t correction_idx_ = 0;

  AES_KEY aes_key_[kKkrtWidth];
};

}  // namespace yacl::crypto

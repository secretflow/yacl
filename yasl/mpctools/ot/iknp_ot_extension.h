#pragma once

#include <cstddef>

#include "absl/types/span.h"

#include "yasl/link/link.h"
#include "yasl/mpctools/ot/options.h"

namespace yasl {

// IknpOtExtSend IknpOtExtRecv
//
// About raw IKNP OT Extension.
// See charpter 2 in https://eprint.iacr.org/2016/799.pdf
//
// For random OT, there is bandwidth optimized OT extension.
// See <<More Efficient Oblivious Transfer and Extensions for Faster Secure
// Computation>> @ https://eprint.iacr.org/2013/552.pdf (Protocol 52)
//
// This file implements the optimized random OT Extension, which is the optimal
// way to generate AND triple for GMW circuits.
//
// NOTE
//  * OT Extension sender requires receiver base ot context.
//  * OT Extension receiver requires sender base ot context.
//
// For a general random OT extension. Usually we perform OT extension with l ==
// 128. Then each side could get a AES key and can extend to any |l| size
// message that is bigger than 128. In GMW, the special point is the string
// length l is 1, but to break correlation. We still need a bigger k, such as 80
// or 128.
//
// NOTE |choices| need to be round up to 128.
void IknpOtExtSend(const std::shared_ptr<link::Context>& ctx,
                   const BaseRecvOptions& base_options,
                   absl::Span<std::array<uint128_t, 2>> send_blocks);

// TODO(shuyan.ycf): replaces `choices` with strong-typed bit vector.
void IknpOtExtRecv(const std::shared_ptr<link::Context>& ctx,
                   const BaseSendOptions& base_options,
                   absl::Span<const uint128_t> choices,
                   absl::Span<uint128_t> recv_blocks);

}  // namespace yasl
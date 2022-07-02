#pragma once

#include <array>
#include <vector>

#include "yasl/base/int128.h"

namespace yasl {

struct BaseRecvOptions {
  // TODO(shuyan.ycf): Wrap a bit choice class.
  // Receiver choices.
  std::vector<bool> choices;
  // Received blocks.
  // Choose uint128_t as block so that it can be perfectly used as AES-PRG seed.
  std::vector<uint128_t> blocks;
};

struct BaseSendOptions {
  // Sender received blocks.
  // Choose uint128_t as block so that it can be perfectly used as AES-PRG seed.
  std::vector<std::array<uint128_t, 2>> blocks;
};

}  // namespace yasl
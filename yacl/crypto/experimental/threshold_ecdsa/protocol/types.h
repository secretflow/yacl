#pragma once

#include <cstdint>
#include <string>

namespace tecdsa {

using PartyIndex = uint32_t;

struct PartyInfo {
  PartyIndex id;
  std::string endpoint;
};

}  // namespace tecdsa

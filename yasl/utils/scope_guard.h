#pragma once

#include "absl/cleanup/cleanup.h"

#define SCOPEGUARD_LINENAME_CAT(name, line) name##line
#define SCOPEGUARD_LINENAME(name, line) SCOPEGUARD_LINENAME_CAT(name, line)
#define ON_SCOPE_EXIT(...) \
  absl::Cleanup SCOPEGUARD_LINENAME(EXIT, __LINE__) = (__VA_ARGS__)

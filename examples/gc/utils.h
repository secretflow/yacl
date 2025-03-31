#include <bits/stdc++.h>
#include <emmintrin.h>
#include <openssl/sha.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <random>

#include "yacl/math/mpint/mp_int.h"

using uint128_t = __uint128_t;

// get the Least Significant Bit of uint128_t
inline bool getLSB(const uint128_t& x) { return (x & 1) == 1; }

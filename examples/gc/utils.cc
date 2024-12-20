#include "utils.h"

void random_uint128_t(uint128_t* data, int nblocks) {
  for (int i = 0; i < nblocks; i++) {
    std::random_device rd;
    std::mt19937_64 eng(rd());
    std::uniform_int_distribution<uint64_t> distr;

    uint64_t high = distr(eng);
    uint64_t low = distr(eng);

    data[i] = make_uint128_t(high, low);
  }
}

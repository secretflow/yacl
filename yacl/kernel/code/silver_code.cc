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

#include "yacl/kernel/code/silver_code.h"

#include <algorithm>
#include <cstdint>
#include <deque>

#include "yacl/base/exception.h"

namespace yacl::crypto {

namespace {

//
// These variables are defined in paper "Silver: Silent VOLE and Oblivious
// Transfer from Hardness of Decoding Structured LDPC Codes", ref:
// https://eprint.iacr.org/2021/1150.pdf (Appendix F Silver Code Details)
//

alignas(32) static constexpr std::array<const double, 5> Left_R5 = {
    0, 0.372071, 0.576568, 0.608917, 0.854475};
alignas(32) static constexpr std::array<std::array<const uint32_t, 4>,
                                        16> diagMtx_g16_w5_seed1_t36{
    {{{0, 4, 11, 15}},
     {{0, 8, 9, 10}},
     {{1, 2, 10, 14}},
     {{0, 5, 8, 15}},
     {{3, 13, 14, 15}},
     {{2, 4, 7, 8}},
     {{0, 9, 12, 15}},
     {{1, 6, 8, 14}},
     {{4, 5, 6, 14}},
     {{1, 3, 8, 13}},
     {{3, 4, 7, 8}},
     {{3, 5, 9, 13}},
     {{8, 11, 12, 14}},
     {{6, 10, 12, 13}},
     {{2, 7, 8, 13}},
     {{0, 6, 10, 15}}}};

alignas(32) static constexpr std::array<const double, 11> Left_R11 = {
    0,        0.00278835, 0.0883852, 0.238023, 0.240532, 0.274624,
    0.390639, 0.531551,   0.637619,  0.945265, 0.965874};
alignas(32) static constexpr std::array<std::array<const uint32_t, 10>,
                                        32> diagMtx_g32_w11_seed2_t36{
    {{{6, 7, 8, 12, 16, 17, 20, 22, 24, 25}},
     {{0, 1, 6, 10, 12, 13, 17, 19, 30, 31}},
     {{1, 4, 7, 10, 12, 16, 21, 22, 30, 31}},
     {{3, 5, 9, 13, 15, 21, 23, 25, 26, 27}},
     {{3, 8, 9, 14, 17, 19, 24, 25, 26, 28}},
     {{3, 11, 12, 13, 14, 16, 17, 21, 22, 30}},
     {{2, 4, 5, 11, 12, 17, 22, 24, 30, 31}},
     {{5, 8, 11, 12, 13, 17, 18, 20, 27, 29}},
     {{13, 16, 17, 18, 19, 20, 21, 22, 26, 30}},
     {{3, 8, 13, 15, 16, 17, 19, 20, 21, 27}},
     {{0, 2, 4, 5, 6, 21, 23, 26, 28, 30}},
     {{2, 4, 6, 8, 10, 11, 22, 26, 28, 30}},
     {{7, 9, 11, 14, 15, 16, 17, 18, 24, 30}},
     {{0, 3, 7, 12, 13, 18, 20, 24, 25, 28}},
     {{1, 5, 7, 8, 12, 13, 21, 24, 26, 27}},
     {{0, 16, 17, 19, 22, 24, 25, 27, 28, 31}},
     {{0, 6, 7, 15, 16, 18, 22, 24, 29, 30}},
     {{2, 3, 4, 7, 15, 17, 18, 20, 22, 26}},
     {{2, 3, 9, 16, 17, 19, 24, 27, 29, 31}},
     {{1, 3, 5, 7, 13, 14, 20, 23, 24, 27}},
     {{0, 2, 3, 9, 10, 14, 19, 20, 21, 25}},
     {{4, 13, 16, 20, 21, 23, 25, 27, 28, 31}},
     {{1, 2, 5, 6, 9, 13, 15, 17, 20, 24}},
     {{0, 4, 7, 8, 12, 13, 20, 23, 28, 30}},
     {{0, 3, 4, 5, 8, 9, 23, 25, 26, 28}},
     {{0, 3, 4, 7, 8, 10, 11, 15, 21, 26}},
     {{5, 6, 7, 8, 10, 11, 15, 21, 22, 25}},
     {{0, 1, 2, 3, 8, 9, 22, 24, 27, 28}},
     {{1, 2, 13, 14, 15, 16, 19, 22, 29, 30}},
     {{2, 14, 15, 16, 19, 20, 25, 26, 28, 29}},
     {{8, 9, 11, 12, 13, 15, 17, 18, 23, 27}},
     {{0, 2, 4, 5, 6, 7, 10, 12, 14, 19}}}};

alignas(32) static constexpr std::array<const uint32_t, 2> R_offset_ = {5, 31};
}  // namespace

SilverCode::SilverCode(uint64_t n, uint32_t weight)
    : n_(n), m_(2 * n), weight_(weight) {
  switch (weight_) {
    case 5:
      YACL_ENFORCE(n >= 5);
      gap_ = 16;
      InitLeftMatrix(absl::MakeSpan(Left_R5));
      break;
    case 11:
      YACL_ENFORCE(n >= 11);
      gap_ = 32;
      InitLeftMatrix(absl::MakeSpan(Left_R11));
      break;
    default:
      YACL_THROW("Only support Silver5 & Silver11");
  }
}

#define REGISTER_DUALENCODE(Type)                                           \
  template void SilverCode::DualEncodeInplaceImpl<Type>(                    \
      absl::Span<Type> inout) const;                                        \
  template void SilverCode::DualEncodeImpl<Type>(absl::Span<const Type> in, \
                                                 absl::Span<Type> out) const;

// REGISTER_TEMPLATE(uint32_t);
REGISTER_DUALENCODE(uint64_t);
REGISTER_DUALENCODE(uint128_t);
#undef REGISTER_TEMPLATE

#define REGISTER_DUALENCODE2(Type0, Type1)                        \
  template void SilverCode::DualEncodeInplace2Impl<Type0, Type1>( \
      absl::Span<Type0> inout0, absl::Span<Type1> inout1) const;  \
  template void SilverCode::DualEncode2Impl<Type0, Type1>(        \
      absl::Span<const Type0> in0, absl::Span<Type0> out0,        \
      absl::Span<const Type1> in1, absl::Span<Type1> out1) const;

REGISTER_DUALENCODE2(uint64_t, uint64_t);
REGISTER_DUALENCODE2(uint128_t, uint128_t);
REGISTER_DUALENCODE2(uint64_t, uint128_t);
#undef REGISTER_DUALENCODE2

template <typename T>
void SilverCode::DualEncodeInplaceImpl(absl::Span<T> inout) const {
  YACL_ENFORCE(inout.size() >= m_);

  // x[n:2n] = x[n:2n] * R^{-1}
  RightEncode(inout.subspan(n_, n_));
  // x[0:n] += x[n:2n] * L
  LeftEncode<T>(inout.subspan(n_, n_), inout.subspan(0, n_));
}

template <typename T>
void SilverCode::DualEncodeImpl(absl::Span<const T> in,
                                absl::Span<T> out) const {
  YACL_ENFORCE(in.size() >= m_);
  YACL_ENFORCE(out.size() >= n_);

  // Copy in[n:2n] to buff
  std::vector<T> buff(in.data() + n_, in.data() + m_);
  // buff = buff * R^{-1}
  RightEncode(absl::MakeSpan(buff));
  // Copy in[0:n] to out[0:n]
  memcpy(out.data(), in.data(), n_ * sizeof(T));
  // out = out + buff * L
  LeftEncode<T>(absl::MakeSpan(buff), out.subspan(0, n_));
}

template <typename T, typename K>
void SilverCode::DualEncodeInplace2Impl(absl::Span<T> inout0,
                                        absl::Span<K> inout1) const {
  YACL_ENFORCE(inout0.size() >= m_);
  YACL_ENFORCE(inout1.size() >= m_);

  // x[n:2n] = x[n:2n] * R^{-1}
  RightEncode2<T, K>(inout0.subspan(n_, n_), inout1.subspan(n_, n_));
  // x[0:n] += x[n:2n] * L
  LeftEncode2<T, K>(inout0.subspan(n_, n_), inout0.subspan(0, n_),
                    inout1.subspan(n_, n_), inout1.subspan(0, n_));
}

template <typename T, typename K>
void SilverCode::DualEncode2Impl(absl::Span<const T> in0, absl::Span<T> out0,
                                 absl::Span<const K> in1,
                                 absl::Span<K> out1) const {
  YACL_ENFORCE(in0.size() >= m_);
  YACL_ENFORCE(out0.size() >= n_);
  YACL_ENFORCE(in1.size() >= m_);
  YACL_ENFORCE(out1.size() >= n_);

  // Copy in[n:2n] to buff
  std::vector<T> buff0(in0.data() + n_, in0.data() + m_);
  std::vector<K> buff1(in1.data() + n_, in1.data() + m_);
  // buff = buff * R^{-1}
  RightEncode2<T, K>(absl::MakeSpan(buff0), absl::MakeSpan(buff1));
  // Copy in[0:n] to out[0:n]
  memcpy(out0.data(), in0.data(), n_ * sizeof(T));
  memcpy(out1.data(), in1.data(), n_ * sizeof(K));
  // out = out + buff * L
  LeftEncode2<T, K>(absl::MakeSpan(buff0), out0.subspan(0, n_),
                    absl::MakeSpan(buff1), out1.subspan(0, n_));
}

void SilverCode::InitLeftMatrix(absl::Span<const double> R) {
  YACL_ENFORCE(R.size() == weight_);

  size_t one_num = R.size();
  size_t collision_counter = 0;

  std::set<uint32_t> one_entry;
  for (size_t i = 0; i < one_num; ++i) {
    // generate one index (non-zero index) by R
    uint32_t tmp = static_cast<uint32_t>(n_ * R[i]) % n_;
    while (collision_counter < 1000 && one_entry.insert(tmp).second == false) {
      tmp = (tmp + 1) % n_;
      // avoid endless loop
      ++collision_counter;
    }
  }

  YACL_ENFORCE(one_entry.size() == one_num);
  // Copy to L_one_idx_
  L_one_idx_ = std::vector<uint32_t>(one_entry.begin(), one_entry.end());
}

template <typename T>
void SilverCode::LeftEncode(absl::Span<const T> in, absl::Span<T> out) const {
  auto one_entry = std::deque<uint32_t>(L_one_idx_.begin(), L_one_idx_.end());
  const size_t size = one_entry.size();

  YACL_ENFORCE(in.size() >= n_);
  YACL_ENFORCE(out.size() >= n_);
  YACL_ENFORCE(size == weight_);

  std::vector<const T*> in_ptrs(size);

  for (size_t i = 0; i < n_;) {
    auto max_idx = one_entry.back();
    YACL_ENFORCE(max_idx ==
                 *std::max_element(one_entry.begin(), one_entry.end()));
    uint32_t step = std::min<uint32_t>(n_ - max_idx, n_ - i);

    auto* out_begin_ptr = out.data() + i;
    auto* out_end_ptr = out.data() + step + i;

    size_t j = 0;
    for (auto& idx : one_entry) {
      in_ptrs[j] = in.data() + idx;
      idx += step;
      ++j;
    }
    one_entry.pop_back();
    one_entry.push_front(0);

    i += step;

    while (out_begin_ptr != out_end_ptr) {
      switch (weight_) {
        case 5:
          // 5-local-linear code, Hamming weight for each column is 5
          *out_begin_ptr = *out_begin_ptr ^ *(in_ptrs[0]) ^ *(in_ptrs[1]) ^
                           *(in_ptrs[2]) ^ *(in_ptrs[3]) ^ *(in_ptrs[4]);
          ++in_ptrs[0];
          ++in_ptrs[1];
          ++in_ptrs[2];
          ++in_ptrs[3];
          ++in_ptrs[4];
          break;
        case 11:
          // 5-local-linear code, Hamming weight for each column is 11
          *out_begin_ptr = *out_begin_ptr ^ *(in_ptrs[0]) ^ *(in_ptrs[1]) ^
                           *(in_ptrs[2]) ^ *(in_ptrs[3]) ^ *(in_ptrs[4]) ^
                           *(in_ptrs[5]) ^ *(in_ptrs[6]) ^ *(in_ptrs[7]) ^
                           *(in_ptrs[8]) ^ *(in_ptrs[9]) ^ *(in_ptrs[10]);
          ++in_ptrs[0];
          ++in_ptrs[1];
          ++in_ptrs[2];
          ++in_ptrs[3];
          ++in_ptrs[4];
          ++in_ptrs[5];
          ++in_ptrs[6];
          ++in_ptrs[7];
          ++in_ptrs[8];
          ++in_ptrs[9];
          ++in_ptrs[10];
          break;
        default:
          //   for (size_t j = 0; j < size; ++j) {
          //     *out_begin_ptr ^= *(in_ptrs[j]);
          //     ++in_ptrs[j];
          //   }
          YACL_THROW("[LeftEncode] silver code does not support weight {}",
                     weight_);
      }
      ++out_begin_ptr;
    }
  }
}

template <typename T, typename K>
void SilverCode::LeftEncode2(absl::Span<const T> in0, absl::Span<T> out0,
                             absl::Span<const K> in1,
                             absl::Span<K> out1) const {
  auto one_entry = std::deque<uint32_t>(L_one_idx_.begin(), L_one_idx_.end());
  const size_t size = one_entry.size();

  YACL_ENFORCE(in0.size() >= n_);
  YACL_ENFORCE(out0.size() >= n_);
  YACL_ENFORCE(in1.size() >= n_);
  YACL_ENFORCE(out1.size() >= n_);
  YACL_ENFORCE(size == weight_);

  std::vector<const T*> in_ptrs0(size);
  std::vector<const K*> in_ptrs1(size);

  for (size_t i = 0; i < n_;) {
    auto max_idx = one_entry.back();
    YACL_ENFORCE(max_idx ==
                 *std::max_element(one_entry.begin(), one_entry.end()));
    uint32_t step = std::min<uint32_t>(n_ - max_idx, n_ - i);

    auto* out_begin_ptr0 = out0.data() + i;
    auto* out_end_ptr0 = out0.data() + step + i;

    auto* out_begin_ptr1 = out1.data() + i;

    size_t j = 0;
    for (auto& idx : one_entry) {
      in_ptrs0[j] = in0.data() + idx;
      in_ptrs1[j] = in1.data() + idx;
      idx += step;
      ++j;
    }
    one_entry.pop_back();
    one_entry.push_front(0);

    i += step;

    while (out_begin_ptr0 != out_end_ptr0) {
      switch (weight_) {
        case 5:
          // 5-local-linear code, Hamming weight for each column is 5
          *out_begin_ptr0 = *out_begin_ptr0 ^ *(in_ptrs0[0]) ^ *(in_ptrs0[1]) ^
                            *(in_ptrs0[2]) ^ *(in_ptrs0[3]) ^ *(in_ptrs0[4]);

          *out_begin_ptr1 = *out_begin_ptr1 ^ *(in_ptrs1[0]) ^ *(in_ptrs1[1]) ^
                            *(in_ptrs1[2]) ^ *(in_ptrs1[3]) ^ *(in_ptrs1[4]);

          ++in_ptrs0[0];
          ++in_ptrs0[1];
          ++in_ptrs0[2];
          ++in_ptrs0[3];
          ++in_ptrs0[4];

          ++in_ptrs1[0];
          ++in_ptrs1[1];
          ++in_ptrs1[2];
          ++in_ptrs1[3];
          ++in_ptrs1[4];
          break;
        case 11:
          // 5-local-linear code, Hamming weight for each column is 11
          *out_begin_ptr0 = *out_begin_ptr0 ^ *(in_ptrs0[0]) ^ *(in_ptrs0[1]) ^
                            *(in_ptrs0[2]) ^ *(in_ptrs0[3]) ^ *(in_ptrs0[4]) ^
                            *(in_ptrs0[5]) ^ *(in_ptrs0[6]) ^ *(in_ptrs0[7]) ^
                            *(in_ptrs0[8]) ^ *(in_ptrs0[9]) ^ *(in_ptrs0[10]);

          *out_begin_ptr1 = *out_begin_ptr1 ^ *(in_ptrs1[0]) ^ *(in_ptrs1[1]) ^
                            *(in_ptrs1[2]) ^ *(in_ptrs1[3]) ^ *(in_ptrs1[4]) ^
                            *(in_ptrs1[5]) ^ *(in_ptrs1[6]) ^ *(in_ptrs1[7]) ^
                            *(in_ptrs1[8]) ^ *(in_ptrs1[9]) ^ *(in_ptrs1[10]);

          ++in_ptrs0[0];
          ++in_ptrs0[1];
          ++in_ptrs0[2];
          ++in_ptrs0[3];
          ++in_ptrs0[4];
          ++in_ptrs0[5];
          ++in_ptrs0[6];
          ++in_ptrs0[7];
          ++in_ptrs0[8];
          ++in_ptrs0[9];
          ++in_ptrs0[10];

          ++in_ptrs1[0];
          ++in_ptrs1[1];
          ++in_ptrs1[2];
          ++in_ptrs1[3];
          ++in_ptrs1[4];
          ++in_ptrs1[5];
          ++in_ptrs1[6];
          ++in_ptrs1[7];
          ++in_ptrs1[8];
          ++in_ptrs1[9];
          ++in_ptrs1[10];
          break;
        default:
          //   for (size_t j = 0; j < size; ++j) {
          //     *out_begin_ptr0 ^= *(in_ptrs0[j]);
          //     ++in_ptrs0[j];
          //     *out_begin_ptr1 ^= *(in_ptrs1[j]);
          //     ++in_ptrs1[j];
          //   }
          YACL_THROW("[LeftEncode] silver code does not support weight {}",
                     weight_);
      }
      ++out_begin_ptr0;
      ++out_begin_ptr1;
    }
  }
}

// Given y and matrix R, find the solve x s.t. y = x * R
// where R is a lower triangle matrix.
//
// Obviously,
// y[n-1] = x[n-1]
// y[n-2] = x[n-2] + R[n-1][n-2] * x[n-1]
// y[n-3] = x[n-3] + R[n-1][n-3] * x[n-1] + R[n-2][n-3] * x[n-2]
// ....
template <typename T>
void SilverCode::RightEncode(absl::Span<T> inout) const {
  YACL_ENFORCE(inout.size() >= n_);

  uint32_t offset0 = n_ - gap_ - 1 - R_offset_[0];
  uint32_t offset1 = n_ - gap_ - 1 - R_offset_[1];

  uint32_t i = n_ - 1;
  uint32_t lower_bound = std::max<uint32_t>(R_offset_[0], R_offset_[1]) + gap_;
  auto* xi = inout.data() + i;
  auto* xx = xi - gap_;
  switch (weight_) {
    case 5:
      while (i > lower_bound) {
        auto tmp = *xi;

        *(xx + diagMtx_g16_w5_seed1_t36[i & 15][0]) ^= tmp;
        *(xx + diagMtx_g16_w5_seed1_t36[i & 15][1]) ^= tmp;
        *(xx + diagMtx_g16_w5_seed1_t36[i & 15][2]) ^= tmp;
        *(xx + diagMtx_g16_w5_seed1_t36[i & 15][3]) ^= tmp;

        inout[offset0] ^= tmp;
        inout[offset1] ^= tmp;

        --offset0;
        --offset1;
        --xx;
        --xi;
        --i;
      }
      break;
    case 11:
      while (i > lower_bound) {
        auto tmp = *xi;

        *(xx + diagMtx_g32_w11_seed2_t36[i & 31][0]) ^= tmp;
        *(xx + diagMtx_g32_w11_seed2_t36[i & 31][1]) ^= tmp;
        *(xx + diagMtx_g32_w11_seed2_t36[i & 31][2]) ^= tmp;
        *(xx + diagMtx_g32_w11_seed2_t36[i & 31][3]) ^= tmp;
        *(xx + diagMtx_g32_w11_seed2_t36[i & 31][4]) ^= tmp;
        *(xx + diagMtx_g32_w11_seed2_t36[i & 31][5]) ^= tmp;
        *(xx + diagMtx_g32_w11_seed2_t36[i & 31][6]) ^= tmp;
        *(xx + diagMtx_g32_w11_seed2_t36[i & 31][7]) ^= tmp;
        *(xx + diagMtx_g32_w11_seed2_t36[i & 31][8]) ^= tmp;
        *(xx + diagMtx_g32_w11_seed2_t36[i & 31][9]) ^= tmp;

        inout[offset0] ^= tmp;
        inout[offset1] ^= tmp;

        --offset0;
        --offset1;
        --xx;
        --xi;
        --i;
      }
      break;
    default:
      YACL_THROW("[RightEncode] silver code does not support weight {}",
                 weight_);
  }

  switch (weight_) {
    case 5:
      for (; i != ~static_cast<uint32_t>(0); --i) {
        auto tmp = inout[i];
        for (int32_t j = 3; j >= 0; --j) {
          uint32_t idx = diagMtx_g16_w5_seed1_t36[i & 15][j] + i - 16;
          if (idx >= n_) {
            break;
          }
          inout[idx] ^= tmp;
        }
        if (n_ > offset0) {
          inout[offset0] ^= tmp;
          --offset0;
        }
        if (n_ > offset1) {
          inout[offset1] ^= tmp;
          --offset1;
        }
      }
      break;
    case 11:
      for (; i != ~static_cast<uint32_t>(0); --i) {
        auto tmp = inout[i];
        for (int32_t j = 9; j >= 0; --j) {
          uint32_t col = diagMtx_g32_w11_seed2_t36[i & 31][j] + i - 32;
          if (col >= n_) {
            break;
          }
          inout[col] ^= tmp;
        }
        if (n_ > offset0) {
          inout[offset0] ^= tmp;
          --offset0;
        }
        if (n_ > offset1) {
          inout[offset1] ^= tmp;
          --offset1;
        }
      }
      break;
    default:
      YACL_THROW("[RightEncode] silver code does not support weight {}",
                 weight_);
  }
}

template <typename T, typename K>
void SilverCode::RightEncode2(absl::Span<T> inout0,
                              absl::Span<K> inout1) const {
  YACL_ENFORCE(inout0.size() >= n_);
  YACL_ENFORCE(inout1.size() >= n_);

  uint32_t offset0 = n_ - gap_ - 1 - R_offset_[0];
  uint32_t offset1 = n_ - gap_ - 1 - R_offset_[1];

  uint32_t i = n_ - 1;
  uint32_t lower_bound = std::max<uint32_t>(R_offset_[0], R_offset_[1]) + gap_;

  auto* xi0 = inout0.data() + i;
  auto* xx0 = xi0 - gap_;
  auto* xi1 = inout1.data() + i;
  auto* xx1 = xi1 - gap_;

  switch (weight_) {
    case 5:
      while (i > lower_bound) {
        auto tmp0 = *xi0;
        auto tmp1 = *xi1;

        *(xx0 + diagMtx_g16_w5_seed1_t36[i & 15][0]) ^= tmp0;
        *(xx0 + diagMtx_g16_w5_seed1_t36[i & 15][1]) ^= tmp0;
        *(xx0 + diagMtx_g16_w5_seed1_t36[i & 15][2]) ^= tmp0;
        *(xx0 + diagMtx_g16_w5_seed1_t36[i & 15][3]) ^= tmp0;

        *(xx1 + diagMtx_g16_w5_seed1_t36[i & 15][0]) ^= tmp1;
        *(xx1 + diagMtx_g16_w5_seed1_t36[i & 15][1]) ^= tmp1;
        *(xx1 + diagMtx_g16_w5_seed1_t36[i & 15][2]) ^= tmp1;
        *(xx1 + diagMtx_g16_w5_seed1_t36[i & 15][3]) ^= tmp1;

        inout0[offset0] ^= tmp0;
        inout0[offset1] ^= tmp0;

        inout1[offset0] ^= tmp1;
        inout1[offset1] ^= tmp1;

        --offset0;
        --offset1;
        --xx0;
        --xi0;
        --xx1;
        --xi1;
        --i;
      }
      break;
    case 11:
      while (i > lower_bound) {
        auto tmp0 = *xi0;
        auto tmp1 = *xi1;

        *(xx0 + diagMtx_g32_w11_seed2_t36[i & 31][0]) ^= tmp0;
        *(xx0 + diagMtx_g32_w11_seed2_t36[i & 31][1]) ^= tmp0;
        *(xx0 + diagMtx_g32_w11_seed2_t36[i & 31][2]) ^= tmp0;
        *(xx0 + diagMtx_g32_w11_seed2_t36[i & 31][3]) ^= tmp0;
        *(xx0 + diagMtx_g32_w11_seed2_t36[i & 31][4]) ^= tmp0;
        *(xx0 + diagMtx_g32_w11_seed2_t36[i & 31][5]) ^= tmp0;
        *(xx0 + diagMtx_g32_w11_seed2_t36[i & 31][6]) ^= tmp0;
        *(xx0 + diagMtx_g32_w11_seed2_t36[i & 31][7]) ^= tmp0;
        *(xx0 + diagMtx_g32_w11_seed2_t36[i & 31][8]) ^= tmp0;
        *(xx0 + diagMtx_g32_w11_seed2_t36[i & 31][9]) ^= tmp0;

        *(xx1 + diagMtx_g32_w11_seed2_t36[i & 31][0]) ^= tmp1;
        *(xx1 + diagMtx_g32_w11_seed2_t36[i & 31][1]) ^= tmp1;
        *(xx1 + diagMtx_g32_w11_seed2_t36[i & 31][2]) ^= tmp1;
        *(xx1 + diagMtx_g32_w11_seed2_t36[i & 31][3]) ^= tmp1;
        *(xx1 + diagMtx_g32_w11_seed2_t36[i & 31][4]) ^= tmp1;
        *(xx1 + diagMtx_g32_w11_seed2_t36[i & 31][5]) ^= tmp1;
        *(xx1 + diagMtx_g32_w11_seed2_t36[i & 31][6]) ^= tmp1;
        *(xx1 + diagMtx_g32_w11_seed2_t36[i & 31][7]) ^= tmp1;
        *(xx1 + diagMtx_g32_w11_seed2_t36[i & 31][8]) ^= tmp1;
        *(xx1 + diagMtx_g32_w11_seed2_t36[i & 31][9]) ^= tmp1;

        inout0[offset0] ^= tmp0;
        inout0[offset1] ^= tmp0;

        inout1[offset0] ^= tmp1;
        inout1[offset1] ^= tmp1;

        --offset0;
        --offset1;
        --xx0;
        --xi0;

        --xx1;
        --xi1;
        --i;
      }
      break;
    default:
      YACL_THROW("[RightEncode] silver code does not support weight {}",
                 weight_);
  }

  switch (weight_) {
    case 5:
      for (; i != ~static_cast<uint32_t>(0); --i) {
        auto tmp0 = inout0[i];
        auto tmp1 = inout1[i];
        for (int32_t j = 3; j >= 0; --j) {
          uint32_t idx = diagMtx_g16_w5_seed1_t36[i & 15][j] + i - 16;
          if (idx >= n_) {
            break;
          }
          inout0[idx] ^= tmp0;
          inout1[idx] ^= tmp1;
        }
        if (n_ > offset0) {
          inout0[offset0] ^= tmp0;
          inout1[offset0] ^= tmp1;
          --offset0;
        }
        if (n_ > offset1) {
          inout0[offset1] ^= tmp0;
          inout1[offset1] ^= tmp1;
          --offset1;
        }
      }
      break;
    case 11:
      for (; i != ~static_cast<uint32_t>(0); --i) {
        auto tmp0 = inout0[i];
        auto tmp1 = inout1[i];
        for (int32_t j = 9; j >= 0; --j) {
          uint32_t col = diagMtx_g32_w11_seed2_t36[i & 31][j] + i - 32;
          if (col >= n_) {
            break;
          }
          inout0[col] ^= tmp0;
          inout1[col] ^= tmp1;
        }
        if (n_ > offset0) {
          inout0[offset0] ^= tmp0;
          inout1[offset0] ^= tmp1;
          --offset0;
        }
        if (n_ > offset1) {
          inout0[offset1] ^= tmp0;
          inout1[offset1] ^= tmp1;
          --offset1;
        }
      }
      break;
    default:
      YACL_THROW("[RightEncode] silver code does not support weight {}",
                 weight_);
  }
}

}  // namespace yacl::crypto

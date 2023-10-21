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

#include "matrix_utils.h"

#include <array>
#include <cstddef>
#include <string>
#include <type_traits>

#ifdef YACL_ENABLE_BMI2
#include "immintrin.h"
#endif

#include "yacl/base/block.h"

#ifdef __x86_64
#include "cpu_features/cpuinfo_x86.h"
#endif

namespace yacl {

namespace {

#ifdef __x86_64
static const auto kCPUSupportsSSE2 = cpu_features::GetX86Info().features.sse2;
#else
static const auto kCPUSupportsSSE2 = true;
#endif

/**
 * Paper:
 * A Fast Computer Method for Matrix Transposing
 * https://ieeexplore.ieee.org/document/1672177
 */

const std::array<uint128_t, 7> trans_mask = {
    MakeUint128(0x0000000000000000, 0xffffffffffffffff),
    MakeUint128(0x00000000ffffffff, 0x00000000ffffffff),
    MakeUint128(0x0000ffff0000ffff, 0x0000ffff0000ffff),
    MakeUint128(0x00ff00ff00ff00ff, 0x00ff00ff00ff00ff),
    MakeUint128(0x0f0f0f0f0f0f0f0f, 0x0f0f0f0f0f0f0f0f),
    MakeUint128(0x3333333333333333, 0x3333333333333333),
    MakeUint128(0x5555555555555555, 0x5555555555555555)};

const std::array<uint128_t, 7> trans_mask_inv = {
    MakeUint128(0xffffffffffffffff, 0x0000000000000000),
    MakeUint128(0xffffffff00000000, 0xffffffff00000000),
    MakeUint128(0xffff0000ffff0000, 0xffff0000ffff0000),
    MakeUint128(0xff00ff00ff00ff00, 0xff00ff00ff00ff00),
    MakeUint128(0xf0f0f0f0f0f0f0f0, 0xf0f0f0f0f0f0f0f0),
    MakeUint128(0xcccccccccccccccc, 0xcccccccccccccccc),
    MakeUint128(0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa)};
}  // namespace

void EklundhTranspose128(std::array<uint128_t, 128>* inout) {
  const uint32_t logn = 7;

  uint32_t width = 64;
  uint32_t nswaps = 1;

  for (uint32_t i = 0; i < logn; i++) {
    uint128_t mask = trans_mask[i];
    uint128_t inv_mask = trans_mask_inv[i];

    for (uint32_t j = 0; j < nswaps; j++) {
      for (uint32_t k = 0; k < width; k++) {
        uint32_t i1 = k + 2 * width * j;
        uint32_t i2 = k + width + 2 * width * j;
        uint128_t& d = (*inout)[i1];
        uint128_t& dd = (*inout)[i2];

        uint128_t t = d;
        uint128_t tt = dd;

        d = (t & mask) ^ ((tt & mask) << width);
        dd = (tt & inv_mask) ^ ((t & inv_mask) >> width);
      }
    }
    nswaps *= 2;
    width /= 2;
  }
}

/*
 * sse_* function from
 * https://github.com/osu-crypto/libOTe/blob/master/libOTe/Tools/Tools.cpp
 * libOTe License:
 *  This project has been placed in the public domain. As such, you are
 * unrestricted in how you use it, commercial or otherwise.
 */
void sse_loadSubSquare(std::array<block, 128>& in, std::array<block, 2>& out,
                       uint64_t x, uint64_t y) {
  static_assert(sizeof(std::array<std::array<uint8_t, 16>, 2>) ==
                sizeof(std::array<block, 2>));
  static_assert(sizeof(std::array<std::array<uint8_t, 16>, 128>) ==
                sizeof(std::array<block, 128>));

  std::array<std::array<uint8_t, 16>, 2>& outByteView =
      *reinterpret_cast<std::array<std::array<uint8_t, 16>, 2>*>(&out);
  std::array<std::array<uint8_t, 16>, 128>& inByteView =
      *reinterpret_cast<std::array<std::array<uint8_t, 16>, 128>*>(&in);

  for (int l = 0; l < 16; l++) {
    outByteView[0][l] = inByteView[16 * x + l][2 * y];
    outByteView[1][l] = inByteView[16 * x + l][2 * y + 1];
  }
}

// given a 16x16 sub square, place its transpose into uint16_tOutView at
// rows  16*h, ..., 16 *(h+1)  a byte  columns w, w+1.
void sse_transposeSubSquare(std::array<block, 128>& out,
                            std::array<block, 2>& in, uint64_t x, uint64_t y) {
  static_assert(sizeof(std::array<std::array<uint16_t, 8>, 128>) ==
                sizeof(std::array<block, 128>));

  std::array<std::array<uint16_t, 8>, 128>& outU16View =
      *reinterpret_cast<std::array<std::array<uint16_t, 8>, 128>*>(&out);

  for (int j = 0; j < 8; j++) {
    outU16View[16 * x + 7 - j][y] = in[0].movemask_epi8();
    outU16View[16 * x + 15 - j][y] = in[1].movemask_epi8();

    in[0] = (in[0] << 1);
    in[1] = (in[1] << 1);
  }
}

void SseTranspose128(std::array<uint128_t, 128>* inout) {
  std::array<block, 128> mtx;
  std::array<block, 2> a;
  std::array<block, 2> b;

  for (int i = 0; i < 128; i++) {
    mtx[i].mData = reinterpret_cast<__m128i>((*inout)[i]);
  }
  for (int j = 0; j < 8; j++) {
    sse_loadSubSquare(mtx, a, j, j);
    sse_transposeSubSquare(mtx, a, j, j);

    for (int k = 0; k < j; k++) {
      sse_loadSubSquare(mtx, a, k, j);
      sse_loadSubSquare(mtx, b, j, k);
      sse_transposeSubSquare(mtx, a, j, k);
      sse_transposeSubSquare(mtx, b, k, j);
    }
  }
  for (int i = 0; i < 128; i++) {
    (*inout)[i] = reinterpret_cast<uint128_t>(mtx[i].mData);
  }
}

void EklundhTranspose128x1024(std::array<std::array<block, 8>, 128>& inout) {
  for (uint64_t i = 0; i < 8; ++i) {
    std::array<uint128_t, 128> sub;
    for (uint64_t j = 0; j < 128; ++j) {
      sub[j] = reinterpret_cast<uint128_t>(inout[j][i].mData);
    }

    EklundhTranspose128(&sub);

    for (uint64_t j = 0; j < 128; ++j) {
      inout[j][i] = block(sub[j]);
    }
  }
}

void EklundhTranspose128x1024(
    std::array<std::array<uint128_t, 8>, 128>* inout) {
  for (uint64_t i = 0; i < 8; ++i) {
    std::array<uint128_t, 128> sub;
    for (uint64_t j = 0; j < 128; ++j) {
      sub[j] = (*inout)[j][i];
    }

    EklundhTranspose128(&sub);

    for (uint64_t j = 0; j < 128; ++j) {
      (*inout)[j][i] = sub[j];
    }
  }
}

inline void SseLoadSubSquarex(std::array<std::array<block, 8>, 128>& in,
                              std::array<block, 2>& out, uint64_t x, uint64_t y,
                              uint64_t i) {
  using OutT = std::array<std::array<uint8_t, 16>, 2>;
  using InT = std::array<std::array<uint8_t, 128>, 128>;

  static_assert(sizeof(OutT) == sizeof(std::array<block, 2>));
  static_assert(sizeof(InT) == sizeof(std::array<std::array<block, 8>, 128>));

  OutT& out_byte_view = *reinterpret_cast<OutT*>(&out);
  InT& in_byte_view = *reinterpret_cast<InT*>(&in);

  auto x16 = (x * 16);

  auto i16y2 = (i * 16) + 2 * y;
  auto i16y21 = (i * 16) + 2 * y + 1;

  out_byte_view[0][0] = in_byte_view[x16 + 0][i16y2];
  out_byte_view[1][0] = in_byte_view[x16 + 0][i16y21];
  out_byte_view[0][1] = in_byte_view[x16 + 1][i16y2];
  out_byte_view[1][1] = in_byte_view[x16 + 1][i16y21];
  out_byte_view[0][2] = in_byte_view[x16 + 2][i16y2];
  out_byte_view[1][2] = in_byte_view[x16 + 2][i16y21];
  out_byte_view[0][3] = in_byte_view[x16 + 3][i16y2];
  out_byte_view[1][3] = in_byte_view[x16 + 3][i16y21];
  out_byte_view[0][4] = in_byte_view[x16 + 4][i16y2];
  out_byte_view[1][4] = in_byte_view[x16 + 4][i16y21];
  out_byte_view[0][5] = in_byte_view[x16 + 5][i16y2];
  out_byte_view[1][5] = in_byte_view[x16 + 5][i16y21];
  out_byte_view[0][6] = in_byte_view[x16 + 6][i16y2];
  out_byte_view[1][6] = in_byte_view[x16 + 6][i16y21];
  out_byte_view[0][7] = in_byte_view[x16 + 7][i16y2];
  out_byte_view[1][7] = in_byte_view[x16 + 7][i16y21];
  out_byte_view[0][8] = in_byte_view[x16 + 8][i16y2];
  out_byte_view[1][8] = in_byte_view[x16 + 8][i16y21];
  out_byte_view[0][9] = in_byte_view[x16 + 9][i16y2];
  out_byte_view[1][9] = in_byte_view[x16 + 9][i16y21];
  out_byte_view[0][10] = in_byte_view[x16 + 10][i16y2];
  out_byte_view[1][10] = in_byte_view[x16 + 10][i16y21];
  out_byte_view[0][11] = in_byte_view[x16 + 11][i16y2];
  out_byte_view[1][11] = in_byte_view[x16 + 11][i16y21];
  out_byte_view[0][12] = in_byte_view[x16 + 12][i16y2];
  out_byte_view[1][12] = in_byte_view[x16 + 12][i16y21];
  out_byte_view[0][13] = in_byte_view[x16 + 13][i16y2];
  out_byte_view[1][13] = in_byte_view[x16 + 13][i16y21];
  out_byte_view[0][14] = in_byte_view[x16 + 14][i16y2];
  out_byte_view[1][14] = in_byte_view[x16 + 14][i16y21];
  out_byte_view[0][15] = in_byte_view[x16 + 15][i16y2];
  out_byte_view[1][15] = in_byte_view[x16 + 15][i16y21];
}

inline void SseTransposeSubSquarex(std::array<std::array<block, 8>, 128>& out,
                                   std::array<block, 2>& in, uint64_t x,
                                   uint64_t y, uint64_t i) {
  static_assert(sizeof(std::array<std::array<uint16_t, 64>, 128>) ==
                sizeof(std::array<std::array<block, 8>, 128>));

  std::array<std::array<uint16_t, 64>, 128>& out_u16_view =
      *reinterpret_cast<std::array<std::array<uint16_t, 64>, 128>*>(&out);

  auto i8y = i * 8 + y;
  auto x16_7 = x * 16 + 7;
  auto x16_15 = x * 16 + 15;

  block b0 = (in[0] << 0);
  block b1 = (in[0] << 1);
  block b2 = (in[0] << 2);
  block b3 = (in[0] << 3);
  block b4 = (in[0] << 4);
  block b5 = (in[0] << 5);
  block b6 = (in[0] << 6);
  block b7 = (in[0] << 7);

  out_u16_view[x16_7 - 0][i8y] = b0.movemask_epi8();
  out_u16_view[x16_7 - 1][i8y] = b1.movemask_epi8();
  out_u16_view[x16_7 - 2][i8y] = b2.movemask_epi8();
  out_u16_view[x16_7 - 3][i8y] = b3.movemask_epi8();
  out_u16_view[x16_7 - 4][i8y] = b4.movemask_epi8();
  out_u16_view[x16_7 - 5][i8y] = b5.movemask_epi8();
  out_u16_view[x16_7 - 6][i8y] = b6.movemask_epi8();
  out_u16_view[x16_7 - 7][i8y] = b7.movemask_epi8();

  b0 = (in[1] << 0);
  b1 = (in[1] << 1);
  b2 = (in[1] << 2);
  b3 = (in[1] << 3);
  b4 = (in[1] << 4);
  b5 = (in[1] << 5);
  b6 = (in[1] << 6);
  b7 = (in[1] << 7);

  out_u16_view[x16_15 - 0][i8y] = b0.movemask_epi8();
  out_u16_view[x16_15 - 1][i8y] = b1.movemask_epi8();
  out_u16_view[x16_15 - 2][i8y] = b2.movemask_epi8();
  out_u16_view[x16_15 - 3][i8y] = b3.movemask_epi8();
  out_u16_view[x16_15 - 4][i8y] = b4.movemask_epi8();
  out_u16_view[x16_15 - 5][i8y] = b5.movemask_epi8();
  out_u16_view[x16_15 - 6][i8y] = b6.movemask_epi8();
  out_u16_view[x16_15 - 7][i8y] = b7.movemask_epi8();
}

// we have long rows of contiguous data data, 128 columns
void SseTranspose128x1024(std::array<std::array<block, 8>, 128>& inout) {
  std::array<block, 2> a;
  std::array<block, 2> b;

  for (int i = 0; i < 8; ++i) {
    for (int j = 0; j < 8; j++) {
      SseLoadSubSquarex(inout, a, j, j, i);
      SseTransposeSubSquarex(inout, a, j, j, i);

      for (int k = 0; k < j; k++) {
        SseLoadSubSquarex(inout, a, k, j, i);
        SseLoadSubSquarex(inout, b, j, k, i);
        SseTransposeSubSquarex(inout, a, j, k, i);
        SseTransposeSubSquarex(inout, b, k, j, i);
      }
    }
  }
}

void SseTranspose128x1024(std::array<std::array<uint128_t, 8>, 128>* inout) {
  std::array<std::array<block, 8>, 128> matrix_block;
  for (uint64_t i = 0; i < 128; i++) {
    matrix_block[i][0] = block(((*inout)[i][0]));
    matrix_block[i][1] = block(((*inout)[i][1]));
    matrix_block[i][2] = block(((*inout)[i][2]));
    matrix_block[i][3] = block(((*inout)[i][3]));
    matrix_block[i][4] = block(((*inout)[i][4]));
    matrix_block[i][5] = block(((*inout)[i][5]));
    matrix_block[i][6] = block(((*inout)[i][6]));
    matrix_block[i][7] = block(((*inout)[i][7]));
  }

  SseTranspose128x1024(matrix_block);

  for (uint64_t i = 0; i < 128; i++) {
    (*inout)[i][0] = reinterpret_cast<uint128_t>(matrix_block[i][0].mData);
    (*inout)[i][1] = reinterpret_cast<uint128_t>(matrix_block[i][1].mData);
    (*inout)[i][2] = reinterpret_cast<uint128_t>(matrix_block[i][2].mData);
    (*inout)[i][3] = reinterpret_cast<uint128_t>(matrix_block[i][3].mData);
    (*inout)[i][4] = reinterpret_cast<uint128_t>(matrix_block[i][4].mData);
    (*inout)[i][5] = reinterpret_cast<uint128_t>(matrix_block[i][5].mData);
    (*inout)[i][6] = reinterpret_cast<uint128_t>(matrix_block[i][6].mData);
    (*inout)[i][7] = reinterpret_cast<uint128_t>(matrix_block[i][7].mData);
  }
}

void MatrixTranspose128(std::array<uint128_t, 128>* inout) {
#ifdef YACL_ENABLE_BMI2
  return AvxTranspose128(inout);
#endif
  if (kCPUSupportsSSE2) {
    return SseTranspose128(inout);
  }

  return EklundhTranspose128(inout);
}

void MatrixTranspose128x1024(std::array<std::array<block, 8>, 128>& inout) {
  if (kCPUSupportsSSE2) {
    return SseTranspose128x1024(inout);
  }

  return EklundhTranspose128x1024(inout);
}

#ifdef YACL_ENABLE_BMI2
// avx_* function from
// https://github.com/osu-crypto/libOTe/blob/master/libOTe/Tools/Tools.cpp
// libOTe License:
// This project has been placed in the public domain. As such, you are
// unrestricted in how you use it, commercial or otherwise.

//  Templates are used for loop unrolling.
// Base case for the following function.
template <size_t blockSizeShift, size_t blockRowsShift, size_t j = 0>
static inline typename std::enable_if<j == (1 << blockSizeShift)>::type
avx_transpose_block_iter1([[maybe_unused]] __m256i* inOut) {}

// Transpose the order of the 2^blockSizeShift by 2^blockSizeShift blocks (but
// not within each block) within each 2^(blockSizeShift+1) by
// 2^(blockSizeShift+1) matrix in a nRows by 2^7 matrix. Only handles the first
// two rows out of every 2^blockRowsShift rows in each block, starting j *
// 2^blockRowsShift rows into the block. When blockRowsShift == 1 this does the
// transposes within the 2 by 2 blocks as well.
template <size_t blockSizeShift, size_t blockRowsShift, size_t j = 0>
static inline
    typename std::enable_if<(j < (1 << blockSizeShift)) &&
                            (blockSizeShift > 0) && (blockSizeShift < 6) &&
                            (blockRowsShift >= 1)>::type
    avx_transpose_block_iter1(__m256i* inOut) {
  avx_transpose_block_iter1<blockSizeShift, blockRowsShift,
                            j + (1 << blockRowsShift)>(inOut);

  // Mask consisting of alternating 2^blockSizeShift 0s and 2^blockSizeShift 1s.
  // Least significant bit is 0.
  uint64_t mask = ((uint64_t)-1) << 32;
  for (int k = 4; k >= (int)blockSizeShift; --k)
    mask = mask ^ (mask >> (1 << k));

  __m256i& x = inOut[j / 2];
  __m256i& y = inOut[j / 2 + (1 << (blockSizeShift - 1))];

  // Handle the 2x2 blocks as well. Each block is within a single 256-bit
  // vector, so it works differently from the other cases.
  if (blockSizeShift == 1) {
    // transpose 256 bit blocks so that two can be done in parallel.
    __m256i u = _mm256_permute2x128_si256(x, y, 0x20);
    __m256i v = _mm256_permute2x128_si256(x, y, 0x31);

    __m256i diff = _mm256_xor_si256(u, _mm256_slli_epi16(v, 1));
    diff = _mm256_and_si256(diff, _mm256_set1_epi16(0xaaaa));
    u = _mm256_xor_si256(u, diff);
    v = _mm256_xor_si256(v, _mm256_srli_epi16(diff, 1));

    // Transpose again to switch back.
    x = _mm256_permute2x128_si256(u, v, 0x20);
    y = _mm256_permute2x128_si256(u, v, 0x31);
  }

  __m256i diff =
      _mm256_xor_si256(x, _mm256_slli_epi64(y, (uint64_t)1 << blockSizeShift));
  diff = _mm256_and_si256(diff, _mm256_set1_epi64x(mask));
  x = _mm256_xor_si256(x, diff);
  y = _mm256_xor_si256(y,
                       _mm256_srli_epi64(diff, (uint64_t)1 << blockSizeShift));
}

// Special case to use the unpack* instructions.
template <size_t blockSizeShift, size_t blockRowsShift, size_t j = 0>
static inline typename std::enable_if<(j < (1 << blockSizeShift)) &&
                                      (blockSizeShift == 6)>::type
avx_transpose_block_iter1(__m256i* inOut) {
  avx_transpose_block_iter1<blockSizeShift, blockRowsShift,
                            j + (1 << blockRowsShift)>(inOut);

  __m256i& x = inOut[j / 2];
  __m256i& y = inOut[j / 2 + (1 << (blockSizeShift - 1))];
  __m256i outX = _mm256_unpacklo_epi64(x, y);
  __m256i outY = _mm256_unpackhi_epi64(x, y);
  x = outX;
  y = outY;
}

// Base case for the following function.
template <size_t blockSizeShift, size_t blockRowsShift, size_t nRows>
static inline typename std::enable_if<nRows == 0>::type
avx_transpose_block_iter2([[maybe_unused]] __m256i* inOut) {}

// Transpose the order of the 2^blockSizeShift by 2^blockSizeShift blocks (but
// not within each block) within each 2^(blockSizeShift+1) by
// 2^(blockSizeShift+1) matrix in a nRows by 2^7 matrix. Only handles the first
// two rows out of every 2^blockRowsShift rows in each block. When
// blockRowsShift == 1 this does the transposes within the 2 by 2 blocks as
// well.
template <size_t blockSizeShift, size_t blockRowsShift, size_t nRows>
static inline typename std::enable_if<(nRows > 0)>::type
avx_transpose_block_iter2(__m256i* inOut) {
  constexpr size_t matSize = 1 << (blockSizeShift + 1);
  static_assert(nRows % matSize == 0,
                "Can't transpose a fractional number of matrices");

  constexpr size_t i = nRows - matSize;
  avx_transpose_block_iter2<blockSizeShift, blockRowsShift, i>(inOut);
  avx_transpose_block_iter1<blockSizeShift, blockRowsShift>(inOut + i / 2);
}

// Base case for the following function.
template <size_t blockSizeShift, size_t matSizeShift, size_t blockRowsShift,
          size_t matRowsShift>
static inline typename std::enable_if<blockSizeShift == matSizeShift>::type
avx_transpose_block([[maybe_unused]] __m256i* inOut) {}

// Transpose the order of the 2^blockSizeShift by 2^blockSizeShift blocks (but
// not within each block) within each 2^matSizeShift by 2^matSizeShift matrix in
// a 2^(matSizeShift + matRowsShift) by 2^7 matrix. Only handles the first two
// rows out of every 2^blockRowsShift rows in each block. When blockRowsShift ==
// 1 this does the transposes within the 2 by 2 blocks as well.
template <size_t blockSizeShift, size_t matSizeShift, size_t blockRowsShift,
          size_t matRowsShift>
static inline typename std::enable_if<(blockSizeShift < matSizeShift)>::type
avx_transpose_block(__m256i* inOut) {
  avx_transpose_block_iter2<blockSizeShift, blockRowsShift,
                            (1 << (matRowsShift + matSizeShift))>(inOut);
  avx_transpose_block<blockSizeShift + 1, matSizeShift, blockRowsShift,
                      matRowsShift>(inOut);
}

static constexpr size_t avxBlockShift = 4;
static constexpr size_t avxBlockSize = 1 << avxBlockShift;

// Base case for the following function.
template <size_t iter = 7>
static inline typename std::enable_if<iter <= avxBlockShift + 1>::type
avx_transpose(__m256i* inOut) {
  for (size_t i = 0; i < 64; i += avxBlockSize)
    avx_transpose_block<1, iter, 1, avxBlockShift + 1 - iter>(inOut + i);
}

// Algorithm roughly from "Extension of Eklundh's matrix transposition algorithm
// and its application in digital image processing". Transpose each block of
// size 2^iter by 2^iter inside a 2^7 by 2^7 matrix.
template <size_t iter = 7>
static inline typename std::enable_if<(iter > avxBlockShift + 1)>::type
avx_transpose(__m256i* inOut) {
  assert((uint64_t)inOut % 32 == 0);
  avx_transpose<iter - avxBlockShift>(inOut);

  constexpr size_t blockSizeShift = iter - avxBlockShift;
  size_t mask = (1 << (iter - 1)) - (1 << (blockSizeShift - 1));
  if (iter == 7)
    // Simpler (but equivalent) iteration for when iter == 7, which means that
    // it doesn't need to count on both sides of the range of bits specified in
    // mask.
    for (size_t i = 0; i < (1 << (blockSizeShift - 1)); ++i)
      avx_transpose_block<blockSizeShift, iter, blockSizeShift, 0>(inOut + i);
  else
    // Iteration trick adapted from "Hacker's Delight".
    for (size_t i = 0; i < 64; i = (i + mask + 1) & ~mask)
      avx_transpose_block<blockSizeShift, iter, blockSizeShift, 0>(inOut + i);
}

void AvxTranspose128(std::array<uint128_t, 128>* inOut) {
  avx_transpose((__m256i*)inOut);
}

// // input is 128 rows off 8 blocks each.
// void AvxTranspose128x1024(std::array<uint128_t, 128>* inOut) {
//   assert((uint64_t)inOut % 32 == 0);
//   AlignedArray<block, 128 * 8> buff;
//   for (uint64_t i = 0; i < 8; ++i) {
//     // AlignedArray<block, 128> sub;
//     auto sub = &buff[128 * i];
//     for (uint64_t j = 0; j < 128; ++j) {
//       sub[j] = inOut[j * 8 + i];
//     }

//     // for (uint64_t j = 0; j < 128; ++j)
//     //{
//     //     buff[128 * i + j] = inOut[i + j * 8];
//     // }

//     avx_transpose128(&buff[128 * i]);
//   }

//   for (uint64_t i = 0; i < 8; ++i) {
//     // AlignedArray<block, 128> sub;
//     auto sub = &buff[128 * i];
//     for (uint64_t j = 0; j < 128; ++j) {
//       inOut[j * 8 + i] = sub[j];
//     }
//   }
// }
#endif

}  // namespace yacl

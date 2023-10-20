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

#include <string.h>

#include <array>
#include <iostream>
#include <random>

#include "gtest/gtest.h"

#include "yacl/utils/matrix_utils.h"

namespace {
std::array<uint128_t, 128> MakeMatrix128() {
  std::random_device rd;
  std::mt19937 rng(rd());
  std::array<uint128_t, 128> ret;
  for (size_t i = 0; i < 128; ++i) {
    ret[i] = yacl::MakeUint128(rng(), rng());
  }
  return ret;
}

std::array<std::array<uint128_t, 8>, 128> MakeMatrix128x1024() {
  std::random_device rd;
  std::mt19937 rng(rd());
  std::array<std::array<uint128_t, 8>, 128> ret;

  for (size_t i = 0; i < 128; ++i) {
    for (size_t j = 0; j < 8; ++j) {
      ret[i][j] = yacl::MakeUint128(rng(), rng());
    }
  }
  return ret;
}

std::array<std::array<yacl::block, 8>, 128> MakeMatrixBlock128x1024() {
  std::random_device rd;
  std::mt19937 rng(rd());
  std::array<std::array<yacl::block, 8>, 128> ret;
  for (size_t i = 0; i < 128; ++i) {
    for (size_t j = 0; j < 8; ++j) {
      ret[i][j] = yacl::block(rng(), rng());
    }
  }
  return ret;
}
}  // namespace

namespace yacl {

TEST(MatrixTranspose, NaiveTransposeTest) {
  auto matrix = MakeMatrix128();

  std::array<uint128_t, 128> matrixTranspose;
  memcpy(matrixTranspose.data(), matrix.data(),
         matrix.size() * sizeof(uint128_t));

  NaiveTranspose(&matrixTranspose);

  std::array<uint128_t, 128> matrixT2;

  memcpy(matrixT2.data(), matrixTranspose.data(),
         matrixTranspose.size() * sizeof(uint128_t));
  NaiveTranspose(&matrixT2);

  EXPECT_EQ(matrix, matrixT2);
}

TEST(MatrixTranspose, EklundhTransposeTest) {
  auto matrix = MakeMatrix128();

  std::array<uint128_t, 128> matrixTranspose;
  memcpy(matrixTranspose.data(), matrix.data(),
         matrix.size() * sizeof(uint128_t));

  EklundhTranspose128(&matrixTranspose);

  std::array<uint128_t, 128> matrixT2;

  memcpy(matrixT2.data(), matrixTranspose.data(),
         matrixTranspose.size() * sizeof(uint128_t));
  NaiveTranspose(&matrixT2);

  EXPECT_EQ(matrix, matrixT2);
}

TEST(MatrixTranspose, SseTransposeTest) {
  auto matrix = MakeMatrix128();

  std::array<uint128_t, 128> matrixTranspose;
  memcpy(matrixTranspose.data(), matrix.data(),
         matrix.size() * sizeof(uint128_t));

  SseTranspose128(&matrixTranspose);

  std::array<uint128_t, 128> matrixT2;

  memcpy(matrixT2.data(), matrixTranspose.data(),
         matrixTranspose.size() * sizeof(uint128_t));
  NaiveTranspose(&matrixT2);

  EXPECT_EQ(matrix, matrixT2);
}

#ifdef YACL_ENABLE_BMI2
TEST(MatrixTranspose, AvxTransposeTest) {
  auto matrix = MakeMatrix128();

  alignas(32) std::array<uint128_t, 128> matrixTranspose;
  memcpy(matrixTranspose.data(), matrix.data(),
         matrix.size() * sizeof(uint128_t));

  AvxTranspose128(&matrixTranspose);

  std::array<uint128_t, 128> matrixT2;

  memcpy(matrixT2.data(), matrixTranspose.data(),
         matrixTranspose.size() * sizeof(uint128_t));
  NaiveTranspose(&matrixT2);

  EXPECT_EQ(matrix, matrixT2);
}
#endif

TEST(MatrixTranspose, MatrixTransposeTest128x1024) {
  auto matrix = MakeMatrix128x1024();

  std::array<std::array<uint128_t, 8>, 128> matrixTranspose;
  memcpy(matrixTranspose.data(), matrix.data(),
         matrix.size() * 8 * sizeof(uint128_t));

  SseTranspose128x1024(&matrixTranspose);

  std::array<std::array<uint128_t, 8>, 128> matrixT2;

  memcpy(matrixT2.data(), matrix.data(), matrix.size() * 8 * sizeof(uint128_t));
  EklundhTranspose128x1024(&matrixT2);

  EXPECT_EQ(matrixTranspose, matrixT2);
}

TEST(MatrixTranspose, MatrixTransposeBlock128x1024) {
  auto matrix = MakeMatrixBlock128x1024();

  std::array<std::array<block, 8>, 128> matrixTranspose;
  memcpy(matrixTranspose.data(), matrix.data(),
         matrix.size() * 8 * sizeof(uint128_t));

  SseTranspose128x1024(matrixTranspose);

  std::array<std::array<block, 8>, 128> matrixT2;

  memcpy(matrixT2.data(), matrix.data(), matrix.size() * 8 * sizeof(uint128_t));
  EklundhTranspose128x1024(matrixT2);

  EXPECT_EQ(memcmp((const uint8_t *)matrixTranspose.data(),
                   (const uint8_t *)matrixT2.data(),
                   matrix.size() * 8 * sizeof(uint128_t)),
            0);
}

}  // end namespace yacl

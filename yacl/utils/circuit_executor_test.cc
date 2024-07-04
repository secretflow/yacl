
// Copyright 2024 Ant Group Co., Ltd.
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

#include "yacl/utils/circuit_executor.h"

#include <algorithm>

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/crypto/block_cipher/block_cipher.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/io/circuit/bristol_fashion.h"

namespace yacl {

namespace {
inline uint64_t Add64(uint64_t in1, uint64_t in2) { return in1 + in2; }
inline uint64_t Sub64(uint64_t in1, uint64_t in2) { return in1 - in2; }
inline uint64_t Neg64(uint64_t in1) { return -in1; }
inline uint64_t Mul64(uint64_t in1, uint64_t in2) { return in1 * in2; }
inline int64_t Div64(int64_t in1, int64_t in2) { return in1 / in2; }
inline uint64_t UDiv64(uint64_t in1, uint64_t in2) { return in1 / in2; }
inline bool Eqz(uint64_t in) { return in == 0; }

inline uint128_t Aes128(uint128_t k, uint128_t m) {
  crypto::BlockCipher enc(crypto::BlockCipher::Mode::AES128_ECB,
                              k);
  return enc.Encrypt(m);
}

[[maybe_unused]] inline std::string ToBinaryString(uint128_t x) {
  dynamic_bitset<uint128_t> y;
  y.append(x);
  return fmt::format("{}", y.to_string());
}

uint128_t ReverseBytes(uint128_t x) {
  auto byte_view = ByteContainerView(&x, sizeof(x));
  uint128_t ret = 0;
  auto buf = std::vector<uint8_t>(sizeof(ret));
  for (size_t i = 0; i < byte_view.size(); ++i) {
    buf[byte_view.size() - i - 1] = byte_view[i];
  }
  std::memcpy(&ret, buf.data(), buf.size());
  return ret;
}

}  // namespace

TEST(ArithmaticTest, Add64Test) {
  /* GIVEN */
  std::vector<uint64_t> inputs = {crypto::FastRandU64(), crypto::FastRandU64()};
  std::vector<uint64_t> result(1);

  /* WHEN */
  PlainExecutor<uint64_t> exec;
  exec.LoadCircuitFile(io::BuiltinBFCircuit::Add64Path());
  exec.SetupInputs(absl::MakeSpan(inputs));
  exec.Exec();
  exec.Finalize(absl::MakeSpan(result));

  /* THEN */
  EXPECT_EQ(result[0], Add64(inputs[0], inputs[1]));
}

TEST(ArithmaticTest, Sub64Test) {
  /* GIVEN */
  std::vector<uint64_t> inputs = {crypto::FastRandU64(), crypto::FastRandU64()};
  std::vector<uint64_t> result(1);

  /* WHEN */
  PlainExecutor<uint64_t> exec;
  exec.LoadCircuitFile(io::BuiltinBFCircuit::Sub64Path());
  exec.SetupInputs(absl::MakeSpan(inputs));
  exec.Exec();
  exec.Finalize(absl::MakeSpan(result));

  /* THEN */
  EXPECT_EQ(result[0], Sub64(inputs[0], inputs[1]));
}

TEST(ArithmaticTest, Neg64Test) {
  /* GIVEN */
  std::vector<uint64_t> inputs = {crypto::FastRandU64()};
  std::vector<uint64_t> result(1);

  /* WHEN */
  PlainExecutor<uint64_t> exec;
  exec.LoadCircuitFile(io::BuiltinBFCircuit::Neg64Path());
  exec.SetupInputs(absl::MakeSpan(inputs));
  exec.Exec();
  exec.Finalize(absl::MakeSpan(result));

  /* THEN */
  EXPECT_EQ(result[0], Neg64(inputs[0]));
}

TEST(ArithmaticTest, Mul64Test) {
  /* GIVEN */
  std::vector<uint64_t> inputs = {crypto::FastRandU64(), crypto::FastRandU64()};
  std::vector<uint64_t> result(1);

  /* WHEN */
  PlainExecutor<uint64_t> exec;
  exec.LoadCircuitFile(io::BuiltinBFCircuit::Mul64Path());
  exec.SetupInputs(absl::MakeSpan(inputs));
  exec.Exec();
  exec.Finalize(absl::MakeSpan(result));

  /* THEN */
  EXPECT_EQ(result[0], Mul64(inputs[0], inputs[1]));
}

TEST(ArithmaticTest, Div64Test) {
  /* GIVEN */
  std::vector<uint64_t> inputs = {crypto::FastRandU64(), crypto::FastRandU64()};
  std::vector<uint64_t> result(1);

  /* WHEN */
  PlainExecutor<uint64_t> exec;
  exec.LoadCircuitFile(io::BuiltinBFCircuit::Div64Path());
  exec.SetupInputs(absl::MakeSpan(inputs));
  exec.Exec();
  exec.Finalize(absl::MakeSpan(result));

  /* THEN */
  EXPECT_EQ(result[0], Div64(inputs[0], inputs[1]));
}

TEST(ArithmaticTest, UDiv64Test) {
  /* GIVEN */
  std::vector<uint64_t> inputs = {crypto::FastRandU64(), crypto::FastRandU64()};
  std::vector<uint64_t> result(1);

  /* WHEN */

  PlainExecutor<uint64_t> exec;
  exec.LoadCircuitFile(io::BuiltinBFCircuit::UDiv64Path());
  exec.SetupInputs(absl::MakeSpan(inputs));
  exec.Exec();
  exec.Finalize(absl::MakeSpan(result));

  /* THEN */
  EXPECT_EQ(result[0], UDiv64(inputs[0], inputs[1]));
}

TEST(ArithmaticTest, EqzTest) {
  /* GIVEN */
  std::vector<uint64_t> inputs = {crypto::FastRandU64() % 2};
  std::vector<uint64_t> result(1);

  /* WHEN */
  PlainExecutor<uint64_t> exec;
  exec.LoadCircuitFile(io::BuiltinBFCircuit::EqzPath());
  exec.SetupInputs(absl::MakeSpan(inputs));
  exec.Exec();
  exec.Finalize(absl::MakeSpan(result));

  /* THEN */
  EXPECT_EQ(result[0], Eqz(inputs[0]));
}

TEST(CryptoTest, Aes128Test) {
  /* GIVEN */

  // NOTE: For AES-128 the wire orders are in the reverse order as used in
  // the examples given in our earlier `Bristol Format', thus bit 0 becomes
  // bit 127 etc, for key, plaintext and message.
  //
  // see: https://nigelsmart.github.io/MPC-Circuits/
  std::vector<uint128_t> inputs = {crypto::FastRandU128(),
                                   crypto::FastRandU128()};
  std::vector<uint128_t> result(1);

  /* WHEN */
  PlainExecutor<uint128_t> exec;
  exec.LoadCircuitFile(io::BuiltinBFCircuit::Aes128Path());
  exec.SetupInputs(absl::MakeSpan(inputs));
  exec.Exec();
  exec.Finalize(absl::MakeSpan(result));

  /* THEN */
  // NOTE: For AES-128 the wire orders are in the reverse order as used in
  // the examples given in our earlier `Bristol Format', thus bit 0 becomes
  // bit 127 etc, for key, plaintext and message.
  //
  // see: https://nigelsmart.github.io/MPC-Circuits/
  //
  // NOTE: it simply means every byte is reversed, not every bit.
  auto compare = Aes128(ReverseBytes(inputs[0]), ReverseBytes(inputs[1]));
  // SPDLOG_INFO(ToBinaryString(ReverseBytes(result[0])));
  // SPDLOG_INFO(ToBinaryString(compare));
  EXPECT_EQ(ReverseBytes(result[0]), compare);
}

}  // namespace yacl

#include "kdf.h"

#include <iostream>

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

namespace yacl::crypto::test {

class KDFTest : public testing::Test {};

TEST_F(KDFTest, Test1) {
  std::vector<uint8_t> key = KDF("key_str", 16);
  std::string key_str = absl::BytesToHexString(
      absl::string_view((const char*)key.data(), key.size()));

  EXPECT_EQ(key_str, "93a42c6b4c02ab6956f0095787c67e5e");
}
}  // namespace yacl::crypto::test
#include "yacl/crypto/primitives/tpre/hash.h"

#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/base/mpint/mp_int.h"  //yacl big number

namespace yacl::crypto::test {
class HashTest : public testing::Test {};

TEST_F(HashTest, Test1) {
  MPInt zero(0);
  auto hash_value = CipherHash("tpre", "sm2");

  std::cout << "hash_value = " << hash_value.ToHexString() << std::endl;
  EXPECT_TRUE(hash_value > zero);
  EXPECT_EQ(hash_value.ToHexString(),
            "B465B279C1693E0C34810B93F8A5095B93F912E3B4DD13265E5157F5B2A25895");
}

}  // namespace yacl::crypto::test
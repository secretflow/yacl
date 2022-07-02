#include "yasl/utils/scope_guard.h"

#include "gtest/gtest.h"

namespace yasl {

TEST(ScopeGuardTest, TestOnScopeExitMacroSupportComma) {
  // GIVEN
  int a = 100;
  int b = 200;
  int c = 0;
  {
    ON_SCOPE_EXIT([a, b, &c] { c = a + b; });
  }
  // THEN
  EXPECT_EQ(c, a + b);
}

}  // namespace yasl

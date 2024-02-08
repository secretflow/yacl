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

#include "yacl/base/exception.h"

#include "absl/strings/match.h"
#include "gtest/gtest.h"

namespace yacl {
namespace {

void CheckExceptionContains(const std::exception& e,
                            const std::string& expected) {
  EXPECT_TRUE(absl::StrContains(e.what(), expected));
}

}  // namespace

TEST(Exception, StackTrace) {
  try {
    EXPECT_FALSE(GetStacktraceString().empty());
    YACL_THROW("test");
  } catch (const Exception& e) {
    // e.g.
    // #0 yacl::Exception_StackTrace_Test::TestBody()+0x40c6b4
    // #1 testing::internal::HandleSehExceptionsInMethodIfSupported<>()+0x48ad4d
    // #2 testing::internal::HandleExceptionsInMethodIfSupported<>()+0x485afa
    // #3 testing::Test::Run()+0x46ff0e
    // #4 testing::TestInfo::Run()+0x470787
    // #5 testing::TestSuite::Run()+0x470e49
    // #6 testing::internal::UnitTestImpl::RunAllTests()+0x47b468
    // #7 testing::internal::HandleSehExceptionsInMethodIfSupported<>()+0x48bb59
    // #8 testing::internal::HandleExceptionsInMethodIfSupported<>()+0x486b00
    // #9 testing::UnitTest::Run()+0x479fb2
    // #10 RUN_ALL_TESTS()+0x468023
    // #11 main+0x467fb1
    // #12 __libc_start_main+0x7f32c99c1192
    //
    std::cout << e.stack_trace() << std::endl;
    ASSERT_FALSE(e.stack_trace().empty());
  }
}

TEST(Exception, Fmt) {
  try {
    YACL_THROW("hello {}", "yacl");
  } catch (const std::exception& e) {
    CheckExceptionContains(e, "hello yacl");
  }
}

TEST(Exception, FmtInThrow) {
  try {
    YACL_THROW(fmt::format("hello {}", "yacl"));
  } catch (const std::exception& e) {
    CheckExceptionContains(e, "hello yacl");
  }
}

TEST(Exception, Enforce) {
  ASSERT_THROW(YACL_ENFORCE(false), EnforceNotMet);
  ASSERT_NO_THROW(YACL_ENFORCE(true));
}

TEST(Exception, EnforceStackTrace) {
  try {
    YACL_ENFORCE(false);
  } catch (const Exception& e) {
    std::cout << e.stack_trace() << std::endl;
    ASSERT_FALSE(e.stack_trace().empty());
  }
}

TEST(Exception, EnforceFmt) {
  try {
    YACL_ENFORCE(false, "enforce {}", "yacl");
  } catch (const std::exception& e) {
    CheckExceptionContains(e, "enforce yacl");
  }
}

TEST(Exception, EnforceThat) {
  ASSERT_THROW(YACL_ENFORCE_EQ(0, 1), EnforceNotMet);
  ASSERT_NO_THROW(YACL_ENFORCE_EQ(1, 1));
}

TEST(Exception, EnforceThatFmt) {
  try {
    YACL_ENFORCE_EQ(0, 1, "enforce {}", "yacl");
  } catch (const std::exception& e) {
    CheckExceptionContains(e, "enforce yacl");
  }
}

TEST(Exception, Compares) {
  ASSERT_THROW(YACL_ENFORCE_EQ(0, 1), EnforceNotMet);
  ASSERT_NO_THROW(YACL_ENFORCE_EQ(1, 1));

  ASSERT_THROW(YACL_ENFORCE_LE(1, 0), EnforceNotMet);
  ASSERT_NO_THROW(YACL_ENFORCE_LE(0, 1));
  ASSERT_NO_THROW(YACL_ENFORCE_LE(1, 1));

  ASSERT_THROW(YACL_ENFORCE_GE(0, 1), EnforceNotMet);
  ASSERT_NO_THROW(YACL_ENFORCE_GE(1, 0));
  ASSERT_NO_THROW(YACL_ENFORCE_GE(1, 1));

  ASSERT_THROW(YACL_ENFORCE_LT(1, 0), EnforceNotMet);
  ASSERT_NO_THROW(YACL_ENFORCE_LT(0, 1));

  ASSERT_THROW(YACL_ENFORCE_GT(0, 1), EnforceNotMet);
  ASSERT_NO_THROW(YACL_ENFORCE_GT(1, 0));
}

}  // namespace yacl

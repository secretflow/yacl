// Copyright 2023 Ant Group Co., Ltd.
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

#include "yacl/secparam.h"

#include "gtest/gtest.h"

// inheader
YACL_MODULE_DECLARE("iknp_ote", SecParam::C::k128, SecParam::S::k40);
YACL_MODULE_DECLARE("aes", SecParam::C::k128, SecParam::S::INF);
YACL_MODULE_DECLARE("hash", SecParam::C::k192, SecParam::S::INF);

namespace yacl::crypto {

TEST(DeclareTest, Test) {
  EXPECT_EQ(YACL_MODULE_SECPARAM_C("iknp_ote"), SecParam::C::k128);
  EXPECT_EQ(YACL_MODULE_SECPARAM_S("iknp_ote"), SecParam::S::k40);
  EXPECT_EQ(YACL_MODULE_SECPARAM_C("aes"), SecParam::C::k128);
  EXPECT_EQ(YACL_MODULE_SECPARAM_C("hash"), SecParam::C::k192);

  YACL_ENFORCE_SECPARAM(SecParam::C::k128, SecParam::S::k40);  // same
  YACL_ENFORCE_SECPARAM(SecParam::C::k112, SecParam::S::k40);  // pass
  YACL_ENFORCE_SECPARAM(SecParam::C::k128, SecParam::S::k30);  // pass
  YACL_ENFORCE_SECPARAM(SecParam::C::k112, SecParam::S::k30);  // pass

  // YACL_ENFORCE_SECPARAM(SecParam::C::INF, SecParam::S::INF);  // fail

  YACL_PRINT_MODULE_SUMMARY();
}

}  // namespace yacl::crypto

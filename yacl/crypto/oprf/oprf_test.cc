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

#include "yacl/crypto/oprf/oprf.h"

#include "absl/strings/escaping.h"
#include "gtest/gtest.h"

namespace yacl::crypto {

TEST(SimpleTest, Works) {
  // get a default config
  const auto config = OprfConfig::GetDefault();

  auto server = OprfServer(config);
  auto client = OprfClient(config);

  const std::string input = "test_element";

  EcPoint c2s_tape;
  client.Blind(input, &c2s_tape);

  EcPoint s2c_tape;
  server.BlindEvaluate(c2s_tape, &s2c_tape);

  client.Finalize(s2c_tape);
}

}  // namespace yacl::crypto

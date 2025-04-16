// Copyright 2025 Guan Yewei
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "yacl/crypto/ecc/hash_to_curve/hash_to_curve.h"

#include "gtest/gtest.h"
#include "yacl/crypto/ecc/hash_to_curve/curve25519.h"

namespace yacl::crypto::test {

TEST(HashToCurveTest, P256EncodeToCurveWorks) {
  std::vector<std::string> rfc_9380_test_msgs = {"", "abc", "abcdef0123456789"};

  std::vector<std::string> rfc_9380_test_px = {
      "F871CAAD25EA3B59C16CF87C1894902F7E7B2C822C3D3F73596C5ACE8DDD14D1",
      "FC3F5D734E8DCE41DDAC49F47DD2B8A57257522A865C124ED02B92B5237BEFA4",
      "F164C6674A02207E414C257CE759D35EDDC7F55BE6D7F415E2CC177E5D8FAA84"};

  std::vector<std::string> rfc_9380_test_py = {
      "87B9AE23335BEE057B99BAC1E68588B18B5691AF476234B8971BC4F011DDC99B",
      "FE4D197ECF5A62645B9690599E1D80E82C500B22AC705A0B421FAC7B47157866",
      "3AA274881D30DB70485368C0467E97DA0E73C18C1D00F34775D012B6FCEE7F97"};

  char kRFC9380P256NuDst[] = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_NU_";

  for (size_t i = 0; i < rfc_9380_test_msgs.size(); ++i) {
    EcPoint px = EncodeToCurveP256(rfc_9380_test_msgs[i], kRFC9380P256NuDst);
    auto p = std::get<AffinePoint>(px);
    EXPECT_EQ(p.x.ToHexString(), rfc_9380_test_px[i]);
    EXPECT_EQ(p.y.ToHexString(), rfc_9380_test_py[i]);
  }
}

TEST(HashToCurveTest, P384EncodeToCurveWorks) {
  std::vector<std::string> rfc_9380_test_msgs = {"", "abc", "abcdef0123456789"};

  std::vector<std::string> rfc_9380_test_px = {
      "DE5A893C83061B2D7CE6A0D8B049F0326F2ADA4B966DC7E72927256B033EF61058029A3B"
      "FB13C1C7ECECD6641881AE20",
      "1F08108B87E703C86C872AB3EB198A19F2B708237AC4BE53D7929FB4BD5194583F40D052"
      "F32DF66AFE5249C9915D139B",
      "4DAC31EC8A82EE3C02BA2D7C9FA431F1E59FFE65BF977B948C59E1D813C2D7963C7BE81A"
      "A6DB39E78FF315A10115C0D0"};

  std::vector<std::string> rfc_9380_test_py = {
      "63F46DA6139785674DA315C1947E06E9A0867F5608CF24724EB3793A1F5B3809EE28EB21"
      "A0C64BE3BE169AFC6CDB38CA",
      "1369DC8D5BF038032336B989994874A2270ADADB67A7FCC32F0F8824BC5118613F0AC8DE"
      "04A1041D90FF8A5AD555F96C",
      "845333CDB5702AD5C525E603F302904D6FC84879F0EF2EE2014A6B13EDD39131BFD66F7B"
      "D7CDC2D9CCF778F0C8892C3F"};

  char kRFC9380P384NuDst[] = "QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_NU_";

  for (size_t i = 0; i < rfc_9380_test_msgs.size(); ++i) {
    EcPoint px = EncodeToCurveP384(rfc_9380_test_msgs[i], kRFC9380P384NuDst);
    auto p = std::get<AffinePoint>(px);
    EXPECT_EQ(p.x.ToHexString(), rfc_9380_test_px[i]);
    EXPECT_EQ(p.y.ToHexString(), rfc_9380_test_py[i]);
  }
}

TEST(HashToCurveTest, P521EncodeToCurveWorks) {
  std::vector<std::string> rfc_9380_test_msgs = {"", "abc", "abcdef0123456789"};

  // ToHexString ignore the leading 0s
  // we also ignore the leading 0s in testdata for test
  std::vector<std::string> rfc_9380_test_px = {
      "1EC604B4E1E3E4C7449B7A41E366E876655538ACF51FD40D08B97BE066F7D020634E906B"
      "1B6942F9174B417027C953D75FB6EC64B8CEE2A3672D4F1987D13974705",
      "C720AB56AA5A7A4C07A7732A0A4E1B909E32D063AE1B58DB5F0EB5E09F08A9884BFF55A2"
      "BEF4668F715788E692C18C1915CD034A6B998311FCF46924CE66A2BE9A",
      "BCAF32A968FF7971B3BBD9CE8EDFBEE1309E2019D7FF373C38387A782B005DCE6CEFFCCF"
      "EDA5C6511C8F7F312F343F3A891029C5858F45EE0BF370ABA25FC990CC"};

  std::vector<std::string> rfc_9380_test_py = {
      "944FC439B4AAD2463E5C9CFA0B0707AF3C9A42E37C5A57BB4ECD12FEF9FB21508568AEDC"
      "DD8D2490472DF4BBAFD79081C81E99F4DA3286EDDF19BE47E9C4CF0E91",
      "3570E87F91A4F3C7A56BE2CB2A078FFC153862A53D5E03E5DAD5BCCC6C529B8BAB0B7DBB"
      "157499E1949E4EDAB21CF5D10B782BC1E945E13D7421AD8121DBC72B1D",
      "923517E767532D82CB8A0B59705EEC2B7779CE05F9181C7D5D5E25694EF8EBD4696343F0"
      "BC27006834D2517215ECF79482A84111F50C1BAE25044FE1DD77744BBD"};

  char kRFC9380P521NuDst[] = "QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_NU_";

  for (size_t i = 0; i < rfc_9380_test_msgs.size(); ++i) {
    EcPoint px = EncodeToCurveP521(rfc_9380_test_msgs[i], kRFC9380P521NuDst);
    auto p = std::get<AffinePoint>(px);
    EXPECT_EQ(p.x.ToHexString(), rfc_9380_test_px[i]);
    EXPECT_EQ(p.y.ToHexString(), rfc_9380_test_py[i]);
  }
}

TEST(HashToCurveTest, Curve25519EncodeToCurveWorks) {
  std::vector<std::string> rfc_9380_test_msgs = {"", "abc", "abcdef0123456789"};

  std::vector<std::string> rfc_9380_test_px = {
      "1BB913F0C9DAEFA0B3375378FFA534BDA5526C97391952A7789EB976EDFE4D08",
      "7C22950B7D900FA866334262FCAEA47A441A578DF43B894B4625C9B450F9A026",
      "31AD08A8B0DEEB2A4D8B0206CA25F567AB4E042746F792F4B7973F3AE2096C52"};

  std::vector<std::string> rfc_9380_test_py = {
      "4548368F4F983243E747B62A600840AE7C1DAB5C723991F85D3A9768479F3EC4",
      "5547BC00E4C09685DCBC6CB6765288B386D8BDCB595FA5A6E3969E08097F0541",
      "405070C28E78B4FA269427C82827261991B9718BD6C6E95D627D701A53C30DB1"};

  char kRFC9380Curve25519NuDst[] = "QUUX-V01-CS02-with-curve25519_XMD:SHA-512_ELL2_NU_";

  for (size_t i = 0; i < rfc_9380_test_msgs.size(); ++i) {
    EcPoint px = EncodeToCurveCurve25519(rfc_9380_test_msgs[i], kRFC9380Curve25519NuDst);
    auto p = std::get<AffinePoint>(px);
    EXPECT_EQ(p.x.ToHexString(), rfc_9380_test_px[i]);
    EXPECT_EQ(p.y.ToHexString(), rfc_9380_test_py[i]);
  }
}

TEST(HashToCurveTest, Curve25519HashToCurveWorks) {
  std::vector<std::string> rfc_9380_test_msgs = {"", "abc", "abcdef0123456789"};

  std::vector<std::string> rfc_9380_test_px = {
      "2DE3780ABB67E861289F5749D16D3E217FFA722192D16BBD9D1BFB9D112B98C0",
      "2B4419F1F2D48F5872DE692B0ACA72CC7B0A60915DD70BDE432E826B6ABC526D",
      "68CA1EA5A6ACF4E9956DAA101709B1EEE6C1BB0DF1DE3B90D4602382A104C036"};

  std::vector<std::string> rfc_9380_test_py = {
      "3B5DC2A498941A1033D176567D457845637554A2FE7A3507D21ABD1C1BD6E878",
      "1B8235F255A268F0A6FA8763E97EB3D22D149343D495DA1160EFF9703F2D07DD",
      "2A375B656207123D10766E68B938B1812A4A6625FF83CB8D5E86F58A4BE08353"};

  char kRFC9380Curve25519RoDst[] = "QUUX-V01-CS02-with-curve25519_XMD:SHA-512_ELL2_RO_";

  for (size_t i = 0; i < rfc_9380_test_msgs.size(); ++i) {
    EcPoint px = HashToCurveCurve25519(rfc_9380_test_msgs[i], kRFC9380Curve25519RoDst);
    auto p = std::get<AffinePoint>(px);
    EXPECT_EQ(p.x.ToHexString(), rfc_9380_test_px[i]);
    EXPECT_EQ(p.y.ToHexString(), rfc_9380_test_py[i]);
  }
}
}  // namespace yacl::crypto::test

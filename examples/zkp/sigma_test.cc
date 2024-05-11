// Copyright 2023 Ant Group Co., Ltd.
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

#include "examples/zkp/sigma.h"

#include "gtest/gtest.h"

#include "yacl/crypto/rand/rand.h"

namespace examples::zkp {

namespace {

Witness GenRandomWitness(const std::shared_ptr<EcGroup>& group, uint32_t num) {
  Witness ret;
  auto order = group->GetOrder();  // [0,group order-1] as witness space
  for (size_t i = 0; i < num; i++) {
    MPInt temp;
    MPInt::RandomLtN(order, &temp);
    YACL_ENFORCE(temp < order);
    ret.emplace_back(temp);
  }
  return ret;
}
}  // namespace

class SigmaTest
    : public ::testing::TestWithParam<std::tuple<std::string, SigmaConfig>> {
 protected:
  SigmaConfig config_;
  std::shared_ptr<EcGroup> group_;

  void TestSigmaOWH() {
    Witness witness = GenRandomWitness(group_, config_.num_witness);
    Witness witness2 = GenRandomWitness(group_, config_.num_witness);

    // Using default seeds
    auto generators = SigmaOWH::MakeGenerators(config_, group_);
    auto stm = SigmaOWH::ToStatement(config_, group_, generators, witness);
    auto stm2 = SigmaOWH::ToStatement(config_, group_, generators, witness2);

    EXPECT_TRUE(stm.size() == config_.num_statement);
    EXPECT_TRUE(stm2.size() == config_.num_statement);
    for (uint32_t i = 0; i < config_.num_statement; i++) {
      EXPECT_FALSE(group_->PointEqual(stm[i], stm2[i]));
    }
  }

  void TestSigmaInstance() {
    {
      SigmaProtocol sigma(config_, group_);

      SigmaProtocol sigma_from_ser(config_, group_,
                                   sigma.GeneratorsSerialize());

      auto msg_gens = sigma.GetGenerators();
      auto msg_gens_from_ser = sigma_from_ser.GetGenerators();
      for (uint64_t i = 0; i < config_.num_generator; i++) {
        EXPECT_TRUE(group_->PointEqual(msg_gens[i], msg_gens_from_ser[i]));
      }
    }
    {
      // length of seeds should be > config_.num_generator
      SigmaProtocol sigma(config_, group_, 12345);
      SigmaProtocol sigma_from_ser(config_, group_,
                                   sigma.GeneratorsSerialize());
      auto msg_gens = sigma.GetGenerators();
      auto msg_gens_from_ser = sigma_from_ser.GetGenerators();
      for (uint64_t i = 0; i < config_.num_generator; i++) {
        EXPECT_TRUE(group_->PointEqual(msg_gens[i], msg_gens_from_ser[i]));
      }
    }
  }

  void TestSigma() {
    SigmaProtocol sigma(config_, group_);
    // displayed as true witness
    auto witness = sigma.GenRandomWitness();
    // displayed as random witness for one-time proof
    auto rnd_witness = sigma.GenRandomWitness();
    auto stm = sigma.ToStatement(witness);

    // start 3-round Interactive proof knowledge of stm
    auto rnd_stm = sigma.RandStm(rnd_witness);
    auto challenge = sigma.GenChallenge();
    auto proof = sigma.Prove(witness, rnd_witness, challenge);
    EXPECT_TRUE(sigma.Verify(stm, rnd_stm, challenge, proof));

    // Non-interactive without other info
    {
      // start Non-interactive(Batchable version) proof knowledge of stm
      auto bat_proof = sigma.ProveBatchable(stm, witness, rnd_witness);
      EXPECT_TRUE(sigma.VerifyBatchable(stm, bat_proof));

      // start Non-interactive(Compact version) proof knowledge of stm
      auto com_proof = sigma.ProveCompact(stm, witness, rnd_witness);
      EXPECT_TRUE(sigma.VerifyCompact(stm, com_proof));
    }
    // Non-interactive with other info
    {
      std::string other_info = "123test";
      // start Non-interactive(Batchable version) proof knowledge of stm
      auto bat_proof =
          sigma.ProveBatchable(stm, witness, rnd_witness, other_info);
      EXPECT_TRUE(sigma.VerifyBatchable(stm, bat_proof, other_info));

      // start Non-interactive(Compact version) proof knowledge of stm
      auto com_proof =
          sigma.ProveCompact(stm, witness, rnd_witness, other_info);
      EXPECT_TRUE(sigma.VerifyCompact(stm, com_proof, other_info));
    }
  }
};

class Secp256k1SigmaTest : public SigmaTest {
 protected:
  void SetUp() override {
    std::string lib_name;
    std::tie(lib_name, config_) = GetParam();
    group_ = EcGroupFactory::Instance().Create(kSigmaEcName,
                                               yacl::ArgLib = lib_name);
  }
};

INSTANTIATE_TEST_SUITE_P(
    Secp256k1SigmaOWHTest, Secp256k1SigmaTest,
    ::testing::Combine(
        // ::testing::ValuesIn(EcGroupFactory::ListEcLibraries(kSigmaEcName))
        ::testing::Values("openssl"),
        ::testing::Values(
            GetSigmaConfig(SigmaType::Dlog),
            GetSigmaConfig(SigmaType::Pedersen),
            GetSigmaConfig(SigmaType::DlogEq),
            GetSigmaConfig(SigmaType::DHTripple),
            GetSigmaConfig(SigmaType::SeveralDlog).SetDynNum(11),
            GetSigmaConfig(SigmaType::SeveralDlogEq).SetDynNum(11),
            GetSigmaConfig(SigmaType::Representation).SetDynNum(11))));

TEST_P(Secp256k1SigmaTest, SigmaOWH) {
  TestSigmaOWH();
  TestSigma();
}

}  // namespace examples::zkp

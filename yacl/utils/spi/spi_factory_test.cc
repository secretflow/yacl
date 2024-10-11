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

#include "yacl/utils/spi/spi_factory.h"

#include <string>
#include <utility>

#include "gtest/gtest.h"

namespace yacl::test {

// Defile SPI type

class MockPheSpi {
 public:
  virtual std::string ToString() = 0;
  virtual ~MockPheSpi() = default;
};

DEFINE_ARG_int(KeySize);

// Define sub factory

class MockPheSpiFactory final : public SpiFactoryBase<MockPheSpi> {
 public:
  static MockPheSpiFactory &Instance() {
    static MockPheSpiFactory factory;
    return factory;
  }
};

#define REGISTER_MOCK_LIBRARY(lib_name, performance, checker, creator)  \
  REGISTER_SPI_LIBRARY_HELPER(MockPheSpiFactory, lib_name, performance, \
                              checker, creator)

// Implement 1: Add a lib for SPI

class MockPaillierLib : public MockPheSpi {
 public:
  explicit MockPaillierLib(int32_t key_size) : key_size_(key_size) {}

  static std::unique_ptr<MockPheSpi> Create(const std::string &phe_name,
                                            const SpiArgs &args) {
    fmt::println("Create MockPaillierLib with args {}", args);

    YACL_ENFORCE(phe_name == "paillier");
    return std::make_unique<MockPaillierLib>(
        args.GetOrDefault(ArgKeySize, 2048));
  }

  static bool Check(const std::string &phe_name, const SpiArgs &args) {
    return phe_name == "paillier" &&
           args.GetOrDefault(ArgKeySize, 2048) <= 4096;
  }

  std::string ToString() override {
    return fmt::format("mock_paillier_lib: key_size={}", key_size_);
  }

 private:
  int32_t key_size_;
};

REGISTER_MOCK_LIBRARY("mock_paillier_lib", 10, MockPaillierLib::Check,
                      MockPaillierLib::Create);

// Implement 2: Another lib

SpiArgKey<std::string> Curve("curve");

class MockQuantumLib : public MockPheSpi {
 public:
  explicit MockQuantumLib(std::string curve) : curve_(std::move(curve)) {}

  static std::unique_ptr<MockPheSpi> Create(const std::string &phe_name,
                                            const SpiArgs &args) {
    YACL_ENFORCE(phe_name == "elgamal");
    return std::make_unique<MockQuantumLib>(
        args.GetOrDefault(Curve, "ed25519"));
  }

  static bool Check(const std::string &phe_name, const SpiArgs &args) {
    return phe_name == "elgamal" &&
           args.GetOrDefault(Curve, "ed25519") == "ed25519";
  }

  std::string ToString() override {
    return fmt::format("mock_quantum_lib: curve={}", curve_);
  }

 private:
  std::string curve_;
};

REGISTER_MOCK_LIBRARY("mock_quantum_lib", 20, MockQuantumLib::Check,
                      MockQuantumLib::Create);

// DO TEST

TEST(SpiFactoryTest, TestArg) {
  ASSERT_EQ((ArgLib = "ABC").Value<std::string>(), "abc");
  ASSERT_EQ((ArgKeySize = 100).Value<int>(), 100);
}

TEST(SpiFactoryTest, TestListLibs) {
  auto libs = MockPheSpiFactory::Instance().ListLibraries();
  ASSERT_EQ(libs.size(), 2);
  ASSERT_TRUE(libs[0] == "mock_paillier_lib" || libs[0] == "mock_quantum_lib");
  ASSERT_TRUE(libs[0] == "mock_paillier_lib" || libs[0] == "mock_quantum_lib");

  libs = MockPheSpiFactory::Instance().ListLibraries("paillier");
  ASSERT_EQ(libs.size(), 1);
  ASSERT_TRUE(libs[0] == "mock_paillier_lib");

  libs = MockPheSpiFactory::Instance().ListLibraries(
      "paillier", ArgLib = "mock_paillier_lib", ArgKeySize = 2048);
  ASSERT_EQ(libs.size(), 1);
  ASSERT_TRUE(libs[0] == "mock_paillier_lib");

  libs = MockPheSpiFactory::Instance().ListLibraries("paillier",
                                                     ArgKeySize = 100000);
  ASSERT_EQ(libs.size(), 0);

  libs = MockPheSpiFactory::Instance().ListLibraries("paillier",
                                                     ArgLib = "no-lib");
  ASSERT_EQ(libs.size(), 0);

  libs =
      MockPheSpiFactory::Instance().ListLibraries("elgamal", Curve = "ed25519");
  ASSERT_EQ(libs.size(), 1);
  ASSERT_TRUE(libs[0] == "mock_quantum_lib");

  libs = MockPheSpiFactory::Instance().ListLibraries("not_exist");
  ASSERT_EQ(libs.size(), 0);
}

TEST(SpiFactoryTest, TestCreate) {
  auto lib = MockPheSpiFactory::Instance().Create("paillier");
  ASSERT_EQ(lib->ToString(), "mock_paillier_lib: key_size=2048");

  lib = MockPheSpiFactory::Instance().Create("paillier",
                                             ArgLib = "mock_paillier_lib");
  ASSERT_EQ(lib->ToString(), "mock_paillier_lib: key_size=2048");

  lib = MockPheSpiFactory::Instance().Create("paillier", ArgKeySize = 3000ULL);
  ASSERT_EQ(lib->ToString(), "mock_paillier_lib: key_size=3000");

  // mock_quantum_lib does not support paillier
  EXPECT_ANY_THROW(lib = MockPheSpiFactory::Instance().Create(
                       "paillier", ArgLib = "mock_quantum_lib"));
}

}  // namespace yacl::test

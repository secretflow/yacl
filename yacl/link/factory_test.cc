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

#include "yacl/link/factory.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <future>
#include <limits>
#include <unordered_map>

#include "fmt/format.h"
#include "gtest/gtest.h"

#include "yacl/crypto/key_utils.h"
#include "yacl/link/context.h"
#include "yacl/link/link.h"

namespace yacl::link::test {

template <typename T, size_t MODE>
struct TestTypes {
  static size_t get_mode() { return MODE; }
  static T get_t_instance() { return T(); }
};

enum class SslMode {
  NONE,        // mode = 0
  RSA_SHA256,  // mode = 1
  SM2_SM3,     // mode = 2
};

inline int PickUnusedPort() {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    YACL_THROW("socket() failed: {}", std::strerror(errno));
  }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(0);

  if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    int err = errno;
    ::close(fd);
    YACL_THROW("bind() failed: {}", std::strerror(err));
  }

  socklen_t len = sizeof(addr);
  if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
    int err = errno;
    ::close(fd);
    YACL_THROW("getsockname() failed: {}", std::strerror(err));
  }

  int port = ntohs(addr.sin_port);
  ::close(fd);
  return port;
}

inline std::pair<std::string, std::string> GenCertFiles(
    const std::string& prefix, const SslMode mode) {
  auto pk_path = fmt::format("{}_pk.pem", prefix);
  auto sk_path = fmt::format("{}_sk.pem", prefix);
  auto cert_path = fmt::format("{}.cer", prefix);

  if (mode == SslMode::RSA_SHA256) {
    auto key_pair = crypto::GenRsaKeyPair();
    crypto::ExportPublicKeyToPemFile(key_pair, pk_path);
    crypto::ExportSecretKeyToPemBuf(key_pair, sk_path);
    auto cert = crypto::MakeX509Cert(crypto::LoadKeyFromFile(pk_path),
                                     crypto::LoadKeyFromFile(sk_path),
                                     {
                                         {"C", "CN"},
                                         {"ST", "ZJ"},
                                         {"L", "HZ"},
                                         {"O", "TEE"},
                                         {"OU", "EGG"},
                                         {"CN", "demo.trustedegg.com"},
                                     },
                                     3, crypto::HashAlgorithm::SHA256);
    crypto::ExportX509CertToFile(cert, cert_path);
  } else if (mode == SslMode::SM2_SM3) {
    auto key_pair = crypto::GenSm2KeyPair();
    crypto::ExportPublicKeyToPemFile(key_pair, pk_path);
    crypto::ExportSecretKeyToPemBuf(key_pair, sk_path);
    auto cert = crypto::MakeX509Cert(crypto::LoadKeyFromFile(pk_path),
                                     crypto::LoadKeyFromFile(sk_path),
                                     {
                                         {"C", "CN"},
                                         {"ST", "ZJ"},
                                         {"L", "HZ"},
                                         {"O", "TEE"},
                                         {"OU", "EGG"},
                                         {"CN", "demo.trustedegg.com"},
                                     },
                                     3, crypto::HashAlgorithm::SM3);
    crypto::ExportX509CertToFile(cert, cert_path);
  } else {
    YACL_THROW("Unknown SSL mode.");
  }

  return {sk_path, cert_path};
}

inline ContextDesc MakeDesc(int count, const SslMode mode) {
  ContextDesc desc;
  desc.id = fmt::format("world_{}", count);
  int alice_port = PickUnusedPort();
  int bob_port = PickUnusedPort();
  while (bob_port == alice_port) {
    bob_port = PickUnusedPort();
  }

  desc.parties.push_back(
      ContextDesc::Party("alice", fmt::format("127.0.0.1:{}", alice_port)));
  desc.parties.push_back(
      ContextDesc::Party("bob", fmt::format("127.0.0.1:{}", bob_port)));
  if (mode != SslMode::NONE) {
    desc.enable_ssl = true;
    desc.server_ssl_opts.ciphers = "";  // auto detect

    // export rsa keys to files
    auto [server_sk_path, server_cer_path] = GenCertFiles("server", mode);
    auto [client_sk_path, client_cer_path] = GenCertFiles("client", mode);

    desc.server_ssl_opts.cert.certificate_path = server_cer_path;
    desc.server_ssl_opts.cert.private_key_path = server_sk_path;

    desc.client_ssl_opts.cert.certificate_path = client_cer_path;
    desc.client_ssl_opts.cert.private_key_path = client_sk_path;
  }
  return desc;
}

template <typename M>
class FactoryTest : public ::testing::Test {
 public:
  void SetUp() override {
    static int desc_count = 0;
    contexts_.resize(2);
    auto desc = MakeDesc(desc_count++, SslMode(M::get_mode()));

    auto create_brpc = [&](int self_rank) {
      contexts_[self_rank] = M::get_t_instance().CreateContext(desc, self_rank);
    };

    std::vector<std::future<void>> creates;
    creates.push_back(std::async(create_brpc, 0));
    creates.push_back(std::async(create_brpc, 1));

    for (auto& f : creates) {
      f.get();
    }
  }

  void TearDown() override {
    auto wait = [&](int self_rank) {
      contexts_[self_rank]->WaitLinkTaskFinish();
    };

    std::vector<std::future<void>> waits;
    waits.push_back(std::async(wait, 0));
    waits.push_back(std::async(wait, 1));

    for (auto& f : waits) {
      f.get();
    }
  }

  std::vector<std::shared_ptr<Context>> contexts_;
};

using FactoryTestTypes =
    ::testing::Types<TestTypes<FactoryMem, 0>, TestTypes<FactoryBrpc, 0>,
                     TestTypes<FactoryBrpc, 1>
#ifdef YACL_WITH_TONGSUO
                     ,
                     TestTypes<FactoryBrpc, 2>
#endif
                     >;

TYPED_TEST_SUITE(FactoryTest, FactoryTestTypes);

TYPED_TEST(FactoryTest, SendAsync) {
  auto test = [&](int self_rank) {
    int dst_rank = (self_rank + 1) % 2;
    this->contexts_[self_rank]->SendAsync(dst_rank, "test", "test");
    Buffer r = this->contexts_[self_rank]->Recv(dst_rank, "test");
    std::string r_str(r.data<const char>(), r.size());
    EXPECT_EQ(r_str, std::string("test"));
  };

  std::vector<std::future<void>> tests;
  tests.push_back(std::async(test, 0));
  tests.push_back(std::async(test, 1));

  for (auto& f : tests) {
    f.get();
  }
}

TYPED_TEST(FactoryTest, AllGather) {
  auto test = [&](int self_rank) {
    auto all =
        yacl::link::AllGather(this->contexts_[self_rank], "test", "test");
    for (Buffer& a : all) {
      EXPECT_EQ(std::string(a.data<const char>(), a.size()),
                std::string("test"));
    }
  };

  std::vector<std::future<void>> tests;
  tests.push_back(std::async(test, 0));
  tests.push_back(std::async(test, 1));

  for (auto& f : tests) {
    f.get();
  }
}

TYPED_TEST(FactoryTest, SendRecv) {
  auto test = [&](int self_rank) {
    if (self_rank == 0) {
      this->contexts_[0]->Send(1, "test", "test");
    } else {
      Buffer r = this->contexts_[1]->Recv(0, "test");
      EXPECT_EQ(std::string(r.data<const char>(), r.size()),
                std::string("test"));
    }
  };

  std::vector<std::future<void>> tests;
  tests.push_back(std::async(test, 0));
  tests.push_back(std::async(test, 1));

  for (auto& f : tests) {
    f.get();
  }
}

}  // namespace yacl::link::test

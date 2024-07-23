

#include <future>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/kernel/algorithms/iknp_ote.h"
#include "yacl/link/test_util.h"

using namespace std;
using namespace yacl;
using namespace yacl::crypto;
using namespace yacl::link;

int main() {
  const int kWorldSize = 2;
  int num_ot = 10;

  auto lctxs = link::test::SetupWorld(kWorldSize);             // setup network
  auto base_ot = MockRots(128);                                // mock base ot
  auto choices = RandBits<dynamic_bitset<uint128_t>>(num_ot);  // get input

  // WHEN
  std::vector<std::array<uint128_t, 2>> send_out(num_ot);
  std::vector<uint128_t> recv_out(num_ot);
  std::future<void> sender = std::async([&] {
    IknpOtExtSend(lctxs[0], base_ot.recv, absl::MakeSpan(send_out), false);
  });  // 发送到base_ot.recv
  std::future<void> receiver = std::async([&] {
    IknpOtExtRecv(lctxs[1], base_ot.send, choices, absl::MakeSpan(recv_out),
                  false);  // 从base_ot.send取
  });
  receiver.get();
  sender.get();

  // THEN
  for (size_t i = 0; i < num_ot; ++i) {
    cout << "send_out:" << send_out[i][choices[i]]
         << "\t recv_out:" << recv_out[i] << endl;
  }
  return 0;
}

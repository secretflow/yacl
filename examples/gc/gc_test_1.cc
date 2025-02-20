#include <algorithm>

#include "absl/strings/escaping.h"
#include "absl/types/span.h"
#include "examples/gc/mitccrh.h"
#include "fmt/format.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/io/circuit/bristol_fashion.h"
#include "yacl/io/stream/file_io.h"
#include "yacl/kernel/algorithms/base_ot.h"
#include "yacl/kernel/algorithms/iknp_ote.h"
#include "yacl/link/test_util.h"
#include "yacl/utils/circuit_executor.h"
using namespace yacl;
using namespace std;
namespace {
using uint128_t = __uint128_t;
}

const uint128_t all_one_uint128_t = ~static_cast<__uint128_t>(0);
const uint128_t select_mask[2] = {0, all_one_uint128_t};

std::shared_ptr<io::BFCircuit> circ_;
vector<uint128_t> wires_;
vector<uint128_t> gb_value;

// enum class Op {
//   adder64,   √
//   aes_128,   √
//   divide64,  √
//   mult2_64,
//   mult64,    √
//   neg64,     √
//   sha256,
//   sub64,     √
//   udivide64, √
//   zero_equal √
// }

inline uint128_t Aes128(uint128_t k, uint128_t m) {
  crypto::SymmetricCrypto enc(crypto::SymmetricCrypto::CryptoType::AES128_ECB,
                              k);
  return enc.Encrypt(m);
}

uint128_t ReverseBytes(uint128_t x) {
  auto byte_view = ByteContainerView(&x, sizeof(x));
  uint128_t ret = 0;
  auto buf = std::vector<uint8_t>(sizeof(ret));
  for (size_t i = 0; i < byte_view.size(); ++i) {
    buf[byte_view.size() - i - 1] = byte_view[i];
  }
  std::memcpy(&ret, buf.data(), buf.size());
  return ret;
}

uint128_t GBAND(uint128_t LA0, uint128_t A1, uint128_t LB0, uint128_t B1,
                uint128_t delta, uint128_t* table, MITCCRH<8>* mitccrh) {
  bool pa = getLSB(LA0);
  bool pb = getLSB(LB0);

  uint128_t HLA0, HA1, HLB0, HB1;
  uint128_t tmp, W0;
  uint128_t H[4];

  H[0] = LA0;
  H[1] = A1;
  H[2] = LB0;
  H[3] = B1;

  mitccrh->hash<2, 2>(H);

  HLA0 = H[0];
  HA1 = H[1];
  HLB0 = H[2];
  HB1 = H[3];

  table[0] = HLA0 ^ HA1;
  table[0] = table[0] ^ (select_mask[pb] & delta);

  W0 = HLA0;
  W0 = W0 ^ (select_mask[pa] & table[0]);

  tmp = HLB0 ^ HB1;
  table[1] = tmp ^ LA0;

  W0 = W0 ^ HLB0;
  W0 = W0 ^ (select_mask[pb] & tmp);
  return W0;
}

uint128_t EVAND(uint128_t A, uint128_t B, const uint128_t* table,
                MITCCRH<8>* mitccrh) {
  uint128_t HA, HB, W;
  int sa, sb;

  sa = getLSB(A);
  sb = getLSB(B);

  uint128_t H[2];
  H[0] = A;
  H[1] = B;
  mitccrh->hash<2, 1>(H);
  HA = H[0];
  HB = H[1];

  W = HA ^ HB;
  W = W ^ (select_mask[sa] & table[0]);
  W = W ^ (select_mask[sb] & table[1]);
  W = W ^ (select_mask[sb] & A);
  return W;
}

template <typename T>
void finalize(absl::Span<T> outputs) {
  // YACL_ENFORCE(outputs.size() >= circ_->nov);

  size_t index = wires_.size();

  for (size_t i = 0; i < circ_->nov; ++i) {
    dynamic_bitset<T> result(circ_->now[i]);
    for (size_t j = 0; j < circ_->now[i]; ++j) {
      int wire_index = index - circ_->now[i] + j;
      result[j] = getLSB(wires_[wire_index]) ^
                  getLSB(gb_value[wire_index]);  // 得到的是逆序的二进制值
                                                 // 对应的混淆电路计算为LSB ^ d
                                                 // 输出线路在后xx位
    }
    outputs[circ_->nov - i - 1] = *(uint128_t*)result.data();
    index -= circ_->now[i];
  }
}

int main() {
  int num_ot = 10;
  const int kWorldSize = 2;
  auto contexts = link::test::SetupWorld(kWorldSize);

  std::vector<std::array<uint128_t, 2>> send_blocks;
  std::vector<uint128_t> recv_blocks;

  send_blocks.resize(num_ot);
  recv_blocks.resize(num_ot);

  // WHEN
  auto choices = yacl::crypto::RandBits<dynamic_bitset<uint128_t>>(num_ot);
  std::future<void> sender = std::async([&] {
    yacl::crypto::BaseOtSend(contexts[0], absl::MakeSpan(send_blocks));
  });
  std::future<void> receiver = std::async([&] {
    yacl::crypto::BaseOtRecv(contexts[1], choices, absl::MakeSpan(recv_blocks));
  });
  sender.get();
  receiver.get();
  cout << "choice" << choices << endl;
  // THEN
  for (unsigned i = 0; i < num_ot; ++i) {
    unsigned idx = choices[i] ? 1 : 0;
    cout << send_blocks[i][idx] << "      " << recv_blocks[i] << endl;
    if (send_blocks[i][idx] != recv_blocks[i]) {
      cout << "error" << endl;
      break;
    }
  }
  return 0;
}

#pragma once
#include <algorithm>
#include <future>
#include <type_traits>
#include <vector>

// #include "absl/std::strings/escaping.h"
#include "absl/types/span.h"
#include "examples/gc/mitccrh.h"
#include "fmt/format.h"

#include "yacl/base/byte_container_view.h"
#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/io/circuit/bristol_fashion.h"
#include "yacl/io/stream/file_io.h"
#include "yacl/kernel/algorithms/base_ot.h"
#include "yacl/kernel/algorithms/iknp_ote.h"
// #include "yacl/kernel/ot_kernel.h"
#include "yacl/kernel/type/ot_store_utils.h"
#include "yacl/link/context.h"
#include "yacl/link/factory.h"
#include "yacl/link/test_util.h"
#include "yacl/utils/circuit_executor.h"

using namespace std;
using namespace yacl;
namespace {
using uint128_t = __uint128_t;
}

uint128_t all_one_uint128_t = ~static_cast<__uint128_t>(0);
uint128_t select_mask[2] = {0, all_one_uint128_t};

class Evaluator {
 public:
  std::shared_ptr<yacl::link::Context> lctx;
  uint128_t delta;
  uint128_t inv_constant;
  uint128_t start_point;
  MITCCRH<8> mitccrh;

  std::vector<uint128_t> wires_;
  std::vector<uint128_t> gb_value;
  yacl::io::BFCircuit circ_;

  uint64_t input;

  void setup() {
    // 通信环境初始化
    size_t world_size = 2;
    yacl::link::ContextDesc ctx_desc;

    for (size_t rank = 0; rank < world_size; rank++) {
      const auto id = fmt::format("id-{}", rank);
      const auto host = fmt::format("127.0.0.1:{}", 10086 + rank);
      ctx_desc.parties.push_back({id, host});
    }

    auto lctx = yacl::link::FactoryBrpc().CreateContext(ctx_desc,
                                                        1);  // yacl::link::test
    lctx->ConnectToMesh();

    uint128_t tmp[3];
    // delta, inv_constant, start_point 接收
    yacl::Buffer r = lctx->Recv(0, "tmp");
    const uint128_t* buffer_data = r.data<const uint128_t>();
    memcpy(tmp, buffer_data, sizeof(uint128_t) * 3);
    std::cout << "tmpRecv" << std::endl;

    delta = tmp[0];
    inv_constant = tmp[1];
    start_point = tmp[2];

    // 秘钥生成
    mitccrh.setS(start_point);
  }

  void inputProcess(yacl::io::BFCircuit param_circ_) {
    circ_ = param_circ_;
    gb_value.resize(circ_.nw);
    wires_.resize(circ_.nw);

    yacl::dynamic_bitset<uint64_t> bi_val;
    bi_val.append(input);  // 直接转换为二进制  输入线路在前64位

    input = yacl::crypto::FastRandU64();
    std::cout << "input of evaluator:" << input << std::endl;

    // 接收garbler混淆值
    yacl::Buffer r = lctx->Recv(0, "garbleInput1");
    cout << "lctx->Recv" << endl;
    const uint128_t* buffer_data = r.data<const uint128_t>();
    cout << "const uint128_t* buffer_data = r.data<const uint128_t>();" << endl;
    memcpy(wires_.data(), buffer_data, sizeof(uint128_t) * 64);
    cout << "memcpy(wires_.data(), buffer_data, sizeof(uint128_t) * 64);"
         << endl;
    std::cout << "recvInput1" << std::endl;

    // // 对evaluator自己的输入值进行混淆
    // r = lctx->Recv(0, "garbleInput2");
    // buffer_data = r.data<const uint128_t>();
    // for (int i = 0; i < circ_.niw[1]; i++) {
    //   wires_[i + circ_.niw[0]] =
    //       buffer_data[i] ^ (select_mask[bi_val[i]] & delta);
    // }
    // std::cout << "recvInput2" << std::endl;
  }
};
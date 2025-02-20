#include <bits/stdc++.h>

#include "gflags/gflags.h"

#include "yacl/base/exception.h"
#include "yacl/link/context.h"
#include "yacl/link/factory.h"

using namespace std;
using namespace yacl;
using uint128_t = __uint128_t;
DEFINE_int32(rank, -1, "rank of the party: 0/1");

int main(int argc, char* argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);

  YACL_ENFORCE(FLAGS_rank != -1, "Invalid Arguemnts: rank");

  size_t world_size = 2;
  yacl::link::ContextDesc ctx_desc;

  for (size_t rank = 0; rank < world_size; rank++) {
    const auto id = fmt::format("id-{}", rank);
    const auto host = fmt::format("127.0.0.1:{}", 10086 + rank);
    ctx_desc.parties.push_back({id, host});
  }

  auto lctx = yacl::link::FactoryBrpc().CreateContext(ctx_desc, FLAGS_rank);
  lctx->ConnectToMesh();

  vector<uint128_t> gb_value(25, 1);

  //统一 delta  constant
  // 发送 混淆X 电路表  （输出电路的标签 ×）
  //  OT
  //  计算结果
  if (FLAGS_rank == 0) {
    lctx->Send(1, ByteContainerView(gb_value.data(), sizeof(uint128_t) * 25),
               "test");
    cout << "send" << endl;
  } else {
    Buffer r = lctx->Recv(0, "test");

    const uint128_t* buffer_data = r.data<const uint128_t>();
    size_t buffer_size = r.size() / 16;

    std::cout << "Received data size: " << buffer_size << std::endl;
    for (size_t i = 0; i < buffer_size; ++i) {
      std::cout << static_cast<int>(buffer_data[i]) << " ";
    }
    cout << endl;

    cout << "recv" << endl;
  }

  return 0;
}
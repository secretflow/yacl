#pragma once
#include "yacl/kernel/type/ot_store_utils.h"
#include "yacl/link/test_util.h"
#include <future>
#include <vector>
#include "yacl/kernel/ot_kernel.h"


using namespace std;
using namespace yacl;
using namespace yacl::crypto;

using OtMsg = uint128_t;
using OtMsgPair = std::array<OtMsg, 2>;
using OtChoices = dynamic_bitset<uint128_t>;

constexpr uint32_t kBatchSize = 128;


// Conversion from cot to rot (OtStoreType == Normal)
void naive_rot2ot(
    const std::shared_ptr<yacl::link::Context>& lctx,
    const OtSendStore& ot_store, absl::Span<const OtMsgPair> msgpairs) {
  static_assert(kBatchSize % 128 == 0);  // batch size should be multiple of 128
  YACL_ENFORCE(ot_store.Type() == OtStoreType::Normal);
  YACL_ENFORCE(ot_store.Size() == msgpairs.size());
  const uint32_t ot_num = msgpairs.size();
  const uint32_t batch_num = (ot_num + kBatchSize - 1) / kBatchSize;

  dynamic_bitset<uint128_t> masked_choices(ot_num);
  auto buf = lctx->Recv(lctx->NextRank(), "");
  std::memcpy(masked_choices.data(), buf.data(), buf.size());

  // for each batch
  for (uint32_t i = 0; i < batch_num; ++i) {
    const uint32_t limit = std::min(kBatchSize, ot_num - i * kBatchSize);

    // generate masks for all msg pairs
    std::vector<OtMsgPair> batch_send(limit);
    for (uint32_t j = 0; j < limit; ++j) {
      auto idx = i * kBatchSize + j;
      // fmt::print("{} {}\n", idx, masked_choices.size());

      if (!masked_choices[idx]) {
        batch_send[j][0] = ot_store.GetBlock(idx, 0) ^ msgpairs[idx][0];
        batch_send[j][1] = ot_store.GetBlock(idx, 1) ^ msgpairs[idx][1];
      } else {
        batch_send[j][0] = ot_store.GetBlock(idx, 1) ^ msgpairs[idx][0];
        batch_send[j][1] = ot_store.GetBlock(idx, 0) ^ msgpairs[idx][1];
      }
    }

    lctx->SendAsync(
        lctx->NextRank(),
        ByteContainerView(batch_send.data(), sizeof(uint128_t) * limit * 2),
        "");
  }
}

void naive_rot2ot_recv(
    const std::shared_ptr<yacl::link::Context>& lctx,
    const OtRecvStore& ot_store, const OtChoices& choices,
    absl::Span<OtMsg> out) {
  static_assert(kBatchSize % 128 == 0);  // batch size should be multiple of 128
  YACL_ENFORCE(ot_store.Type() == OtStoreType::Normal);
  YACL_ENFORCE(ot_store.Size() == choices.size());
  const uint32_t ot_num = ot_store.Size();
  const uint32_t batch_num = (ot_num + kBatchSize - 1) / kBatchSize;

  auto masked_choice = ot_store.CopyBitBuf() ^ choices;
  lctx->SendAsync(
      lctx->NextRank(),
      ByteContainerView(masked_choice.data(),
                        sizeof(uint128_t) * masked_choice.num_blocks()),
      "Sending masked choices");

  // for each batch
  for (uint32_t i = 0; i < batch_num; ++i) {
    const uint32_t limit = std::min(kBatchSize, ot_num - i * kBatchSize);

    // receive masked messages
    auto buf = lctx->Recv(lctx->NextRank(), "");
    std::vector<OtMsgPair> batch_recv(limit);
    std::memcpy(batch_recv.data(), buf.data(), buf.size());

    for (uint32_t j = 0; j < limit; ++j) {
      auto idx = i * kBatchSize + j;
      // fmt::print("{} {}\n", idx, choices.size());
      out[idx] = batch_recv[j][choices[idx]] ^ ot_store.GetBlock(idx);
    }
  }
}

int main(){

    auto lctxs = link::test::SetupWorld(2);

  const size_t num_ot = 1;
  const auto ext_algorithm = yacl::crypto::OtKernel::ExtAlgorithm::SoftSpoken;

  yacl::crypto::OtSendStore ot_send(num_ot, yacl::crypto::OtStoreType::Normal);  // placeholder
  yacl::crypto::OtRecvStore ot_recv(num_ot, yacl::crypto::OtStoreType::Normal);  // placeholder

  yacl::crypto::OtKernel kernel0(yacl::crypto::OtKernel::Role::Sender, ext_algorithm);
  yacl::crypto::OtKernel kernel1(yacl::crypto::OtKernel::Role::Receiver, ext_algorithm);

  // WHEN
  auto sender = std::async([&] {
    kernel0.init(lctxs[0]);
    kernel0.eval_rot(lctxs[0], num_ot, &ot_send);
  });
  auto receiver = std::async([&] {
    kernel1.init(lctxs[1]);
    kernel1.eval_rot(lctxs[1], num_ot, &ot_recv);
  });
  sender.get();
  receiver.get();

  cout << "$: ";
  for(int i = 0; i < num_ot; i++){
    cout << ot_send.GetBlock(i, ot_recv.GetChoice(i)) <<"  " << ot_send.GetBlock(i, ot_recv.GetChoice(i))<< "  " << ot_recv.GetBlock(i) << endl; 
  }


  
  vector<array<uint128_t,2>> msgPairs(1);
  msgPairs[0][0] = yacl::crypto::FastRandU128();
  msgPairs[0][1] = yacl::crypto::FastRandU128();

  cout << "Msg: ";
  cout << msgPairs[0][0] << "  " << msgPairs[0][1] << endl;

  int choice = 0;

  int d = choice ^  ot_recv.GetChoice(0);
  
  uint128_t x0 = ot_send.GetBlock(0, d) ^ msgPairs[0][0];
  uint128_t x1 = ot_send.GetBlock(0, d ^ 1) ^ msgPairs[0][1];

  uint128_t result = x0 ^ ot_send.GetBlock(0, ot_recv.GetChoice(0));

  cout << result;



    return 0;
}
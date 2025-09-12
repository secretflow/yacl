// Copyright 2025 Ant Group Co., Ltd.
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

#include "yacl/link/link_bridge.h"

#include <cstring>
#include <memory>
#include <vector>

#include "yacl/base/buffer.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/link/mbox_capi.h"
#include "yacl/link/transport/channel.h"

namespace yacl::link {

// Structure to hold the channel and msgloop data
struct ChannelMboxData {
  std::vector<std::shared_ptr<transport::IChannel>> channels;
  std::shared_ptr<transport::IReceiverLoop> msg_loop;
};

// Send function implementation using channels
static mbox_error_t channel_send_fn(void* user_data, size_t dst,
                                    const char* key, const uint8_t* data,
                                    size_t data_len) {
  if (user_data == nullptr || key == nullptr ||
      (data == nullptr && data_len > 0)) {
    return MBOX_ERROR_INVALID_ARGUMENT;
  }

  auto* channel_data = static_cast<ChannelMboxData*>(user_data);
  if (dst >= channel_data->channels.size() ||
      channel_data->channels[dst] == nullptr) {
    return MBOX_ERROR_INVALID_ARGUMENT;
  }

  try {
    channel_data->channels[dst]->Send(key, ByteContainerView(data, data_len));
    return MBOX_SUCCESS;
  } catch (const std::bad_alloc&) {
    return MBOX_ERROR_MEMORY;
  } catch (const std::exception& e) {
    // Handle other exceptions as network errors
    return MBOX_ERROR_NETWORK;
  }
}

// Receive function implementation using channels
static mbox_error_t channel_recv_fn(void* user_data, size_t src,
                                    const char* key, int64_t timeout_ms,
                                    uint8_t** buffer, size_t* buffer_len) {
  if (user_data == nullptr || key == nullptr || buffer == nullptr ||
      buffer_len == nullptr) {
    return MBOX_ERROR_INVALID_ARGUMENT;
  }

  auto* channel_data = static_cast<ChannelMboxData*>(user_data);
  if (src >= channel_data->channels.size() ||
      channel_data->channels[src] == nullptr) {
    return MBOX_ERROR_INVALID_ARGUMENT;
  }

  try {
    // Set timeout if provided
    if (timeout_ms >= 0) {
      channel_data->channels[src]->SetRecvTimeout(timeout_ms);
    }

    Buffer received_data = channel_data->channels[src]->Recv(key);

    if (received_data.size() == 0) {
      *buffer = nullptr;
      *buffer_len = 0;
      return MBOX_ERROR_NOT_FOUND;
    }

    // TODO: zero-copy optimization
    // Allocate buffer for received data
    *buffer = static_cast<uint8_t*>(malloc(received_data.size()));
    if (*buffer == nullptr) {
      return MBOX_ERROR_MEMORY;
    }

    std::memcpy(*buffer, received_data.data(), received_data.size());
    *buffer_len = received_data.size();

    return MBOX_SUCCESS;
  } catch (const std::bad_alloc&) {
    return MBOX_ERROR_MEMORY;
  } catch (const IoError& e) {
    // TODO: refine exception handling
    return MBOX_ERROR_NOT_FOUND;
  } catch (const std::exception& e) {
    return MBOX_ERROR_NETWORK;
  }
}

// Free function for user data
static void channel_free_user_data_fn(void* user_data) {
  if (user_data != nullptr) {
    delete static_cast<ChannelMboxData*>(user_data);
  }
}

// Bridge function to create a mbox instance from channels and receiver loop
mbox_t* CreateMbox(std::vector<std::shared_ptr<transport::IChannel>> channels,
                   std::shared_ptr<transport::IReceiverLoop> msg_loop) {
  if (channels.empty() || msg_loop == nullptr) {
    return nullptr;
  }

  try {
    // Create user data structure
    auto* channel_data = new (std::nothrow) ChannelMboxData();
    if (channel_data == nullptr) {
      return nullptr;
    }

    channel_data->channels = std::move(channels);
    channel_data->msg_loop = std::move(msg_loop);

    // Create vtable with channel-based functions
    mbox_vtable_t vtable;
    vtable.user_data = channel_data;
    vtable.send_fn = channel_send_fn;
    vtable.recv_fn = channel_recv_fn;
    vtable.free_user_data_fn = channel_free_user_data_fn;

    // Create mbox instance using the vtable
    return mbox_create(vtable);
  } catch (const std::bad_alloc&) {
    return nullptr;
  } catch (...) {
    return nullptr;
  }
}

}  // namespace yacl::link
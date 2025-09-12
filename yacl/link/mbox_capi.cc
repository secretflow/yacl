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

#include "yacl/link/mbox_capi.h"

#include <cstdlib>
#include <cstring>
#include <new>

// mbox_t is defined in the header as an opaque type
struct mbox_s {
  mbox_vtable_t impl;
};

extern "C" {

mbox_t* mbox_create(mbox_vtable_t vtable) {
  if (vtable.send_fn == nullptr || vtable.recv_fn == nullptr) {
    return nullptr;
  }

  try {
    mbox_t* mbox = new (std::nothrow) mbox_t();
    if (mbox == nullptr) {
      return nullptr;
    }
    mbox->impl = vtable;
    return mbox;
  } catch (...) {
    return nullptr;
  }
}

void mbox_destroy(mbox_t* mbox) {
  if (mbox == nullptr) {
    return;
  }

  // Call the free function if provided
  if (mbox->impl.free_user_data_fn != nullptr &&
      mbox->impl.user_data != nullptr) {
    mbox->impl.free_user_data_fn(mbox->impl.user_data);
  }

  delete mbox;
}

mbox_error_t mbox_send(mbox_t* mbox, size_t dst, const char* key,
                       const uint8_t* data, size_t data_len) {
  if (mbox == nullptr) {
    return MBOX_ERROR_NOT_INITIALIZED;
  }

  if (key == nullptr) {
    return MBOX_ERROR_INVALID_ARGUMENT;
  }

  if (data == nullptr && data_len > 0) {
    return MBOX_ERROR_INVALID_ARGUMENT;
  }

  if (mbox->impl.send_fn == nullptr) {
    return MBOX_ERROR_INTERNAL;
  }

  return mbox->impl.send_fn(mbox->impl.user_data, dst, key, data, data_len);
}

mbox_error_t mbox_recv(mbox_t* mbox, size_t src, const char* key,
                       int64_t timeout_ms, uint8_t** buffer,
                       size_t* buffer_len) {
  if (mbox == nullptr) {
    return MBOX_ERROR_NOT_INITIALIZED;
  }

  if (key == nullptr || buffer == nullptr || buffer_len == nullptr) {
    return MBOX_ERROR_INVALID_ARGUMENT;
  }

  if (mbox->impl.recv_fn == nullptr) {
    return MBOX_ERROR_INTERNAL;
  }

  return mbox->impl.recv_fn(mbox->impl.user_data, src, key, timeout_ms, buffer,
                            buffer_len);
}

}  // extern "C"
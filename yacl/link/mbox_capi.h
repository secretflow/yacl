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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/// Error codes for cross-language error handling.
typedef enum {
  MBOX_SUCCESS = 0,                  ///< Operation completed successfully.
  MBOX_ERROR_INVALID_ARGUMENT = -1,  ///< Invalid argument provided.
  MBOX_ERROR_NOT_FOUND = -2,         ///< Message not found or timeout.
  MBOX_ERROR_MEMORY = -3,            ///< Memory allocation failed.
  MBOX_ERROR_NETWORK = -4,           ///< Network communication error.
  MBOX_ERROR_INTERNAL = -5,          ///< Internal error in implementation.
  MBOX_ERROR_NOT_INITIALIZED = -6  ///< Mbox instance not properly initialized.
} mbox_error_t;

// Opaque handle for mbox instance
typedef struct mbox_s mbox_t;
typedef struct mbox_vtable_s {
  void* user_data;  // user implementation pointer.
  // Send function pointer
  mbox_error_t (*send_fn)(void* user_data, size_t dst, const char* key,
                          const uint8_t* data, size_t data_len);
  // Recv function pointer
  mbox_error_t (*recv_fn)(void* user_data, size_t src, const char* key,
                          int64_t timeout_ms, uint8_t** buffer,
                          size_t* buffer_len);
  // Free user data function pointer
  void (*free_user_data_fn)(void* user_data);
} mbox_vtable_t;

/// Creates a new mbox instance using the default C++ implementation.
///
/// @return A new mbox instance, or nullptr on failure.
mbox_t* mbox_create(mbox_vtable_t vtable);

/// Destroys a mbox instance created by mbox_create().
///
/// @param mbox The mbox instance to destroy. If nullptr, the function does
///             nothing. After destruction, the pointer becomes invalid.
void mbox_destroy(mbox_t* mbox);

/// Sends a message to a specific destination.
///
/// @param mbox     The mbox instance.
/// @param dst      Destination party ID (0-based index).
/// @param key      Message identifier (null-terminated string).
/// @param data     Raw message data to send.
/// @param data_len Length of data in bytes.
///
/// @return MBOX_SUCCESS on success, appropriate error code on failure.
mbox_error_t mbox_send(mbox_t* mbox, size_t dst, const char* key,
                       const uint8_t* data, size_t data_len);

/// Receives a message from a specific source.
///
/// @param mbox       The mbox instance.
/// @param src        Source party ID to receive from (0-based index).
/// @param key        Message identifier to receive (null-terminated string).
/// @param timeout_ms Timeout in milliseconds (-1 for infinite wait).
/// @param buffer     Output parameter set to a newly allocated buffer
///                   containing the received data. The caller must free this
///                   buffer with free().
/// @param buffer_len Output parameter set to the length of the received data.
///
/// @return MBOX_SUCCESS on success, appropriate error code on failure.
///
/// @note On success, `*buffer_len` contains the number of bytes received.
/// @note The returned buffer must be freed by the caller using free().
mbox_error_t mbox_recv(mbox_t* mbox, size_t src, const char* key,
                       int64_t timeout_ms, uint8_t** buffer,
                       size_t* buffer_len);

#ifdef __cplusplus
}
#endif

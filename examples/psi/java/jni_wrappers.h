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

#pragma once

#include <jni.h>

#include <vector>

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/math/mpint/mp_int.h"

namespace jni {

inline jbyteArray buffer_to_jbyteArrary(JNIEnv *env,
                                        yacl::ByteContainerView in) {
  const auto *by = reinterpret_cast<const jbyte *>(in.data());
  jbyteArray ret = env->NewByteArray(in.size());
  env->SetByteArrayRegion(ret, 0, in.size(), by);
  return ret;
}

inline std::vector<uint8_t> jbyteArray_to_bytes(JNIEnv *env, jbyteArray in) {
  jbyte *in_ptr = env->GetByteArrayElements(in, nullptr);
  uint64_t in_len = (uint64_t)env->GetArrayLength(in);
  std::vector<uint8_t> ret(in_len);
  std::memcpy(ret.data(), in_ptr, in_len);
  env->ReleaseByteArrayElements(in, in_ptr, 0);
  return ret;
}

inline uint128_t jbyteArray_to_uint128(JNIEnv *env, jbyteArray in) {
  jbyte *in_ptr = env->GetByteArrayElements(in, nullptr);
  size_t in_len = env->GetArrayLength(in);
  YACL_ENFORCE(in_len >= 16);

  uint128_t ret = 0;
  for (int i = 0; i < 16; i++) {
    // Shifting previous value 8 bits to right and
    // add it with next value
    char b = *(in_ptr + i);
    ret = (ret << 8) + (b & 255);
  }
  env->ReleaseByteArrayElements(in, in_ptr, 0);
  return ret;
}

inline std::vector<uint64_t> jlongArray_to_longs(JNIEnv *env, jlongArray in) {
  jlong *in_ptr = env->GetLongArrayElements(in, nullptr);
  uint64_t in_len = (uint64_t)env->GetArrayLength(in);
  std::vector<uint64_t> ret;
  for (uint64_t i = 0; i < in_len; i++) {
    ret.emplace_back(static_cast<uint64_t>(in_ptr[i]));
  }
  env->ReleaseLongArrayElements(in, in_ptr, 0);
  return ret;
}

inline std::string jstring_to_string(JNIEnv *env, jstring in) {
  jboolean isCopy;
  const char *convertedValue = (env)->GetStringUTFChars(in, &isCopy);
  std::string ret = convertedValue;
  env->ReleaseStringUTFChars(in, convertedValue);
  return ret;
}

}  // namespace jni
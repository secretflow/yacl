// Copyright 2024 Ant Group Co., Ltd.
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

#include "psi/cpp/ecdh_psi.h"
#include "psi/java/EcdhPsi.hdrs.h/EcdhPsi.h"
#include "psi/java/jni_wrappers.h"

#include "yacl/math/mpint/mp_int.h"
#include "yacl/utils/serialize.h"

namespace yc = yacl::crypto;

/*
 * Class:     EcdhPsi
 * Method:    jni_ecc_keygen
 * Signature: ()[B
 */
JNIEXPORT jbyteArray JNICALL Java_EcdhPsi_jni_1ecc_1keygen(JNIEnv *env,
                                                           jclass java_class) {
  yacl::math::MPInt sk;
  auto ec = yc::EcGroupFactory::Instance().Create("FourQ");
  yc::MPInt::RandomLtN(ec->GetOrder(), &sk);
  auto buf = sk.Serialize();
  return jni::buffer_to_jbyteArray(env, sk.Serialize());
}

/*
 * Class:     EcdhPsi
 * Method:    jni_mask_strings
 * Signature: ([Ljava/lang/String;[B)[Ljava/lang/String;
 */
JNIEXPORT jobjectArray JNICALL
Java_EcdhPsi_jni_1mask_1strings(JNIEnv *env, jclass java_class,
                                jobjectArray in_bytes, jbyteArray sk_bytes) {
  // Setup
  int len = env->GetArrayLength(in_bytes);
  auto ec = yc::EcGroupFactory::Instance().Create("FourQ");
  yacl::math::MPInt sk;
  sk.Deserialize(jni::jbyteArray_to_bytes(env, sk_bytes));

  // Declare the output jobjectArray
  jclass bytearray_class = env->FindClass("[B");
  jobjectArray out = env->NewObjectArray(len, bytearray_class, NULL);

  // For each input jstring, hash to curve and mul
  for (int i = 0; i < len; i++) {
    auto temp_in = jni::jstring_to_string(
        env, (jstring)env->GetObjectArrayElement(in_bytes, i));
    auto temp_out =
        ec->HashToCurve(yc::HashToCurveStrategy::Autonomous, temp_in);
    ec->MulInplace(&temp_out, sk);
    auto buffer = ec->SerializePoint(temp_out);
    env->SetObjectArrayElement(out, i, jni::buffer_to_jbyteArray(env, buffer));
  }
  return out;
}

/*
 * Class:     EcdhPsi
 * Method:    jni_mask_ec_point_and_hash_to_u128
 * Signature: ([Ljava/lang/String;[B)[Ljava/lang/String;
 */
JNIEXPORT jobjectArray JNICALL
Java_EcdhPsi_jni_1mask_1ec_1point_1and_1hash_1to_1u128(JNIEnv *env,
                                                       jclass java_class,
                                                       jobjectArray in_bytes,
                                                       jbyteArray sk_bytes) {
  // Setup
  int len = env->GetArrayLength(in_bytes);
  auto ec = yc::EcGroupFactory::Instance().Create("FourQ");
  yacl::math::MPInt sk;
  sk.Deserialize(jni::jbyteArray_to_bytes(env, sk_bytes));

  // Declare the output jobjectArray
  jclass bytearray_class = env->FindClass("[B");
  jobjectArray out = env->NewObjectArray(len, bytearray_class, NULL);

  // For each input jstring, hash to curve and mul
  for (int i = 0; i < len; i++) {
    auto temp_in = ec->DeserializePoint(jni::jbyteArray_to_bytes(
        env, (jbyteArray)env->GetObjectArrayElement(in_bytes, i)));
    auto temp_out =
        yacl::crypto::Blake3_128(ec->SerializePoint(ec->Mul(temp_in, sk)));

    yacl::Buffer buf(sizeof(uint128_t));
    memcpy(buf.data(), &temp_out, buf.size());
    env->SetObjectArrayElement(out, i, jni::buffer_to_jbyteArray(env, buf));
  }
  return out;
}

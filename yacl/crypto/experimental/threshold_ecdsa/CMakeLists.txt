# Copyright 2026 Ant Group Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.22)
project(threshold_ecdsa LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL QUIET)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

add_library(tecdsa_core
  crypto/scalar.cc
  crypto/ec_point.cc
  crypto/ecdsa_verify.cc
  crypto/hash.cc
  crypto/random.cc
  crypto/commitment.cc
  crypto/encoding.cc
  crypto/paillier.cc
  crypto/strict_proofs_codec.cc
  crypto/strict_proofs_math.cc
  crypto/strict_proofs.cc
  crypto/transcript.cc
  net/envelope.cc
  net/in_memory_transport.cc
  protocol/session.cc
  protocol/session_router.cc
  protocol/keygen_session_codec.cc
  protocol/keygen_session_phase1.cc
  protocol/keygen_session_phase2.cc
  protocol/keygen_session_phase3.cc
  protocol/keygen_session.cc
  protocol/sign_session_codec.cc
  protocol/sign_session_math.cc
  protocol/sign_session_transcript.cc
  protocol/sign_session_mta_proofs.cc
  protocol/sign_session_phase_core.cc
  protocol/sign_session_phase_handlers.cc
  protocol/sign_session_phase_state.cc
  protocol/sign_session.cc
)

target_include_directories(tecdsa_core PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/../../../../
  ${CMAKE_CURRENT_SOURCE_DIR}
)

if(OpenSSL_FOUND)
  target_link_libraries(tecdsa_core PUBLIC OpenSSL::Crypto)
else()
  target_link_libraries(tecdsa_core PUBLIC crypto)
endif()

add_library(tecdsa_m0 ALIAS tecdsa_core)

add_executable(crypto_primitives_tests tests/crypto_primitives_test.cc)
target_link_libraries(crypto_primitives_tests PRIVATE tecdsa_core)

add_executable(protocol_infrastructure_tests tests/protocol_infrastructure_test.cc)
target_link_libraries(protocol_infrastructure_tests PRIVATE tecdsa_core)

add_executable(keygen_flow_tests tests/keygen_flow_test.cc)
target_link_libraries(keygen_flow_tests PRIVATE tecdsa_core)

add_executable(sign_flow_tests
  tests/sign_flow_test.cc
  tests/sign_flow_test_cases.cc
  tests/sign_flow_test_support.cc
)
target_link_libraries(sign_flow_tests PRIVATE tecdsa_core)

enable_testing()
add_test(NAME crypto_primitives_tests COMMAND crypto_primitives_tests)
add_test(NAME protocol_infrastructure_tests COMMAND protocol_infrastructure_tests)
add_test(NAME keygen_flow_tests COMMAND keygen_flow_tests)
add_test(NAME sign_flow_tests COMMAND sign_flow_tests)

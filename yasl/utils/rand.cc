// Copyright 2022 Ant Group Co., Ltd.
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

#include "yasl/utils/rand.h"

#include <mutex>
#include <thread>

#include "yasl/crypto/pseudo_random_generator.h"

// By default, the OpenSSL CSPRNG supports a security level of 256 bits,
// provided it was able to seed itself from a trusted entropy source.
// On all major platforms supported by OpenSSL (including the Unix-like
// platforms and Windows), OpenSSL is configured to automatically seed
// the CSPRNG on first use using the operating systems's random generator.
//
// OpenSSL comes with a default implementation of the RAND API which
// is based on the deterministic random bit generator (DRBG) model
// as described in [NIST SP 800-90A Rev. 1].
// It seeds and reseeds itself automatically using trusted random
// sources provided by the operating system.
//
// Reference:
// https://www.openssl.org/docs/man3.0/man7/RAND.html
// https://www.openssl.org/docs/man3.0/man3/RAND_seed.html
// https://www.openssl.org/docs/manmaster/man3/RAND_bytes.html

namespace yasl {

namespace {

std::once_flag seed_flag;

void OpensslSeedOnce() {
  // NistAesCtrDrbg seed with intel rdseed
  std::call_once(seed_flag, []() {
    PseudoRandomGenerator<uint64_t> prg(0, PRG_MODE::kNistAesCtrDrbg);
    std::array<uint8_t, 32> rand_bytes;
    prg.Fill(absl::MakeSpan(rand_bytes));

    RAND_seed(rand_bytes.data(), rand_bytes.size());
  });
}

}  // namespace

uint64_t DrbgRandSeed() {
  OpensslSeedOnce();

  uint64_t rand64;

  // RAND_bytes() thread safety OpenSSL >= 1.1.0
  YASL_ENFORCE(RAND_bytes(reinterpret_cast<unsigned char*>(&rand64),
                          sizeof(rand64)) == 1);
  return rand64;
}

}  // namespace yasl

// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <algorithm>
#include <memory>
#include <string>

#include "yacl/crypto/rand/entropy_source/entropy_source.h"

#ifdef __x86_64
#include <immintrin.h>

#include "cpuinfo_x86.h"

namespace yacl::crypto {

// RdSeed (hardware) Entropy Source
//
// From wiki:
// RDRAND (for "read random") is an instruction for returning random numbers
// from an Intel on-chip hardware random number generator which has been seeded
// by an on-chip entropy source. It is also known as Intel Secure Key
// Technology, codenamed Bull Mountain. Intel introduced the feature around
// 2012, and AMD added support for the instruction in June 2015. (RDRAND is
// available in Ivy Bridge processors[a] and is part of the Intel 64 and IA-32
// instruction set architectures.)
//
// NOTE:
// RDSEED is similar to RDRAND and provides lower-level access to the
// entropy-generating hardware. The RDSEED generator and processor instruction
// rdseed are available with Intel Broadwell CPUs and AMD Zen CPUs.
//
class RdSeedEntropySource : public EntropySource {
 public:
  // ----------- //
  //    SPI
  // ----------- //
  static std::unique_ptr<EntropySource> Create(
      const std::string &type, [[maybe_unused]] const SpiArgs &config) {
    // this entropy source should be used only if the CPU has rdseed support
    YACL_ENFORCE(cpu_features::GetX86Info().features.rdseed);
    YACL_ENFORCE(absl::AsciiStrToLower(type) == "hardware" ||
                 absl::AsciiStrToLower(type) == "auto");
    return std::make_unique<RdSeedEntropySource>();
  }

  // this checker would always return ture
  static bool Check(const std::string &type,
                    [[maybe_unused]] const SpiArgs &config) {
    return cpu_features::GetX86Info().features.rdseed &&
           (absl::AsciiStrToLower(type) == "hardware" ||
            absl::AsciiStrToLower(type) == "auto");
  }

  Buffer GetEntropy(uint32_t bits_of_entropy) override;

  std::string Name() override { return "rdseed entropy source"; }
};

}  // namespace yacl::crypto

#endif

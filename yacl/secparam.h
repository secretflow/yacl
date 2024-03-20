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

#include <cstdint>
#include <map>
#include <string>
#include <utility>

#include "fmt/color.h"

#include "yacl/base/exception.h"
#include "yacl/math/gadget.h"
#include "yacl/utils/compile_time_utils.h"

namespace yacl::crypto {

// ------------------
// Security parameter
// ------------------

class SecParam {
 public:
  // Computational Security Parameter: A number associated with the amount of
  // work (that is, the number of operations) that is required to break a
  // cryptographic algorithm or system. This is also known as "Security
  // Strength".
  //
  // The recommended security strength time frames by NIST (SP.800-57pt1r5) are
  // listed in the following. Note that we only consider the "Acceptable"
  // decision made by NIST.
  //
  // +-------------------+-------------+------------+
  // | Security Strength | Before 2030 | After 2030 |
  // |-------------------+-------------+------------|
  // |   less than 112   |      N      |      N     |
  // |       112         |      Y      |      N     |
  // |       128         |      Y      |      Y     |
  // |       192         |      Y      |      Y     |
  // |       256         |      Y      |      Y     |
  // +-------------------+-------------+------------+
  //
  // Note that security stregth is an abstract concept, which may not directly
  // refer to the key size of a concerete crypto algorithm. See:
  // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
  //
  // +-------------------+---------------+---------------+---------+-----------+
  // | Security Strength | Symmetric-Key | FFC           | IFC     | ECC       |
  // +-------------------+---------------+---------------+---------+-----------+
  // | <80               | 2TDEA         | L=1024 N=160  | k=1024  | f=160-223 |
  // | 112               | 3TDEA         | L=2048 N=224  | k=2048  | f=224-255 |
  // | 128               | AES-128       | L=3072 N=256  | k=3072  | f=256-383 |
  // | 192               | AES-192       | L=7680 N=384  | k=7680  | f=384-511 |
  // | 256               | AES-256       | L=15360 N=512 | k=15360 | f=512+    |
  // +-------------------+---------------+---------------+---------+-----------+
  // FFC: finite field cryptography, L is the pk length, N is the sk length
  // IFC: integer factorization cryptography, k is modulus length
  // ECC: elliptic curve cryptograpjy, f is the key length (depending on curves)
  enum class C {
    UNKNOWN,
    k112,  // not recommended in any cases (last reviewed: 2023-9)
    k128,  // default for yacl
    k192,  // not yet supported by most yacl's algorithms
    k256,  //
    INF,   // information-theorectically secure (or, unconditional security)
  };

  // convert to int
  static constexpr uint32_t MakeInt(C c);

  // Statistical Security Parameter: (from wikipedia) A measure of the
  // probability with which an adversary can break the scheme. Statistial
  // security parameter is usually used in the security proof of statistical
  // indistinguishability. The recommended value is 40, which indicates a
  // probability of 2^{-40}.
  enum class S {
    UNKNOWN,  //
    k30,      //
    k40,      // default for yacl
    k64,      //
    INF       // the adversary can not statistically guess out anything (as
              // contrary to "almost anything")
  };
  // convert s to int
  static constexpr uint32_t MakeInt(S s);

  static C glob_c;  // global computational security paramter
  static S glob_s;  // global statistical security paramter
};

// -----------------------
// Function implementaions
// -----------------------
constexpr uint32_t SecParam::MakeInt(SecParam::C c) {
  switch (c) {
    case SecParam::C::k112:
      return 112;
    case SecParam::C::k128:
      return 128;
    case SecParam::C::k192:
      return 192;
    case SecParam::C::k256:
      return 256;
    case SecParam::C::INF:
      return UINT32_MAX;
    default:
      return 0;  // this should never be called
  }
}

constexpr uint32_t SecParam::MakeInt(SecParam::S s) {
  switch (s) {
    case SecParam::S::k30:
      return 30;
    case SecParam::S::k40:
      return 40;
    case SecParam::S::k64:
      return 64;
    case SecParam::S::INF:
      return UINT32_MAX;
    default:
      return 0;  // this should never be called
  }
}

// --------------------------------
// LPN Parameter (security related)
// --------------------------------

enum class LpnNoiseAsm { RegularNoise, UniformNoise };

// For more parameter choices, see results in
// https://eprint.iacr.org/2019/273.pdf Page 20, Table 1.
class LpnParam {
 public:
  uint64_t n = 10485760;  // primal lpn, security param = 128
  uint64_t k = 452000;    // primal lpn, security param = 128
  uint64_t t = 1280;      // primal lpn, security param = 128
  LpnNoiseAsm noise_asm = LpnNoiseAsm::RegularNoise;

  LpnParam(uint64_t n, uint64_t k, uint64_t t, LpnNoiseAsm noise_asm)
      : n(n), k(k), t(t), noise_asm(noise_asm) {}

  static LpnParam GetDefault() {
    return {10485760, 452000, 1280, LpnNoiseAsm::RegularNoise};
  }
};

// --------------------------------------
// dual LPN Parameter (security related)
// --------------------------------------

// Linear Test, more details could be found in
// https://eprint.iacr.org/2022/1014.pdf Definition 2.5 bias( Reg_t^N ) equal or
// less than e^{-td/N} where t is the number of noise in dual-LPN problem, d is
// the minimum weight of vectors in dual-LPN matrix. Thus, we can view d/N as
// the minimum distance ratio for dual-LPN matrix.
//
// Implementation of GenRegNoiseWeight is mostly from:
// https://github.com/osu-crypto/libOTe/blob/master/libOTe/TwoChooseOne/ConfigureCode.cpp
// which would return the number of noise in MpVole
//
uint64_t inline GenRegNoiseWeight(double min_dist_ratio, uint64_t sec) {
  if (min_dist_ratio > 0.5 || min_dist_ratio <= 0) {
    YACL_THROW("mini distance too small, rate {}", min_dist_ratio);
  }

  auto d = std::log2(1 - 2 * min_dist_ratio);
  auto t = std::max<uint64_t>(128, -double(sec) / d);

  return math::RoundUpTo(t, 8);
}

}  // namespace yacl::crypto

// ------------------
//    Yacl module
// ------------------

// Yacl module's security parameter setup
//
// What is the boundary of Yacl's module? Note that each module's declaration
// only relect its actual security parameter if it is self-contained (which
// means it has no further module dependencies, e.g. module b)
//
//  +----------+           +------------+
//  |   main   | --------->| new module |
//  +----------+.          +------------+
//                         dec: <INF, 30>                         <128, 30>
//                               |                            [APPLICATION]
// ========================================================================
//                               |                                   [YACL]
//                               V                                <128, 40>
//  +----------+ depends on +----------+
//  | module a | ---------> | module b |
//  +----------+            +----------+
// dec: <192, 40>          dec: <128, INF>
//
template <uint32_t hash>
struct YaclModule {
  using SecParam = yacl::crypto::SecParam;
  [[maybe_unused]] static constexpr std::string_view name = "unknown";
  [[maybe_unused]] static const SecParam::C c = SecParam::C::UNKNOWN;
  [[maybe_unused]] static const SecParam::S s = SecParam::S::UNKNOWN;
};

// Yacl global registry (which is a compile-time map)
// this map only stores the unique module name hash (supposedly), and a
// compile-time interal counter which counts the number of registerd modules
struct YaclModuleCtr {};  // compile-time counter initialization (start at 0)

template <uint32_t counter>
struct YaclRegistry {
  [[maybe_unused]] static constexpr uint32_t hash = 0;
};

// Yacl module handler, which helps to print all registed module infos
class YaclModuleHandler {
 public:
  using SecParam = yacl::crypto::SecParam;

  template <uint32_t N>
  static void PrintAll() {
    fmt::print(fg(fmt::color::green), "{:-^50}\n", "module summary");
    interate_helper(std::make_integer_sequence<uint32_t, N>{}, true);
    std::string c_str = fmt::format("{}", SecParam::MakeInt(SecParam::glob_c));
    std::string s_str = fmt::format("{}", SecParam::MakeInt(SecParam::glob_s));
    if (SecParam::MakeInt(SecParam::glob_c) == UINT32_MAX) {
      c_str = "-";
    }
    if (SecParam::MakeInt(SecParam::glob_s) == UINT32_MAX) {
      s_str = "-";
    }

    fmt::print(fg(fmt::color::yellow), "{0:<10}\t{1:<5}\t{2:<5}\n", "*all*",
               c_str, s_str);
    fmt::print(fg(fmt::color::green), "{:-^50}\n", "");
  }

  template <uint32_t N>
  static std::pair<SecParam::C, SecParam::S> GetGlob() {
    interate_helper(std::make_integer_sequence<uint32_t, N>{});
    return {SecParam::glob_c, SecParam::glob_s};
  }

 private:
  template <uint32_t N>
  static void iterator(bool print) {
    using Module = YaclModule<YaclRegistry<N>::hash>;
    if (print) {
      std::string c_str = fmt::format("{}", SecParam::MakeInt(Module::c));
      std::string s_str = fmt::format("{}", SecParam::MakeInt(Module::s));
      if (SecParam::MakeInt(Module::c) == UINT32_MAX) {
        c_str = "-";
      }
      if (SecParam::MakeInt(Module::s) == UINT32_MAX) {
        s_str = "-";
      }
      fmt::print("{0:<10}\t{1:<5}\t{2:<5}\n", Module::name, c_str, s_str);
    }
    SecParam::glob_c =
        SecParam::glob_c > Module::c ? Module::c : SecParam::glob_c;
    SecParam::glob_s =
        SecParam::glob_s > Module::s ? Module::s : SecParam::glob_s;
  }

  template <uint32_t... uints>
  static void interate_helper(
      [[maybe_unused]] std::integer_sequence<uint32_t, uints...> int_seq,
      [[maybe_unused]] bool print = false) {
    ((iterator<uints>(print)), ...);
  }
};

// This macro is designed to be used by each cryptographic module in its header
// (*.h file), note that module name is *case sensitive*
//
// Please make sure your declearation is correct for this module. By
// "cryptographic" traditional, you may want to declare a security level
// assuming the existance of certain theoritical tools, but those tools in
// reality may be instantiate against comp. adversaries. You need to configure
// this for your module sine yacl will automatically performs check.
//
// Example (IKNP OT Extension)
// ----------------
// YACL_MODULE_DECLARE_SECPARAM("iknp_ote", SecParam::C::k128, SecParam::S::INF)
//
#define YACL_MODULE_DECLARE(NAME, COMP, STAT)        \
  template <>                                        \
  struct YaclModule<CT_CRC32(NAME)> {                \
    using SecParam = yacl::crypto::SecParam;         \
    static constexpr std::string_view name = NAME;   \
    static constexpr SecParam::C c = (COMP);         \
    static constexpr SecParam::S s = (STAT);         \
  };                                                 \
                                                     \
  template <>                                        \
  struct YaclRegistry<COUNTER_READ(YaclModuleCtr)> { \
    static constexpr uint32_t hash = CT_CRC32(NAME); \
  };                                                 \
  COUNTER_INC(YaclModuleCtr);

// Get module's security parameter
#define YACL_MODULE_SECPARAM_C(NAME) YaclModule<CT_CRC32(NAME)>::c
#define YACL_MODULE_SECPARAM_S(NAME) YaclModule<CT_CRC32(NAME)>::s
#define YACL_MODULE_SECPARAM_C_UINT(NAME) \
  SecParam::MakeInt(YACL_MODULE_SECPARAM_C(NAME))
#define YACL_MODULE_SECPARAM_S_UINT(NAME) \
  SecParam::MakeInt(YACL_MODULE_SECPARAM_S(NAME))

// Get yacl's global security parameter
#define YACL_GLOB_SECPARAM_C \
  YaclModuleHandler::GetGlob<COUNTER_READ(YaclModuleCtr)>().first
#define YACL_GLOB_SECPARAM_S \
  YaclModuleHandler::GetGlob<COUNTER_READ(YaclModuleCtr)>().second
#define YACL_GLOB_SECPARAM_C_UINT SecParam::MakeInt(YACL_GLOB_SECPARAM_C)
#define YACL_GLOB_SECPARAM_S_UINT SecParam::MakeInt(YACL_GLOB_SECPARAM_S)

// Print all module summary
#define YACL_PRINT_MODULE_SUMMARY() \
  YaclModuleHandler::PrintAll<COUNTER_READ(YaclModuleCtr)>()

// Enforce Yacl security level, fails when condition not met
#define YACL_ENFORCE_SECPARAM(COMP, STAT)                                    \
  YACL_ENFORCE(                                                              \
      YACL_GLOB_SECPARAM_C >= (COMP) && YACL_GLOB_SECPARAM_S >= (STAT),      \
      "Enforce SecurityParameter failed, expected c>{}, s>{}, but yacl got " \
      "global (c, s) = ({}, {})",                                            \
      SecParam::MakeInt(COMP), SecParam::MakeInt(STAT),                      \
      YACL_GLOB_SECPARAM_C_UINT, YACL_GLOB_SECPARAM_S_UINT)

// alias
using SecParam = yacl::crypto::SecParam;

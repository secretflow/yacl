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
#include <string>

#include "fmt/color.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/utils/compile_time_utils.h"

namespace yacl::crypto {

// Security parameter
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
  static constexpr uint32_t MakeInt(const C c) {
    switch (c) {
      case C::k112:
        return 112;
      case C::k128:
        return 128;
      case C::k192:
        return 192;
      case C::k256:
        return 256;
      case C::INF:
        return UINT32_MAX;
      default:
        return 0;  // this should never be called
    }
  }

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
  static constexpr uint32_t MakeInt(const S s) {
    switch (s) {
      case S::k30:
        return 30;
      case S::k40:
        return 40;
      case S::k64:
        return 64;
      case S::INF:
        return UINT32_MAX;
      default:
        return 0;  // this should never be called
    }
  }

  static C glob_c;  // global computational security paramter
  static S glob_s;  // global statistical security paramter
};

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
// ************************************************************************
//                               |                                   [YACL]
//                               V                                <128, 40>
//  +----------+ depends on +----------+
//  | module a | ---------> | module b |
//  +----------+            +----------+
// dec: <192, 40>          dec: <128, INF>
//
template <uint32_t hash>
struct YaclModule {
  [[maybe_unused]] static constexpr std::string_view name = "unknown";
  [[maybe_unused]] static const SecParam::C c = SecParam::C::UNKNOWN;
  [[maybe_unused]] static const SecParam::S s = SecParam::S::UNKNOWN;
};

// Yacl global registry (which is a compile-time map)
// this map only stores the unique module name hash (supposedly), and a
// compile-time interal counter which counts the number of registerd modules
namespace internal {
struct YaclModuleCtr {};  // compile-time counter initialization (start at 0)
}  // namespace internal

template <uint32_t counter>
struct YaclRegistry {
  [[maybe_unused]] static constexpr uint32_t hash = 0;
};

// Yacl module handler, which helps to print all registed module infos
class YaclModuleHandler {
 public:
  template <uint32_t N>
  static void PrintAll() {
    fmt::print(fg(fmt::color::green), "{:-^50}\n", "module summary");
    interate_helper(std::make_integer_sequence<uint32_t, N>{}, true);
    fmt::print(fg(fmt::color::yellow), "{0:<10}\t{1:<5}\t{2:<5}\n", "*target*",
               SecParam::MakeInt(SecParam::glob_c),
               SecParam::MakeInt(SecParam::glob_s));
    fmt::print(fg(fmt::color::green), "{:-^50}\n", "");
  }

  template <uint32_t N>
  static std::pair<SecParam::C, SecParam::S> GetGlob() {
    interate_helper(std::make_integer_sequence<uint32_t, N>{});
    return {SecParam::glob_c, SecParam::glob_s};
  }

 private:
  template <uint32_t N>
  static void iterator(bool print = false) {
    using Module = YaclModule<YaclRegistry<N>::hash>;
    if (print) {
      fmt::print("{0:<10}\t{1:<5}\t{2:<5}\n", Module::name,
                 SecParam::MakeInt(Module::c), SecParam::MakeInt(Module::s));
    }
    SecParam::glob_c =
        SecParam::glob_c > Module::c ? Module::c : SecParam::glob_c;
    SecParam::glob_s =
        SecParam::glob_s > Module::s ? Module::s : SecParam::glob_s;
  }

  template <uint32_t... uints>
  static void interate_helper(
      [[maybe_unused]] std::integer_sequence<uint32_t, uints...> int_seq,
      bool print = false) {
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
#define YACL_MODULE_DECLARE(NAME, COMP, STAT)                  \
  template <>                                                  \
  struct YaclModule<CT_CRC32(NAME)> {                          \
    static constexpr std::string_view name = NAME;             \
    static constexpr SecParam::C c = (COMP);                   \
    static constexpr SecParam::S s = (STAT);                   \
  };                                                           \
                                                               \
  template <>                                                  \
  struct YaclRegistry<COUNTER_READ(internal::YaclModuleCtr)> { \
    static constexpr uint32_t hash = CT_CRC32(NAME);           \
  };                                                           \
  COUNTER_INC(internal::YaclModuleCtr);

// Get module's security parameter
#define YACL_MODULE_SECPARAM_C(NAME) YaclModule<CT_CRC32(NAME)>::c
#define YACL_MODULE_SECPARAM_S(NAME) YaclModule<CT_CRC32(NAME)>::s
#define YACL_MODULE_SECPARAM_C_UINT(NAME) \
  SecParam::MakeInt(YaclModule<CT_CRC32(NAME)>::c)
#define YACL_MODULE_SECPARAM_S_UINT(NAME) \
  SecParam::MakeInt(YaclModule<CT_CRC32(NAME)>::s)

// Print all module summary
#define YACL_PRINT_MODULE_SUMMARY() \
  YaclModuleHandler::PrintAll<COUNTER_READ(internal::YaclModuleCtr)>();

// Enforce Yacl security level, fails when condition not met
#define YACL_ENFORCE_SECPARAM(COMP, STAT)                                     \
  YACL_ENFORCE(                                                               \
      YaclModuleHandler::GetGlob<COUNTER_READ(internal::YaclModuleCtr)>()     \
                  .first >= COMP &&                                           \
          YaclModuleHandler::GetGlob<COUNTER_READ(internal::YaclModuleCtr)>() \
                  .second >= STAT,                                            \
      "Enforce SecurityParameter failed, expected c>{}, s>{}, but yacl got "  \
      "global (c, s) = ({}, {})",                                             \
      SecParam::MakeInt(COMP), SecParam::MakeInt(STAT),                       \
      SecParam::MakeInt(                                                      \
          YaclModuleHandler::GetGlob<COUNTER_READ(internal::YaclModuleCtr)>() \
              .first),                                                        \
      SecParam::MakeInt(                                                      \
          YaclModuleHandler::GetGlob<COUNTER_READ(internal::YaclModuleCtr)>() \
              .second));

}  // namespace yacl::crypto

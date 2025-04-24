// Copyright 2024 Ant Group Co., Ltd.
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

#include "yacl/math/bigint/gmp/gmp_loader.h"

#include <dlfcn.h>
#include <spdlog/spdlog.h>

#define TO_STRING(x) #x
#define LOAD_GMPZ_FUNC(func) LoadFunc(handle_, TO_STRING(__g##func), &func##_)
#define LOAD_GMP_FUNC(func) LoadFunc(handle_, TO_STRING(__##func), &func##_)

namespace yacl::math::gmp {

GMPLoader::GMPLoader() {
#if defined(__APPLE__)
  // Try to load the macOS version of the library first
  handle_ = dlopen("libgmp.dylib", RTLD_NOW);
  if (handle_ == nullptr) {
    // Try homebrew path as fallback
    handle_ = dlopen("/usr/local/lib/libgmp.dylib", RTLD_NOW);
    if (handle_ == nullptr) {
      // Try Apple Silicon homebrew path
      handle_ = dlopen("/opt/homebrew/lib/libgmp.dylib", RTLD_NOW);
    }
  }
#else
  // Linux and other platforms
  handle_ = dlopen("libgmp.so", RTLD_NOW);
#endif

  if (handle_ == nullptr) {
    SPDLOG_INFO("GmpLoader: dlopen failed: {}", dlerror());
    return;
  }

  // clang-format off
  loaded_ = LOAD_GMPZ_FUNC(mpz_init) &&
            LOAD_GMPZ_FUNC(mpz_init2) &&
            LOAD_GMPZ_FUNC(mpz_init_set) &&
            LOAD_GMPZ_FUNC(mpz_init_set_str) &&
            LOAD_GMPZ_FUNC(mpz_init_set_si) &&
            LOAD_GMPZ_FUNC(mpz_set) &&
            LOAD_GMPZ_FUNC(mpz_set_str) &&
            LOAD_GMPZ_FUNC(mpz_set_d) &&
            LOAD_GMPZ_FUNC(mpz_set_si) &&
            LOAD_GMPZ_FUNC(mpz_set_ui) &&
            LOAD_GMPZ_FUNC(mpz_get_ui) &&
            LOAD_GMPZ_FUNC(mpz_get_d) &&
            LOAD_GMPZ_FUNC(mpz_clear) &&
            LOAD_GMPZ_FUNC(mpz_setbit) &&
            LOAD_GMPZ_FUNC(mpz_clrbit) &&
            LOAD_GMPZ_FUNC(mpz_tstbit) &&
            LOAD_GMPZ_FUNC(mpz_and) &&
            LOAD_GMPZ_FUNC(mpz_ior) &&
            LOAD_GMPZ_FUNC(mpz_xor) &&
            LOAD_GMPZ_FUNC(mpz_add) &&
            LOAD_GMPZ_FUNC(mpz_add_ui) &&
            LOAD_GMPZ_FUNC(mpz_fdiv_q) &&
            LOAD_GMPZ_FUNC(mpz_tdiv_q) &&
            LOAD_GMPZ_FUNC(mpz_fdiv_r) &&
            LOAD_GMPZ_FUNC(mpz_fdiv_q_ui) &&
            LOAD_GMPZ_FUNC(mpz_sub) &&
            LOAD_GMPZ_FUNC(mpz_sub_ui) &&
            LOAD_GMPZ_FUNC(mpz_mul) &&
            LOAD_GMPZ_FUNC(mpz_mul_ui) &&
            LOAD_GMPZ_FUNC(mpz_fdiv_ui) &&
            LOAD_GMPZ_FUNC(mpz_neg) &&
            LOAD_GMPZ_FUNC(mpz_abs) &&
            LOAD_GMPZ_FUNC(mpz_cmp) &&
            LOAD_GMPZ_FUNC(mpz_cmp_si) &&
            LOAD_GMPZ_FUNC(mpz_cmpabs) &&
            LOAD_GMPZ_FUNC(mpz_cmpabs_ui) &&
            LOAD_GMPZ_FUNC(mpz_lcm) &&
            LOAD_GMPZ_FUNC(mpz_gcd) &&
            LOAD_GMPZ_FUNC(mpz_get_str) &&
            LOAD_GMPZ_FUNC(mpz_swap) &&
            LOAD_GMPZ_FUNC(mpz_mul_2exp) &&
            LOAD_GMPZ_FUNC(mpz_tdiv_q_2exp) &&
            LOAD_GMPZ_FUNC(mpz_invert) &&
            LOAD_GMPZ_FUNC(mpz_pow_ui) &&
            LOAD_GMPZ_FUNC(mpz_powm) &&
            LOAD_GMPZ_FUNC(mpz_urandomb) &&
            LOAD_GMPZ_FUNC(mpz_urandomm) &&
            LOAD_GMPZ_FUNC(mpz_nextprime) &&
            LOAD_GMPZ_FUNC(mpz_size) &&
            LOAD_GMPZ_FUNC(mpz_sizeinbase) &&
            LOAD_GMPZ_FUNC(mpz_getlimbn) &&
            LOAD_GMPZ_FUNC(mpz_limbs_read) &&
            LOAD_GMPZ_FUNC(mpz_limbs_modify) &&
            LOAD_GMPZ_FUNC(mpz_limbs_finish) &&
            LOAD_GMPZ_FUNC(mpz_import) &&
            LOAD_GMPZ_FUNC(mpz_export) &&
            LOAD_GMPZ_FUNC(mpz_probab_prime_p) &&
            LOAD_GMP_FUNC(gmp_randinit_default) &&
            LOAD_GMP_FUNC(gmp_randclear);
  // clang-format on

  if (!loaded_ || !IsUsing64BitNumbs()) {
    dlclose(handle_);
    handle_ = nullptr;
    loaded_ = false;
  }
}

GMPLoader::~GMPLoader() {  // NOLINT
  // Not calling dlclose here to avoid unloading the library. This is because
  // static objects may still be using the library.
}

template <typename FUNC_PTR_TYPE>
bool GMPLoader::LoadFunc(void* handle, const char* func_name,
                         FUNC_PTR_TYPE* func_ptr) {
  *func_ptr = reinterpret_cast<FUNC_PTR_TYPE>(dlsym(handle, func_name));
  if (*func_ptr == nullptr) {
    SPDLOG_ERROR("Failed to load gmp function {}", func_name);
    return false;
  }
  return true;
}

bool GMPLoader::IsUsing64BitNumbs() const {
  mpz_t z;
  mpz_init_set_str_(z, "18446744073709551615", 10);
  const size_t limbs = mpz_size_(z);
  mpz_clear_(z);
  if (limbs != 1) {
    SPDLOG_WARN("GMP is not using 64-bit numbs");
    return false;
  }
  return true;
}

}  // namespace yacl::math::gmp

#undef LOAD_GMP_FUNC
#undef LOAD_GMPZ_FUNC
#undef TO_STRING

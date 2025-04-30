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

#pragma once

#include <gmp.h>

#define DECLARE_FUNC(func, new_name) decltype(&func) new_name = nullptr;
#define DECLARE_GMP_FUNC(func) DECLARE_FUNC(func, func##_)

namespace yacl::math::gmp {

class GMPLoader {
 public:
  ~GMPLoader();

  GMPLoader(const GMPLoader&) = delete;
  GMPLoader& operator=(const GMPLoader&) = delete;
  GMPLoader(GMPLoader&&) = delete;
  GMPLoader& operator=(GMPLoader&&) = delete;

  bool IsLoaded() const { return loaded_; }

  static GMPLoader& Instance() {
    static GMPLoader instance;
    return instance;
  }

  DECLARE_GMP_FUNC(mpz_init)
  DECLARE_GMP_FUNC(mpz_init2)
  DECLARE_GMP_FUNC(mpz_init_set)
  DECLARE_GMP_FUNC(mpz_init_set_str)
  DECLARE_GMP_FUNC(mpz_init_set_si)
  DECLARE_GMP_FUNC(mpz_set)
  DECLARE_GMP_FUNC(mpz_set_str)
  DECLARE_GMP_FUNC(mpz_set_d)
  DECLARE_GMP_FUNC(mpz_set_si)
  DECLARE_GMP_FUNC(mpz_set_ui)
  DECLARE_GMP_FUNC(mpz_get_ui)
  DECLARE_GMP_FUNC(mpz_get_d)
  DECLARE_GMP_FUNC(mpz_clear)
  DECLARE_GMP_FUNC(mpz_setbit)
  DECLARE_GMP_FUNC(mpz_clrbit)
  DECLARE_GMP_FUNC(mpz_tstbit)
  DECLARE_GMP_FUNC(mpz_and)
  DECLARE_GMP_FUNC(mpz_ior)
  DECLARE_GMP_FUNC(mpz_xor)
  DECLARE_GMP_FUNC(mpz_add)
  DECLARE_GMP_FUNC(mpz_add_ui)
  DECLARE_GMP_FUNC(mpz_sub)
  DECLARE_GMP_FUNC(mpz_sub_ui)
  DECLARE_GMP_FUNC(mpz_mul)
  DECLARE_GMP_FUNC(mpz_mul_ui)
  DECLARE_GMP_FUNC(mpz_fdiv_q)
  DECLARE_GMP_FUNC(mpz_tdiv_q)
  DECLARE_GMP_FUNC(mpz_fdiv_r)
  DECLARE_GMP_FUNC(mpz_fdiv_q_ui)
  DECLARE_GMP_FUNC(mpz_fdiv_ui)
  DECLARE_GMP_FUNC(mpz_neg)
  DECLARE_GMP_FUNC(mpz_abs)
  DECLARE_GMP_FUNC(mpz_cmp)
  DECLARE_FUNC(_mpz_cmp_si, mpz_cmp_si_)
  DECLARE_GMP_FUNC(mpz_cmpabs)
  DECLARE_GMP_FUNC(mpz_cmpabs_ui)
  DECLARE_GMP_FUNC(mpz_lcm)
  DECLARE_GMP_FUNC(mpz_gcd)
  DECLARE_GMP_FUNC(mpz_get_str)
  DECLARE_GMP_FUNC(mpz_swap)
  DECLARE_GMP_FUNC(mpz_mul_2exp)
  DECLARE_GMP_FUNC(mpz_tdiv_q_2exp)
  DECLARE_GMP_FUNC(mpz_invert)
  DECLARE_GMP_FUNC(mpz_pow_ui)
  DECLARE_GMP_FUNC(mpz_powm)
  DECLARE_GMP_FUNC(mpz_urandomb)
  DECLARE_GMP_FUNC(mpz_urandomm)
  DECLARE_GMP_FUNC(mpz_nextprime)
  DECLARE_GMP_FUNC(mpz_size)
  DECLARE_GMP_FUNC(mpz_sizeinbase)
  DECLARE_GMP_FUNC(mpz_getlimbn)
  DECLARE_GMP_FUNC(mpz_limbs_read)
  DECLARE_GMP_FUNC(mpz_limbs_modify)
  DECLARE_GMP_FUNC(mpz_limbs_finish)
  DECLARE_GMP_FUNC(mpz_import)
  DECLARE_GMP_FUNC(mpz_export)
  DECLARE_GMP_FUNC(mpz_probab_prime_p)
  DECLARE_GMP_FUNC(gmp_randinit_default)
  DECLARE_GMP_FUNC(gmp_randclear)

 private:
  GMPLoader();

  template <typename FUNC_PTR_TYPE>
  static bool LoadFunc(void* handle, const char* func_name,
                       FUNC_PTR_TYPE* func_ptr);

  bool IsUsing64BitNumbs() const;

  void* handle_ = nullptr;

  bool loaded_ = false;
};

}  // namespace yacl::math::gmp

#undef DECLARE_GMP_FUNC
#undef DECLARE_FUNC

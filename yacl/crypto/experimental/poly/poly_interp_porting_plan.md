# poly-interp -> yacl::crypto::experimental::poly (Porting Plan)

This document lists the concrete (file/symbol-level) changes needed to merge
`poly-interp` (prime-field + polynomial ops + fast interpolation) into
`yacl/crypto/experimental/poly/`.

Scope decisions (per request)
- Destination: `yacl/crypto/experimental/poly/`
- Keep GMP acceleration path
- Follow YACL conventions: Bazel BUILD, naming style, `YACL_ENFORCE` / `YACL_THROW_*`

---

## 1) New files to add under yacl

Create directory
- [x] `yacl/crypto/experimental/poly/`

Core headers (rename from `.hpp` -> `.h` and adopt `#pragma once`)
- [x] `yacl/crypto/experimental/poly/prime_field.h`
  - Source: `poly-interp/include/poly_interp/prime_field.hpp`
- [x] `yacl/crypto/experimental/poly/fp_poly.h`
  - Source: `poly-interp/include/poly_interp/fp_poly.hpp`

Build + tests
- [x] `yacl/crypto/experimental/poly/BUILD.bazel`
- [x] `yacl/crypto/experimental/poly/prime_field_test.cc` (optional but recommended)
- [x] `yacl/crypto/experimental/poly/fp_poly_test.cc` (optional but recommended)
- [x] `yacl/crypto/experimental/poly/interp_correctness_test.cc` (optional but recommended)

Changelog
- [x] `CHANGELOG.md` add an entry (new feature in `yacl::...` non-anonymous namespace)

Notes
- Markdown files are ignored by yacl's license checker, but all new `.h/.cc` must
  carry the Apache-2.0 header (see `yacl/base/*.h` for the exact format).

---

## 2) Bazel BUILD integration (exact target sketch)

Add `yacl/crypto/experimental/poly/BUILD.bazel` with targets:

- `yacl_cc_library(name = "poly", hdrs = ["prime_field.h", "fp_poly.h"], deps = [...])`
- If GMP path is kept, add conditional deps/defines:
  - [x] `defines = select({"@yacl//bazel/config:gmp": ["BIGNUM_WITH_GMP"], "//conditions:default": []})`
  - [x] `deps += select({"//bazel/config:gmp": ["//yacl/math/bigint/gmp:gmp_loader"], "//conditions:default": []})`

Why `BIGNUM_WITH_GMP`?
- YACL already uses it as the canonical build knob for GMP (see
  `//bazel/config:gmp` and `yacl/math/bigint/*`). Reusing it avoids introducing a
  new flag like `PI_HAVE_GMP`.

Tests
- [x] Add `yacl_cc_test` targets for the three tests above (deps include
  `:poly` + `@googletest//:gtest_main` is already injected by `yacl_cc_test`).

---

## 3) Naming + namespace changes (symbol-level)

### 3.1 Namespaces

Current
- `namespace pf { ... }`

Change to
- [x] `namespace yacl::crypto::experimental::poly { ... }`

`detail` namespace
- [x] keep internal helpers under `namespace internal { ... }` or `namespace detail { ... }`
  but **inside** `yacl::crypto::experimental::poly`.

### 3.2 Types and public API names

YACL style uses CamelCase types and CamelBack methods.

Prime field (`prime_field.h`)
- [x] `struct Fp` -> `class Fp` or keep `struct Fp` (OK), but ensure naming
  matches readability checks.
- [x] `struct FpCtx` -> rename to `FpContext` (recommended) OR `PrimeField`.
- [x] Method renames on context:
  - `modulus()` -> `GetModulus()`
  - `zero()` -> `Zero()`
  - `one()` -> `One()`
  - `from_uint()` -> `FromUint64()`
  - `from_int()` -> `FromInt64()`
  - `is_zero()` -> `IsZero()`
  - `eq()` -> `Equal()`
  - `add/sub/neg/mul/sqr/addmul/pow/inv/div` -> `Add/Sub/Neg/Mul/Sqr/AddMul/Pow/Inv/Div`
  - `batch_inv()` -> `BatchInv()`

Polynomial (`fp_poly.h`)
- [x] `class FpPoly` -> rename to `FpPolynomial` (recommended) or `Poly`
- [x] `SubproductTree` keep as nested `struct SubproductTree` (OK) but ensure
  method names CamelBack:
  - `build()` -> `Build()`
  - `n_points()` -> `NumPoints()`
  - `n_levels()` -> `NumLevels()`

Operators
- [x] Keep arithmetic operators if desired (`operator+/*/...`), but consider
  adding explicit named methods (YACL code often prefers named methods for
  clarity).

Debug printing
- [x] Remove `operator<<` overloads from headers OR gate them behind a macro
  (to avoid dragging `<ostream>` into most dependents). Prefer `ToString()`.

---

## 4) Exception / enforce style changes (exact replacements)

Replace direct `throw std::...` checks with YACL helpers.

In `prime_field.h`
- [x] `throw std::invalid_argument(...)` -> `YACL_THROW_ARGUMENT_ERROR(...)` or `YACL_ENFORCE(...)`
- [x] `throw std::domain_error("inverse of zero")` -> `YACL_ENFORCE(!IsZero(a), ...)`

In `fp_poly.h`
- [x] `throw std::logic_error(...)` and `throw std::invalid_argument(...)` in
  `require_ctx()/require_compat()/leading_coeff()/divrem/mod/...` -> `YACL_ENFORCE` / `YACL_THROW_ARGUMENT_ERROR`

Include needed headers
- [x] Add `#include "yacl/base/exception.h"` in any file using YACL macros.

Guideline
- For programming errors / invariants: `YACL_ENFORCE` is fine.
- For user input errors: prefer `YACL_THROW_ARGUMENT_ERROR`.

---

## 5) GMP acceleration path (keep it, but make it YACL-compatible)

### 5.1 Macro / feature flag

Current
- `#ifdef PI_HAVE_GMP`

Change to
- [x] `#ifdef BIGNUM_WITH_GMP` (same flag used in yacl's bigint GMP backend)

### 5.2 Linking model mismatch (important)

`poly-interp` currently calls `mpn_mul/mpn_mul_n/mpn_sqr` directly.

In YACL, GMP is typically accessed via `dlopen` + function pointers (see
`yacl/math/bigint/gmp/gmp_loader.*`) and does **not** link `-lgmp` by default.

You must pick one of the following integration strategies:

Option A (lowest integration cost; "GMP-accelerated", not "mpn-fast")
- [x] Rewrite the Kronecker path to use only `mpz_*` APIs (multiply via
  `mpz_mul`), and call them through `yacl::math::gmp::GMPLoader` function
  pointers (or via existing `GMPInt` wrapper).
- Pros: no changes to `gmp_loader`, no `-lgmp` link requirement.
- Cons: slower than raw `mpn_*`.

Option B (keep current mpn speed; recommended if performance matters)
- [ ] Extend `yacl/math/bigint/gmp/gmp_loader.h/.cc` to also load the needed
  `__gmpn_*` symbols as function pointers:
  - `mpn_mul_`, `mpn_mul_n_`, `mpn_sqr_` (and any other mpn calls you keep)
- [ ] Change the poly Kronecker implementation to call these function pointers
  instead of direct `mpn_*` calls.
- Pros: preserves your current fast path; still no explicit `-lgmp` link.
- Cons: requires touching shared YACL GMP loader; needs careful symbol name
  mapping and runtime checks.

Option C (explicitly link libgmp)
- [ ] Add Bazel `linkopts = ["-lgmp"]` (and platform-specific handling) for the
  poly library/targets when GMP is enabled.
- Pros: easiest code-wise.
- Cons: diverges from YACL's current GMP policy (dlopen) and complicates
  portability.

Recommendation
- Prefer Option B if you care about the original mpn-based speed.
- Otherwise Option A is acceptable and simpler.

---

## 6) Compiler / portability alignment

YACL platform matrix
- GCC/Clang are supported; MSVC is not (see README).

Your code assumptions to keep/adjust
- [x] Keep `unsigned __int128` requirement; prefer reusing `yacl/base/int128.h`
  typedefs (`uint128_t`) instead of defining your own `u128`.
- [x] Replace builtin bit ops with Abseil where convenient:
  - `__builtin_clzll` -> `absl::countl_zero`
  - `__builtin_ctz` -> `absl::countr_zero`
  This avoids compiler-specific builtins and matches yacl style.

---

## 7) Header hygiene and -Werror readiness

YACL builds with `-Wall -Wextra -Werror` via `yacl_cc_library`.

Apply these cleanups
- [x] Remove duplicate includes (e.g., `fp_poly.hpp` includes `<vector>` twice).
- [x] Remove unused includes (e.g., `<functional>` appears unused).
- [x] Avoid `using namespace ...` in headers (clang-tidy `google-build-using-namespace`).
- [x] Avoid non-`constexpr` globals in headers.
- [x] Ensure all `static thread_local` caches are in unnamed/internal namespace
  and have internal linkage.

---

## 8) API placement inside yacl

Where to expose it
- [x] Public headers under `yacl/crypto/experimental/poly/*.h` are fine.
- [x] If you expect other repos to depend on it, add tests and document the
  stability expectations (experimental APIs can change).

---

## 9) Minimal symbol mapping cheat-sheet

For quick ref while porting:

Prime field
- `pf::Fp` -> `yacl::crypto::experimental::poly::Fp`
- `pf::FpCtx` -> `...::FpContext` (recommended)

Polynomial
- `pf::FpPoly` -> `...::FpPolynomial` (recommended)
- `FpPoly::SubproductTree` -> `FpPolynomial::SubproductTree`

Build flag
- `PI_HAVE_GMP` -> `BIGNUM_WITH_GMP`

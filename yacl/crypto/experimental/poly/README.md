# yacl/crypto/experimental/poly

This directory contains **experimental** prime-field and polynomial utilities:

- Prime field: `prime_field.h` (`Fp`, `FpContext`)
- Polynomial + interpolation: `fp_poly.h` (`FpPolynomial`)

## Code layout

`FpPolynomial` is declared in `fp_poly.h` and implemented across multiple `.cc`
files to keep each piece focused:

- `fp_poly.cc`: core polynomial utilities (constructors, add/sub/eval, etc.)
- `fp_poly_mul.cc`: multiplication backends (naive / NTT+CRT, optional GMP)
- `fp_poly_div.cc`: division/mod and series inversion helpers
- `fp_poly_interp.cc`: subproduct tree, multipoint evaluation, interpolation

## Stability

These headers live under `yacl/crypto/experimental/`, so the API is **not**
considered stable and may change without notice.

## Bazel

- Library: `//yacl/crypto/experimental/poly:poly`
- Tests:
  - `//yacl/crypto/experimental/poly:prime_field_test`
  - `//yacl/crypto/experimental/poly:fp_poly_test`
  - `//yacl/crypto/experimental/poly:interp_correctness_test`

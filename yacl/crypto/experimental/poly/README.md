# yacl/crypto/experimental/poly

This directory contains **experimental** prime-field and polynomial utilities:

- Prime field: `prime_field.h` (`Fp`, `FpContext`)
- Polynomial + interpolation: `fp_poly.h` (`FpPolynomial`)

## Stability

These headers live under `yacl/crypto/experimental/`, so the API is **not**
considered stable and may change without notice.

## Bazel

- Library: `//yacl/crypto/experimental/poly:poly`
- Tests:
  - `//yacl/crypto/experimental/poly:prime_field_test`
  - `//yacl/crypto/experimental/poly:fp_poly_test`
  - `//yacl/crypto/experimental/poly:interp_correctness_test`


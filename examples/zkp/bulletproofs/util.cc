#include "zkp/bulletproofs/util.h"

#include <stdexcept> // For std::runtime_error
#include "yacl/base/exception.h" // For YACL_ENFORCE
#include "absl/types/span.h" // For absl::Span
#include <limits> // Include for std::numeric_limits

namespace examples::zkp {

// Helper to zero MPInt safely
inline void SecureZeroMPInt(MPInt& mp) {
    // MPInt lacks a direct secure clear. Setting to zero is the best effort.
    mp.Set(0);
}

// --- VecPoly1 Implementation ---
VecPoly1::VecPoly1(std::vector<MPInt> a_vec, std::vector<MPInt> b_vec)
    : a(std::move(a_vec)), b(std::move(b_vec)) {}

VecPoly1::~VecPoly1() {
    for (auto& mp : a) { SecureZeroMPInt(mp); }
    for (auto& mp : b) { SecureZeroMPInt(mp); }
}

VecPoly1 VecPoly1::Zero(size_t n) {
    return VecPoly1(std::vector<MPInt>(n), std::vector<MPInt>(n));
}

std::vector<MPInt> VecPoly1::Eval(const MPInt& x) const {
    size_t n = a.size();
    YACL_ENFORCE(n == b.size(), "Vector sizes must match");
    std::vector<MPInt> result(n);
    for (size_t i = 0; i < n; ++i) {
        // result[i] = a[i] + b[i] * x
        result[i] = a[i] + (b[i] * x);
    }
    return result;
}

// Note: Karatsuba method needs modular arithmetic applied carefully.
Poly2 VecPoly1::InnerProduct(const VecPoly1& rhs, const MPInt& order) const {
    const VecPoly1& lhs = *this;
    YACL_ENFORCE(lhs.a.size() == rhs.a.size() && lhs.b.size() == rhs.b.size() &&
                 lhs.a.size() == lhs.b.size(), "Vector sizes must match");

    MPInt t0 = examples::zkp::InnerProduct(lhs.a, rhs.a, order);
    MPInt t2 = examples::zkp::InnerProduct(lhs.b, rhs.b, order);

    auto l0_plus_l1 = AddVectors(lhs.a, lhs.b, order);
    auto r0_plus_r1 = AddVectors(rhs.a, rhs.b, order);

    MPInt t1_plus_t0_plus_t2 = examples::zkp::InnerProduct(l0_plus_l1, r0_plus_r1, order);

    // t1 = (t1 + t0 + t2) - t0 - t2
    MPInt t1;
    MPInt::SubMod(t1_plus_t0_plus_t2, t0, order, &t1);
    MPInt::SubMod(t1, t2, order, &t1);

    return Poly2(t0, t1, t2);
}

// --- Poly2 Implementation ---
Poly2::Poly2(MPInt a_val, MPInt b_val, MPInt c_val)
    : a(std::move(a_val)), b(std::move(b_val)), c(std::move(c_val)) {}

Poly2::~Poly2() {
    SecureZeroMPInt(a);
    SecureZeroMPInt(b);
    SecureZeroMPInt(c);
}

MPInt Poly2::Eval(const MPInt& x, const MPInt& order) const {
    // Compute a + b*x + c*x^2 mod order using Horner's method
    // result = c*x + b
    MPInt result;
    MPInt::MulMod(c, x, order, &result);
    MPInt::AddMod(result, b, order, &result);
    // result = result*x + a
    MPInt::MulMod(result, x, order, &result);
    MPInt::AddMod(result, a, order, &result);
    return result;
}

#ifdef YACL_ENABLE_YOLOPROOFS
// --- VecPoly3 Implementation ---
VecPoly3::VecPoly3(std::vector<MPInt> a_vec, std::vector<MPInt> b_vec,
                 std::vector<MPInt> c_vec, std::vector<MPInt> d_vec)
    : a(std::move(a_vec)), b(std::move(b_vec)), c(std::move(c_vec)), d(std::move(d_vec)) {}

VecPoly3::~VecPoly3() {
    for (auto& mp : a) { SecureZeroMPInt(mp); }
    for (auto& mp : b) { SecureZeroMPInt(mp); }
    for (auto& mp : c) { SecureZeroMPInt(mp); }
    for (auto& mp : d) { SecureZeroMPInt(mp); }
}

VecPoly3 VecPoly3::Zero(size_t n) {
    return VecPoly3(std::vector<MPInt>(n), std::vector<MPInt>(n),
                    std::vector<MPInt>(n), std::vector<MPInt>(n));
}

std::vector<MPInt> VecPoly3::Eval(const MPInt& x, const MPInt& order) const {
    size_t n = a.size();
    YACL_ENFORCE(b.size() == n && c.size() == n && d.size() == n, "Vector sizes must match");
    std::vector<MPInt> result(n);
    MPInt x2, x3, temp1, temp2, temp3;
    MPInt::MulMod(x, x, order, &x2);
    MPInt::MulMod(x2, x, order, &x3);

    for (size_t i = 0; i < n; ++i) {
        // result[i] = a[i] + b[i]*x + c[i]*x^2 + d[i]*x^3
        MPInt::MulMod(b[i], x, order, &temp1);  // b*x
        MPInt::MulMod(c[i], x2, order, &temp2); // c*x^2
        MPInt::MulMod(d[i], x3, order, &temp3); // d*x^3
        MPInt::AddMod(a[i], temp1, order, &result[i]); // a + b*x
        MPInt::AddMod(result[i], temp2, order, &result[i]); // + c*x^2
        MPInt::AddMod(result[i], temp3, order, &result[i]); // + d*x^3
    }
    return result;
}

Poly6 VecPoly3::SpecialInnerProduct(const VecPoly3& rhs, const MPInt& order) const {
    const VecPoly3& lhs = *this;
    // TODO: Add checks that lhs.a and rhs.c are zero if strictly needed.
    YACL_ENFORCE(lhs.b.size() == rhs.a.size() /* && other sizes match */, "Vector sizes must match");

    MPInt t1 = examples::zkp::InnerProduct(lhs.b, rhs.a, order);
    MPInt t2 = examples::zkp::InnerProduct(lhs.b, rhs.b, order);
    MPInt::AddMod(t2, examples::zkp::InnerProduct(lhs.c, rhs.a, order), order, &t2);
    MPInt t3 = examples::zkp::InnerProduct(lhs.c, rhs.b, order);
    MPInt::AddMod(t3, examples::zkp::InnerProduct(lhs.d, rhs.a, order), order, &t3);
    MPInt t4 = examples::zkp::InnerProduct(lhs.b, rhs.d, order);
    MPInt::AddMod(t4, examples::zkp::InnerProduct(lhs.d, rhs.b, order), order, &t4);
    MPInt t5 = examples::zkp::InnerProduct(lhs.c, rhs.d, order);
    MPInt t6 = examples::zkp::InnerProduct(lhs.d, rhs.d, order);

    return Poly6(t1, t2, t3, t4, t5, t6);
}

// --- Poly6 Implementation ---
Poly6::Poly6(MPInt t1_val, MPInt t2_val, MPInt t3_val, MPInt t4_val, MPInt t5_val, MPInt t6_val)
    : t1(std::move(t1_val)), t2(std::move(t2_val)), t3(std::move(t3_val)),
      t4(std::move(t4_val)), t5(std::move(t5_val)), t6(std::move(t6_val)) {}

Poly6::~Poly6() {
    SecureZeroMPInt(t1);
    SecureZeroMPInt(t2);
    SecureZeroMPInt(t3);
    SecureZeroMPInt(t4);
    SecureZeroMPInt(t5);
    SecureZeroMPInt(t6);
}

MPInt Poly6::Eval(const MPInt& x, const MPInt& order) const {
    // Evaluate t1*x + t2*x^2 + ... + t6*x^6 using Horner's method
    MPInt result = t6;
    MPInt::MulMod(result, x, order, &result);
    MPInt::AddMod(result, t5, order, &result); // t6*x + t5
    MPInt::MulMod(result, x, order, &result);
    MPInt::AddMod(result, t4, order, &result); // (t6*x + t5)*x + t4
    MPInt::MulMod(result, x, order, &result);
    MPInt::AddMod(result, t3, order, &result); // ... *x + t3
    MPInt::MulMod(result, x, order, &result);
    MPInt::AddMod(result, t2, order, &result); // ... *x + t2
    MPInt::MulMod(result, x, order, &result);
    MPInt::AddMod(result, t1, order, &result); // ... *x + t1
    MPInt::MulMod(result, x, order, &result); // * x
    return result;
}
#endif // YACL_ENABLE_YOLOPROOFS

// --- Standalone Utility Functions Implementations ---

MPInt InnerProduct(const absl::Span<const MPInt>& a,
                   const absl::Span<const MPInt>& b,
                   const MPInt& order) {
    YACL_ENFORCE(a.size() == b.size(), "Vectors must have the same size");
    MPInt result(0);
    MPInt term;
    for (size_t i = 0; i < a.size(); ++i) {
        MPInt::MulMod(a[i], b[i], order, &term);
        MPInt::AddMod(result, term, order, &result);
    }
    return result;
}

std::vector<MPInt> AddVectors(const absl::Span<const MPInt>& a,
                              const absl::Span<const MPInt>& b,
                              const MPInt& order) {
    YACL_ENFORCE(a.size() == b.size(), "Vectors must have the same size");
    std::vector<MPInt> result(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        MPInt::AddMod(a[i], b[i], order, &result[i]);
    }
    return result;
}

std::vector<MPInt> Powers(const MPInt& x, size_t n, const MPInt& order) {
    std::vector<MPInt> result(n);
    if (n == 0) {
        return result;
    }
    result[0].Set(1);
    for (size_t i = 1; i < n; ++i) {
        MPInt::MulMod(result[i - 1], x, order, &result[i]);
    }
    return result;
}

// Make SumOfPowersOptimized static as it's an internal helper
static MPInt SumOfPowersOptimized(const MPInt& x, size_t n, const MPInt& order) {
    YACL_ENFORCE(n > 0 && (n & (n - 1)) == 0, "n must be a power of 2");
    if (n == 1) {
        return MPInt(1);
    }
    MPInt result;
    result.Set(1);
    MPInt::AddMod(result, x, order, &result); // 1 + x

    MPInt factor = x;
    size_t m = n;
    while (m > 2) {
        MPInt factor_sq;
        MPInt::MulMod(factor, factor, order, &factor_sq); // factor^2
        MPInt term;
        MPInt::MulMod(result, factor_sq, order, &term);
        MPInt::AddMod(result, term, order, &result);
        factor = factor_sq;
        m /= 2;
    }
    return result;
}

MPInt SumOfPowers(const MPInt& x, size_t n, const MPInt& order) {
    if (n == 0) {
        return MPInt(0);
    }
    // Check if n is a power of 2 using bitwise trick
    if ((n & (n - 1)) == 0) {
        return SumOfPowersOptimized(x, n, order);
    } else {
        // Slow version for non-power-of-2 n
        std::vector<MPInt> powers = Powers(x, n, order);
        MPInt result(0);
        for (const auto& p : powers) {
            MPInt::AddMod(result, p, order, &result);
        }
        return result;
    }
}

MPInt ScalarExpVartime(const MPInt& x, uint64_t n) {
    MPInt result;
    // Check if n fits within uint32_t
    YACL_ENFORCE(n <= std::numeric_limits<uint32_t>::max(),
                 "Exponent too large for MPInt::Pow");
    // Cast n to uint32_t for the correct MPInt::Pow overload
    MPInt::Pow(x, static_cast<uint32_t>(n), &result);
    return result;
}

} // namespace examples::zkp 
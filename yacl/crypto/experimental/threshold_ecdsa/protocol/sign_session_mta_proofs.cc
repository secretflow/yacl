#include "yacl/crypto/experimental/threshold_ecdsa/protocol/sign_session_internal.h"

#include <optional>

#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"

namespace tecdsa::sign_internal {
A1RangeProof ProveA1Range(const MtaProofContext& ctx,
                          const BigInt& n,
                          const AuxRsaParams& verifier_aux,
                          const BigInt& c,
                          const BigInt& witness_m,
                          const BigInt& witness_r) {
  const BigInt n2 = n * n;
  const BigInt gamma = n + BigInt(1);
  const BigInt n_tilde = verifier_aux.n_tilde;
  const BigInt h1 = verifier_aux.h1;
  const BigInt h2 = verifier_aux.h2;
  const BigInt q_mul_n_tilde = Scalar::ModulusQMpInt() * n_tilde;
  const BigInt q3_mul_n_tilde = QPow3() * n_tilde;

  while (true) {
    const BigInt alpha = RandomBelow(QPow3());
    const BigInt beta = SampleZnStar(n);
    const BigInt gamma_rand = RandomBelow(q3_mul_n_tilde);
    const BigInt rho = RandomBelow(q_mul_n_tilde);

    const BigInt z = MulMod(PowMod(h1, witness_m, n_tilde), PowMod(h2, rho, n_tilde), n_tilde);
    const BigInt u = MulMod(PowMod(gamma, alpha, n2), PowMod(beta, n, n2), n2);
    const BigInt w = MulMod(PowMod(h1, alpha, n_tilde), PowMod(h2, gamma_rand, n_tilde), n_tilde);

    const Scalar e_scalar = BuildA1RangeChallenge(ctx, n, gamma, verifier_aux, c, z, u, w);
    const BigInt e = e_scalar.mp_value();
    const BigInt s = MulMod(PowMod(witness_r, e, n), beta, n);
    const BigInt s1 = (e * witness_m) + alpha;
    const BigInt s2 = (e * rho) + gamma_rand;
    if (s1 > QPow3()) {
      continue;
    }

    return A1RangeProof{
        .z = z,
        .u = u,
        .w = w,
        .s = s,
        .s1 = s1,
        .s2 = s2,
    };
  }
}

bool VerifyA1Range(const MtaProofContext& ctx,
                   const BigInt& n,
                   const AuxRsaParams& verifier_aux,
                   const BigInt& c,
                   const A1RangeProof& proof) {
  const BigInt n2 = n * n;
  const BigInt gamma = n + BigInt(1);
  const BigInt n_tilde = verifier_aux.n_tilde;
  const BigInt h1 = verifier_aux.h1;
  const BigInt h2 = verifier_aux.h2;

  if (!IsInRange(c, n2) || !IsInRange(proof.u, n2) ||
      !IsInRange(proof.z, n_tilde) ||
      !IsInRange(proof.w, n_tilde) ||
      !IsZnStarElement(proof.s, n)) {
    return false;
  }
  if (proof.s1 < 0 || proof.s1 > QPow3()) {
    return false;
  }
  if (proof.s2 < 0) {
    return false;
  }

  const Scalar e_scalar = BuildA1RangeChallenge(ctx, n, gamma, verifier_aux, c, proof.z, proof.u, proof.w);
  const BigInt e = e_scalar.mp_value();

  const BigInt c_pow_e = PowMod(c, e, n2);
  const std::optional<BigInt> c_pow_e_inv = InvertMod(c_pow_e, n2);
  if (!c_pow_e_inv.has_value()) {
    return false;
  }

  BigInt rhs_u = MulMod(PowMod(gamma, proof.s1, n2), PowMod(proof.s, n, n2), n2);
  rhs_u = MulMod(rhs_u, *c_pow_e_inv, n2);
  if (NormalizeMod(proof.u, n2) != rhs_u) {
    return false;
  }

  const BigInt lhs_n_tilde = MulMod(PowMod(h1, proof.s1, n_tilde), PowMod(h2, proof.s2, n_tilde), n_tilde);
  const BigInt rhs_n_tilde = MulMod(proof.w, PowMod(proof.z, e, n_tilde), n_tilde);
  return lhs_n_tilde == rhs_n_tilde;
}

A2MtAwcProof ProveA2MtAwc(const MtaProofContext& ctx,
                          const BigInt& n,
                          const AuxRsaParams& verifier_aux,
                          const BigInt& c1,
                          const BigInt& c2,
                          const ECPoint& statement_x,
                          const BigInt& witness_x,
                          const BigInt& witness_y,
                          const BigInt& witness_r) {
  const BigInt n2 = n * n;
  const BigInt gamma = n + BigInt(1);
  const BigInt n_tilde = verifier_aux.n_tilde;
  const BigInt h1 = verifier_aux.h1;
  const BigInt h2 = verifier_aux.h2;
  const BigInt q_mul_n_tilde = Scalar::ModulusQMpInt() * n_tilde;
  const BigInt q3_mul_n_tilde = QPow3() * n_tilde;

  while (true) {
    const BigInt alpha = RandomBelow(QPow3());
    const Scalar alpha_scalar(alpha);
    if (alpha_scalar.value() == 0) {
      continue;
    }

    const BigInt rho = RandomBelow(q_mul_n_tilde);
    const BigInt rho2 = RandomBelow(q3_mul_n_tilde);
    const BigInt sigma = RandomBelow(q_mul_n_tilde);
    const BigInt beta = SampleZnStar(n);
    const BigInt gamma_rand = RandomBelow(QPow7());
    const BigInt tau = RandomBelow(q3_mul_n_tilde);

    const ECPoint u = ECPoint::GeneratorMultiply(alpha_scalar);
    const BigInt z = MulMod(PowMod(h1, witness_x, n_tilde), PowMod(h2, rho, n_tilde), n_tilde);
    const BigInt z2 = MulMod(PowMod(h1, alpha, n_tilde), PowMod(h2, rho2, n_tilde), n_tilde);
    const BigInt t = MulMod(PowMod(h1, witness_y, n_tilde), PowMod(h2, sigma, n_tilde), n_tilde);

    BigInt v = MulMod(PowMod(c1, alpha, n2), PowMod(gamma, gamma_rand, n2), n2);
    v = MulMod(v, PowMod(beta, n, n2), n2);
    const BigInt w = MulMod(PowMod(h1, gamma_rand, n_tilde), PowMod(h2, tau, n_tilde), n_tilde);

    A2MtAwcProof proof{
        .u = u,
        .z = z,
        .z2 = z2,
        .t = t,
        .v = v,
        .w = w,
    };
    const Scalar e_scalar =
        BuildA2MtAwcChallenge(ctx, n, gamma, verifier_aux, c1, c2, statement_x, proof);
    const BigInt e = e_scalar.mp_value();

    const BigInt s = MulMod(PowMod(witness_r, e, n), beta, n);
    const BigInt s1 = (e * witness_x) + alpha;
    const BigInt s2 = (e * rho) + rho2;
    const BigInt t1 = (e * witness_y) + gamma_rand;
    const BigInt t2 = (e * sigma) + tau;
    if (s1 > QPow3() || t1 > QPow7()) {
      continue;
    }
    proof.s = s;
    proof.s1 = s1;
    proof.s2 = s2;
    proof.t1 = t1;
    proof.t2 = t2;
    return proof;
  }
}

bool VerifyA2MtAwc(const MtaProofContext& ctx,
                   const BigInt& n,
                   const AuxRsaParams& verifier_aux,
                   const BigInt& c1,
                   const BigInt& c2,
                   const ECPoint& statement_x,
                   const A2MtAwcProof& proof) {
  const BigInt n2 = n * n;
  const BigInt gamma = n + BigInt(1);
  const BigInt n_tilde = verifier_aux.n_tilde;
  const BigInt h1 = verifier_aux.h1;
  const BigInt h2 = verifier_aux.h2;

  if (!IsInRange(c1, n2) || !IsInRange(c2, n2) ||
      !IsInRange(proof.v, n2) || !IsInRange(proof.z, n_tilde) ||
      !IsInRange(proof.z2, n_tilde) ||
      !IsInRange(proof.t, n_tilde) ||
      !IsInRange(proof.w, n_tilde) ||
      !IsZnStarElement(proof.s, n)) {
    return false;
  }
  if (proof.s1 < 0 || proof.s1 > QPow3() || proof.t1 < 0 || proof.t1 > QPow7() ||
      proof.s2 < 0 || proof.t2 < 0) {
    return false;
  }

  const Scalar e_scalar =
      BuildA2MtAwcChallenge(ctx, n, gamma, verifier_aux, c1, c2, statement_x, proof);

  try {
    const Scalar s1_mod_q(proof.s1);
    if (s1_mod_q.value() == 0) {
      return false;
    }
    const ECPoint lhs_curve = ECPoint::GeneratorMultiply(s1_mod_q);
    ECPoint rhs_curve = proof.u;
    if (e_scalar.value() != 0) {
      rhs_curve = rhs_curve.Add(statement_x.Mul(e_scalar));
    }
    if (lhs_curve != rhs_curve) {
      return false;
    }
  } catch (const std::exception&) {
    return false;
  }

  const BigInt e = e_scalar.mp_value();
  const BigInt lhs_nt_1 = MulMod(PowMod(h1, proof.s1, n_tilde), PowMod(h2, proof.s2, n_tilde), n_tilde);
  const BigInt rhs_nt_1 = MulMod(PowMod(proof.z, e, n_tilde), proof.z2, n_tilde);
  if (lhs_nt_1 != rhs_nt_1) {
    return false;
  }

  const BigInt lhs_nt_2 = MulMod(PowMod(h1, proof.t1, n_tilde), PowMod(h2, proof.t2, n_tilde), n_tilde);
  const BigInt rhs_nt_2 = MulMod(PowMod(proof.t, e, n_tilde), proof.w, n_tilde);
  if (lhs_nt_2 != rhs_nt_2) {
    return false;
  }

  BigInt lhs_paillier = MulMod(PowMod(c1, proof.s1, n2), PowMod(proof.s, n, n2), n2);
  lhs_paillier = MulMod(lhs_paillier, PowMod(gamma, proof.t1, n2), n2);
  const BigInt rhs_paillier = MulMod(PowMod(c2, e, n2), proof.v, n2);
  return lhs_paillier == rhs_paillier;
}

A3MtAProof ProveA3MtA(const MtaProofContext& ctx,
                      const BigInt& n,
                      const AuxRsaParams& verifier_aux,
                      const BigInt& c1,
                      const BigInt& c2,
                      const BigInt& witness_x,
                      const BigInt& witness_y,
                      const BigInt& witness_r) {
  const BigInt n2 = n * n;
  const BigInt gamma = n + BigInt(1);
  const BigInt n_tilde = verifier_aux.n_tilde;
  const BigInt h1 = verifier_aux.h1;
  const BigInt h2 = verifier_aux.h2;
  const BigInt q_mul_n_tilde = Scalar::ModulusQMpInt() * n_tilde;
  const BigInt q3_mul_n_tilde = QPow3() * n_tilde;

  while (true) {
    const BigInt alpha = RandomBelow(QPow3());
    const BigInt rho = RandomBelow(q_mul_n_tilde);
    const BigInt rho2 = RandomBelow(q3_mul_n_tilde);
    const BigInt sigma = RandomBelow(q_mul_n_tilde);
    const BigInt beta = SampleZnStar(n);
    const BigInt gamma_rand = RandomBelow(QPow7());
    const BigInt tau = RandomBelow(q3_mul_n_tilde);

    const BigInt z = MulMod(PowMod(h1, witness_x, n_tilde), PowMod(h2, rho, n_tilde), n_tilde);
    const BigInt z2 = MulMod(PowMod(h1, alpha, n_tilde), PowMod(h2, rho2, n_tilde), n_tilde);
    const BigInt t = MulMod(PowMod(h1, witness_y, n_tilde), PowMod(h2, sigma, n_tilde), n_tilde);
    BigInt v = MulMod(PowMod(c1, alpha, n2), PowMod(gamma, gamma_rand, n2), n2);
    v = MulMod(v, PowMod(beta, n, n2), n2);
    const BigInt w = MulMod(PowMod(h1, gamma_rand, n_tilde), PowMod(h2, tau, n_tilde), n_tilde);

    A3MtAProof proof{
        .z = z,
        .z2 = z2,
        .t = t,
        .v = v,
        .w = w,
    };
    const Scalar e_scalar = BuildA3MtAChallenge(ctx, n, gamma, verifier_aux, c1, c2, proof);
    const BigInt e = e_scalar.mp_value();

    const BigInt s = MulMod(PowMod(witness_r, e, n), beta, n);
    const BigInt s1 = (e * witness_x) + alpha;
    const BigInt s2 = (e * rho) + rho2;
    const BigInt t1 = (e * witness_y) + gamma_rand;
    const BigInt t2 = (e * sigma) + tau;
    if (s1 > QPow3() || t1 > QPow7()) {
      continue;
    }
    proof.s = s;
    proof.s1 = s1;
    proof.s2 = s2;
    proof.t1 = t1;
    proof.t2 = t2;
    return proof;
  }
}

bool VerifyA3MtA(const MtaProofContext& ctx,
                 const BigInt& n,
                 const AuxRsaParams& verifier_aux,
                 const BigInt& c1,
                 const BigInt& c2,
                 const A3MtAProof& proof) {
  const BigInt n2 = n * n;
  const BigInt gamma = n + BigInt(1);
  const BigInt n_tilde = verifier_aux.n_tilde;
  const BigInt h1 = verifier_aux.h1;
  const BigInt h2 = verifier_aux.h2;

  if (!IsInRange(c1, n2) || !IsInRange(c2, n2) ||
      !IsInRange(proof.v, n2) || !IsInRange(proof.z, n_tilde) ||
      !IsInRange(proof.z2, n_tilde) ||
      !IsInRange(proof.t, n_tilde) ||
      !IsInRange(proof.w, n_tilde) ||
      !IsZnStarElement(proof.s, n)) {
    return false;
  }
  if (proof.s1 < 0 || proof.s1 > QPow3() || proof.t1 < 0 || proof.t1 > QPow7() ||
      proof.s2 < 0 || proof.t2 < 0) {
    return false;
  }

  const Scalar e_scalar = BuildA3MtAChallenge(ctx, n, gamma, verifier_aux, c1, c2, proof);
  const BigInt e = e_scalar.mp_value();

  const BigInt lhs_nt_1 = MulMod(PowMod(h1, proof.s1, n_tilde), PowMod(h2, proof.s2, n_tilde), n_tilde);
  const BigInt rhs_nt_1 = MulMod(PowMod(proof.z, e, n_tilde), proof.z2, n_tilde);
  if (lhs_nt_1 != rhs_nt_1) {
    return false;
  }

  const BigInt lhs_nt_2 = MulMod(PowMod(h1, proof.t1, n_tilde), PowMod(h2, proof.t2, n_tilde), n_tilde);
  const BigInt rhs_nt_2 = MulMod(PowMod(proof.t, e, n_tilde), proof.w, n_tilde);
  if (lhs_nt_2 != rhs_nt_2) {
    return false;
  }

  BigInt lhs_paillier = MulMod(PowMod(c1, proof.s1, n2), PowMod(proof.s, n, n2), n2);
  lhs_paillier = MulMod(lhs_paillier, PowMod(gamma, proof.t1, n2), n2);
  const BigInt rhs_paillier = MulMod(PowMod(c2, e, n2), proof.v, n2);
  return lhs_paillier == rhs_paillier;
}

}  // namespace tecdsa::sign_internal

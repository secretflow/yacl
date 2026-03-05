#include "yacl/crypto/experimental/threshold_ecdsa/crypto/paillier.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"

#include <algorithm>
#include <array>
#include <cstddef>

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"

namespace tecdsa {
namespace {

constexpr size_t kMaxKeygenAttempts = 128;

}  // namespace

PaillierProvider::PaillierProvider(unsigned long modulus_bits) {
  if (modulus_bits < 256) {
    TECDSA_THROW_ARGUMENT("Paillier modulus_bits must be >= 256");
  }
  GenerateKeyPair(modulus_bits);
  if (!VerifyKeyPair()) {
    TECDSA_THROW("native Paillier generated invalid key pair");
  }
}

BigInt PaillierProvider::EncryptBigInt(const BigInt& plaintext) const {
  return EncryptWithProvidedRandomBigInt(plaintext, SampleZnStar());
}

PaillierCiphertextWithRandomBigInt PaillierProvider::EncryptWithRandomBigInt(
    const BigInt& plaintext) const {
  PaillierCiphertextWithRandomBigInt out;
  out.randomness = SampleZnStar();
  out.ciphertext = EncryptWithProvidedRandomBigInt(plaintext, out.randomness);
  return out;
}

BigInt PaillierProvider::EncryptWithProvidedRandomBigInt(
    const BigInt& plaintext,
    const BigInt& randomness) const {
  if (!initialized_) {
    TECDSA_THROW_LOGIC("Paillier key pair is not initialized");
  }
  if (!IsInZnStar(randomness)) {
    TECDSA_THROW_ARGUMENT("Paillier randomness must be in Z*_N");
  }

  const BigInt plain = NormalizeMod(plaintext, n_);
  const BigInt g_pow_m = NormalizeMod((plain * n_) + BigInt(1), n2_);
  const BigInt r_pow_n = randomness.PowMod(n_, n2_);
  return NormalizeMod(g_pow_m * r_pow_n, n2_);
}

BigInt PaillierProvider::DecryptBigInt(const BigInt& ciphertext) const {
  if (!initialized_) {
    TECDSA_THROW_LOGIC("Paillier key pair is not initialized");
  }

  const BigInt cipher = NormalizeMod(ciphertext, n2_);
  const BigInt u = cipher.PowMod(lambda_, n2_);
  const BigInt l_of_u = LFunction(u);
  return NormalizeMod(l_of_u * mu_, n_);
}

BigInt PaillierProvider::AddCiphertextsBigInt(const BigInt& lhs_cipher,
                                              const BigInt& rhs_cipher) const {
  if (!initialized_) {
    TECDSA_THROW_LOGIC("Paillier key pair is not initialized");
  }
  const BigInt lhs = NormalizeMod(lhs_cipher, n2_);
  const BigInt rhs = NormalizeMod(rhs_cipher, n2_);
  return NormalizeMod(lhs * rhs, n2_);
}

BigInt PaillierProvider::AddPlaintextBigInt(const BigInt& cipher,
                                            const BigInt& plain) const {
  if (!initialized_) {
    TECDSA_THROW_LOGIC("Paillier key pair is not initialized");
  }
  const BigInt c = NormalizeMod(cipher, n2_);
  const BigInt p = NormalizeMod(plain, n_);
  const BigInt g_pow_p = NormalizeMod((p * n_) + BigInt(1), n2_);
  return NormalizeMod(c * g_pow_p, n2_);
}

BigInt PaillierProvider::MulPlaintextBigInt(const BigInt& cipher,
                                            const BigInt& plain) const {
  if (!initialized_) {
    TECDSA_THROW_LOGIC("Paillier key pair is not initialized");
  }
  const BigInt c = NormalizeMod(cipher, n2_);
  const BigInt p = NormalizeMod(plain, n_);
  return c.PowMod(p, n2_);
}

bool PaillierProvider::VerifyKeyPair() const {
  if (!initialized_) {
    return false;
  }
  if (p_ <= 1 || q_ <= 1 || p_ == q_) {
    return false;
  }
  if (n_ != p_ * q_) {
    return false;
  }
  if (n2_ != n_ * n_) {
    return false;
  }
  if (g_ != n_ + BigInt(1)) {
    return false;
  }
  if (lambda_ <= 1) {
    return false;
  }

  const BigInt p_minus_1 = p_ - BigInt(1);
  const BigInt q_minus_1 = q_ - BigInt(1);
  const BigInt lambda_check = BigInt::Lcm(p_minus_1, q_minus_1);
  if (lambda_check != lambda_) {
    return false;
  }

  const BigInt gcd = BigInt::Gcd(lambda_, n_);
  if (gcd != 1) {
    return false;
  }

  const auto mu_check = bigint::TryInvertMod(lambda_, n_);
  if (!mu_check.has_value() || *mu_check != mu_) {
    return false;
  }

  const BigInt n_minus_1 = n_ - BigInt(1);
  const std::array<BigInt, 4> plain_cases = {
      BigInt(0),
      BigInt(1),
      BigInt(2),
      n_minus_1,
  };
  for (const auto& plain : plain_cases) {
    const BigInt cipher = EncryptWithProvidedRandomBigInt(plain, BigInt(1));
    const BigInt decrypted = DecryptBigInt(cipher);
    if (decrypted != NormalizeMod(plain, n_)) {
      return false;
    }
  }

  return true;
}

BigInt PaillierProvider::modulus_n_bigint() const {
  if (!initialized_) {
    TECDSA_THROW_LOGIC("Paillier key pair is not initialized");
  }
  return n_;
}

BigInt PaillierProvider::modulus_n2_bigint() const {
  if (!initialized_) {
    TECDSA_THROW_LOGIC("Paillier key pair is not initialized");
  }
  return n2_;
}

BigInt PaillierProvider::generator_bigint() const {
  if (!initialized_) {
    TECDSA_THROW_LOGIC("Paillier key pair is not initialized");
  }
  return g_;
}

BigInt PaillierProvider::private_lambda_bigint() const {
  if (!initialized_) {
    TECDSA_THROW_LOGIC("Paillier key pair is not initialized");
  }
  return lambda_;
}

BigInt PaillierProvider::modulus_n() const {
  return modulus_n_bigint();
}

BigInt PaillierProvider::modulus_n2() const {
  return modulus_n2_bigint();
}

BigInt PaillierProvider::generator() const {
  return generator_bigint();
}

BigInt PaillierProvider::private_lambda() const {
  return private_lambda_bigint();
}

void PaillierProvider::GenerateKeyPair(unsigned long modulus_bits) {
  const size_t p_bits =
      std::max<size_t>(2, (static_cast<size_t>(modulus_bits) + 1) / 2 + 1);
  const size_t q_bits = p_bits;

  for (size_t attempt = 0; attempt < kMaxKeygenAttempts; ++attempt) {
    do {
      p_ = RandomOddWithBitSize(p_bits);
    } while (!IsProbablePrime(p_));

    do {
      do {
        q_ = RandomOddWithBitSize(q_bits);
      } while (!IsProbablePrime(q_));
    } while (q_ == p_);

    n_ = p_ * q_;
    n2_ = n_ * n_;
    g_ = n_ + BigInt(1);

    const BigInt p_minus_1 = p_ - BigInt(1);
    const BigInt q_minus_1 = q_ - BigInt(1);
    lambda_ = BigInt::Lcm(p_minus_1, q_minus_1);
    if (lambda_ <= 1) {
      continue;
    }

    const auto mu_opt = bigint::TryInvertMod(lambda_, n_);
    if (!mu_opt.has_value()) {
      continue;
    }
    mu_ = *mu_opt;

    initialized_ = true;
    return;
  }

  TECDSA_THROW("failed to generate valid native Paillier key pair");
}

BigInt PaillierProvider::NormalizeMod(const BigInt& value, const BigInt& modulus) {
  return bigint::NormalizeMod(value, modulus);
}

bool PaillierProvider::IsProbablePrime(const BigInt& candidate) {
  if (candidate <= 1) {
    return false;
  }
  return candidate.IsPrime();
}

BigInt PaillierProvider::RandomBelow(const BigInt& upper_exclusive) {
  return bigint::RandomBelow(upper_exclusive);
}

BigInt PaillierProvider::RandomOddWithBitSize(size_t bits) {
  if (bits < 2) {
    TECDSA_THROW_ARGUMENT("prime bit size must be >= 2");
  }

  BigInt candidate;
  BigInt::RandomMonicExactBits(bits, &candidate);
  candidate.SetBit(0, 1);
  if (candidate.BitCount() != bits) {
    TECDSA_THROW("failed to sample odd integer with exact bit size");
  }
  return candidate;
}

BigInt PaillierProvider::SampleZnStar() const {
  if (!initialized_) {
    TECDSA_THROW_LOGIC("Paillier key pair is not initialized");
  }
  return bigint::RandomZnStar(n_);
}

bool PaillierProvider::IsInZnStar(const BigInt& value) const {
  if (!initialized_) {
    return false;
  }
  if (value <= 0 || value >= n_) {
    return false;
  }

  const BigInt gcd = BigInt::Gcd(value, n_);
  return gcd == 1;
}

BigInt PaillierProvider::LFunction(const BigInt& value) const {
  const BigInt normalized = NormalizeMod(value, n2_);
  const BigInt numer = normalized - BigInt(1);
  if (numer.Mod(n_) != 0) {
    TECDSA_THROW_ARGUMENT("invalid Paillier L(x) input");
  }
  return numer / n_;
}

}  // namespace tecdsa

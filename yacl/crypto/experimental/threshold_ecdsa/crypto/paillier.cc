#include "yacl/crypto/experimental/threshold_ecdsa/crypto/paillier.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <stdexcept>

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/random.h"

namespace tecdsa {
namespace {

constexpr int kPrimalityChecks = 40;
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

mpz_class PaillierProvider::Encrypt(const mpz_class& plaintext) const {
  return EncryptWithProvidedRandom(plaintext, SampleZnStar());
}

PaillierCiphertextWithRandom PaillierProvider::EncryptWithRandom(
    const mpz_class& plaintext) const {
  PaillierCiphertextWithRandom out;
  out.randomness = SampleZnStar();
  out.ciphertext = EncryptWithProvidedRandom(plaintext, out.randomness);
  return out;
}

mpz_class PaillierProvider::EncryptWithProvidedRandom(
    const mpz_class& plaintext,
    const mpz_class& randomness) const {
  if (!initialized_) {
    TECDSA_THROW_LOGIC("Paillier key pair is not initialized");
  }
  if (!IsInZnStar(randomness)) {
    TECDSA_THROW_ARGUMENT("Paillier randomness must be in Z*_N");
  }

  const mpz_class plain = NormalizeMod(plaintext, n_);
  const mpz_class g_pow_m = NormalizeMod((plain * n_) + 1, n2_);

  mpz_class r_pow_n;
  mpz_powm(r_pow_n.get_mpz_t(), randomness.get_mpz_t(), n_.get_mpz_t(), n2_.get_mpz_t());
  return NormalizeMod(g_pow_m * r_pow_n, n2_);
}

mpz_class PaillierProvider::Decrypt(const mpz_class& ciphertext) const {
  if (!initialized_) {
    TECDSA_THROW_LOGIC("Paillier key pair is not initialized");
  }

  const mpz_class cipher = NormalizeMod(ciphertext, n2_);
  mpz_class u;
  mpz_powm(u.get_mpz_t(), cipher.get_mpz_t(), lambda_.get_mpz_t(), n2_.get_mpz_t());

  const mpz_class l_of_u = LFunction(u);
  return NormalizeMod(l_of_u * mu_, n_);
}

mpz_class PaillierProvider::AddCiphertexts(const mpz_class& lhs_cipher,
                                           const mpz_class& rhs_cipher) const {
  if (!initialized_) {
    TECDSA_THROW_LOGIC("Paillier key pair is not initialized");
  }
  const mpz_class lhs = NormalizeMod(lhs_cipher, n2_);
  const mpz_class rhs = NormalizeMod(rhs_cipher, n2_);
  return NormalizeMod(lhs * rhs, n2_);
}

mpz_class PaillierProvider::AddPlaintext(const mpz_class& cipher,
                                         const mpz_class& plain) const {
  if (!initialized_) {
    TECDSA_THROW_LOGIC("Paillier key pair is not initialized");
  }
  const mpz_class c = NormalizeMod(cipher, n2_);
  const mpz_class p = NormalizeMod(plain, n_);
  const mpz_class g_pow_p = NormalizeMod((p * n_) + 1, n2_);
  return NormalizeMod(c * g_pow_p, n2_);
}

mpz_class PaillierProvider::MulPlaintext(const mpz_class& cipher,
                                         const mpz_class& plain) const {
  if (!initialized_) {
    TECDSA_THROW_LOGIC("Paillier key pair is not initialized");
  }
  const mpz_class c = NormalizeMod(cipher, n2_);
  const mpz_class p = NormalizeMod(plain, n_);
  mpz_class out;
  mpz_powm(out.get_mpz_t(), c.get_mpz_t(), p.get_mpz_t(), n2_.get_mpz_t());
  return out;
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
  if (g_ != n_ + 1) {
    return false;
  }
  if (lambda_ <= 1) {
    return false;
  }

  mpz_class p_minus_1 = p_ - 1;
  mpz_class q_minus_1 = q_ - 1;
  mpz_class lambda_check;
  mpz_lcm(lambda_check.get_mpz_t(), p_minus_1.get_mpz_t(), q_minus_1.get_mpz_t());
  if (lambda_check != lambda_) {
    return false;
  }

  mpz_class gcd;
  mpz_gcd(gcd.get_mpz_t(), lambda_.get_mpz_t(), n_.get_mpz_t());
  if (gcd != 1) {
    return false;
  }

  mpz_class mu_check;
  if (mpz_invert(mu_check.get_mpz_t(), lambda_.get_mpz_t(), n_.get_mpz_t()) == 0 ||
      mu_check != mu_) {
    return false;
  }

  const mpz_class n_minus_1 = n_ - 1;
  const std::array<mpz_class, 4> plain_cases = {
      mpz_class(0),
      mpz_class(1),
      mpz_class(2),
      n_minus_1,
  };
  for (const auto& plain : plain_cases) {
    const mpz_class cipher = EncryptWithProvidedRandom(plain, mpz_class(1));
    const mpz_class decrypted = Decrypt(cipher);
    if (decrypted != NormalizeMod(plain, n_)) {
      return false;
    }
  }

  return true;
}

mpz_class PaillierProvider::modulus_n() const {
  if (!initialized_) {
    TECDSA_THROW_LOGIC("Paillier key pair is not initialized");
  }
  return n_;
}

mpz_class PaillierProvider::modulus_n2() const {
  if (!initialized_) {
    TECDSA_THROW_LOGIC("Paillier key pair is not initialized");
  }
  return n2_;
}

mpz_class PaillierProvider::generator() const {
  if (!initialized_) {
    TECDSA_THROW_LOGIC("Paillier key pair is not initialized");
  }
  return g_;
}

mpz_class PaillierProvider::private_lambda() const {
  if (!initialized_) {
    TECDSA_THROW_LOGIC("Paillier key pair is not initialized");
  }
  return lambda_;
}

void PaillierProvider::GenerateKeyPair(unsigned long modulus_bits) {
  // Use one extra bit per prime so that the resulting N is comfortably above
  // 2^modulus_bits. This improves success rate for the protocol's N > q^8 gate
  // when modulus_bits is configured to 2048.
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
    g_ = n_ + 1;

    mpz_class p_minus_1 = p_ - 1;
    mpz_class q_minus_1 = q_ - 1;
    mpz_lcm(lambda_.get_mpz_t(), p_minus_1.get_mpz_t(), q_minus_1.get_mpz_t());
    if (lambda_ <= 1) {
      continue;
    }

    if (mpz_invert(mu_.get_mpz_t(), lambda_.get_mpz_t(), n_.get_mpz_t()) == 0) {
      continue;
    }

    initialized_ = true;
    return;
  }

  TECDSA_THROW("failed to generate valid native Paillier key pair");
}

mpz_class PaillierProvider::NormalizeMod(const mpz_class& value, const mpz_class& modulus) {
  if (modulus <= 0) {
    TECDSA_THROW_ARGUMENT("modulus must be positive");
  }
  mpz_class out = value % modulus;
  if (out < 0) {
    out += modulus;
  }
  return out;
}

bool PaillierProvider::IsProbablePrime(const mpz_class& candidate) {
  if (candidate <= 1) {
    return false;
  }
  return mpz_probab_prime_p(candidate.get_mpz_t(), kPrimalityChecks) > 0;
}

mpz_class PaillierProvider::RandomBelow(const mpz_class& upper_exclusive) {
  if (upper_exclusive <= 0) {
    TECDSA_THROW_ARGUMENT("upper bound for random sampling must be positive");
  }

  const size_t bit_len = mpz_sizeinbase(upper_exclusive.get_mpz_t(), 2);
  const size_t byte_len = std::max<size_t>(1, (bit_len + 7) / 8);
  const size_t extra_bits = byte_len * 8 - bit_len;

  while (true) {
    Bytes random = Csprng::RandomBytes(byte_len);
    if (extra_bits > 0) {
      random[0] &= static_cast<uint8_t>(0xFFu >> extra_bits);
    }

    mpz_class candidate;
    mpz_import(
        candidate.get_mpz_t(), random.size(), 1, sizeof(uint8_t), 1, 0, random.data());
    if (candidate < upper_exclusive) {
      return candidate;
    }
  }
}

mpz_class PaillierProvider::RandomOddWithBitSize(size_t bits) {
  if (bits < 2) {
    TECDSA_THROW_ARGUMENT("prime bit size must be >= 2");
  }

  const size_t byte_len = (bits + 7) / 8;
  const size_t extra_bits = byte_len * 8 - bits;
  while (true) {
    Bytes random = Csprng::RandomBytes(byte_len);
    if (extra_bits > 0) {
      random[0] &= static_cast<uint8_t>(0xFFu >> extra_bits);
    }
    random[0] |= static_cast<uint8_t>(1u << (7 - extra_bits));
    random.back() |= 0x01;

    mpz_class candidate;
    mpz_import(
        candidate.get_mpz_t(), random.size(), 1, sizeof(uint8_t), 1, 0, random.data());
    if (mpz_sizeinbase(candidate.get_mpz_t(), 2) == bits) {
      return candidate;
    }
  }
}

mpz_class PaillierProvider::SampleZnStar() const {
  if (!initialized_) {
    TECDSA_THROW_LOGIC("Paillier key pair is not initialized");
  }

  mpz_class candidate;
  mpz_class gcd;
  do {
    candidate = RandomBelow(n_);
    mpz_gcd(gcd.get_mpz_t(), candidate.get_mpz_t(), n_.get_mpz_t());
  } while (candidate == 0 || gcd != 1);

  return candidate;
}

bool PaillierProvider::IsInZnStar(const mpz_class& value) const {
  if (!initialized_) {
    return false;
  }
  if (value <= 0 || value >= n_) {
    return false;
  }

  mpz_class gcd;
  mpz_gcd(gcd.get_mpz_t(), value.get_mpz_t(), n_.get_mpz_t());
  return gcd == 1;
}

mpz_class PaillierProvider::LFunction(const mpz_class& value) const {
  const mpz_class normalized = NormalizeMod(value, n2_);
  mpz_class numer = normalized - 1;
  if (numer % n_ != 0) {
    TECDSA_THROW_ARGUMENT("invalid Paillier L(x) input");
  }
  return numer / n_;
}

}  // namespace tecdsa

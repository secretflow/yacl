#pragma once

#include <cstddef>
#include <gmpxx.h>

#include "yacl/math/mpint/mp_int.h"

namespace tecdsa {

using BigInt = yacl::math::MPInt;

struct PaillierCiphertextWithRandomBigInt {
  BigInt ciphertext;
  BigInt randomness;
};

struct PaillierCiphertextWithRandom {
  mpz_class ciphertext;
  mpz_class randomness;
};

struct PaillierPublicKey {
  mpz_class n;
};

class PaillierProvider {
 public:
  explicit PaillierProvider(unsigned long modulus_bits);
  ~PaillierProvider() = default;

  PaillierProvider(const PaillierProvider&) = delete;
  PaillierProvider& operator=(const PaillierProvider&) = delete;

  PaillierProvider(PaillierProvider&& other) noexcept = default;
  PaillierProvider& operator=(PaillierProvider&& other) noexcept = default;

  BigInt EncryptBigInt(const BigInt& plaintext) const;
  PaillierCiphertextWithRandomBigInt EncryptWithRandomBigInt(const BigInt& plaintext) const;
  BigInt EncryptWithProvidedRandomBigInt(const BigInt& plaintext,
                                         const BigInt& randomness) const;
  BigInt DecryptBigInt(const BigInt& ciphertext) const;
  BigInt AddCiphertextsBigInt(const BigInt& lhs_cipher,
                              const BigInt& rhs_cipher) const;
  BigInt AddPlaintextBigInt(const BigInt& cipher, const BigInt& plain) const;
  BigInt MulPlaintextBigInt(const BigInt& cipher, const BigInt& plain) const;

  BigInt modulus_n_bigint() const;
  BigInt modulus_n2_bigint() const;
  BigInt generator_bigint() const;
  BigInt private_lambda_bigint() const;

  mpz_class Encrypt(const mpz_class& plaintext) const;
  PaillierCiphertextWithRandom EncryptWithRandom(const mpz_class& plaintext) const;
  mpz_class EncryptWithProvidedRandom(const mpz_class& plaintext,
                                      const mpz_class& randomness) const;

  mpz_class Decrypt(const mpz_class& ciphertext) const;

  mpz_class AddCiphertexts(const mpz_class& lhs_cipher,
                           const mpz_class& rhs_cipher) const;
  mpz_class AddPlaintext(const mpz_class& cipher, const mpz_class& plain) const;
  mpz_class MulPlaintext(const mpz_class& cipher, const mpz_class& plain) const;

  bool VerifyKeyPair() const;

  mpz_class modulus_n() const;
  mpz_class modulus_n2() const;
  mpz_class generator() const;
  mpz_class private_lambda() const;

 private:
  void GenerateKeyPair(unsigned long modulus_bits);
  static BigInt NormalizeMod(const BigInt& value, const BigInt& modulus);
  static bool IsProbablePrime(const BigInt& candidate);
  static BigInt RandomBelow(const BigInt& upper_exclusive);
  static BigInt RandomOddWithBitSize(size_t bits);

  BigInt SampleZnStar() const;
  bool IsInZnStar(const BigInt& value) const;
  BigInt LFunction(const BigInt& value) const;

  BigInt p_;
  BigInt q_;
  BigInt n_;
  BigInt n2_;
  BigInt g_;
  BigInt lambda_;
  BigInt mu_;
  bool initialized_ = false;
};

}  // namespace tecdsa

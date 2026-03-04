#pragma once

#include <cstddef>
#include <gmpxx.h>

namespace tecdsa {

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
  static mpz_class NormalizeMod(const mpz_class& value, const mpz_class& modulus);
  static bool IsProbablePrime(const mpz_class& candidate);
  static mpz_class RandomBelow(const mpz_class& upper_exclusive);
  static mpz_class RandomOddWithBitSize(size_t bits);

  mpz_class SampleZnStar() const;
  bool IsInZnStar(const mpz_class& value) const;
  mpz_class LFunction(const mpz_class& value) const;

  mpz_class p_;
  mpz_class q_;
  mpz_class n_;
  mpz_class n2_;
  mpz_class g_;
  mpz_class lambda_;
  mpz_class mu_;
  bool initialized_ = false;
};

}  // namespace tecdsa

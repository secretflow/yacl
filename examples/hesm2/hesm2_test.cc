#include "gtest/gtest.h"
#include "hesm2/ahesm2.h"
#include "hesm2/config.h"
#include "hesm2/private_key.h"
#include "hesm2/public_key.h"

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::hesm2 {

class Hesm2Test : public ::testing::Test {
 protected:
  static void SetUpTestSuite() {
    // Initialize configuration (load/generate tables) once for all tests
    InitializeConfig();
  }

  void SetUp() override {
    ec_group_ = yacl::crypto::EcGroupFactory::Instance().Create(
        "sm2", yacl::ArgLib = "openssl");
    ASSERT_NE(ec_group_, nullptr);
    private_key_ = std::make_unique<PrivateKey>(ec_group_);
    public_key_ = std::make_unique<PublicKey>(private_key_->GetPublicKey());
  }

  std::shared_ptr<yacl::crypto::EcGroup> ec_group_;
  std::unique_ptr<PrivateKey> private_key_;
  std::unique_ptr<PublicKey> public_key_;
};

TEST_F(Hesm2Test, EncryptDecryptZero) {
  yacl::math::MPInt m(0);
  Ciphertext ct = Encrypt(m, *public_key_);
  DecryptResult res = Decrypt(ct, *private_key_);
  EXPECT_TRUE(res.success);
  EXPECT_EQ(res.m, m);
}

TEST_F(Hesm2Test, EncryptDecryptPositive) {
  yacl::math::MPInt m(12345);
  Ciphertext ct = Encrypt(m, *public_key_);
  DecryptResult res = Decrypt(ct, *private_key_);
  EXPECT_TRUE(res.success);
  EXPECT_EQ(res.m, m);
}

TEST_F(Hesm2Test, EncryptDecryptNegative) {
  yacl::math::MPInt m(-12345);
  Ciphertext ct = Encrypt(m, *public_key_);
  DecryptResult res = Decrypt(ct, *private_key_);
  EXPECT_TRUE(res.success);
  EXPECT_EQ(res.m, m);
}

TEST_F(Hesm2Test, HomomorphicAdd) {
  yacl::math::MPInt m1(100);
  yacl::math::MPInt m2(200);
  Ciphertext c1 = Encrypt(m1, *public_key_);
  Ciphertext c2 = Encrypt(m2, *public_key_);

  Ciphertext c_sum = HAdd(c1, c2, *public_key_);
  DecryptResult res = Decrypt(c_sum, *private_key_);

  EXPECT_TRUE(res.success);
  EXPECT_EQ(res.m, m1 + m2);
}

TEST_F(Hesm2Test, HomomorphicSub) {
  yacl::math::MPInt m1(200);
  yacl::math::MPInt m2(50);
  Ciphertext c1 = Encrypt(m1, *public_key_);
  Ciphertext c2 = Encrypt(m2, *public_key_);

  Ciphertext c_diff = HSub(c1, c2, *public_key_);
  DecryptResult res = Decrypt(c_diff, *private_key_);

  EXPECT_TRUE(res.success);
  EXPECT_EQ(res.m, m1 - m2);
}

TEST_F(Hesm2Test, HomomorphicSubNegativeResult) {
  yacl::math::MPInt m1(50);
  yacl::math::MPInt m2(200);
  Ciphertext c1 = Encrypt(m1, *public_key_);
  Ciphertext c2 = Encrypt(m2, *public_key_);

  Ciphertext c_diff = HSub(c1, c2, *public_key_);
  DecryptResult res = Decrypt(c_diff, *private_key_);

  EXPECT_TRUE(res.success);
  EXPECT_EQ(res.m, m1 - m2);
}

TEST_F(Hesm2Test, HomomorphicMul) {
  yacl::math::MPInt m(100);
  yacl::math::MPInt k(5);
  Ciphertext c = Encrypt(m, *public_key_);

  Ciphertext c_prod = HMul(c, k, *public_key_);
  DecryptResult res = Decrypt(c_prod, *private_key_);

  EXPECT_TRUE(res.success);
  EXPECT_EQ(res.m, m * k);
}

TEST_F(Hesm2Test, HomomorphicMulZero) {
  yacl::math::MPInt m(100);
  yacl::math::MPInt k(0);
  Ciphertext c = Encrypt(m, *public_key_);

  Ciphertext c_prod = HMul(c, k, *public_key_);
  DecryptResult res = Decrypt(c_prod, *private_key_);

  EXPECT_TRUE(res.success);
  EXPECT_EQ(res.m, yacl::math::MPInt(0));
}

TEST_F(Hesm2Test, HomomorphicMulNegativeScalar) {
  yacl::math::MPInt m(100);
  yacl::math::MPInt k(-5);
  Ciphertext c = Encrypt(m, *public_key_);

  Ciphertext c_prod = HMul(c, k, *public_key_);
  DecryptResult res = Decrypt(c_prod, *private_key_);

  EXPECT_TRUE(res.success);
  EXPECT_EQ(res.m, m * k);
}

TEST_F(Hesm2Test, ParDecrypt) {
  yacl::math::MPInt m(12345);
  Ciphertext ct = Encrypt(m, *public_key_);
  DecryptResult res = ParDecrypt(ct, *private_key_);
  EXPECT_TRUE(res.success);
  EXPECT_EQ(res.m, m);
}

TEST_F(Hesm2Test, ZeroCheck) {
  yacl::math::MPInt m0(0);
  Ciphertext c0 = Encrypt(m0, *public_key_);
  DecryptResult res0 = ZeroCheck(c0, *private_key_);
  EXPECT_TRUE(res0.success);
  EXPECT_EQ(res0.m, yacl::math::MPInt(0));

  yacl::math::MPInt m1(100);
  Ciphertext c1 = Encrypt(m1, *public_key_);
  DecryptResult res1 = ZeroCheck(c1, *private_key_);
  EXPECT_FALSE(res1.success);
}

TEST_F(Hesm2Test, SerializationCiphertext) {
  yacl::math::MPInt m(12345);
  Ciphertext ct = Encrypt(m, *public_key_);

  yacl::Buffer buf = SerializeCiphertext(ct, *public_key_);
  Ciphertext ct_des = DeserializeCiphertext(buf, *public_key_);

  DecryptResult res = Decrypt(ct_des, *private_key_);
  EXPECT_TRUE(res.success);
  EXPECT_EQ(res.m, m);
}

TEST_F(Hesm2Test, SerializationCiphertexts) {
  std::vector<Ciphertext> cts;
  for (int i = 0; i < 10; ++i) {
    cts.push_back(Encrypt(yacl::math::MPInt(i), *public_key_));
  }

  yacl::Buffer buf = SerializeCiphertexts(cts, *public_key_);
  std::vector<Ciphertext> cts_des = DeserializeCiphertexts(buf, *public_key_);

  ASSERT_EQ(cts_des.size(), cts.size());
  for (size_t i = 0; i < cts.size(); ++i) {
    DecryptResult res = Decrypt(cts_des[i], *private_key_);
    EXPECT_TRUE(res.success);
    EXPECT_EQ(res.m, yacl::math::MPInt(i));
  }
}

TEST_F(Hesm2Test, SerializationPublicKey) {
  yacl::Buffer buf = public_key_->Serialize();
  PublicKey pk_des = PublicKey::Deserialize(buf, ec_group_);

  // Encrypt with deserialized key
  yacl::math::MPInt m(999);
  Ciphertext ct = Encrypt(m, pk_des);
  DecryptResult res = Decrypt(ct, *private_key_);

  EXPECT_TRUE(res.success);
  EXPECT_EQ(res.m, m);
}

TEST_F(Hesm2Test, BoundaryMmax) {
  // Mmax is supported
  yacl::math::MPInt m_max(Mmax);
  Ciphertext ct = Encrypt(m_max, *public_key_);
  DecryptResult res = Decrypt(ct, *private_key_);
  EXPECT_TRUE(res.success);
  EXPECT_EQ(res.m, m_max);
}

TEST_F(Hesm2Test, BoundaryNegativeMmax) {
  // -Mmax is supported
  yacl::math::MPInt m_min = -yacl::math::MPInt(Mmax);
  Ciphertext ct = Encrypt(m_min, *public_key_);
  DecryptResult res = Decrypt(ct, *private_key_);
  EXPECT_TRUE(res.success);
  EXPECT_EQ(res.m, m_min);
}

TEST_F(Hesm2Test, HomomorphicSelfSub) {
  yacl::math::MPInt m(123456);
  Ciphertext ct = Encrypt(m, *public_key_);

  // ct - ct = 0
  Ciphertext c_diff = HSub(ct, ct, *public_key_);
  DecryptResult res =
      Decrypt(c_diff, *private_key_);  // Should use fast path for 0

  EXPECT_TRUE(res.success);
  EXPECT_EQ(res.m, yacl::math::MPInt(0));
}

TEST_F(Hesm2Test, HomomorphicIdentityMul) {
  yacl::math::MPInt m(54321);
  Ciphertext ct = Encrypt(m, *public_key_);

  // ct * 1 = ct
  Ciphertext c_id = HMul(ct, yacl::math::MPInt(1), *public_key_);
  DecryptResult res = Decrypt(c_id, *private_key_);

  EXPECT_TRUE(res.success);
  EXPECT_EQ(res.m, m);

  // ct * -1 = -m
  Ciphertext c_neg = HMul(ct, yacl::math::MPInt(-1), *public_key_);
  DecryptResult res_neg = Decrypt(c_neg, *private_key_);

  EXPECT_TRUE(res_neg.success);
  EXPECT_EQ(res_neg.m, -m);
}

TEST_F(Hesm2Test, LargeNumberDecrypt) {
  // Choose a number that requires T2 lookup but is within Mmax.
  // Mmax is approx 2^33.
  // Jmax is 2^20 (approx 10^6).
  // Let's pick a number larger than Jmax to force T2 usage.
  // 5 * Jmax should be safe and exercise the search logic.
  yacl::math::MPInt m = yacl::math::MPInt(Jmax) * 5 + 1234;
  ASSERT_LT(m, yacl::math::MPInt(Mmax));

  Ciphertext ct = Encrypt(m, *public_key_);

  // Use ParDecrypt for large numbers as it might be designed for speed
  DecryptResult res = ParDecrypt(ct, *private_key_);

  EXPECT_TRUE(res.success);
  EXPECT_EQ(res.m, m);

  // Test single threaded Decrypt as well
  DecryptResult res_st = Decrypt(ct, *private_key_);
  EXPECT_TRUE(res_st.success);
  EXPECT_EQ(res_st.m, m);
}

TEST_F(Hesm2Test, DecryptFailureOutOfRange) {
  // Construct a ciphertext that decrypts to Mmax + something by homomorphic
  // addition. Encrypt(Mmax) + Encrypt(1) = Encrypt(Mmax + 1) This is a valid
  // group operation, but Decrypt should fail to find the DLP.

  yacl::math::MPInt m1(Mmax);
  yacl::math::MPInt m2(1);

  Ciphertext c1 = Encrypt(m1, *public_key_);
  Ciphertext c2 = Encrypt(m2, *public_key_);

  Ciphertext c_overflow = HAdd(c1, c2, *public_key_);

  // Decrypt should return failure because the result is outside the precomputed
  // table range
  DecryptResult res = Decrypt(c_overflow, *private_key_);
  EXPECT_FALSE(res.success);
  EXPECT_EQ(res.m, yacl::math::MPInt(0));  // Typically returns 0 on failure
}

}  // namespace examples::hesm2

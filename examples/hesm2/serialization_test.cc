#include <iostream>
#include <vector>

#include "hesm2/ahesm2.h"
#include "hesm2/ciphertext.h"
#include "hesm2/public_key.h"

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/utils/spi/spi_factory.h"

using namespace examples::hesm2;
using namespace yacl::crypto;
using namespace yacl::math;

void TestCiphertextSerialization() {
  std::cout << "Testing Ciphertext Serialization..." << std::endl;
  std::shared_ptr<EcGroup> ec_group = EcGroupFactory::Instance().Create("sm2");
  MPInt sk_val;
  MPInt::RandomLtN(ec_group->GetOrder(), &sk_val);
  auto pk_point = ec_group->MulBase(sk_val);

  PublicKey pk(pk_point, ec_group);

  auto c0 = Encrypt(yacl::math::MPInt(0), pk);
  yacl::Buffer buf = SerializeCiphertext(c0, pk);
  // Deserialize
  Ciphertext ct_des = DeserializeCiphertext(buf, pk);

  // Check equality using PointEqual
  if (ec_group->PointEqual(c0.GetC1(), ct_des.GetC1()) &&
      ec_group->PointEqual(c0.GetC2(), ct_des.GetC2())) {
    std::cout << "Ciphertext Serialization Test Passed!" << std::endl;
  } else {
    std::cout << "Ciphertext Serialization Test Failed!" << std::endl;
    exit(1);
  }
}
void TestCiphertextVectorSerialization() {
  std::cout << "Testing Ciphertext Vector Serialization..." << std::endl;
  std::shared_ptr<EcGroup> ec_group = EcGroupFactory::Instance().Create("sm2");
  MPInt sk_val;
  MPInt::RandomLtN(ec_group->GetOrder(), &sk_val);
  auto pk_point = ec_group->MulBase(sk_val);

  PublicKey pk(pk_point, ec_group);

  std::vector<Ciphertext> cts;
  for (int i = 0; i < 5; ++i) {
    MPInt m(i + 100);
    cts.push_back(Encrypt(m, pk));
  }

  // Serialize
  yacl::Buffer buf = SerializeCiphertexts(cts, pk);

  // Deserialize
  std::vector<Ciphertext> cts_des = DeserializeCiphertexts(buf, pk);

  if (cts_des.size() != cts.size()) {
    std::cout << "Vector Size Mismatch!" << std::endl;
    exit(1);
  }

  for (size_t i = 0; i < cts_des.size(); ++i) {
    if (!ec_group->PointEqual(cts[i].GetC1(), cts_des[i].GetC1()) ||
        !ec_group->PointEqual(cts[i].GetC2(), cts_des[i].GetC2())) {
      std::cout << "Vector Element " << i << " Mismatch!" << std::endl;
      exit(1);
    }
  }
  std::cout << "Ciphertext Vector Serialization Test Passed!" << std::endl;
}

void TestPublicKeySerialization() {
  std::cout << "Testing PublicKey Serialization..." << std::endl;
  std::shared_ptr<EcGroup> ec_group = EcGroupFactory::Instance().Create("sm2");
  MPInt sk_val;
  MPInt::RandomLtN(ec_group->GetOrder(), &sk_val);
  auto pk_point = ec_group->MulBase(sk_val);

  PublicKey pk(pk_point, ec_group);

  // Serialize
  yacl::Buffer buf = pk.Serialize();

  // Deserialize
  PublicKey pk_des = PublicKey::Deserialize(buf, ec_group);

  if (ec_group->PointEqual(pk.GetPoint(), pk_des.GetPoint())) {
    std::cout << "PublicKey Serialization Test Passed!" << std::endl;
  } else {
    std::cout << "PublicKey Serialization Test Failed!" << std::endl;
    exit(1);
  }
}

int main() {
  TestPublicKeySerialization();
  TestCiphertextSerialization();
  TestCiphertextVectorSerialization();
  return 0;
}

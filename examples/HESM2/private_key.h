// Completed by Guowei Ling

#ifndef PRIVATE_KEY_H_
#define PRIVATE_KEY_H_

#include "public_key.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"

class PrivateKey {
public:
    explicit PrivateKey(std::shared_ptr<yacl::crypto::EcGroup> ec_group)
        : ec_group_(std::move(ec_group)),
          k_(GenerateRandomK(ec_group_->GetOrder())),
          public_key_(GeneratePublicKey()) {}

    const yacl::math::MPInt& GetK() const { return k_; }
    const PublicKey& GetPublicKey() const { return public_key_; }
    const yacl::crypto::EcGroup& GetEcGroup() const { return *ec_group_; }

private:
    static yacl::math::MPInt GenerateRandomK(const yacl::math::MPInt& order) {
        yacl::math::MPInt k;
        yacl::math::MPInt::RandomLtN(order, &k);
        return k;
    }

    PublicKey GeneratePublicKey() const {
        auto generator = ec_group_->GetGenerator();
        auto point = ec_group_->Mul(generator, k_);
        return {point, ec_group_};
    }

    std::shared_ptr<yacl::crypto::EcGroup> ec_group_;
    yacl::math::MPInt k_;
    PublicKey public_key_;
};

#endif  // PRIVATE_KEY_H_

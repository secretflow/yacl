// Completed by Guowei Ling

#ifndef PUBLIC_KEY_H_
#define PUBLIC_KEY_H_

#include <utility>

#include "yacl/crypto/ecc/ecc_spi.h"

class PublicKey {
public:
    PublicKey(yacl::crypto::EcPoint  point, std::shared_ptr<yacl::crypto::EcGroup> ec_group)
        : point_(std::move(point)), ec_group_(std::move(ec_group)) {}

    const yacl::crypto::EcPoint& GetPoint() const { return point_; }
    const yacl::crypto::EcGroup& GetEcGroup() const { return *ec_group_; }

private:
    yacl::crypto::EcPoint point_;
    std::shared_ptr<yacl::crypto::EcGroup> ec_group_;
};

#endif  // PUBLIC_KEY_H_

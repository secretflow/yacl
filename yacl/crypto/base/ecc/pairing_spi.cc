#include "yacl/crypto/base/ecc/pairing_spi.h"

namespace yacl::crypto {

PairingGroupFactory &PairingGroupFactory::Instance() {
  static PairingGroupFactory factory;
  return factory;
}

void PairingGroupFactory::Register(const std::string &lib_name,
                                   uint64_t performance,
                                   const PairingCheckerT &checker,
                                   const PairingCreatorT &creator) {
  SpiFactoryBase<PairingGroup>::Register(
      lib_name, performance,
      [checker](const std::string &curve_name, const SpiArgs &) {
        CurveMeta meta;
        try {
          meta = GetCurveMetaByName(curve_name);
        } catch (const yacl::Exception &) {
          return false;
        }
        return checker(meta);
      },
      [creator](const std::string &curve_name, const SpiArgs &) {
        return creator(GetCurveMetaByName(curve_name));
      });
}

}  // namespace yacl::crypto

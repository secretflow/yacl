#include "zkp/bulletproofs/ipa_config.h"

#include <unordered_map>
#include "yacl/base/exception.h"

namespace examples::zkp {

bool IpaConfig::CheckValid() const {
  return witness_count > 0;
}

void IpaConfig::SetDynamicNumber(size_t dynamic_number) {
  witness_count = dynamic_number;
}

bool IpaConfig::operator==(const IpaConfig& other) const {
  return type == other.type && witness_count == other.witness_count;
}

namespace {

std::unordered_map<IpaType, IpaConfig> BuildConfigMap() {
  std::unordered_map<IpaType, IpaConfig> configs;
  
  // Inner product proof
  configs[IpaType::InnerProduct] = IpaConfig{
      .type = IpaType::InnerProduct,
      .witness_count = 0,
      .num_rnd_witness = 0,
      .num_generator = 0,
      .num_statement = 0,
      .hash_algo = yacl::crypto::HashAlgorithm::SHA256,
      .point_format = yacl::crypto::PointOctetFormat::Uncompressed,
  };
  
  return configs;
}

}  // namespace

IpaConfig GetInnerProduct(size_t witness_count) {
  static const auto configs = BuildConfigMap();
  auto config = configs.at(IpaType::InnerProduct);
  config.witness_count = witness_count;
  return config;
}

void SetDynamicNumber(IpaConfig* config, size_t dynamic_number) {
  YACL_ENFORCE(config != nullptr, "Config cannot be null");
  config->SetDynamicNumber(dynamic_number);
}

}  // namespace examples::zkp
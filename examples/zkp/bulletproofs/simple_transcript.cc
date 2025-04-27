#include "zkp/bulletproofs/simple_transcript.h"

#include <algorithm>
#include <cstring>

namespace examples::zkp {

SimpleTranscript::SimpleTranscript(std::string_view label) {
  // Initialize with an empty state - convert array to vector
  auto initial_hash = yacl::crypto::Sha256(yacl::ByteContainerView());
  state_ = std::vector<uint8_t>(initial_hash.begin(), initial_hash.end());
  
  // If a label is provided, append it
  if (!label.empty()) {
    AppendMessage("label", label);
  }
}

void SimpleTranscript::RangeProofDomainSep(uint64_t n, uint64_t m) {
  AppendMessage("dom-sep", "rangeproof v1");
  AppendU64("n", n);
  AppendU64("m", m);
}

void SimpleTranscript::InnerproductDomainSep(uint64_t n) {
  AppendMessage("dom-sep", "ipp v1");
  AppendU64("n", n);
}

void SimpleTranscript::R1csDomainSep() {
  AppendMessage("dom-sep", "r1cs v1");
}

void SimpleTranscript::R1cs1phaseDomainSep() {
  AppendMessage("dom-sep", "r1cs-1phase");
}

void SimpleTranscript::R1cs2phaseDomainSep() {
  AppendMessage("dom-sep", "r1cs-2phase");
}

void SimpleTranscript::AppendScalar(std::string_view label, const yacl::math::MPInt& scalar) {
  // Convert the scalar to a byte representation
  yacl::Buffer scalar_bytes = scalar.Serialize();
  
  // Append the scalar bytes with the given label
  AppendMessage(label, std::string_view(
      reinterpret_cast<const char*>(scalar_bytes.data()), scalar_bytes.size()));
}

void SimpleTranscript::AppendPoint(std::string_view label, 
                               const yacl::crypto::EcPoint& point,
                               const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  // Serialize the point to bytes
  yacl::Buffer point_bytes = curve->SerializePoint(point);
  
  // Append the point bytes with the given label
  AppendMessage(label, std::string_view(
      reinterpret_cast<const char*>(point_bytes.data()), point_bytes.size()));
}

void SimpleTranscript::ValidateAndAppendPoint(std::string_view label,
                                         const yacl::crypto::EcPoint& point,
                                         const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  // Check if the point is the identity (infinity point)
  if (curve->IsInfinity(point)) {
    throw yacl::Exception(
        "Transcript validation failed: point is the identity element");
  }
  
  // Append the point if it's valid
  AppendPoint(label, point, curve);
}

yacl::math::MPInt SimpleTranscript::ChallengeScalar(
    std::string_view label, 
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  // Generate 64 bytes of challenge data
  std::array<uint8_t, 64> buf{};
  ChallengeBytes(label, buf.data(), buf.size());
  
  // Convert the challenge bytes to a scalar modulo the curve order
  yacl::math::MPInt scalar;
  scalar.FromMagBytes(yacl::ByteContainerView(buf.data(), buf.size()));
  
  // Ensure the scalar is in the proper range (0, curve_order)
  scalar = scalar % curve->GetOrder();
  
  return scalar;
}

void SimpleTranscript::AppendMessage(std::string_view label, std::string_view message) {
  // Prepare the data to be appended (label length + label + message)
  std::vector<uint8_t> data;
  
  // Append the label length as a byte
  data.push_back(static_cast<uint8_t>(label.size()));
  
  // Append the label
  data.insert(data.end(), label.begin(), label.end());
  
  // Append the message
  data.insert(data.end(), message.begin(), message.end());
  
  // Update the transcript state
  UpdateState(data);
}

void SimpleTranscript::AppendU64(std::string_view label, uint64_t value) {
  // Convert uint64_t to 8 bytes in little-endian format
  std::array<uint8_t, 8> bytes{};
  bytes[0] = static_cast<uint8_t>(value & 0xFF);
  bytes[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
  bytes[2] = static_cast<uint8_t>((value >> 16) & 0xFF);
  bytes[3] = static_cast<uint8_t>((value >> 24) & 0xFF);
  bytes[4] = static_cast<uint8_t>((value >> 32) & 0xFF);
  bytes[5] = static_cast<uint8_t>((value >> 40) & 0xFF);
  bytes[6] = static_cast<uint8_t>((value >> 48) & 0xFF);
  bytes[7] = static_cast<uint8_t>((value >> 56) & 0xFF);
  
  // Append the bytes with the given label
  AppendMessage(label, std::string_view(
      reinterpret_cast<const char*>(bytes.data()), bytes.size()));
}

void SimpleTranscript::ChallengeBytes(std::string_view label, uint8_t* dest, size_t length) {
  // First, update the state with the challenge request
  std::vector<uint8_t> request;
  
  // Append a specific challenge indicator
  const char* challenge_indicator = "challenge";
  request.insert(request.end(), challenge_indicator, 
                challenge_indicator + strlen(challenge_indicator));
  
  // Append the label
  request.push_back(static_cast<uint8_t>(label.size()));
  request.insert(request.end(), label.begin(), label.end());
  
  // Append the length requested
  request.push_back(static_cast<uint8_t>(length));
  
  // Update state with the challenge request
  UpdateState(request);
  
  // Derive the challenge bytes from the current state using YACL's Shake256
  // Note: Shake256 returns a vector, not an array
  std::vector<uint8_t> output = yacl::crypto::Shake256(
      yacl::ByteContainerView(state_.data(), state_.size()), length);
  
  // Copy the challenge bytes to the destination
  std::copy_n(output.begin(), length, dest);
}

void SimpleTranscript::UpdateState(const std::vector<uint8_t>& data) {
  // Create a context that includes current state and new data
  std::vector<uint8_t> context;
  context.insert(context.end(), state_.begin(), state_.end());
  context.insert(context.end(), data.begin(), data.end());
  
  // Update the state with the hash of the context
  // Convert array to vector
  auto new_hash = yacl::crypto::Sha256(yacl::ByteContainerView(context.data(), context.size()));
  state_ = std::vector<uint8_t>(new_hash.begin(), new_hash.end());
}

} // namespace examples::zkp
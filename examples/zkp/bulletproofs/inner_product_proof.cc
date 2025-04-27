#include "zkp/bulletproofs/inner_product_proof.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <stdexcept>

#include "zkp/bulletproofs/util.h"  // For exponentiation helpers

namespace examples::zkp {

yacl::crypto::EcPoint MultiScalarMul(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const std::vector<yacl::math::MPInt>& scalars,
    const std::vector<yacl::crypto::EcPoint>& points) {
  
  if (scalars.size() != points.size()) {
    throw yacl::Exception("Mismatched vector lengths in multiscalar mul");
  }
  
  // For now we implement this naively - in production code you would
  // use a more optimized algorithm like Straus/Pippenger
  yacl::crypto::EcPoint result = curve->GetGenerator();
  curve->MulInplace(&result, yacl::math::MPInt(0));  // Set to identity
  
  for (size_t i = 0; i < scalars.size(); i++) {
    yacl::crypto::EcPoint term = curve->Mul(points[i], scalars[i]);
    result = curve->Add(result, term);
  }
  
  return result;
}

InnerProductProof InnerProductProof::Create(
    SimpleTranscript* transcript,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const yacl::crypto::EcPoint& Q,
    const std::vector<yacl::math::MPInt>& G_factors,
    const std::vector<yacl::math::MPInt>& H_factors,
    std::vector<yacl::crypto::EcPoint> G_vec,
    std::vector<yacl::crypto::EcPoint> H_vec,
    std::vector<yacl::math::MPInt> a_vec,
    std::vector<yacl::math::MPInt> b_vec) {
  
  // Create mutable copies just like in Rust
  auto G = G_vec;
  auto H = H_vec;
  auto a = a_vec;
  auto b = b_vec;
  
  size_t n = G.size();
  
  // All of the input vectors must have the same length
  assert(H.size() == n);
  assert(a.size() == n);
  assert(b.size() == n);
  assert(G_factors.size() == n);
  assert(H_factors.size() == n);
  
  // Must be a power of two
  assert((n & (n - 1)) == 0);
  
  transcript->InnerproductDomainSep(n);
  
  // Calculate lg_n just like in Rust
  size_t lg_n = 0;
  size_t temp_n = n;
  while (temp_n > 0) {
    lg_n++;
    temp_n >>= 1;
  }
  lg_n -= 1;  // Adjust for off-by-one
  
  std::vector<yacl::crypto::EcPoint> L_vec;
  std::vector<yacl::crypto::EcPoint> R_vec;
  L_vec.reserve(lg_n);
  R_vec.reserve(lg_n);
  
  // Main reduction loop
  while (n > 1) {
    size_t n_prime = n / 2;
    
    // Split vectors in half - use clean indexing to avoid bugs
    std::vector<yacl::math::MPInt> a_L(a.begin(), a.begin() + n_prime);
    std::vector<yacl::math::MPInt> a_R(a.begin() + n_prime, a.end());
    std::vector<yacl::math::MPInt> b_L(b.begin(), b.begin() + n_prime);
    std::vector<yacl::math::MPInt> b_R(b.begin() + n_prime, b.end());
    std::vector<yacl::crypto::EcPoint> G_L(G.begin(), G.begin() + n_prime);
    std::vector<yacl::crypto::EcPoint> G_R(G.begin() + n_prime, G.end());
    std::vector<yacl::crypto::EcPoint> H_L(H.begin(), H.begin() + n_prime);
    std::vector<yacl::crypto::EcPoint> H_R(H.begin() + n_prime, H.end());
    
    // Compute c_L and c_R (inner products)
    yacl::math::MPInt c_L = InnerProduct(a_L, b_R);
    yacl::math::MPInt c_R = InnerProduct(a_R, b_L);
    
    // Compute L point with the exact same logic as Rust
    std::vector<yacl::math::MPInt> L_scalars;
    std::vector<yacl::crypto::EcPoint> L_points;
    
    // a_L * G_factors[n_prime..n]
    for (size_t i = 0; i < n_prime; i++) {
      L_scalars.push_back(a_L[i].MulMod(G_factors[n_prime + i], curve->GetOrder()));
      L_points.push_back(G_R[i]);
    }
    
    // b_R * H_factors[0..n_prime]
    for (size_t i = 0; i < n_prime; i++) {
      L_scalars.push_back(b_R[i].MulMod(H_factors[i], curve->GetOrder()));
      L_points.push_back(H_L[i]);
    }
    
    // c_L * Q
    L_scalars.push_back(c_L);
    L_points.push_back(Q);
    
    yacl::crypto::EcPoint L = MultiScalarMul(curve, L_scalars, L_points);
    L_vec.push_back(L);
    
    // Compute R point with the exact same logic as Rust
    std::vector<yacl::math::MPInt> R_scalars;
    std::vector<yacl::crypto::EcPoint> R_points;
    
    // a_R * G_factors[0..n_prime]
    for (size_t i = 0; i < n_prime; i++) {
      R_scalars.push_back(a_R[i].MulMod(G_factors[i], curve->GetOrder()));
      R_points.push_back(G_L[i]);
    }
    
    // b_L * H_factors[n_prime..n]
    for (size_t i = 0; i < n_prime; i++) {
      R_scalars.push_back(b_L[i].MulMod(H_factors[n_prime + i], curve->GetOrder()));
      R_points.push_back(H_R[i]);
    }
    
    // c_R * Q
    R_scalars.push_back(c_R);
    R_points.push_back(Q);
    
    yacl::crypto::EcPoint R = MultiScalarMul(curve, R_scalars, R_points);
    R_vec.push_back(R);
    
    // Add points to transcript and generate challenge
    transcript->AppendPoint("L", L, curve);
    transcript->AppendPoint("R", R, curve);
    
    yacl::math::MPInt u = transcript->ChallengeScalar("u", curve);
    yacl::math::MPInt u_inv = u.InvertMod(curve->GetOrder());
    
    // Update vectors for next round - exactly like the Rust implementation
    std::vector<yacl::math::MPInt> new_a;
    std::vector<yacl::math::MPInt> new_b;
    std::vector<yacl::crypto::EcPoint> new_G;
    std::vector<yacl::crypto::EcPoint> new_H;
    
    for (size_t i = 0; i < n_prime; i++) {
      // a_L[i] * u + u_inv * a_R[i]
      new_a.push_back((a_L[i].MulMod(u, curve->GetOrder())).AddMod(u_inv.MulMod(a_R[i], curve->GetOrder()), curve->GetOrder()));
      
      // b_L[i] * u_inv + u * b_R[i]
      new_b.push_back((b_L[i].MulMod(u_inv, curve->GetOrder())).AddMod(u.MulMod(b_R[i], curve->GetOrder()), curve->GetOrder()));
      
      // Compute new G[i] = G_L[i] * u_inv + G_R[i] * u with their respective factors
      std::vector<yacl::math::MPInt> g_scalars = {
        (u_inv.MulMod(G_factors[i], curve->GetOrder())), 
        (u.MulMod(G_factors[n_prime + i], curve->GetOrder()))
      };
      std::vector<yacl::crypto::EcPoint> g_points = {G_L[i], G_R[i]};
      new_G.push_back(MultiScalarMul(curve, g_scalars, g_points));
      
      // Compute new H[i] = H_L[i] * u + H_R[i] * u_inv with their respective factors
      std::vector<yacl::math::MPInt> h_scalars = {
        (u.MulMod(H_factors[i], curve->GetOrder())), 
        (u_inv.MulMod(H_factors[n_prime + i], curve->GetOrder()))
      };
      std::vector<yacl::crypto::EcPoint> h_points = {H_L[i], H_R[i]};
      new_H.push_back(MultiScalarMul(curve, h_scalars, h_points));
    }
    
    // Replace old vectors with new ones
    a = new_a;
    b = new_b;
    G = new_G;
    H = new_H;
    
    // Halve n for next iteration
    n = n_prime;
  }
  
  // When n=1, we have our final a and b values
  return InnerProductProof(L_vec, R_vec, a[0], b[0]);
}

// Utility function to compute floor(log2(x))
size_t FloorLog2(size_t x) {
  if (x == 0) return 0;  // Handle special case
  size_t result = 0;
  while (x > 1) {
    x >>= 1;
    result++;
  }
  return result;
}

std::tuple<std::vector<yacl::math::MPInt>, 
           std::vector<yacl::math::MPInt>, 
           std::vector<yacl::math::MPInt>> 
InnerProductProof::VerificationScalars(
    size_t n,
    SimpleTranscript* transcript,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
  
  size_t lg_n = L_vec_.size();
  
  // Basic checks
  if (lg_n >= 32) {
    throw yacl::Exception("Inner product proof too large");
  }
  
  if (n != (1ULL << lg_n)) {
    throw yacl::Exception("Length n doesn't match proof size");
  }
  
  transcript->InnerproductDomainSep(n);
  
  // 1. Recompute challenges
  std::vector<yacl::math::MPInt> challenges;
  challenges.reserve(lg_n);
  
  for (size_t i = 0; i < lg_n; i++) {
    transcript->AppendPoint("L", L_vec_[i], curve);
    transcript->AppendPoint("R", R_vec_[i], curve);
    challenges.push_back(transcript->ChallengeScalar("u", curve));
  }
  
  // 2. Compute inverses
  std::vector<yacl::math::MPInt> challenges_inv;
  challenges_inv.reserve(lg_n);
  
  // Compute individual inverses and their product (we don't have batch inversion)
  yacl::math::MPInt all_inv_product(1);
  for (const auto& challenge : challenges) {
    yacl::math::MPInt inv = challenge.InvertMod(curve->GetOrder());
    challenges_inv.push_back(inv);
    all_inv_product = all_inv_product.MulMod(inv, curve->GetOrder());
  }
  
  // 3. Compute squares of challenges and their inverses
  std::vector<yacl::math::MPInt> challenges_sq;
  std::vector<yacl::math::MPInt> challenges_inv_sq;
  
  for (size_t i = 0; i < lg_n; i++) {
    challenges_sq.push_back(challenges[i].MulMod(challenges[i], curve->GetOrder()));
    challenges_inv_sq.push_back(challenges_inv[i].MulMod(challenges_inv[i], curve->GetOrder()));
  }
  
  // 4. Compute s values exactly as in Rust
  std::vector<yacl::math::MPInt> s;
  s.reserve(n);
  s.push_back(all_inv_product);
  
  for (size_t i = 1; i < n; i++) {
    // Count leading zeros of i to compute lg_i
    uint32_t i_u32 = static_cast<uint32_t>(i);
    uint32_t leading_zeros = 0;
    for (int bit = 31; bit >= 0; bit--) {
      if ((i_u32 & (1 << bit)) == 0) {
        leading_zeros++;
      } else {
        break;
      }
    }
    
    size_t lg_i = 32 - 1 - leading_zeros;
    size_t k = 1ULL << lg_i;
    
    // Get the corresponding squared challenge
    // The challenges are stored in "creation order" [u_k,...,u_1]
    yacl::math::MPInt u_lg_i_sq = challenges_sq[(lg_n - 1) - lg_i];
    
    // s[i] = s[i-k] * u_lg_i_sq
    s.push_back(s[i - k].MulMod(u_lg_i_sq, curve->GetOrder()));
  }
  
  return {challenges_sq, challenges_inv_sq, s};
}

bool InnerProductProof::Verify(
    size_t n,
    SimpleTranscript* transcript,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const std::vector<yacl::math::MPInt>& G_factors,
    const std::vector<yacl::math::MPInt>& H_factors,
    const yacl::crypto::EcPoint& P,
    const yacl::crypto::EcPoint& Q,
    const std::vector<yacl::crypto::EcPoint>& G,
    const std::vector<yacl::crypto::EcPoint>& H) const {
  
  try {
    std::cout << "Verifying proof with n=" << n << ", lg_n=" << L_vec_.size() << std::endl;
    
    // Get verification scalars
    auto [u_sq, u_inv_sq, s] = VerificationScalars(n, transcript, curve);
    
    std::cout << "Final a*b: " << a_.MulMod(b_, curve->GetOrder()) << std::endl;
    
    // The verification equation must be constructed exactly like in Rust
    std::vector<yacl::math::MPInt> scalars;
    std::vector<yacl::crypto::EcPoint> points;
    
    // 1. a*b*Q
    scalars.push_back(a_.MulMod(b_, curve->GetOrder()));
    points.push_back(Q);
    
    // 2. g_times_a_times_s
    for (size_t i = 0; i < G.size(); i++) {
      yacl::math::MPInt scalar = a_.MulMod(s[i], curve->GetOrder()).MulMod(G_factors[i], curve->GetOrder());
      scalars.push_back(scalar);
      points.push_back(G[i]);
    }
    
    // 3. h_times_b_div_s
    // 1/s[i] is s[!i], and !i runs from n-1 to 0 as i runs from 0 to n-1
    for (size_t i = 0; i < H.size(); i++) {
      yacl::math::MPInt scalar = b_.MulMod(s[n - 1 - i], curve->GetOrder()).MulMod(H_factors[i], curve->GetOrder());
      scalars.push_back(scalar);
      points.push_back(H[i]);
    }
    
    // 4. neg_u_sq
    for (const auto& ui_sq : u_sq) {
      // -u_sq mod order = order - u_sq
      yacl::math::MPInt neg_ui_sq = yacl::math::MPInt(0).SubMod(ui_sq, curve->GetOrder());
      scalars.push_back(neg_ui_sq);
    }
    for (const auto& L_i : L_vec_) {
      points.push_back(L_i);
    }
    
    // 5. neg_u_inv_sq
    for (const auto& ui_inv_sq : u_inv_sq) {
      // -u_inv_sq mod order = order - u_inv_sq
      yacl::math::MPInt neg_ui_inv_sq = yacl::math::MPInt(0).SubMod(ui_inv_sq, curve->GetOrder());
      scalars.push_back(neg_ui_inv_sq);
    }
    for (const auto& R_i : R_vec_) {
      points.push_back(R_i);
    }
    
    // Final multiscalar multiplication
    yacl::crypto::EcPoint expect_P = MultiScalarMul(curve, scalars, points);
    
    std::cout << "Expected vs Actual result: " 
              << (curve->PointEqual(expect_P, P) ? "MATCH" : "DIFFERENT") << std::endl;
    
    return curve->PointEqual(expect_P, P);
  } catch (const std::exception& e) {
    std::cerr << "Verification error: " << e.what() << std::endl;
    return false;
  }
}

size_t InnerProductProof::SerializedSize() const {
  size_t point_size = 32; // Typical compressed EC point size
  size_t scalar_size = 32; // Typical EC scalar size
  return (L_vec_.size() * 2 + 2) * point_size;
}

std::vector<uint8_t> InnerProductProof::ToBytes(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
  std::vector<uint8_t> bytes;
  
  // First, write the number of L/R pairs (needed for deserialization)
  uint32_t lg_n = static_cast<uint32_t>(L_vec_.size());
  bytes.resize(sizeof(lg_n));
  std::memcpy(bytes.data(), &lg_n, sizeof(lg_n));
  
  // Serialize L and R vectors with size prefixes for each point
  for (size_t i = 0; i < L_vec_.size(); i++) {
    // L point
    yacl::Buffer L_bytes = curve->SerializePoint(L_vec_[i]);
    uint32_t L_size = static_cast<uint32_t>(L_bytes.size());
    
    size_t prev_size = bytes.size();
    bytes.resize(prev_size + sizeof(L_size) + L_size);
    std::memcpy(bytes.data() + prev_size, &L_size, sizeof(L_size));
    std::memcpy(bytes.data() + prev_size + sizeof(L_size), 
               L_bytes.data<uint8_t>(), L_size);
    
    // R point
    yacl::Buffer R_bytes = curve->SerializePoint(R_vec_[i]);
    uint32_t R_size = static_cast<uint32_t>(R_bytes.size());
    
    prev_size = bytes.size();
    bytes.resize(prev_size + sizeof(R_size) + R_size);
    std::memcpy(bytes.data() + prev_size, &R_size, sizeof(R_size));
    std::memcpy(bytes.data() + prev_size + sizeof(R_size), 
               R_bytes.data<uint8_t>(), R_size);
  }
  
  // Serialize a and b with size prefixes
  yacl::Buffer a_bytes = a_.Serialize();
  uint32_t a_size = static_cast<uint32_t>(a_bytes.size());
  
  size_t prev_size = bytes.size();
  bytes.resize(prev_size + sizeof(a_size) + a_size);
  std::memcpy(bytes.data() + prev_size, &a_size, sizeof(a_size));
  std::memcpy(bytes.data() + prev_size + sizeof(a_size), 
             a_bytes.data<uint8_t>(), a_size);
  
  yacl::Buffer b_bytes = b_.Serialize();
  uint32_t b_size = static_cast<uint32_t>(b_bytes.size());
  
  prev_size = bytes.size();
  bytes.resize(prev_size + sizeof(b_size) + b_size);
  std::memcpy(bytes.data() + prev_size, &b_size, sizeof(b_size));
  std::memcpy(bytes.data() + prev_size + sizeof(b_size), 
             b_bytes.data<uint8_t>(), b_size);
  
  return bytes;
}

InnerProductProof InnerProductProof::FromBytes(
    const std::vector<uint8_t>& bytes,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  if (bytes.size() < sizeof(uint32_t)) {
    throw yacl::Exception("Invalid proof format: too short");
  }
  
  // Read the number of L/R pairs
  uint32_t lg_n;
  std::memcpy(&lg_n, bytes.data(), sizeof(lg_n));
  
  if (lg_n >= 32) {
    throw yacl::Exception("Proof too large");
  }
  
  std::vector<yacl::crypto::EcPoint> L_vec;
  std::vector<yacl::crypto::EcPoint> R_vec;
  L_vec.reserve(lg_n);
  R_vec.reserve(lg_n);
  
  size_t pos = sizeof(lg_n);
  
  // Read L and R points
  for (uint32_t i = 0; i < lg_n; i++) {
    // Check if there's enough data for size prefixes
    if (pos + sizeof(uint32_t) > bytes.size()) {
      throw yacl::Exception("Invalid proof format: truncated data");
    }
    
    // Read L point
    uint32_t L_size;
    std::memcpy(&L_size, bytes.data() + pos, sizeof(L_size));
    pos += sizeof(L_size);
    
    if (pos + L_size > bytes.size()) {
      throw yacl::Exception("Invalid proof format: truncated point data");
    }
    
    L_vec.push_back(curve->DeserializePoint(
        yacl::ByteContainerView(bytes.data() + pos, L_size)));
    pos += L_size;
    
    // Read R point
    if (pos + sizeof(uint32_t) > bytes.size()) {
      throw yacl::Exception("Invalid proof format: truncated data");
    }
    
    uint32_t R_size;
    std::memcpy(&R_size, bytes.data() + pos, sizeof(R_size));
    pos += sizeof(R_size);
    
    if (pos + R_size > bytes.size()) {
      throw yacl::Exception("Invalid proof format: truncated point data");
    }
    
    R_vec.push_back(curve->DeserializePoint(
        yacl::ByteContainerView(bytes.data() + pos, R_size)));
    pos += R_size;
  }
  
  // Read a and b scalars
  if (pos + sizeof(uint32_t) > bytes.size()) {
    throw yacl::Exception("Invalid proof format: truncated data");
  }
  
  uint32_t a_size;
  std::memcpy(&a_size, bytes.data() + pos, sizeof(a_size));
  pos += sizeof(a_size);
  
  if (pos + a_size > bytes.size()) {
    throw yacl::Exception("Invalid proof format: truncated scalar data");
  }
  
  yacl::math::MPInt a;
  a.FromMagBytes(yacl::ByteContainerView(bytes.data() + pos, a_size));
  pos += a_size;
  
  if (pos + sizeof(uint32_t) > bytes.size()) {
    throw yacl::Exception("Invalid proof format: truncated data");
  }
  
  uint32_t b_size;
  std::memcpy(&b_size, bytes.data() + pos, sizeof(b_size));
  pos += sizeof(b_size);
  
  if (pos + b_size > bytes.size()) {
    throw yacl::Exception("Invalid proof format: truncated scalar data");
  }
  
  yacl::math::MPInt b;
  b.FromMagBytes(yacl::ByteContainerView(bytes.data() + pos, b_size));
  
  // Make sure a and b are in the correct range
  a = a.Mod(curve->GetOrder());
  b = b.Mod(curve->GetOrder());
  
  return InnerProductProof(L_vec, R_vec, a, b);
}

yacl::math::MPInt InnerProduct(
    const std::vector<yacl::math::MPInt>& a,
    const std::vector<yacl::math::MPInt>& b) {
  if (a.size() != b.size()) {
    throw yacl::Exception("Vectors must have the same length for inner product");
  }
  
  yacl::math::MPInt result(0);
  for (size_t i = 0; i < a.size(); i++) {
    result = result + a[i] * b[i];
  }
  
  return result;
}

} // namespace examples::zkp
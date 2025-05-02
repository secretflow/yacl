#include "zkp/bulletproofs/inner_product_proof.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <stdexcept>

#include "zkp/bulletproofs/util.h"  // For exponentiation helpers

namespace examples::zkp {



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

  std::cout << "InnerProductProof::Create" << std::endl;
  
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

  if (lg_n >= 32) {
    throw yacl::Exception("Inner product proof too large: lg_n >= 32");
  }
  
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
    yacl::math::MPInt c_L = InnerProduct(a_L, b_R, curve);
    yacl::math::MPInt c_R = InnerProduct(a_R, b_L, curve);
    
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

// Utility function to compute floor(log2(x)) - DEFINED BEFORE USE
size_t FloorLog2(size_t x) {
  if (x == 0) return 0;
#ifdef __GNUC__
    // Use GCC/Clang built-in if available (more efficient)
    // __builtin_clzll returns number of leading zeros for unsigned long long
    // Handle x=0 separately as clz(0) is undefined.
    return (sizeof(unsigned long long) * 8 - 1) - __builtin_clzll(static_cast<unsigned long long>(x));
#else
    // Portable fallback
    size_t result = 0;
    // Shift right until x becomes 0. The number of shifts is floor(log2(original_x)).
    while (x >>= 1) { // Condition is true as long as x > 0 after shift
        ++result;
    }
    return result;
#endif
}

std::tuple<std::vector<yacl::math::MPInt>,
           std::vector<yacl::math::MPInt>,
           std::vector<yacl::math::MPInt>>
InnerProductProof::VerificationScalars(
    size_t n, // The original vector length (vector size = n)
    SimpleTranscript* transcript,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {

  size_t lg_n = L_vec_.size(); // Number of rounds = log2(n)

#if DEBUG_IPP
  std::cout << "\n--- InnerProductProof::VerificationScalars Start (n=" << n << ", lg_n=" << lg_n << ") ---" << std::endl;
#endif

  // --- Basic Checks ---
  YACL_ENFORCE(lg_n < 32, "Inner product proof too large (lg_n >= 32)");
  YACL_ENFORCE(n > 0 && (n == (1ULL << lg_n)), "Input n must be 2^lg_n and positive"); // Check n is power of 2 and matches lg_n
  YACL_ENFORCE(R_vec_.size() == lg_n, "L_vec and R_vec size mismatch");

  transcript->InnerproductDomainSep(n);

  // --- 1. Recompute challenges u_i from transcript ---
  std::vector<yacl::math::MPInt> challenges(lg_n);
  std::vector<yacl::math::MPInt> challenges_inv(lg_n); // Store inverses too

#if DEBUG_IPP
  std::cout << "Recomputing challenges..." << std::endl;
#endif
  for (size_t i = 0; i < lg_n; ++i) {
    // Append points in the same order as prover
    transcript->AppendPoint("L", L_vec_[i], curve);
    transcript->AppendPoint("R", R_vec_[i], curve);
    // Recompute challenge for this round
    challenges[i] = transcript->ChallengeScalar("u", curve);
    challenges_inv[i] = challenges[i].InvertMod(curve->GetOrder()); // Compute inverse now
#if DEBUG_IPP
    std::cout << "  u_" << (i + 1) << " = " << challenges[i] << ", u_inv_" << (i + 1) << " = " << challenges_inv[i] << std::endl;
#endif
  }

  // --- 2. Compute squares of challenges and inverses ---
  std::vector<yacl::math::MPInt> challenges_sq(lg_n);
  std::vector<yacl::math::MPInt> challenges_inv_sq(lg_n);
  for (size_t i = 0; i < lg_n; ++i) {
      challenges_sq[i] = challenges[i].MulMod(challenges[i], curve->GetOrder());
      challenges_inv_sq[i] = challenges_inv[i].MulMod(challenges_inv[i], curve->GetOrder());
  }

  // --- 3. Compute s vector ---
  std::vector<yacl::math::MPInt> s(n);
  // Compute s[0] = product_{j=0}^{lg_n-1} u_{j+1}^{-1}
  yacl::math::MPInt s_0(1);
  for (const auto& inv : challenges_inv) {
      s_0 = s_0.MulMod(inv, curve->GetOrder());
  }
  s[0] = s_0;

#if DEBUG_IPP
  std::cout << "Computing s vector (size " << n << ")..." << std::endl;
  std::cout << "  s[0] = " << s[0] << std::endl;
#endif

  for (size_t i = 1; i < n; ++i) {
      // Find the 0-based index of the highest set bit of i
      size_t lg_i = FloorLog2(i);
      size_t k = 1ULL << lg_i; // k = 2^{lg_i}

      // *** FIX: USE RUST INDEXING SCHEME ***
      // The challenges are stored in "creation order" as [u_1, u_2,..., u_lg_n]
      // challenges_sq holds [u_1^2, u_2^2, ..., u_lg_n^2]
      // Rust code uses index (lg_n - 1) - lg_i
      size_t challenge_idx = (lg_n - 1) - lg_i;
      YACL_ENFORCE(challenge_idx < challenges_sq.size(), "Logic error: challenge_idx out of bounds");
      const yacl::math::MPInt& u_sq_for_level = challenges_sq[challenge_idx];

      // Find the previous index `i - k`
      size_t prev_i = i - k;
      YACL_ENFORCE(prev_i < i, "Logic error: prev_i >= i");

      // Calculate s[i] = s[prev_i] * u_sq_for_level
      s.at(i) = s.at(prev_i).MulMod(u_sq_for_level, curve->GetOrder());

#if DEBUG_IPP >= 2 // Only print s vector for higher debug levels
      // Correct the debug print to show the challenge index used
      std::cout << "  s[" << i << "] = s[" << prev_i << "] * challenges_sq[" << challenge_idx << "] = " << s[i] << std::endl;
#endif
  }

#if DEBUG_IPP
  std::cout << "--- InnerProductProof::VerificationScalars End ---" << std::endl;
#endif

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

  std::cout << "InnerProductProof::Verify" << std::endl;
  
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
    
    //debug
    std::cout << "expect_P: " << curve->SerializePoint(expect_P) << std::endl;
    std::cout << "P: " << curve->SerializePoint(P) << std::endl;

    auto expect_P_affine = curve->GetAffinePoint(expect_P);
    auto P_affine = curve->GetAffinePoint(P);

    std::cout << "expect_P_affine: " << expect_P_affine << std::endl;
    std::cout << "P_affine: " << P_affine << std::endl;

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

yacl::Buffer InnerProductProof::ToBytes(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
  yacl::Buffer bytes;
  
  // First, write the number of L/R pairs (needed for deserialization)
  uint32_t lg_n = static_cast<uint32_t>(L_vec_.size());
  bytes.resize(sizeof(lg_n));
  std::memcpy(bytes.data<uint8_t>(), &lg_n, sizeof(lg_n));
  
  // Serialize L and R vectors with size prefixes for each point
  for (size_t i = 0; i < L_vec_.size(); i++) {
    // L point
    yacl::Buffer L_bytes = curve->SerializePoint(L_vec_[i]);
    uint32_t L_size = static_cast<uint32_t>(L_bytes.size());
    
    size_t prev_size = bytes.size();
    bytes.resize(prev_size + sizeof(L_size) + L_size);
    std::memcpy(bytes.data<uint8_t>() + prev_size, &L_size, sizeof(L_size));
    std::memcpy(bytes.data<uint8_t>() + prev_size + sizeof(L_size), 
               L_bytes.data<uint8_t>(), L_size);
    
    // R point
    yacl::Buffer R_bytes = curve->SerializePoint(R_vec_[i]);
    uint32_t R_size = static_cast<uint32_t>(R_bytes.size());
    
    prev_size = bytes.size();
    bytes.resize(prev_size + sizeof(R_size) + R_size);
    std::memcpy(bytes.data<uint8_t>() + prev_size, &R_size, sizeof(R_size));
    std::memcpy(bytes.data<uint8_t>() + prev_size + sizeof(R_size), 
               R_bytes.data<uint8_t>(), R_size);
  }
  
  // Serialize a and b with size prefixes
  yacl::Buffer a_bytes = a_.Serialize();
  uint32_t a_size = static_cast<uint32_t>(a_bytes.size());
  
  size_t prev_size = bytes.size();
  bytes.resize(prev_size + sizeof(a_size) + a_size);
  std::memcpy(bytes.data<uint8_t>() + prev_size, &a_size, sizeof(a_size));
  std::memcpy(bytes.data<uint8_t>() + prev_size + sizeof(a_size), 
             a_bytes.data<uint8_t>(), a_size);
  
  yacl::Buffer b_bytes = b_.Serialize();
  uint32_t b_size = static_cast<uint32_t>(b_bytes.size());
  
  prev_size = bytes.size();
  bytes.resize(prev_size + sizeof(b_size) + b_size);
  std::memcpy(bytes.data<uint8_t>() + prev_size, &b_size, sizeof(b_size));
  std::memcpy(bytes.data<uint8_t>() + prev_size + sizeof(b_size), 
             b_bytes.data<uint8_t>(), b_size);
  
  return bytes;
}


InnerProductProof InnerProductProof::FromBytes(
    const yacl::ByteContainerView& bytes,
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
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

  // Implement this naively - in production code you would
  // use a more optimized algorithm like Straus/Pippenger or batch operations
  yacl::crypto::EcPoint result = curve->GetGenerator();
  curve->MulInplace(&result, yacl::math::MPInt(0));  // Set to identity (point at infinity)

  // Debugging output can be very noisy, commenting out for clarity unless specifically needed
  // for (size_t i = 0; i < scalars.size(); i++) {
  //   std::cout << "MultiScalarMul: i = " << i << ", scalar = " << scalars[i] << std::endl;
  //   yacl::crypto::EcPoint term = curve->Mul(points[i], scalars[i]);
  //   std::cout << "MultiScalarMul: term = " << curve->SerializePoint(term) << std::endl;
  //   result = curve->Add(result, term);
  // }

  // Reverting to the naive loop as batch operations are not available
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
  auto G = G_vec; // These are the initial G points
  auto H = H_vec; // These are the initial H points
  auto a = a_vec;
  auto b = b_vec;

  size_t n = G.size();

  // All of the input vectors must have the same length
  assert(H.size() == n);
  assert(a.size() == n);
  assert(b.size() == n);
  assert(G_factors.size() == n);
  assert(H_factors.size() == n);

  // Must be a power of two and non-zero
  assert((n > 0) && ((n & (n - 1)) == 0));

  transcript->InnerproductDomainSep(n);

  // Calculate lg_n (log2(n))
  size_t lg_n = 0;
  if (n > 1) {
    // Use GCC/Clang intrinsic for counting leading zeros
    // This gives floor(log2(n)) if n is a power of 2 and > 0
#if defined(__GNUC__) || defined(__clang__)
    if (sizeof(size_t) == 4) {
       lg_n = 31 - __builtin_clz(n);
    } else { // Assuming 64-bit
       lg_n = 63 - __builtin_clzll(n);
    }
#else
    size_t temp_n = n;
    while (temp_n > 1) {
        lg_n++;
        temp_n >>= 1;
    }
#endif
  }


  if (lg_n >= 32 && n > (1ULL << 32)) { // Check against max possible n for 32-bit lg_n
       throw yacl::Exception("Inner product proof too large: n must be power of 2 up to 2^32");
  }
  if (n > 0 && n == (1ULL << 32)) { // Special case for n = 2^32
      lg_n = 32;
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

    // Compute L point using current vectors (NO initial factors applied here)
    std::vector<yacl::math::MPInt> L_scalars;
    std::vector<yacl::crypto::EcPoint> L_points;
    L_scalars.reserve(2 * n_prime + 1); // Reserve space
    L_points.reserve(2 * n_prime + 1);

    // a_L * G_R
    L_scalars.insert(L_scalars.end(), a_L.begin(), a_L.end());
    L_points.insert(L_points.end(), G_R.begin(), G_R.end());

    // b_R * H_L
    L_scalars.insert(L_scalars.end(), b_R.begin(), b_R.end());
    L_points.insert(L_points.end(), H_L.begin(), H_L.end());

    // c_L * Q
    L_scalars.push_back(c_L);
    L_points.push_back(Q);

    yacl::crypto::EcPoint L = MultiScalarMul(curve, L_scalars, L_points);
    L_vec.push_back(L);

    // Compute R point using current vectors (NO initial factors applied here)
    std::vector<yacl::math::MPInt> R_scalars;
    std::vector<yacl::crypto::EcPoint> R_points;
    R_scalars.reserve(2 * n_prime + 1); // Reserve space
    R_points.reserve(2 * n_prime + 1);

    // a_R * G_L
    R_scalars.insert(R_scalars.end(), a_R.begin(), a_R.end());
    R_points.insert(R_points.end(), G_L.begin(), G_L.end());

    // b_L * H_R
    R_scalars.insert(R_scalars.end(), b_L.begin(), b_L.end());
    R_points.insert(R_points.end(), H_R.begin(), H_R.end());

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

    // Update vectors for next round - standard IPP recursion (NO factors applied here)
    std::vector<yacl::math::MPInt> new_a;
    std::vector<yacl::math::MPInt> new_b;
    std::vector<yacl::crypto::EcPoint> new_G;
    std::vector<yacl::crypto::EcPoint> new_H;
    new_a.reserve(n_prime); // Reserve space
    new_b.reserve(n_prime);
    new_G.reserve(n_prime);
    new_H.reserve(n_prime);


    for (size_t i = 0; i < n_prime; i++) {
      // a_L[i] * u + u_inv * a_R[i]
      new_a.push_back((a_L[i].MulMod(u, curve->GetOrder())).AddMod(u_inv.MulMod(a_R[i], curve->GetOrder()), curve->GetOrder()));

      // b_L[i] * u_inv + u * b_R[i]
      new_b.push_back((b_L[i].MulMod(u_inv, curve->GetOrder())).AddMod(u.MulMod(b_R[i], curve->GetOrder()), curve->GetOrder()));

      // Compute new G[i] = G_L[i] * u_inv + G_R[i] * u  (Standard recursion, NO factors)
      std::vector<yacl::math::MPInt> g_scalars = { u_inv, u };
      std::vector<yacl::crypto::EcPoint> g_points = {G_L[i], G_R[i]};
      new_G.push_back(MultiScalarMul(curve, g_scalars, g_points));

      // Compute new H[i] = H_L[i] * u + H_R[i] * u_inv (Standard recursion, Note the switch for H bases, NO factors)
      std::vector<yacl::math::MPInt> h_scalars = { u, u_inv }; // Note order for H bases
      std::vector<yacl::crypto::EcPoint> h_points = {H_L[i], H_R[i]};
      new_H.push_back(MultiScalarMul(curve, h_scalars, h_points));
    }

    // Replace old vectors with new ones
    a = std::move(new_a); // Use move semantics for efficiency
    b = std::move(new_b);
    G = std::move(new_G); // Now G is G^(k+1)
    H = std::move(new_H); // Now H is H^(k+1)

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
  // Use GCC/Clang intrinsic for count leading zeros
#if defined(__GNUC__) || defined(__clang__)
  if (sizeof(size_t) == 4) {
      return 31 - __builtin_clz(x);
  } else { // Assuming 64-bit
      return 63 - __builtin_clzll(x);
  }
#else
  // Fallback for other compilers
  while (x > 1) {
    x >>= 1;
    result++;
  }
  return result;
#endif
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
   if (n == 0) {
       if (lg_n != 0) throw yacl::Exception("Length n doesn't match proof size");
   } else if ((n & (n - 1)) != 0) { // n must be a power of two if > 0
       throw yacl::Exception("Length n must be a power of two");
   }
   if (n > 0 && lg_n >= 32 && n > (1ULL << 32)) { // Check against max possible n for 32-bit lg_n
       throw yacl::Exception("Inner product proof too large");
   }
    if (n > 0 && n == (1ULL << 32)) { // Special case for n = 2^32
      if (lg_n != 32) throw yacl::Exception("Length n doesn't match proof size");
    } else if (n > 0 && n != (1ULL << lg_n)) {
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
  // std::cout << "VerificationScalars: Calculating inverses..." << std::endl; // Comment out verbose debug
  std::vector<yacl::math::MPInt> challenges_inv;
  challenges_inv.reserve(lg_n);

  // Compute individual inverses (YACL doesn't have batch inversion)
  for (const auto& challenge : challenges) {
    yacl::math::MPInt inv = challenge.InvertMod(curve->GetOrder());
    // std::cout << "VerificationScalars: challenge = " << challenge << ", inv = " << inv << std::endl; // Comment out verbose debug
    challenges_inv.push_back(inv);
  }

  // 3. Compute squares of challenges
  std::vector<yacl::math::MPInt> challenges_sq;
  challenges_sq.reserve(lg_n);
  for (const auto& challenge : challenges) {
    challenges_sq.push_back(challenge.MulMod(challenge, curve->GetOrder()));
  }

  // 4. Compute s values
  std::vector<yacl::math::MPInt> s;
  s.reserve(n);

  if (n > 0) {
      // s[0] = product of all u_inv
      yacl::math::MPInt all_inv_product(1);
      for (const auto& inv : challenges_inv) {
           all_inv_product = all_inv_product.MulMod(inv, curve->GetOrder());
      }
      s.push_back(all_inv_product); // s[0]

      for (size_t i = 1; i < n; i++) {
          // Find the index k of the lowest set bit of i (ctz)
  #if defined(__GNUC__) || defined(__clang__)
          size_t k;
          if (sizeof(size_t) == 4) {
             k = __builtin_ctz(i);
          } else { // Assuming 64-bit
             k = __builtin_ctzll(i);
          }
  #else
          size_t k = 0;
          size_t temp_i = i;
          while ((temp_i & 1) == 0 && temp_i != 0) {
              k++;
              temp_i >>= 1;
          }
  #endif

          // The challenge corresponding to this bit index is challenges[k]
          yacl::math::MPInt u_k_sq = challenges_sq[k];

          // s[i] = s[i - (1 << k)] * u_k^2
          s.push_back(s[i - (1ULL << k)].MulMod(u_k_sq, curve->GetOrder()));
      }
  }


  return {challenges_sq, challenges_inv, s}; // Return challenges_inv directly
}


// ... other includes and functions ...

bool InnerProductProof::Verify(
    size_t n,
    SimpleTranscript* transcript,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const std::vector<yacl::math::MPInt>& G_factors, // Original G factors
    const std::vector<yacl::math::MPInt>& H_factors, // Original H factors
    const yacl::crypto::EcPoint& P, // Original commitment
    const yacl::crypto::EcPoint& Q,
    const std::vector<yacl::crypto::EcPoint>& G, // Original G bases
    const std::vector<yacl::crypto::EcPoint>& H) const { // Original H bases

  try {
    std::cout << "Verifying proof with n=" << n << ", lg_n=" << L_vec_.size() << std::endl;

    // Get verification scalars: challenges_sq, challenges_inv, s vector
    auto [u_sq, u_inv, s] = VerificationScalars(n, transcript, curve);
    size_t lg_n = L_vec_.size(); // Re-get lg_n after VerificationScalars call

    std::cout << "Final a*b: " << a_.MulMod(b_, curve->GetOrder()) << std::endl;

    // Calculate u_inv_sq from u_inv
    std::vector<yacl::math::MPInt> u_inv_sq;
    u_inv_sq.reserve(lg_n);
    for(const auto& inv : u_inv) {
        u_inv_sq.push_back(inv.MulMod(inv, curve->GetOrder()));
    }

    // Compute LHS = P + sum(u_sq * L) + sum(u_inv_sq * R)
    yacl::crypto::EcPoint lhs_P = P; // Start with P
    if (lg_n > 0) {
        // Check sizes
        if (u_sq.size() != lg_n || L_vec_.size() != lg_n || u_inv_sq.size() != lg_n || R_vec_.size() != lg_n) {
             throw yacl::Exception("Verifier size mismatch in L/R vectors or challenges");
        }
        std::vector<yacl::math::MPInt> lhs_scalars;
        std::vector<yacl::crypto::EcPoint> lhs_points;
        lhs_scalars.reserve(2 * lg_n);
        lhs_points.reserve(2 * lg_n);
        // Add terms for L_vec
        for(size_t i=0; i<lg_n; ++i) { lhs_scalars.push_back(u_sq[i]); lhs_points.push_back(L_vec_[i]); }
        // Add terms for R_vec
        for(size_t i=0; i<lg_n; ++i) { lhs_scalars.push_back(u_inv_sq[i]); lhs_points.push_back(R_vec_[i]); }
        if (!lhs_scalars.empty()){ lhs_P = curve->Add(lhs_P, MultiScalarMul(curve, lhs_scalars, lhs_points)); }
    }

    // Compute RHS = Q*(a*b) + sum(s * G_factors * G) + sum(s_inv_rev * H_factors * H)
    std::vector<yacl::math::MPInt> rhs_scalars;
    std::vector<yacl::crypto::EcPoint> rhs_points;
    size_t rhs_size_estimate = 1 + (n > 0 ? 2 * n : 0);
    rhs_scalars.reserve(rhs_size_estimate);
    rhs_points.reserve(rhs_size_estimate);
    // Term 1: Q*(a*b)
    rhs_scalars.push_back(a_.MulMod(b_, curve->GetOrder())); rhs_points.push_back(Q);
    if (n > 0) {
        // Check sizes
        if (s.size() != n || G_factors.size() != n || G.size() != n || H_factors.size() != n || H.size() != n) {
             throw yacl::Exception("Verifier size mismatch in G/H vectors or factors");
        }
        // Term 2: sum(s[i] * G_factors[i] * G[i])
        for (size_t i = 0; i < n; i++) { rhs_scalars.push_back(s[i].MulMod(G_factors[i], curve->GetOrder())); rhs_points.push_back(G[i]); }
        // Term 3: sum(s[n-1-i] * H_factors[i] * H[i])
        for (size_t i = 0; i < n; i++) { rhs_scalars.push_back(s[n - 1 - i].MulMod(H_factors[i], curve->GetOrder())); rhs_points.push_back(H[i]); }
    }
    yacl::crypto::EcPoint rhs_P = MultiScalarMul(curve, rhs_scalars, rhs_points);

    // --- DETAILED COMPARISON ---
    yacl::Buffer lhs_bytes = curve->SerializePoint(lhs_P);
    yacl::Buffer rhs_bytes = curve->SerializePoint(rhs_P);
    auto lhs_affine = curve->GetAffinePoint(lhs_P);
    auto rhs_affine = curve->GetAffinePoint(rhs_P);

    std::cout << "LHS Bytes: " << lhs_bytes.size() << " bytes, Data ptr: " << static_cast<const void*>(lhs_bytes.data()) << std::endl; // Print size and address
    std::cout << "RHS Bytes: " << rhs_bytes.size() << " bytes, Data ptr: " << static_cast<const void*>(rhs_bytes.data()) << std::endl;

    bool bytes_equal = (lhs_bytes.size() == rhs_bytes.size()) &&
                       (std::memcmp(lhs_bytes.data(), rhs_bytes.data(), lhs_bytes.size()) == 0);

    bool affines_equal = (lhs_affine.x == rhs_affine.x) && (lhs_affine.y == rhs_affine.y);

    bool point_equal_result = curve->PointEqual(lhs_P, rhs_P);

    std::cout << "LHS Affine: (" << lhs_affine.x << ", " << lhs_affine.y << ")" << std::endl;
    std::cout << "RHS Affine: (" << rhs_affine.x << ", " << rhs_affine.y << ")" << std::endl;

    std::cout << "Comparison - Bytes Equal: " << (bytes_equal ? "Yes" : "No") << std::endl;
    std::cout << "Comparison - Affines Equal: " << (affines_equal ? "Yes" : "No") << std::endl;
    std::cout << "Comparison - PointEqual Result: " << (point_equal_result ? "Yes" : "No") << std::endl;

    // Use the result from PointEqual as the final verification status,
    // but the detailed comparison helps diagnose the inconsistency.
    bool final_result = point_equal_result;

    std::cout << "Expected vs Actual result: " << (final_result ? "MATCH" : "DIFFERENT") << std::endl;
    return final_result;
    // --- END DETAILED COMPARISON ---

  } catch (const std::exception& e) {
    std::cerr << "Verification error: " << e.what() << std::endl;
    return false;
  }
}

// ... other functions (MultiScalarMul, Create, VerificationScalars, etc.) remain the same ...



size_t InnerProductProof::SerializedSize() const {
  // This is just an estimate, depends on the actual point serialization size
  // A more accurate method would be to actually serialize and get the size.
  // Let's use a fixed typical compressed size for secp256k1 + 1 byte for header (if applicable)
  size_t point_size = 33;
  // Each point serialization includes a 4-byte size prefix in ToBytes/FromBytes
  size_t size_prefix_size = sizeof(uint32_t);

  // Total size = size of lg_n (4 bytes) + lg_n * (size_prefix + L_size + size_prefix + R_size) + (size_prefix + a_size) + (size_prefix + b_size)
  // Assuming a_size and b_size are roughly scalar_size (32 bytes for 256-bit curve)
  size_t scalar_size = 32;

  // Simplified estimate using typical sizes
  return sizeof(uint32_t) + L_vec_.size() * (size_prefix_size + point_size) * 2 + (size_prefix_size + scalar_size) * 2;
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

  if (lg_n >= 32 && lg_n != 32) { // Maximum expected lg_n for typical systems (allowing n=2^32)
    throw yacl::Exception("Proof too large");
  }

  std::vector<yacl::crypto::EcPoint> L_vec;
  std::vector<yacl::crypto::EcPoint> R_vec;
  L_vec.reserve(lg_n);
  R_vec.reserve(lg_n);

  size_t pos = sizeof(lg_n);

  // Read L and R points
  for (uint32_t i = 0; i < lg_n; i++) {
    // Read L point
    if (pos + sizeof(uint32_t) > bytes.size()) {
      throw yacl::Exception("Invalid proof format: truncated data (L size)");
    }
    uint32_t L_size;
    std::memcpy(&L_size, bytes.data() + pos, sizeof(L_size));
    pos += sizeof(L_size);

    if (pos + L_size > bytes.size()) {
      throw yacl::Exception("Invalid proof format: truncated point data (L)");
    }
    L_vec.push_back(curve->DeserializePoint(
        yacl::ByteContainerView(bytes.data() + pos, L_size)));
    pos += L_size;

    // Read R point
    if (pos + sizeof(uint32_t) > bytes.size()) {
      throw yacl::Exception("Invalid proof format: truncated data (R size)");
    }
    uint32_t R_size;
    std::memcpy(&R_size, bytes.data() + pos, sizeof(R_size));
    pos += sizeof(R_size);

    if (pos + R_size > bytes.size()) {
      throw yacl::Exception("Invalid proof format: truncated point data (R)");
    }
    R_vec.push_back(curve->DeserializePoint(
        yacl::ByteContainerView(bytes.data() + pos, R_size)));
    pos += R_size;
  }

  // Read a and b scalars
  if (pos + sizeof(uint32_t) > bytes.size()) {
    throw yacl::Exception("Invalid proof format: truncated data (a size)");
  }
  uint32_t a_size;
  std::memcpy(&a_size, bytes.data() + pos, sizeof(a_size));
  pos += sizeof(a_size);

  if (pos + a_size > bytes.size()) {
    throw yacl::Exception("Invalid proof format: truncated scalar data (a)");
  }
  yacl::math::MPInt a;
  a.FromMagBytes(yacl::ByteContainerView(bytes.data() + pos, a_size));
  pos += a_size; // Advance pos past a

  if (pos + sizeof(uint32_t) > bytes.size()) {
    throw yacl::Exception("Invalid proof format: truncated data (b size)");
  }
  uint32_t b_size;
  std::memcpy(&b_size, bytes.data() + pos, sizeof(b_size));
  pos += sizeof(b_size);

  if (pos + b_size > bytes.size()) {
    throw yacl::Exception("Invalid proof format: truncated scalar data (b)");
  }
  yacl::math::MPInt b;
  b.FromMagBytes(yacl::ByteContainerView(bytes.data() + pos, b_size));
  pos += b_size; // Advance pos past b

  // Check if there's any remaining data
  if (pos != bytes.size()) {
      throw yacl::Exception("Invalid proof format: unexpected remaining data");
  }

  // Make sure a and b are in the correct range
  a = a.Mod(curve->GetOrder());
  b = b.Mod(curve->GetOrder());

  return InnerProductProof(L_vec, R_vec, a, b);
}


yacl::math::MPInt InnerProduct(
    const std::vector<yacl::math::MPInt>& a,
    const std::vector<yacl::math::MPInt>& b,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) { // Added curve param
  if (a.size() != b.size()) {
    throw yacl::Exception("Vectors must have the same length for inner product");
  }
  if (a.empty()) { // Handle empty vector case
      return yacl::math::MPInt(0);
  }

  const auto& order = curve->GetOrder(); // Get order

  yacl::math::MPInt result(0);
  for (size_t i = 0; i < a.size(); i++) {
    // result = result + a[i] * b[i]; // Original
    // Ensure a[i] and b[i] are within order if necessary, though they should be from RandomLtN
    // Calculate product modulo order, then add modulo order
    yacl::math::MPInt term = a[i].MulMod(b[i], order);
    result = result.AddMod(term, order);
  }

  return result; // Result is already modulo order
}

} // namespace examples::zkp
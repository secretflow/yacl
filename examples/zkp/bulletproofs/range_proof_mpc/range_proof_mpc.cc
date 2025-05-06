#include "zkp/bulletproofs/range_proof_mpc/range_proof_mpc.h"

#include <algorithm>

#include "yacl/crypto/rand/rand.h"
#include "zkp/bulletproofs/range_proof_mpc/dealer.h"
#include "zkp/bulletproofs/range_proof_mpc/party.h"
#include "zkp/bulletproofs/util.h"

namespace examples::zkp {

RangeProofMPC::RangeProofMPC(
    const yacl::crypto::EcPoint& A,
    const yacl::crypto::EcPoint& S,
    const yacl::crypto::EcPoint& T_1,
    const yacl::crypto::EcPoint& T_2,
    const yacl::math::MPInt& t_x,
    const yacl::math::MPInt& t_x_blinding,
    const yacl::math::MPInt& e_blinding,
    const InnerProductProof& ipp_proof)
    : A_(A),
      S_(S),
      T_1_(T_1),
      T_2_(T_2),
      t_x_(t_x),
      t_x_blinding_(t_x_blinding),
      e_blinding_(e_blinding),
      ipp_proof_(ipp_proof) {}

std::pair<RangeProofMPC, yacl::crypto::EcPoint> RangeProofMPC::CreateSingle(
    const BulletproofGens& bp_gens,
    const PedersenGens& pc_gens,
    SimpleTranscript& transcript,
    uint64_t v,
    const yacl::math::MPInt& v_blinding,
    size_t n) {

    auto [proof, value_commitments] = CreateMultiple(bp_gens, pc_gens, transcript, {v}, {v_blinding}, n);

    return {proof, value_commitments[0]};
}

std::pair<RangeProofMPC, std::vector<yacl::crypto::EcPoint>> RangeProofMPC::CreateMultiple(
    const BulletproofGens& bp_gens,
    const PedersenGens& pc_gens,
    SimpleTranscript& transcript,
    const std::vector<uint64_t>& values,
    const std::vector<yacl::math::MPInt>& blindings,
    size_t n) {
  
  auto curve = pc_gens.GetCurve();

  if (values.size() != blindings.size()) {
    throw yacl::Exception("Number of values must match number of blinding factors");
  }
  
  size_t m = values.size();
  
  // Create the dealer for the protocol
  auto dealer = Dealer::New(bp_gens, pc_gens, transcript, n, m);
  
  // Create parties for each value
  std::vector<PartyAwaitingPosition> parties;
  for (size_t i = 0; i < m; i++) {
    parties.push_back(Party::New(bp_gens, pc_gens, values[i], blindings[i], n));
  }
  
  // Protocol step 1: Parties commit to bits
  std::vector<PartyAwaitingBitChallenge> parties_awaiting_challenge;
  std::vector<BitCommitment> bit_commitments;
  
  for (size_t j = 0; j < m; j++) {
    auto [party_bits, bit_commitment] = parties[j].AssignPosition(j);
    parties_awaiting_challenge.push_back(std::move(party_bits));
    bit_commitments.push_back(bit_commitment);
  }

  // Extract value commitments
  std::vector<yacl::crypto::EcPoint> value_commitments;
  for (const auto& commitment : bit_commitments) {
    value_commitments.push_back(commitment.GetV());
  }
  
  // Protocol step 2: Dealer issues first challenge
  auto [dealer_poly, bit_challenge] = dealer.ReceiveBitCommitments(bit_commitments);
  
  // Protocol step 3: Parties respond to challenge
  std::vector<PartyAwaitingPolyChallenge> parties_awaiting_poly;
  std::vector<PolyCommitment> poly_commitments;
  
  for (size_t j = 0; j < m; j++) {
    auto [party_poly, poly_commitment] = parties_awaiting_challenge[j].ApplyChallenge(bit_challenge);
    parties_awaiting_poly.push_back(std::move(party_poly));
    poly_commitments.push_back(poly_commitment);
  }
  
  // Protocol step 4: Dealer issues second challenge
  auto [dealer_proof, poly_challenge] = dealer_poly.ReceivePolyCommitments(poly_commitments);
  
  // Protocol step 5: Parties create final responses
  std::vector<ProofShare> proof_shares;
  for (size_t j = 0; j < m; j++) {
    proof_shares.push_back(parties_awaiting_poly[j].ApplyChallenge(poly_challenge));
  }
  
  // Protocol step 6: Dealer creates final proof
  auto proof = dealer_proof.ReceiveTrustedShares(proof_shares);
  
  
  return {proof, value_commitments};
}

bool RangeProofMPC::VerifySingle(
    const BulletproofGens& bp_gens,
    const PedersenGens& pc_gens,
    SimpleTranscript& transcript,
    const yacl::crypto::EcPoint& V,
    size_t n) const {
  
  // Call verify_multiple with a single value commitment
  return VerifyMultiple(bp_gens, pc_gens, transcript, {V}, n);
}

// *** REWRITTEN VerifyMultiple ***
bool RangeProofMPC::VerifyMultiple(
    const BulletproofGens& bp_gens,
    const PedersenGens& pc_gens,
    SimpleTranscript& transcript,
    const std::vector<yacl::crypto::EcPoint>& value_commitments, // Note: Input is vector<EcPoint>
    size_t n) const {

  auto curve = pc_gens.GetCurve();
  const auto& order = curve->GetOrder();
  size_t m = value_commitments.size();
  size_t nm = n * m;

  // --- Basic Validations ---
  YACL_ENFORCE(n == 8 || n == 16 || n == 32 || n == 64, "Invalid bitsize");
  YACL_ENFORCE(bp_gens.gens_capacity() >= n, "Insufficient generator capacity for bitsize");
  YACL_ENFORCE(bp_gens.party_capacity() >= m, "Insufficient generator capacity for party count");
  YACL_ENFORCE(m > 0, "Must verify at least one commitment");
  YACL_ENFORCE(IsPowerOfTwo(m), "Number of commitments must be a power of two");

  // --- Replay Transcript Protocol ---
  transcript.RangeProofDomainSep(n, m);

  // Append value commitments
  // TODO: Ensure AppendPoint uses COMPRESSED format if needed for consistency with  ref.
  for (const auto& V : value_commitments) {
    // Note:  uses CompressedRistretto here. If C++ V is uncompressed, ensure AppendPoint handles it consistently.
    transcript.AppendPoint("V", V, curve);
  }

  // Append proof components (A, S)
  // TODO: Ensure ValidateAndAppendPoint uses COMPRESSED format if needed.
  transcript.ValidateAndAppendPoint("A", A_, curve); // Check for non-identity
  transcript.ValidateAndAppendPoint("S", S_, curve); // Check for non-identity

  // Derive challenges y, z
  yacl::math::MPInt y = transcript.ChallengeScalar("y", curve);
  yacl::math::MPInt z = transcript.ChallengeScalar("z", curve);

  // Append proof components (T1, T2)
  // TODO: Ensure ValidateAndAppendPoint uses COMPRESSED format if needed.
  transcript.ValidateAndAppendPoint("T_1", T_1_, curve); // Check for non-identity
  transcript.ValidateAndAppendPoint("T_2", T_2_, curve); // Check for non-identity

  // Derive challenge x
  yacl::math::MPInt x = transcript.ChallengeScalar("x", curve);

  // Append scalars (t_x, t_x_blinding, e_blinding)
  transcript.AppendScalar("t_x", t_x_);
  transcript.AppendScalar("t_x_blinding", t_x_blinding_);
  transcript.AppendScalar("e_blinding", e_blinding_);

  // Derive challenge w (for IPP commitment point Q)
  yacl::math::MPInt w = transcript.ChallengeScalar("w", curve);

  // --- Prepare for Mega-Check MSM ---

  // Get Inner Product Proof verification scalars (this also advances transcript state for IPP)
  auto [u_sq, u_inv_sq, s] = ipp_proof_.VerificationScalars(nm, &transcript, curve);
  YACL_ENFORCE(u_sq.size() == ipp_proof_.GetLVec().size(), "IPP scalar size mismatch (u_sq)");
  YACL_ENFORCE(u_inv_sq.size() == ipp_proof_.GetLVec().size(), "IPP scalar size mismatch (u_inv_sq)");
  YACL_ENFORCE(s.size() == nm, "IPP scalar size mismatch (s)");

  // Reverse s vector to get s_inv
  std::vector<yacl::math::MPInt> s_inv(s.rbegin(), s.rend());

  // Get final IPP scalars a, b
  yacl::math::MPInt a = ipp_proof_.GetA();
  yacl::math::MPInt b = ipp_proof_.GetB();

  // Precompute helper values
  yacl::math::MPInt z_squared = z.MulMod(z, order);
  yacl::math::MPInt minus_z = z.MulMod(yacl::math::MPInt(-1), order); // 0 - z mod order
  yacl::math::MPInt y_inv = y.InvertMod(order);
  yacl::math::MPInt x_squared = x.MulMod(x, order);
  yacl::math::MPInt minus_one = yacl::math::MPInt(-1); // Used for negation

  // Precompute powers of 2: [1, 2, 4, ..., 2^(n-1)]
  std::vector<yacl::math::MPInt> powers_of_2 = ExpIterVector(yacl::math::MPInt(2), n, curve);

  // Precompute concat_z_and_2: [z^0*2^0, ..., z^0*2^(n-1), z^1*2^0, ..., z^(m-1)*2^(n-1)]
  std::vector<yacl::math::MPInt> concat_z_and_2;
  concat_z_and_2.reserve(nm);
  for (size_t j = 0; j < m; ++j) {
    yacl::math::MPInt z_j = ScalarExp(z, j, curve);
    for (size_t i = 0; i < n; ++i) {
      concat_z_and_2.push_back(z_j.MulMod(powers_of_2[i], order));
    }
  }
  YACL_ENFORCE(concat_z_and_2.size() == nm, "concat_z_and_2 size mismatch");


  // Calculate delta(y,z)
  yacl::math::MPInt delta = Delta(n, m, y, z, curve);

  // Get G and H vectors from Bulletproof generators
  std::vector<yacl::crypto::EcPoint> G_vec = bp_gens.GetAllG(n, m);
  std::vector<yacl::crypto::EcPoint> H_vec = bp_gens.GetAllH(n, m);
  YACL_ENFORCE(G_vec.size() == nm && H_vec.size() == nm, "BP Generator size mismatch");

  // Generate random scalar 'c' for batching verification equations
  yacl::math::MPInt c;
  c.RandomLtN(order, &c); // Use YACL's random scalar generation

  // --- Assemble Scalars and Points for the Mega-Check MSM ---
  // The equation we want to check is: mega_check == Identity
  // Based on Rust: mega_check = MSM(scalars, points)
  std::vector<yacl::math::MPInt> mega_check_scalars;
  std::vector<yacl::crypto::EcPoint> mega_check_points;
  // Reserve approximate size
  mega_check_scalars.reserve(m + 8 + 2 * nm + 2 * ipp_proof_.GetLVec().size());
  mega_check_points.reserve(m + 8 + 2 * nm + 2 * ipp_proof_.GetLVec().size());

  // Term 1: A (scalar 1)
  mega_check_scalars.push_back(yacl::math::MPInt(1));
  mega_check_points.push_back(A_);

  // Term 2: S^x
  mega_check_scalars.push_back(x);
  mega_check_points.push_back(S_);

  // Term 3: T_1^(c*x)
  mega_check_scalars.push_back(c.MulMod(x, order));
  mega_check_points.push_back(T_1_);

  // Term 4: T_2^(c*x^2)
  mega_check_scalars.push_back(c.MulMod(x_squared, order));
  mega_check_points.push_back(T_2_);

  // Term 5: IPP L vectors (L_i ^ u_sq[i])
  for (size_t i = 0; i < ipp_proof_.GetLVec().size(); ++i) {
    mega_check_scalars.push_back(u_sq[i]);
    mega_check_points.push_back(ipp_proof_.GetLVec()[i]);
  }

  // Term 6: IPP R vectors (R_i ^ u_inv_sq[i])
   for (size_t i = 0; i < ipp_proof_.GetRVec().size(); ++i) {
    mega_check_scalars.push_back(u_inv_sq[i]);
    mega_check_points.push_back(ipp_proof_.GetRVec()[i]);
  }

  // Term 7: Blinding Base H (B_blinding) with combined scalar
  // Scalar: -e_blinding - c * t_x_blinding
  yacl::math::MPInt h_base_scalar = e_blinding_.MulMod(minus_one, order); // -e_blinding
  h_base_scalar = h_base_scalar.AddMod(c.MulMod(t_x_blinding_, order).MulMod(minus_one, order), order); // - c*t_x_blinding
  mega_check_scalars.push_back(h_base_scalar);
  mega_check_points.push_back(pc_gens.B_blinding); // B_blinding

  // Term 8: Pedersen Base G (B) with combined scalar
  // Scalar: w*(t_x - a*b) + c*(delta - t_x)
  yacl::math::MPInt g_base_scalar_part1 = t_x_.SubMod(a.MulMod(b, order), order);
  g_base_scalar_part1 = g_base_scalar_part1.MulMod(w, order);
  yacl::math::MPInt g_base_scalar_part2 = delta.SubMod(t_x_, order);
  g_base_scalar_part2 = g_base_scalar_part2.MulMod(c, order);
  yacl::math::MPInt g_base_scalar = g_base_scalar_part1.AddMod(g_base_scalar_part2, order);
  mega_check_scalars.push_back(g_base_scalar);
  mega_check_points.push_back(pc_gens.B); // B

  // Term 9: Bulletproof G vectors with g_scalars
  // g_scalar = -z - a * s_i
  for (size_t i = 0; i < nm; ++i) {
      yacl::math::MPInt g_scalar = minus_z.SubMod(a.MulMod(s[i], order), order);
      mega_check_scalars.push_back(g_scalar);
      mega_check_points.push_back(G_vec[i]);
  }

  // Term 10: Bulletproof H vectors with h_scalars
  // h_scalar = z + y_inv^i * (zz * concat_z_and_2_i - b * s_inv_i)
  std::vector<yacl::math::MPInt> y_inv_powers = ExpIterVector(y_inv, nm, curve); // Precompute powers of y_inv
  for (size_t i = 0; i < nm; ++i) {
      yacl::math::MPInt term_in_paren = z_squared.MulMod(concat_z_and_2[i], order);
      term_in_paren = term_in_paren.SubMod(b.MulMod(s_inv[i], order), order);
      yacl::math::MPInt h_scalar = z.AddMod(y_inv_powers[i].MulMod(term_in_paren, order), order);
      mega_check_scalars.push_back(h_scalar);
      mega_check_points.push_back(H_vec[i]);
  }

  // Term 11: Value Commitments V_j with combined scalar
  // scalar = c * zz * z^j
  for (size_t j = 0; j < m; ++j) {
      yacl::math::MPInt z_j = ScalarExp(z, j, curve);
      yacl::math::MPInt vc_scalar = c.MulMod(z_squared, order).MulMod(z_j, order);
      mega_check_scalars.push_back(vc_scalar);
      mega_check_points.push_back(value_commitments[j]);
  }

  // --- Perform the Multi-Scalar Multiplication ---
  yacl::crypto::EcPoint mega_check_result = MultiScalarMul(curve, mega_check_scalars, mega_check_points);

  // --- Final Check ---
  // The proof is valid if the MSM result is the identity point
  if (!curve->IsInfinity(mega_check_result)) {
      std::cerr << "RangeProofMPC Verification Failed: Mega-Check MSM is not identity." << std::endl;
      // Optional: Add more debug prints here if needed
      // std::cout << "Debug: A = " << curve->SerializePoint(A_) << std::endl;
      // ... print other proof components and scalars ...
  }

  return curve->IsInfinity(mega_check_result);
}

// --- Delta Calculation (Seems correct, kept from previous version) ---
yacl::math::MPInt RangeProofMPC::Delta(
    size_t n,
    size_t m,
    const yacl::math::MPInt& y,
    const yacl::math::MPInt& z,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) {

  const auto& order = curve->GetOrder();
  yacl::math::MPInt one(1);
  yacl::math::MPInt z_squared = z.MulMod(z, order);

  // Calculate sum_y = sum_{j=0}^{m-1} z^j * SumOfPowers(y, n)
  // Simplified from original Rust: sum_of_powers(y, nm)
  yacl::math::MPInt sum_y = SumOfPowers(y, n*m, curve);

  // Calculate sum_2 = sum_{j=0}^{m-1} z^j * SumOfPowers(2, n)
  yacl::math::MPInt sum_of_powers_2_n = SumOfPowers(yacl::math::MPInt(2), n, curve);
  yacl::math::MPInt sum_z_j = SumOfPowers(z, m, curve); // sum_{j=0}^{m-1} z^j
  yacl::math::MPInt sum_2 = sum_of_powers_2_n.MulMod(sum_z_j, order);

  // delta = (z - z^2) * sum_y - z^3 * sum_2
  yacl::math::MPInt term1 = (z.SubMod(z_squared, order)).MulMod(sum_y, order);
  yacl::math::MPInt z_cubed = z_squared.MulMod(z, order);
  yacl::math::MPInt term2 = (z_cubed.MulMod(sum_2, order));

  yacl::math::MPInt delta = term1.SubMod(term2, order);

  // Ensure result is positive
  // No need for explicit check if using Mod correctly, but doesn't hurt
  delta = delta.Mod(order);

  return delta;
}

yacl::Buffer RangeProofMPC::ToBytes(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
    // ... (previous implementation seems reasonable, ensure points match compression choice)
    // Calculate total size first
    yacl::Buffer A_bytes = curve->SerializePoint(A_);
    yacl::Buffer S_bytes = curve->SerializePoint(S_);
    yacl::Buffer T1_bytes = curve->SerializePoint(T_1_);
    yacl::Buffer T2_bytes = curve->SerializePoint(T_2_);
    yacl::Buffer t_x_bytes = t_x_.Serialize();
    yacl::Buffer t_x_blinding_bytes = t_x_blinding_.Serialize();
    yacl::Buffer e_blinding_bytes = e_blinding_.Serialize();
    yacl::Buffer ipp_bytes = ipp_proof_.ToBytes(curve);

    // Use uint32_t for size like IPP proof serialization for consistency?
    // Using size_t for now based on previous code.
    size_t header_size = 8 * sizeof(size_t); // 8 size fields

    int64_t total_size = header_size +
                        A_bytes.size() + S_bytes.size() +
                        T1_bytes.size() + T2_bytes.size() +
                        t_x_bytes.size() + t_x_blinding_bytes.size() +
                        e_blinding_bytes.size() + ipp_bytes.size();

    yacl::Buffer buf(total_size);
    char* ptr = buf.data<char>(); // Use char* for easier pointer arithmetic

    auto write_sized_data = [&](const yacl::Buffer& data) {
        size_t size = data.size();
        std::memcpy(ptr, &size, sizeof(size_t));
        ptr += sizeof(size_t);
        std::memcpy(ptr, data.data(), size);
        ptr += size;
    };

    write_sized_data(A_bytes);
    write_sized_data(S_bytes);
    write_sized_data(T1_bytes);
    write_sized_data(T2_bytes);
    write_sized_data(t_x_bytes);
    write_sized_data(t_x_blinding_bytes);
    write_sized_data(e_blinding_bytes);
    write_sized_data(ipp_bytes);

    YACL_ENFORCE(ptr == buf.data<char>() + total_size, "Serialization size mismatch");

    return buf;
}


RangeProofMPC RangeProofMPC::FromBytes(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const yacl::ByteContainerView& bytes) {

    const char* ptr = reinterpret_cast<const char*>(bytes.data());
    const char* end = ptr + bytes.size();

    auto read_data = [&](const char* name) -> yacl::ByteContainerView {
        if (ptr + sizeof(size_t) > end) {
        throw yacl::Exception(fmt::format("Not enough data to read size of {}", name));
        }
        size_t size;
        std::memcpy(&size, ptr, sizeof(size_t));
        ptr += sizeof(size_t);

        if (ptr + size > end) {
        throw yacl::Exception(fmt::format("Not enough data to read {}", name));
        }
        yacl::ByteContainerView data(ptr, size);
        ptr += size;
        return data;
    };

    yacl::ByteContainerView A_data = read_data("A");
    yacl::ByteContainerView S_data = read_data("S");
    yacl::ByteContainerView T1_data = read_data("T_1");
    yacl::ByteContainerView T2_data = read_data("T_2");
    yacl::ByteContainerView t_x_data = read_data("t_x");
    yacl::ByteContainerView t_x_blinding_data = read_data("t_x_blinding");
    yacl::ByteContainerView e_blinding_data = read_data("e_blinding");
    yacl::ByteContainerView ipp_data = read_data("ipp_proof");

    // TODO: Optionally check if ptr == end after reading everything

    yacl::crypto::EcPoint A = curve->DeserializePoint(A_data);
    yacl::crypto::EcPoint S = curve->DeserializePoint(S_data);
    yacl::crypto::EcPoint T_1 = curve->DeserializePoint(T1_data);
    yacl::crypto::EcPoint T_2 = curve->DeserializePoint(T2_data);

    yacl::math::MPInt t_x;
    t_x.Deserialize(t_x_data);

    yacl::math::MPInt t_x_blinding;
    t_x_blinding.Deserialize(t_x_blinding_data);

    yacl::math::MPInt e_blinding;
    e_blinding.Deserialize(e_blinding_data);

    InnerProductProof ipp_proof = InnerProductProof::FromBytes(ipp_data, curve);

    return RangeProofMPC(A, S, T_1, T_2, t_x, t_x_blinding, e_blinding, ipp_proof);
}


} // namespace examples::zkp
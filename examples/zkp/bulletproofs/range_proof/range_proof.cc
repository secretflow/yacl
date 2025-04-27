#include "zkp/bulletproofs/range_proof/range_proof.h"

#include <algorithm>

#include "yacl/crypto/rand/rand.h"
#include "zkp/bulletproofs/range_proof/dealer.h"
#include "zkp/bulletproofs/range_proof/party.h"
#include "zkp/bulletproofs/util.h"

namespace examples::zkp {

RangeProof::RangeProof(
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

std::pair<RangeProof, yacl::crypto::EcPoint> RangeProof::CreateSingle(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    SimpleTranscript& transcript,
    uint64_t v,
    const yacl::math::MPInt& v_blinding,
    size_t n) {
  
  // Create Pedersen and Bulletproof generators
  PedersenGens pc_gens(curve);
  BulletproofGens bp_gens(curve, n, 1);  // Single party, n-bit proof
  
  // Create the dealer for the protocol
  auto dealer = Dealer::New(bp_gens, pc_gens, transcript, n, 1);
  
  // Create a party for the single value
  auto party = Party::New(bp_gens, pc_gens, v, v_blinding, n);
  
  // Protocol step 1: Party commits to bits
  auto [party_bits, bit_commitment] = party.AssignPosition(0);
  
  // Protocol step 2: Dealer issues first challenge
  auto [dealer_poly, bit_challenge] = dealer.ReceiveBitCommitments({bit_commitment});
  
  // Protocol step 3: Party responds to challenge
  auto [party_poly, poly_commitment] = party_bits.ApplyChallenge(bit_challenge);
  
  // Protocol step 4: Dealer issues second challenge
  auto [dealer_proof, poly_challenge] = dealer_poly.ReceivePolyCommitments({poly_commitment});
  
  // Protocol step 5: Party creates final response
  auto proof_share = party_poly.ApplyChallenge(poly_challenge);
  
  // Protocol step 6: Dealer creates final proof
  auto proof = dealer_proof.ReceiveTrustedShares({proof_share});
  
  // Return the proof and value commitment
  return {proof, bit_commitment.GetV()};
}

std::pair<RangeProof, std::vector<yacl::crypto::EcPoint>> RangeProof::CreateMultiple(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    SimpleTranscript& transcript,
    const std::vector<uint64_t>& values,
    const std::vector<yacl::math::MPInt>& blindings,
    size_t n) {
  
  if (values.size() != blindings.size()) {
    throw yacl::Exception("Number of values must match number of blinding factors");
  }
  
  size_t m = values.size();
  
  // Create Pedersen and Bulletproof generators
  PedersenGens pc_gens(curve);
  BulletproofGens bp_gens(curve, n, m);
  
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
  
  // Extract value commitments
  std::vector<yacl::crypto::EcPoint> value_commitments;
  for (const auto& commitment : bit_commitments) {
    value_commitments.push_back(commitment.GetV());
  }
  
  return {proof, value_commitments};
}

bool RangeProof::VerifySingle(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    SimpleTranscript& transcript,
    const yacl::crypto::EcPoint& V,
    size_t n) const {
  
  // Call verify_multiple with a single value commitment
  return VerifyMultiple(curve, transcript, {V}, n);
}

bool RangeProof::VerifyMultiple(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    SimpleTranscript& transcript,
    const std::vector<yacl::crypto::EcPoint>& value_commitments,
    size_t n) const {
  
  PedersenGens pc_gens(curve);
  size_t m = value_commitments.size();
  BulletproofGens bp_gens(curve, n, m);
  
  // Basic validations
  if (!(n == 8 || n == 16 || n == 32 || n == 64)) {
    throw yacl::Exception("Invalid bitsize");
  }
  
  if (bp_gens.gens_capacity() < n) {
    throw yacl::Exception("Insufficient generator capacity for bitsize");
  }
  
  if (bp_gens.party_capacity() < m) {
    throw yacl::Exception("Insufficient generator capacity for party count");
  }
  
  // Set domain separator for the range proof
  transcript.RangeProofDomainSep(n, m);
  
  // Append value commitments to transcript
  for (const auto& V : value_commitments) {
    transcript.AppendPoint("V", V, curve);
  }
  
  // Append proof components to transcript
  transcript.AppendPoint("A", A_, curve);
  transcript.AppendPoint("S", S_, curve);
  
  // Get challenges y and z
  yacl::math::MPInt y = transcript.ChallengeScalar("y", curve);
  yacl::math::MPInt z = transcript.ChallengeScalar("z", curve);
  yacl::math::MPInt z_squared = (z * z) % curve->GetOrder();
  yacl::math::MPInt minus_z = curve->GetOrder() - z;
  
  // Continue protocol transcript
  transcript.AppendPoint("T_1", T_1_, curve);
  transcript.AppendPoint("T_2", T_2_, curve);
  
  // Get challenge x
  yacl::math::MPInt x = transcript.ChallengeScalar("x", curve);
  
  // Add values to transcript
  transcript.AppendScalar("t_x", t_x_);
  transcript.AppendScalar("t_x_blinding", t_x_blinding_);
  transcript.AppendScalar("e_blinding", e_blinding_);
  
  // Get challenge w
  yacl::math::MPInt w = transcript.ChallengeScalar("w", curve);
  
  // Generate a random scalar for batch verification
  yacl::math::MPInt c;
  yacl::math::MPInt::RandomExactBits(curve->GetField().BitCount(), &c);
  
  // Verification scalars from inner product proof
  auto [u_sq, u_inv_sq, s] = ipp_proof_.VerificationScalars(n * m, &transcript, curve);
  
  // s_inv is s in reversed order
  std::vector<yacl::math::MPInt> s_inv(s.rbegin(), s.rend());
  
  // Get a and b from inner product proof
  yacl::math::MPInt a = ipp_proof_.GetA();
  yacl::math::MPInt b = ipp_proof_.GetB();
  
  // Construct powers of 2 for verification
  std::vector<yacl::math::MPInt> powers_of_2;
  yacl::math::MPInt two(2);
  yacl::math::MPInt power(1);
  for (size_t i = 0; i < n; i++) {
    powers_of_2.push_back(power);
    power = (power * two) % curve->GetOrder();
  }
  
  // Construct z_and_2 vector
  std::vector<yacl::math::MPInt> z_and_2;
  for (size_t i = 0; i < m; i++) {
    yacl::math::MPInt z_exp = ScalarExp(z, i, curve);
    for (size_t j = 0; j < n; j++) {
      z_and_2.push_back((powers_of_2[j] * z_exp) % curve->GetOrder());
    }
  }
  
  // Compute verification scalars for G and H vectors
  std::vector<yacl::math::MPInt> g_scalars;
  for (size_t i = 0; i < n * m; i++) {
    g_scalars.push_back((minus_z - a * s[i]) % curve->GetOrder());
  }
  
  std::vector<yacl::math::MPInt> h_scalars;
  yacl::math::MPInt y_inv = y.InvertMod(curve->GetOrder());
  
  for (size_t i = 0; i < n * m; i++) {
    yacl::math::MPInt y_inv_i = ScalarExp(y_inv, i, curve);
    h_scalars.push_back((z + z_squared * z_and_2[i] + y * b * s_inv[i]) % curve->GetOrder());
  }
  
  // Calculate delta for verification
  yacl::math::MPInt delta = Delta(n, m, y, z, curve);
  
  // Left side of verification equation: g^t_x
  yacl::crypto::EcPoint left_point = curve->Mul(pc_gens.GetGPoint(), t_x_);
  
  // Right side of verification equation
  yacl::crypto::EcPoint right_point = curve->GetGenerator();
  curve->MulInplace(&right_point, yacl::math::MPInt(0)); // Set to identity
  
  // Add V^{z^2} terms
  for (size_t i = 0; i < value_commitments.size(); i++) {
    yacl::math::MPInt z_i_plus_2 = ScalarExp(z, i + 2, curve);
    yacl::math::MPInt scalar = (z_squared * z_i_plus_2) % curve->GetOrder();
    right_point = curve->Add(right_point, curve->Mul(value_commitments[i], scalar));
  }
  
  // Add g^delta term
  right_point = curve->Add(right_point, curve->Mul(pc_gens.GetGPoint(), delta));
  
  // Add T_1^x term
  right_point = curve->Add(right_point, curve->Mul(T_1_, x));
  
  // Add T_2^{x^2} term
  yacl::math::MPInt x_squared = (x * x) % curve->GetOrder();
  right_point = curve->Add(right_point, curve->Mul(T_2_, x_squared));
  
  // Check if left == right
  if (!curve->PointEqual(left_point, right_point)) {
    return false;
  }
  
  // Verify inner product argument
  yacl::crypto::EcPoint Q = curve->Mul(pc_gens.GetGPoint(), w);
  
  std::vector<yacl::math::MPInt> G_factors(n * m, yacl::math::MPInt(1));
  
  // H_factors are powers of y_inv
  std::vector<yacl::math::MPInt> H_factors;
  yacl::math::MPInt current = yacl::math::MPInt(1);
  for (size_t i = 0; i < n * m; i++) {
    H_factors.push_back(current);
    current = (current * y_inv) % curve->GetOrder();
  }
  
  bool ipp_result = ipp_proof_.Verify(
      n * m,
      &transcript,
      curve,
      G_factors, 
      H_factors,
      left_point,  // P point from verification
      Q,
      bp_gens.GetAllG(n, m),
      bp_gens.GetAllH(n, m));
  
  return ipp_result;
}

yacl::math::MPInt RangeProof::Delta(
    size_t n,
    size_t m,
    const yacl::math::MPInt& y,
    const yacl::math::MPInt& z,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  
  // Calculate sum_y = sum_{j=0}^{m-1} sum_{i=0}^{n-1} y^(i+j*n)
  yacl::math::MPInt sum_y(0);
  yacl::math::MPInt y_n = ScalarExp(y, n, curve);
  
  for (size_t j = 0; j < m; j++) {
    yacl::math::MPInt y_j_n = ScalarExp(y, j * n, curve);
    
    if (y == yacl::math::MPInt(1)) {
      sum_y = (sum_y + y_j_n * yacl::math::MPInt(n)) % curve->GetOrder();
    } else {
      yacl::math::MPInt numerator = (yacl::math::MPInt(1) - y_n) % curve->GetOrder();
      yacl::math::MPInt denominator = (yacl::math::MPInt(1) - y) % curve->GetOrder();
      yacl::math::MPInt sum_y_i = (numerator * denominator.InvertMod(curve->GetOrder())) % curve->GetOrder();
      sum_y = (sum_y + y_j_n * sum_y_i) % curve->GetOrder();
    }
  }
  
  // Calculate sum_2 = sum_{j=0}^{m-1} sum_{i=0}^{n-1} 2^i
  yacl::math::MPInt sum_2(0);
  for (size_t j = 0; j < m; j++) {
    // Sum_{i=0}^{n-1} 2^i = 2^n - 1
    yacl::math::MPInt two_n = yacl::math::MPInt(1) << n;
    yacl::math::MPInt sum_2_i = (two_n - yacl::math::MPInt(1)) % curve->GetOrder();
    yacl::math::MPInt z_j = ScalarExp(z, j, curve);
    sum_2 = (sum_2 + z_j * sum_2_i) % curve->GetOrder();
  }
  
  // delta = (z - z^2) * sum_y - z^3 * sum_2
  yacl::math::MPInt z_squared = (z * z) % curve->GetOrder();
  yacl::math::MPInt term1 = ((z - z_squared) * sum_y) % curve->GetOrder();
  yacl::math::MPInt z_cubed = (z_squared * z) % curve->GetOrder();
  yacl::math::MPInt term2 = (z_cubed * sum_2) % curve->GetOrder();
  
  yacl::math::MPInt delta = (term1 - term2) % curve->GetOrder();
  if (delta < yacl::math::MPInt(0)) {
    delta = (delta + curve->GetOrder()) % curve->GetOrder();
  }
  
  return delta;
}

yacl::Buffer RangeProof::ToBytes(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
  // Calculate total size first
  yacl::Buffer A_bytes = curve->SerializePoint(A_);
  yacl::Buffer S_bytes = curve->SerializePoint(S_);
  yacl::Buffer T1_bytes = curve->SerializePoint(T_1_);
  yacl::Buffer T2_bytes = curve->SerializePoint(T_2_);
  yacl::Buffer t_x_bytes = t_x_.Serialize();
  yacl::Buffer t_x_blinding_bytes = t_x_blinding_.Serialize();
  yacl::Buffer e_blinding_bytes = e_blinding_.Serialize();
  yacl::Buffer ipp_bytes = ipp_proof_.ToBytes(curve);
  
  // Calculate total size needed (8 size fields + data)
  int64_t total_size = 8 * sizeof(uint32_t) + 
                       A_bytes.size() + S_bytes.size() + 
                       T1_bytes.size() + T2_bytes.size() + 
                       t_x_bytes.size() + t_x_blinding_bytes.size() + 
                       e_blinding_bytes.size() + ipp_bytes.size();
  
  // Create buffer and set current position
  yacl::Buffer buf(total_size);
  int64_t pos = 0;
  
  // Helper function to write a size-prefixed block
  auto write_sized_data = [&buf, &pos](const yacl::Buffer& data) {
    uint32_t size = static_cast<uint32_t>(data.size());
    std::memcpy(buf.data<uint8_t>() + pos, &size, sizeof(size));
    pos += sizeof(size);
    std::memcpy(buf.data<uint8_t>() + pos, data.data<uint8_t>(), data.size());
    pos += data.size();
  };
  
  // Write all components
  write_sized_data(A_bytes);
  write_sized_data(S_bytes);
  write_sized_data(T1_bytes);
  write_sized_data(T2_bytes);
  write_sized_data(t_x_bytes);
  write_sized_data(t_x_blinding_bytes);
  write_sized_data(e_blinding_bytes);
  write_sized_data(ipp_bytes);
  
  return buf;
}

RangeProof RangeProof::FromBytes(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const yacl::ByteContainerView& bytes) {
  
  size_t offset = 0;
  
  // Helper function to read a size-prefixed blob
  auto read_blob = [&bytes, &offset](const char* name) -> std::pair<uint32_t, yacl::ByteContainerView> {
    if (offset + sizeof(uint32_t) > bytes.size()) {
      throw yacl::Exception(std::string("Not enough data to read size of ") + name);
    }
    
    uint32_t size;
    std::memcpy(&size, bytes.data() + offset, sizeof(size));
    offset += sizeof(size);
    
    if (offset + size > bytes.size()) {
      throw yacl::Exception(std::string("Not enough data to read ") + name);
    }
    
    yacl::ByteContainerView data(bytes.data() + offset, size);
    offset += size;
    
    return {size, data};
  };
  
  // Read all components
  auto [A_size, A_data] = read_blob("A");
  auto [S_size, S_data] = read_blob("S");
  auto [T1_size, T1_data] = read_blob("T_1");
  auto [T2_size, T2_data] = read_blob("T_2");
  auto [t_x_size, t_x_data] = read_blob("t_x");
  auto [t_x_blinding_size, t_x_blinding_data] = read_blob("t_x_blinding");
  auto [e_blinding_size, e_blinding_data] = read_blob("e_blinding");
  auto [ipp_size, ipp_data] = read_blob("ipp_proof");
  
  // Deserialize each component
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
  
  return RangeProof(A, S, T_1, T_2, t_x, t_x_blinding, e_blinding, ipp_proof);
}

} // namespace examples::zkp
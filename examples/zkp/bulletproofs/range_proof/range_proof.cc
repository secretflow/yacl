#include "zkp/bulletproofs/range_proof/range_proof.h"

#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/rand/rand.h"
#include "zkp/bulletproofs/range_proof/party.h"
#include "zkp/bulletproofs/range_proof/dealer.h"
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
  // Create generators
  PedersenGens pc_gens(curve);
  BulletproofGens bp_gens(curve, 1, n);  // Single party, n-bit capacity
  
  // Create the multi-party computation state machine
  auto dealer = Dealer::New(bp_gens, pc_gens, transcript, n, 1);
  
  // Create a party for the single prover
  auto party = Party::New(bp_gens, pc_gens, v, v_blinding, n);
  
  // Assign position 0 to the party
  auto [party_bits, bit_commitment] = party.AssignPosition(0);
  
  // Dealer receives bit commitments and issues first challenge
  auto [dealer_poly, bit_challenge] = dealer.ReceiveBitCommitments({bit_commitment});
  
  // Party applies challenge and generates polynomial commitments
  auto [party_poly, poly_commitment] = party_bits.ApplyChallenge(bit_challenge);
  
  // Dealer receives polynomial commitments and issues second challenge
  auto [dealer_proof, poly_challenge] = dealer_poly.ReceivePolyCommitments({poly_commitment});
  
  // Party applies challenge and generates proof share
  auto proof_share = party_poly.ApplyChallenge(poly_challenge);
  
  // Dealer assembles final proof from shares
  auto proof = dealer_proof.ReceiveTrustedShares({proof_share});
  
  // Return the proof and the value commitment
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
  
  // Create generators
  PedersenGens pc_gens(curve);
  BulletproofGens bp_gens(curve, m, n);  // m parties, n-bit capacity
  
  // Create the multi-party computation state machine
  auto dealer = Dealer::New(bp_gens, pc_gens, transcript, n, m);
  
  // Create parties for each value and blinding factor
  std::vector<PartyAwaitingPosition> parties;
  for (size_t i = 0; i < m; i++) {
    parties.push_back(Party::New(bp_gens, pc_gens, values[i], blindings[i], n));
  }
  
  // Assign positions to parties and collect bit commitments
  std::vector<PartyAwaitingBitChallenge> parties_awaiting_challenge;
  std::vector<BitCommitment> bit_commitments;
  
  for (size_t j = 0; j < m; j++) {
    auto [party_bits, bit_commitment] = parties[j].AssignPosition(j);
    parties_awaiting_challenge.push_back(std::move(party_bits));
    bit_commitments.push_back(bit_commitment);
  }
  
  // Dealer receives bit commitments and issues first challenge
  auto [dealer_poly, bit_challenge] = dealer.ReceiveBitCommitments(bit_commitments);
  
  // Parties apply challenge and generate polynomial commitments
  std::vector<PartyAwaitingPolyChallenge> parties_awaiting_poly;
  std::vector<PolyCommitment> poly_commitments;
  
  for (size_t j = 0; j < m; j++) {
    auto [party_poly, poly_commitment] = parties_awaiting_challenge[j].ApplyChallenge(bit_challenge);
    parties_awaiting_poly.push_back(std::move(party_poly));
    poly_commitments.push_back(poly_commitment);
  }
  
  // Dealer receives polynomial commitments and issues second challenge
  auto [dealer_proof, poly_challenge] = dealer_poly.ReceivePolyCommitments(poly_commitments);
  
  // Parties apply challenge and generate proof shares
  std::vector<ProofShare> proof_shares;
  for (size_t j = 0; j < m; j++) {
    proof_shares.push_back(parties_awaiting_poly[j].ApplyChallenge(poly_challenge));
  }

  // Dealer assembles final proof from shares
  auto proof = dealer_proof.ReceiveTrustedShares(proof_shares);

  // Extract value commitments from bit commitments
  std::vector<yacl::crypto::EcPoint> value_commitments;
  for (const auto& commitment : bit_commitments) {
    value_commitments.push_back(commitment.GetV());
  }
  
  // Return the proof and the value commitments
  return {proof, value_commitments};
}

ProofError RangeProof::VerifySingle(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    SimpleTranscript& transcript,
    const yacl::crypto::EcPoint& V,
    size_t n) const {
  // Call verify_multiple with a single value commitment
  return VerifyMultiple(curve, transcript, {V}, n);
}

ProofError RangeProof::VerifyMultiple(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    SimpleTranscript& transcript,
    const std::vector<yacl::crypto::EcPoint>& value_commitments,
    size_t n) const {
  // Create generators
  PedersenGens pc_gens(curve);
  
  size_t m = value_commitments.size();
  BulletproofGens bp_gens(curve, m, n);  // m parties, n-bit capacity
  
  // First, replay the "interactive" protocol using the proof data to recompute all challenges
  if (!(n == 8 || n == 16 || n == 32 || n == 64)) {
    return ProofError::kInvalidBitsize;
  }
  
  if (bp_gens.gens_capacity() < n) {
    return ProofError::kInvalidGeneratorsLength;
  }
  
  if (bp_gens.party_capacity() < m) {
    return ProofError::kInvalidGeneratorsLength;
  }
  
  // Set domain separator for the range proof
  transcript.RangeproofDomainSep(n, m);
  
  // Commit each V individually
  for (const auto& V : value_commitments) {
    transcript.AppendPoint("V", V);
  }
  
  // Commit A and S points
  transcript.AppendPoint("A", A_);
  transcript.AppendPoint("S", S_);
  
  // Get challenges y and z
  yacl::math::MPInt y = transcript.ChallengeScalar("y");
  yacl::math::MPInt z = transcript.ChallengeScalar("z");
  yacl::math::MPInt zz = z * z;
  yacl::math::MPInt minus_z = yacl::math::MPInt::Zero() - z;
  
  // Commit T_1 and T_2 points
  transcript.AppendPoint("T_1", T_1_);
  transcript.AppendPoint("T_2", T_2_);
  
  // Get challenge x
  yacl::math::MPInt x = transcript.ChallengeScalar("x");
  
  // Add t_x, t_x_blinding, and e_blinding to the transcript
  transcript.AppendScalar("t_x", t_x_);
  transcript.AppendScalar("t_x_blinding", t_x_blinding_);
  transcript.AppendScalar("e_blinding", e_blinding_);
  
  // Get challenge w for inner product proof
  yacl::math::MPInt w = transcript.ChallengeScalar("w");
  
  // Generate a random scalar for batch verification
  yacl::math::MPInt c;
  yacl::math::MPInt::RandomExactBits(curve->GetField().BitCount(), &c);
  
  // Get verification scalars from the inner product proof
  auto [x_sq, x_inv_sq, s] = ipp_proof_.GetVerificationScalars(n * m, transcript);
  auto s_inv = std::vector<yacl::math::MPInt>(s.rbegin(), s.rend());
  
  yacl::math::MPInt a = ipp_proof_.GetA();
  yacl::math::MPInt b = ipp_proof_.GetB();
  
  // Construct powers of 2 and powers of z for the verification
  std::vector<yacl::math::MPInt> powers_of_2 = ExpIterVector(yacl::math::MPInt(2), n);
  
  std::vector<yacl::math::MPInt> concat_z_and_2;
  concat_z_and_2.reserve(n * m);
  
  for (size_t i = 0; i < m; i++) {
    yacl::math::MPInt z_exp = ScalarExpVartime(z, i);
    for (size_t j = 0; j < n; j++) {
      concat_z_and_2.push_back(powers_of_2[j] * z_exp);
    }
  }
  
  // Compute g and h vectors for verification
  std::vector<yacl::math::MPInt> g_scalars;
  g_scalars.reserve(n * m);
  
  for (size_t i = 0; i < n * m; i++) {
    g_scalars.push_back(minus_z - a * s[i]);
  }
  
    std::vector<yacl::math::MPInt> h_scalars;
  h_scalars.reserve(n * m);
  
  yacl::math::MPInt y_inv = y.Inverse(curve->GetField());
  std::vector<yacl::math::MPInt> powers_of_y_inv = ExpIterVector(y_inv, n * m);
  
  for (size_t i = 0; i < n * m; i++) {
    h_scalars.push_back(z + z * z * concat_z_and_2[i] + y * b * s_inv[i]);
  }
  
  // Compute delta(y,z) for verification
  yacl::math::MPInt delta = Delta(n, m, y, z);
  
  // Compute the verification check: left == right?
  yacl::crypto::EcPoint left_point = curve->Mul(pc_gens.GetGPoint(), t_x_);
  yacl::crypto::EcPoint right_point = curve->GetIdentity();
  
  // Compute the right-hand side of the verification equation
  // First term: V^{z^2}
  for (size_t i = 0; i < value_commitments.size(); i++) {
    yacl::math::MPInt z_i = ScalarExpVartime(z, i + 2); // z^{i+2}
    right_point = curve->Add(right_point, curve->Mul(value_commitments[i], zz * z_i));
  }
  
  // Second term: g^delta
  right_point = curve->Add(right_point, curve->Mul(pc_gens.GetGPoint(), delta));
  
  // Third term: T_1^x
  right_point = curve->Add(right_point, curve->Mul(T_1_, x));
  
  // Fourth term: T_2^{x^2}
  right_point = curve->Add(right_point, curve->Mul(T_2_, x * x));
  
  // Check if left == right
  if (!curve->PointEqual(left_point, right_point)) {
    return ProofError::kVerificationError;
  }
  
  // Verify the inner product proof
  yacl::crypto::EcPoint Q = curve->Mul(pc_gens.GetGPoint(), w);
  
  std::vector<yacl::math::MPInt> G_factors(n * m, yacl::math::MPInt(1));
  std::vector<yacl::math::MPInt> H_factors = powers_of_y_inv;
  
  ProofError ipp_result = ipp_proof_.Verify(
      transcript, Q, G_factors, H_factors, bp_gens.GetAllG(n, m), bp_gens.GetAllH(n, m), 
      a, b, pc_gens.GetHPoint(), e_blinding_);
  
  if (ipp_result != ProofError::kOk) {
    return ipp_result;
  }
  
  return ProofError::kOk;
}

yacl::math::MPInt RangeProof::Delta(
    size_t n,
    size_t m,
    const yacl::math::MPInt& y,
    const yacl::math::MPInt& z) {
  // Compute <1, y^n>_m = sum_{j=0}^{m-1} sum_{i=0}^{n-1} y^(i+j*n)
  yacl::math::MPInt sum_y;
  yacl::math::MPInt y_n = ScalarExpVartime(y, n);
  
  for (size_t j = 0; j < m; j++) {
    // Compute sum_{i=0}^{n-1} y^i using the formula for geometric series
    yacl::math::MPInt y_j_n = ScalarExpVartime(y, j * n);
    
    if (y == yacl::math::MPInt(1)) {
      sum_y = sum_y + y_j_n * yacl::math::MPInt(n);
    } else {
      yacl::math::MPInt numerator = yacl::math::MPInt(1) - y_n;
      yacl::math::MPInt denominator = yacl::math::MPInt(1) - y;
      yacl::math::MPInt sum_y_i = numerator / denominator;
      sum_y = sum_y + y_j_n * sum_y_i;
    }
  }
  
  // Compute <1, 2^n>_m = sum_{j=0}^{m-1} sum_{i=0}^{n-1} 2^i
  yacl::math::MPInt sum_2;
  for (size_t j = 0; j < m; j++) {
    // Sum_{i=0}^{n-1} 2^i = 2^n - 1
    yacl::math::MPInt two_n = yacl::math::MPInt(1) << n;
    yacl::math::MPInt sum_2_i = two_n - yacl::math::MPInt(1);
    yacl::math::MPInt z_j = ScalarExpVartime(z, j);
    sum_2 = sum_2 + z_j * sum_2_i;
  }
  
  // Compute delta = (z - z^2) * <1, y^n>_m - z^3 * <1, 2^n>_m
  yacl::math::MPInt term1 = (z - z * z) * sum_y;
  yacl::math::MPInt term2 = z * z * z * sum_2;
  yacl::math::MPInt delta = term1 - term2;
  
  return delta;
}

yacl::Buffer RangeProof::ToBytes() const {
  // Default implementation for backward compatibility
  return ToBytes(A_.GetCurve());
}

yacl::Buffer RangeProof::ToBytes(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
  yacl::Buffer result;
  
  // Serialize A point
  std::vector<uint8_t> A_bytes = A_.Serialize();
  size_t A_size = A_bytes.size();
  result.append(&A_size, sizeof(size_t));
  result.append(A_bytes.data(), A_bytes.size());
  
  // Serialize S point
  std::vector<uint8_t> S_bytes = S_.Serialize();
  size_t S_size = S_bytes.size();
  result.append(&S_size, sizeof(size_t));
  result.append(S_bytes.data(), S_bytes.size());
  
  // Serialize T_1 point
  std::vector<uint8_t> T1_bytes = T_1_.Serialize();
  size_t T1_size = T1_bytes.size();
  result.append(&T1_size, sizeof(size_t));
  result.append(T1_bytes.data(), T1_bytes.size());
  
  // Serialize T_2 point
  std::vector<uint8_t> T2_bytes = T_2_.Serialize();
  size_t T2_size = T2_bytes.size();
  result.append(&T2_size, sizeof(size_t));
  result.append(T2_bytes.data(), T2_bytes.size());
  
  // Serialize scalars
  std::vector<uint8_t> t_x_bytes = t_x_.ToBytes();
  size_t t_x_size = t_x_bytes.size();
  result.append(&t_x_size, sizeof(size_t));
  result.append(t_x_bytes.data(), t_x_bytes.size());
  
  std::vector<uint8_t> t_x_blinding_bytes = t_x_blinding_.ToBytes();
  size_t t_x_blinding_size = t_x_blinding_bytes.size();
  result.append(&t_x_blinding_size, sizeof(size_t));
  result.append(t_x_blinding_bytes.data(), t_x_blinding_bytes.size());
  
  std::vector<uint8_t> e_blinding_bytes = e_blinding_.ToBytes();
  size_t e_blinding_size = e_blinding_bytes.size();
  result.append(&e_blinding_size, sizeof(size_t));
  result.append(e_blinding_bytes.data(), e_blinding_bytes.size());
  
  // Serialize inner product proof
  yacl::Buffer ipp_bytes = ipp_proof_.ToBytes();
  size_t ipp_size = ipp_bytes.size();
  result.append(&ipp_size, sizeof(size_t));
  result.append(ipp_bytes.data(), ipp_bytes.size());
  
  return result;
}

RangeProof RangeProof::FromBytes(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    yacl::ByteContainerView bytes) {
  const uint8_t* data = bytes.data();
  size_t offset = 0;
  
  // Deserialize A point
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for A point size");
  }
  size_t A_size;
  std::memcpy(&A_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + A_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for A point");
  }
  yacl::crypto::EcPoint A = curve->DecodePoint(
      yacl::ByteContainerView(data + offset, A_size));
  offset += A_size;
  
  // Deserialize S point
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for S point size");
  }
  size_t S_size;
  std::memcpy(&S_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + S_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for S point");
  }
  yacl::crypto::EcPoint S = curve->DecodePoint(
      yacl::ByteContainerView(data + offset, S_size));
  offset += S_size;
  
  // Deserialize T_1 point
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for T_1 point size");
  }
  size_t T1_size;
  std::memcpy(&T1_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + T1_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for T_1 point");
  }
  yacl::crypto::EcPoint T_1 = curve->DecodePoint(
      yacl::ByteContainerView(data + offset, T1_size));
  offset += T1_size;
  
  // Deserialize T_2 point
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for T_2 point size");
  }
  size_t T2_size;
  std::memcpy(&T2_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + T2_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for T_2 point");
  }
  yacl::crypto::EcPoint T_2 = curve->DecodePoint(
      yacl::ByteContainerView(data + offset, T2_size));
  offset += T2_size;
  
  // Deserialize scalars
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for t_x size");
  }
  size_t t_x_size;
  std::memcpy(&t_x_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + t_x_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for t_x");
  }
  yacl::math::MPInt t_x = yacl::math::MPInt::FromBytes(
      yacl::ByteContainerView(data + offset, t_x_size));
  offset += t_x_size;
  
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for t_x_blinding size");
  }
  size_t t_x_blinding_size;
  std::memcpy(&t_x_blinding_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + t_x_blinding_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for t_x_blinding");
  }
  yacl::math::MPInt t_x_blinding = yacl::math::MPInt::FromBytes(
      yacl::ByteContainerView(data + offset, t_x_blinding_size));
  offset += t_x_blinding_size;
  
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for e_blinding size");
  }
  size_t e_blinding_size;
  std::memcpy(&e_blinding_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + e_blinding_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for e_blinding");
  }
  yacl::math::MPInt e_blinding = yacl::math::MPInt::FromBytes(
      yacl::ByteContainerView(data + offset, e_blinding_size));
  offset += e_blinding_size;
  
  // Deserialize inner product proof
  if (offset + sizeof(size_t) > bytes.size()) {
    throw yacl::Exception("Insufficient data for inner product proof size");
  }
  size_t ipp_size;
  std::memcpy(&ipp_size, data + offset, sizeof(size_t));
  offset += sizeof(size_t);
  
  if (offset + ipp_size > bytes.size()) {
    throw yacl::Exception("Insufficient data for inner product proof");
  }
  InnerProductProof ipp_proof = InnerProductProof::FromBytes(
      curve, yacl::ByteContainerView(data + offset, ipp_size));
  
  return RangeProof(A, S, T_1, T_2, t_x, t_x_blinding, e_blinding, ipp_proof);
}

} // namespace examples::zkp
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/keygen_session.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/errors.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/commitment.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/bigint_utils.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/encoding.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/random.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/transcript.h"
#include "yacl/crypto/experimental/threshold_ecdsa/common/secure_zeroize.h"

namespace tecdsa {
namespace {

constexpr size_t kCommitmentLen = 32;
constexpr size_t kPointCompressedLen = 33;
constexpr size_t kScalarLen = 32;
constexpr size_t kMaxOpenRandomnessLen = 1024;
constexpr size_t kMaxPaillierModulusFieldLen = 8192;
constexpr size_t kMaxProofBlobLen = 16384;
constexpr size_t kMaxProofFieldLen = 16384;
constexpr uint32_t kMinPaillierKeygenBits = 2048;
constexpr uint32_t kMinAuxRsaKeygenBits = 2048;
constexpr size_t kMaxPaillierKeygenAttempts = 32;
constexpr char kPhase1CommitDomain[] = "GG2019/keygen/phase1";
constexpr char kSchnorrProofId[] = "GG2019/Schnorr/v1";

void ValidateParticipantsOrThrow(const std::vector<PartyIndex>& participants, PartyIndex self_id) {
  if (participants.size() < 2) {
    TECDSA_THROW_ARGUMENT("KeygenSession requires at least 2 participants");
  }

  std::unordered_set<PartyIndex> dedup;
  bool self_present = false;
  for (PartyIndex id : participants) {
    if (id == 0) {
      TECDSA_THROW_ARGUMENT("participants must not contain 0");
    }
    if (!dedup.insert(id).second) {
      TECDSA_THROW_ARGUMENT("participants must be unique");
    }
    if (id == self_id) {
      self_present = true;
    }
  }

  if (!self_present) {
    TECDSA_THROW_ARGUMENT("self_id must be in participants");
  }
}

std::unordered_set<PartyIndex> BuildPeerSet(const std::vector<PartyIndex>& participants,
                                            PartyIndex self_id) {
  std::unordered_set<PartyIndex> peers;
  for (PartyIndex id : participants) {
    if (id != self_id) {
      peers.insert(id);
    }
  }
  return peers;
}

void AppendU32Be(uint32_t value, Bytes* out) {
  out->push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out->push_back(static_cast<uint8_t>(value & 0xFF));
}

uint32_t ReadU32Be(std::span<const uint8_t> input, size_t* offset) {
  if (*offset + 4 > input.size()) {
    TECDSA_THROW_ARGUMENT("Not enough bytes to read u32");
  }

  const size_t i = *offset;
  *offset += 4;
  return (static_cast<uint32_t>(input[i]) << 24) |
         (static_cast<uint32_t>(input[i + 1]) << 16) |
         (static_cast<uint32_t>(input[i + 2]) << 8) |
         static_cast<uint32_t>(input[i + 3]);
}

void AppendSizedField(std::span<const uint8_t> field, Bytes* out) {
  if (field.size() > UINT32_MAX) {
    TECDSA_THROW_ARGUMENT("Sized field exceeds uint32 length");
  }
  AppendU32Be(static_cast<uint32_t>(field.size()), out);
  out->insert(out->end(), field.begin(), field.end());
}

Bytes ReadSizedField(std::span<const uint8_t> input,
                     size_t* offset,
                     size_t max_len,
                     const char* field_name) {
  const uint32_t len = ReadU32Be(input, offset);
  if (len > max_len) {
    TECDSA_THROW_ARGUMENT(std::string(field_name) + " exceeds maximum length");
  }
  if (*offset + len > input.size()) {
    TECDSA_THROW_ARGUMENT(std::string(field_name) + " has inconsistent length");
  }

  Bytes out(input.begin() + static_cast<std::ptrdiff_t>(*offset),
            input.begin() + static_cast<std::ptrdiff_t>(*offset + len));
  *offset += len;
  return out;
}

void AppendPoint(const ECPoint& point, Bytes* out) {
  const Bytes encoded = EncodePoint(point);
  if (encoded.size() != kPointCompressedLen) {
    TECDSA_THROW("Encoded secp256k1 point must be 33 bytes");
  }
  out->insert(out->end(), encoded.begin(), encoded.end());
}

ECPoint ReadPoint(std::span<const uint8_t> input, size_t* offset) {
  if (*offset + kPointCompressedLen > input.size()) {
    TECDSA_THROW_ARGUMENT("Not enough bytes for compressed secp256k1 point");
  }

  const std::span<const uint8_t> view =
      input.subspan(*offset, kPointCompressedLen);
  *offset += kPointCompressedLen;
  return DecodePoint(view);
}

void AppendScalar(const Scalar& scalar, Bytes* out) {
  const std::array<uint8_t, kScalarLen> encoded = scalar.ToCanonicalBytes();
  out->insert(out->end(), encoded.begin(), encoded.end());
}

Scalar ReadScalar(std::span<const uint8_t> input, size_t* offset) {
  if (*offset + kScalarLen > input.size()) {
    TECDSA_THROW_ARGUMENT("Not enough bytes for scalar");
  }
  const std::span<const uint8_t> view = input.subspan(*offset, kScalarLen);
  *offset += kScalarLen;
  return Scalar::FromCanonicalBytes(view);
}

void AppendMpIntField(const BigInt& value, Bytes* out) {
  const Bytes encoded = EncodeMpInt(value);
  AppendSizedField(encoded, out);
}

BigInt ReadMpIntField(std::span<const uint8_t> input,
                      size_t* offset,
                      size_t max_len,
                      const char* field_name) {
  const Bytes encoded = ReadSizedField(input, offset, max_len, field_name);
  return DecodeMpInt(encoded, max_len);
}

Scalar RandomNonZeroScalar() {
  while (true) {
    const Scalar candidate = Csprng::RandomScalar();
    if (candidate.value() != 0) {
      return candidate;
    }
  }
}

Scalar EvaluatePolynomialAt(const std::vector<Scalar>& coefficients, PartyIndex party_id) {
  if (coefficients.empty()) {
    TECDSA_THROW_ARGUMENT("Polynomial coefficients must not be empty");
  }

  const BigInt& q = Scalar::ModulusQMpInt();
  const BigInt x = BigInt(party_id).Mod(q);

  BigInt acc(0);
  BigInt power(1);
  for (const Scalar& coefficient : coefficients) {
    acc = bigint::NormalizeMod(acc + coefficient.mp_value() * power, q);
    power = bigint::NormalizeMod(power * x, q);
  }
  return Scalar(acc);
}

Scalar BuildSchnorrChallenge(const Bytes& session_id,
                             PartyIndex party_id,
                             const ECPoint& statement,
                             const ECPoint& a) {
  Transcript transcript;
  const Bytes statement_bytes = EncodePoint(statement);
  const Bytes a_bytes = EncodePoint(a);
  transcript.append_proof_id(kSchnorrProofId);
  transcript.append_session_id(session_id);
  transcript.append_u32_be("party_id", party_id);
  transcript.append_fields({
      TranscriptFieldRef{.label = "X", .data = statement_bytes},
      TranscriptFieldRef{.label = "A", .data = a_bytes},
  });

  return transcript.challenge_scalar_mod_q();
}

const BigInt& MinPaillierModulusQ8() {
  static const BigInt q_to_8 = []() {
    BigInt out(1);
    const BigInt& q = Scalar::ModulusQMpInt();
    for (size_t i = 0; i < 8; ++i) {
      out *= q;
    }
    return out;
  }();
  return q_to_8;
}

void ValidatePaillierPublicKeyOrThrow(const PaillierPublicKey& pub) {
  if (pub.n <= MinPaillierModulusQ8()) {
    TECDSA_THROW_ARGUMENT("Paillier modulus must satisfy N > q^8");
  }
}

StrictProofVerifierContext BuildStrictProofContext(const Bytes& session_id,
                                                   PartyIndex prover_id) {
  StrictProofVerifierContext context;
  context.session_id = session_id;
  context.prover_id = prover_id;
  return context;
}

bool StrictMetadataCompatible(const ProofMetadata& expected, const ProofMetadata& candidate) {
  return IsProofMetadataCompatible(expected, candidate, /*require_strict_scheme=*/true);
}

}  // namespace

KeygenSession::KeygenSession(KeygenSessionConfig cfg)
    : Session(std::move(cfg.session_id), cfg.self_id, cfg.timeout),
      participants_(std::move(cfg.participants)),
      threshold_(cfg.threshold),
      paillier_modulus_bits_(cfg.paillier_modulus_bits),
      aux_rsa_modulus_bits_(cfg.aux_rsa_modulus_bits),
      strict_mode_(cfg.strict_mode),
      require_aux_param_proof_(cfg.require_aux_param_proof),
      expected_square_free_proof_profile_(std::move(cfg.expected_square_free_proof_profile)),
      expected_aux_param_proof_profile_(std::move(cfg.expected_aux_param_proof_profile)),
      peers_(BuildPeerSet(participants_, cfg.self_id)) {
  ValidateParticipantsOrThrow(participants_, cfg.self_id);
  if (threshold_ >= participants_.size()) {
    TECDSA_THROW_ARGUMENT("threshold must be less than participant count");
  }
  if (paillier_modulus_bits_ < kMinPaillierKeygenBits) {
    TECDSA_THROW_ARGUMENT("paillier_modulus_bits must be >= 2048");
  }
  if (aux_rsa_modulus_bits_ < kMinAuxRsaKeygenBits) {
    TECDSA_THROW_ARGUMENT("aux_rsa_modulus_bits must be >= 2048");
  }
  if (strict_mode_) {
    if (expected_square_free_proof_profile_.scheme != StrictProofScheme::kUnknown &&
        !IsStrictProofScheme(expected_square_free_proof_profile_.scheme)) {
      TECDSA_THROW_ARGUMENT("strict keygen expected square-free profile must use strict scheme");
    }
    if (require_aux_param_proof_ &&
        expected_aux_param_proof_profile_.scheme != StrictProofScheme::kUnknown &&
        !IsStrictProofScheme(expected_aux_param_proof_profile_.scheme)) {
      TECDSA_THROW_ARGUMENT("strict keygen expected aux profile must use strict scheme");
    }
  }
  result_.keygen_session_id = session_id();
  result_.square_free_proof_profile = expected_square_free_proof_profile_;
  result_.aux_param_proof_profile = expected_aux_param_proof_profile_;
  result_.strict_mode = strict_mode_;
  result_.require_aux_param_proof = require_aux_param_proof_;
}

KeygenPhase KeygenSession::phase() const {
  return phase_;
}

size_t KeygenSession::received_peer_count_in_phase() const {
  switch (phase_) {
    case KeygenPhase::kPhase1:
      return seen_phase1_.size();
    case KeygenPhase::kPhase2: {
      size_t complete = 0;
      for (PartyIndex peer : peers_) {
        if (seen_phase2_opens_.contains(peer) && seen_phase2_shares_.contains(peer)) {
          ++complete;
        }
      }
      return complete;
    }
    case KeygenPhase::kPhase3:
      return seen_phase3_.size();
    case KeygenPhase::kCompleted:
      return peers_.size();
  }
  TECDSA_THROW_ARGUMENT("invalid keygen phase");
}

uint32_t KeygenSession::threshold() const {
  return threshold_;
}

bool KeygenSession::PollTimeout(std::chrono::steady_clock::time_point now) {
  const bool timed_out = Session::PollTimeout(now);
  if (timed_out) {
    ClearSensitiveIntermediates();
  }
  return timed_out;
}

bool KeygenSession::HandleEnvelope(const Envelope& envelope) {
  if (PollTimeout()) {
    return false;
  }
  if (IsTerminal()) {
    return false;
  }

  std::string error;
  if (!ValidateSessionBinding(envelope.session_id, envelope.to, &error)) {
    return false;
  }

  if (!peers_.contains(envelope.from)) {
    return false;
  }

  switch (phase_) {
    case KeygenPhase::kPhase1:
      if (envelope.type != MessageTypeForPhase(KeygenPhase::kPhase1)) {
        Abort("unexpected envelope type for keygen phase1");
        return false;
      }
      return HandlePhase1CommitEnvelope(envelope);
    case KeygenPhase::kPhase2:
      if (envelope.type == MessageTypeForPhase(KeygenPhase::kPhase2)) {
        return HandlePhase2OpenEnvelope(envelope);
      }
      if (envelope.type == Phase2ShareMessageType()) {
        return HandlePhase2ShareEnvelope(envelope);
      }
      Abort("unexpected envelope type for keygen phase2");
      return false;
    case KeygenPhase::kPhase3:
      if (envelope.type != MessageTypeForPhase(KeygenPhase::kPhase3)) {
        Abort("unexpected envelope type for keygen phase3");
        return false;
      }
      return HandlePhase3XiProofEnvelope(envelope);
    case KeygenPhase::kCompleted:
      return false;
  }
  TECDSA_THROW_ARGUMENT("invalid keygen phase");
}

Envelope KeygenSession::MakePhaseBroadcastEnvelope(const Bytes& payload) const {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot create envelope for terminal session");
  }

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase(phase_);
  out.payload = payload;
  return out;
}

uint32_t KeygenSession::MessageTypeForPhase(KeygenPhase phase) {
  switch (phase) {
    case KeygenPhase::kPhase1:
      return static_cast<uint32_t>(KeygenMessageType::kPhase1);
    case KeygenPhase::kPhase2:
      return static_cast<uint32_t>(KeygenMessageType::kPhase2);
    case KeygenPhase::kPhase3:
      return static_cast<uint32_t>(KeygenMessageType::kPhase3);
    case KeygenPhase::kCompleted:
      return static_cast<uint32_t>(KeygenMessageType::kAbort);
  }
  TECDSA_THROW_ARGUMENT("invalid keygen phase");
}

uint32_t KeygenSession::Phase2ShareMessageType() {
  return static_cast<uint32_t>(KeygenMessageType::kPhase2Share);
}

void KeygenSession::ClearSensitiveIntermediates() {
  SecureZeroize(&local_poly_coefficients_);
  SecureZeroize(&local_shares_);
  SecureZeroize(&pending_phase2_shares_);
  SecureZeroize(&phase2_verified_shares_);
  SecureZeroize(&local_open_randomness_);
  SecureZeroize(&local_commitment_);

  if (local_phase3_payload_.has_value()) {
    SecureZeroize(&local_phase3_payload_->proof.z);
    local_phase3_payload_.reset();
  }

  for (auto& [party, open_data] : phase2_open_data_) {
    (void)party;
    SecureZeroize(&open_data.randomness);
  }
  phase2_open_data_.clear();

  for (auto& [party, phase3_data] : phase3_broadcasts_) {
    (void)party;
    SecureZeroize(&phase3_data.proof.z);
  }
  phase3_broadcasts_.clear();
}

void KeygenSession::Abort(const std::string& reason) {
  if (IsTerminal()) {
    return;
  }
  ClearSensitiveIntermediates();
  Session::Abort(reason);
}

void KeygenSession::Complete() {
  if (IsTerminal()) {
    return;
  }
  ClearSensitiveIntermediates();
  Session::Complete();
}

Envelope KeygenSession::BuildPhase1CommitEnvelope() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase1 envelope for terminal keygen session");
  }
  if (phase_ != KeygenPhase::kPhase1) {
    TECDSA_THROW_LOGIC("BuildPhase1CommitEnvelope must be called in keygen phase1");
  }

  EnsureLocalPolynomialPrepared();
  EnsureLocalPaillierPrepared();
  EnsureLocalStrictProofArtifactsPrepared();
  phase1_commitments_[self_id()] = local_commitment_;
  result_.all_paillier_public[self_id()] = local_paillier_public_;
  result_.all_aux_rsa_params[self_id()] = local_aux_rsa_params_;
  if (!local_aux_param_proof_.blob.empty()) {
    result_.all_aux_param_proofs[self_id()] = local_aux_param_proof_;
  }
  if (strict_mode_) {
    strict_phase1_non_legacy_parties_.insert(self_id());
  }

  Bytes payload;
  payload.reserve(kCommitmentLen + 4 + 4 * 512 + 4 + 64);
  payload.insert(payload.end(), local_commitment_.begin(), local_commitment_.end());
  AppendMpIntField(local_paillier_->modulus_n_bigint(), &payload);
  AppendMpIntField(local_aux_rsa_params_.n_tilde, &payload);
  AppendMpIntField(local_aux_rsa_params_.h1, &payload);
  AppendMpIntField(local_aux_rsa_params_.h2, &payload);
  const Bytes aux_param_proof_wire = EncodeAuxRsaParamProof(local_aux_param_proof_);
  AppendSizedField(aux_param_proof_wire, &payload);

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase(KeygenPhase::kPhase1);
  out.payload = std::move(payload);
  return out;
}

std::vector<Envelope> KeygenSession::BuildPhase2OpenAndShareEnvelopes() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase2 envelopes for terminal keygen session");
  }
  if (phase_ != KeygenPhase::kPhase2) {
    TECDSA_THROW_LOGIC("BuildPhase2OpenAndShareEnvelopes must be called in keygen phase2");
  }

  EnsureLocalPolynomialPrepared();
  local_phase2_ready_ = true;
  phase2_open_data_[self_id()] = Phase2OpenData{local_y_i_, local_open_randomness_, local_vss_commitments_};
  phase2_verified_shares_[self_id()] = local_shares_.at(self_id());

  Bytes open_payload;
  open_payload.reserve(kPointCompressedLen + 4 + local_open_randomness_.size() +
                       4 + kPointCompressedLen * local_vss_commitments_.size());
  AppendPoint(local_y_i_, &open_payload);
  AppendSizedField(local_open_randomness_, &open_payload);
  AppendU32Be(static_cast<uint32_t>(local_vss_commitments_.size()), &open_payload);
  for (const ECPoint& commitment : local_vss_commitments_) {
    AppendPoint(commitment, &open_payload);
  }

  std::vector<Envelope> out;
  out.reserve(1 + peers_.size());

  Envelope open_msg;
  open_msg.session_id = session_id();
  open_msg.from = self_id();
  open_msg.to = kBroadcastPartyId;
  open_msg.type = MessageTypeForPhase(KeygenPhase::kPhase2);
  open_msg.payload = std::move(open_payload);
  out.push_back(std::move(open_msg));

  for (PartyIndex peer : participants_) {
    if (peer == self_id()) {
      continue;
    }
    Envelope share_msg;
    share_msg.session_id = session_id();
    share_msg.from = self_id();
    share_msg.to = peer;
    share_msg.type = Phase2ShareMessageType();
    AppendScalar(local_shares_.at(peer), &share_msg.payload);
    out.push_back(std::move(share_msg));
  }

  MaybeAdvanceAfterPhase2();
  return out;
}

Envelope KeygenSession::BuildPhase3XiProofEnvelope() {
  if (IsTerminal()) {
    TECDSA_THROW_LOGIC("cannot build phase3 envelope for terminal keygen session");
  }
  if (phase_ != KeygenPhase::kPhase3) {
    TECDSA_THROW_LOGIC("BuildPhase3XiProofEnvelope must be called in keygen phase3");
  }
  if (!phase2_aggregates_ready_) {
    TECDSA_THROW_LOGIC("phase2 aggregates are not ready");
  }

  if (!local_phase3_payload_.has_value()) {
    if (result_.x_i.value() == 0) {
      Abort("aggregated local share is zero");
      TECDSA_THROW("aggregated local share is zero");
    }

    Phase3BroadcastData payload;
    payload.X_i = ECPoint::GeneratorMultiply(result_.x_i);
    payload.proof = BuildSchnorrProof(payload.X_i, result_.x_i);
    local_phase3_payload_ = payload;

    local_phase3_ready_ = true;
    phase3_broadcasts_[self_id()] = payload;
    result_.X_i = payload.X_i;
    result_.all_X_i[self_id()] = payload.X_i;
  }

  Bytes serialized;
  const Bytes square_free_proof_wire = EncodeSquareFreeProof(local_square_free_proof_);
  serialized.reserve(kPointCompressedLen + kPointCompressedLen + kScalarLen +
                     4 + square_free_proof_wire.size());
  AppendPoint(local_phase3_payload_->X_i, &serialized);
  AppendPoint(local_phase3_payload_->proof.a, &serialized);
  AppendScalar(local_phase3_payload_->proof.z, &serialized);
  AppendSizedField(square_free_proof_wire, &serialized);
  result_.all_square_free_proofs[self_id()] = local_square_free_proof_;

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase(KeygenPhase::kPhase3);
  out.payload = std::move(serialized);

  MaybeAdvanceAfterPhase3();
  return out;
}

bool KeygenSession::HasResult() const {
  if (status() != SessionStatus::kCompleted || phase_ != KeygenPhase::kCompleted ||
      !phase2_aggregates_ready_ || !local_phase3_ready_ ||
      result_.all_X_i.size() != participants_.size() ||
      result_.all_paillier_public.size() != participants_.size() ||
      result_.all_aux_rsa_params.size() != participants_.size() ||
      result_.local_paillier == nullptr) {
    return false;
  }

  if (!strict_mode_) {
    return true;
  }

  if (result_.all_square_free_proofs.size() != participants_.size()) {
    return false;
  }
  if (result_.square_free_proof_profile.scheme == StrictProofScheme::kUnknown) {
    return false;
  }
  if (strict_phase1_non_legacy_parties_.size() != participants_.size()) {
    return false;
  }
  if (require_aux_param_proof_) {
    if (result_.all_aux_param_proofs.size() != participants_.size()) {
      return false;
    }
    if (result_.aux_param_proof_profile.scheme == StrictProofScheme::kUnknown) {
      return false;
    }
  }

  for (PartyIndex party : participants_) {
    if (!strict_phase1_non_legacy_parties_.contains(party)) {
      return false;
    }
    const auto pk_it = result_.all_paillier_public.find(party);
    const auto aux_it = result_.all_aux_rsa_params.find(party);
    const auto square_it = result_.all_square_free_proofs.find(party);
    if (pk_it == result_.all_paillier_public.end() || aux_it == result_.all_aux_rsa_params.end() ||
        square_it == result_.all_square_free_proofs.end()) {
      return false;
    }
    if (!StrictMetadataCompatible(result_.square_free_proof_profile, square_it->second.metadata)) {
      return false;
    }
    const StrictProofVerifierContext context = BuildStrictProofContext(session_id(), party);
    if (!VerifySquareFreeProofGmr98(pk_it->second.n, square_it->second, context)) {
      return false;
    }
    if (require_aux_param_proof_) {
      const auto aux_pf_it = result_.all_aux_param_proofs.find(party);
      if (aux_pf_it == result_.all_aux_param_proofs.end()) {
        return false;
      }
      if (!StrictMetadataCompatible(result_.aux_param_proof_profile, aux_pf_it->second.metadata)) {
        return false;
      }
      if (!VerifyAuxRsaParamProofStrict(aux_it->second, aux_pf_it->second, context)) {
        return false;
      }
    }
  }

  return true;
}

const KeygenResult& KeygenSession::result() const {
  if (!HasResult()) {
    TECDSA_THROW_LOGIC("keygen result is not ready");
  }
  return result_;
}

void KeygenSession::EnsureLocalPolynomialPrepared() {
  if (!local_poly_coefficients_.empty()) {
    return;
  }

  while (true) {
    std::vector<Scalar> candidate_coefficients;
    candidate_coefficients.reserve(threshold_ + 1);
    candidate_coefficients.push_back(RandomNonZeroScalar());
    for (uint32_t i = 0; i < threshold_; ++i) {
      candidate_coefficients.push_back(RandomNonZeroScalar());
    }

    std::unordered_map<PartyIndex, Scalar> candidate_shares;
    candidate_shares.reserve(participants_.size());
    bool has_zero_share = false;
    for (PartyIndex party : participants_) {
      const Scalar share = EvaluatePolynomialAt(candidate_coefficients, party);
      if (share.value() == 0) {
        has_zero_share = true;
        break;
      }
      candidate_shares[party] = share;
    }
    if (has_zero_share) {
      continue;
    }

    local_poly_coefficients_ = std::move(candidate_coefficients);
    local_shares_ = std::move(candidate_shares);
    break;
  }

  local_y_i_ = ECPoint::GeneratorMultiply(local_poly_coefficients_[0]);

  local_vss_commitments_.clear();
  local_vss_commitments_.reserve(local_poly_coefficients_.size());
  for (const Scalar& coefficient : local_poly_coefficients_) {
    local_vss_commitments_.push_back(ECPoint::GeneratorMultiply(coefficient));
  }

  const Bytes y_i_bytes = EncodePoint(local_y_i_);
  const CommitmentResult commit = CommitMessage(kPhase1CommitDomain, y_i_bytes);
  local_commitment_ = commit.commitment;
  local_open_randomness_ = commit.randomness;
}

void KeygenSession::EnsureLocalPaillierPrepared() {
  if (local_paillier_ != nullptr) {
    return;
  }

  for (size_t attempt = 0; attempt < kMaxPaillierKeygenAttempts; ++attempt) {
    auto candidate = std::make_shared<PaillierProvider>(paillier_modulus_bits_);
    const BigInt candidate_n = candidate->modulus_n_bigint();
    if (candidate_n > MinPaillierModulusQ8()) {
      local_paillier_ = std::move(candidate);
      local_paillier_public_ = PaillierPublicKey{.n = candidate_n};
      result_.local_paillier = local_paillier_;
      result_.all_paillier_public[self_id()] = local_paillier_public_;
      return;
    }
  }

  TECDSA_THROW("failed to generate Paillier modulus N > q^8");
}

void KeygenSession::EnsureLocalStrictProofArtifactsPrepared() {
  if (local_aux_rsa_params_.n_tilde > 0) {
    return;
  }

  if (local_paillier_ == nullptr) {
    TECDSA_THROW_LOGIC("local Paillier key must be prepared before strict artifacts");
  }

  const StrictProofVerifierContext context = BuildStrictProofContext(session_id(), self_id());
  local_aux_rsa_params_ = GenerateAuxRsaParams(aux_rsa_modulus_bits_, self_id());
  local_square_free_proof_ = BuildSquareFreeProofGmr98(local_paillier_public_.n,
                                                        local_paillier_->private_lambda(),
                                                        context);
  if (require_aux_param_proof_) {
    local_aux_param_proof_ = BuildAuxRsaParamProof(local_aux_rsa_params_, context);
  } else {
    local_aux_param_proof_ = AuxRsaParamProof{};
  }

  if (expected_square_free_proof_profile_.scheme == StrictProofScheme::kUnknown) {
    expected_square_free_proof_profile_ = local_square_free_proof_.metadata;
  }
  if (require_aux_param_proof_ &&
      expected_aux_param_proof_profile_.scheme == StrictProofScheme::kUnknown) {
    expected_aux_param_proof_profile_ = local_aux_param_proof_.metadata;
  }
  result_.square_free_proof_profile = expected_square_free_proof_profile_;
  result_.aux_param_proof_profile =
      require_aux_param_proof_ ? expected_aux_param_proof_profile_ : ProofMetadata{};

  if (strict_mode_) {
    if (!StrictMetadataCompatible(expected_square_free_proof_profile_, local_square_free_proof_.metadata)) {
      TECDSA_THROW("local square-free proof metadata does not match expected strict profile");
    }
    if (!VerifySquareFreeProofGmr98(local_paillier_public_.n, local_square_free_proof_, context)) {
      TECDSA_THROW("failed to self-verify local square-free proof");
    }
    if (require_aux_param_proof_) {
      if (!StrictMetadataCompatible(expected_aux_param_proof_profile_, local_aux_param_proof_.metadata)) {
        TECDSA_THROW("local aux proof metadata does not match expected strict profile");
      }
      if (!VerifyAuxRsaParamProofStrict(local_aux_rsa_params_, local_aux_param_proof_, context)) {
        TECDSA_THROW("failed to self-verify local aux param proof");
      }
    }
  }
}

bool KeygenSession::HandlePhase1CommitEnvelope(const Envelope& envelope) {
  const bool inserted = seen_phase1_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    if (envelope.payload.size() < kCommitmentLen + 4 + 1) {
      TECDSA_THROW_ARGUMENT("phase1 payload is too short");
    }

    size_t offset = 0;
    Bytes commitment(envelope.payload.begin(), envelope.payload.begin() + static_cast<std::ptrdiff_t>(kCommitmentLen));
    offset += kCommitmentLen;

    const BigInt paillier_n = ReadMpIntField(
        envelope.payload, &offset, kMaxPaillierModulusFieldLen, "keygen phase1 Paillier modulus");

    const PaillierPublicKey pub{.n = paillier_n};
    ValidatePaillierPublicKeyOrThrow(pub);

    AuxRsaParams aux_params;
    AuxRsaParamProof aux_param_proof;
    bool has_aux_param_proof = false;
    if (offset == envelope.payload.size()) {
      if (strict_mode_) {
        TECDSA_THROW_ARGUMENT("legacy phase1 payload shape is not allowed in strict mode");
      }
      aux_params = DeriveAuxRsaParamsFromModulus(pub.n, envelope.from);
    } else {
      aux_params.n_tilde = ReadMpIntField(
          envelope.payload, &offset, kMaxPaillierModulusFieldLen, "keygen phase1 aux Ntilde");
      aux_params.h1 = ReadMpIntField(
          envelope.payload, &offset, kMaxPaillierModulusFieldLen, "keygen phase1 aux h1");
      aux_params.h2 = ReadMpIntField(
          envelope.payload, &offset, kMaxPaillierModulusFieldLen, "keygen phase1 aux h2");
      if (!ValidateAuxRsaParams(aux_params)) {
        TECDSA_THROW_ARGUMENT("invalid aux RSA parameters");
      }
      const Bytes aux_param_proof_wire = ReadSizedField(
          envelope.payload, &offset, kMaxProofFieldLen, "keygen phase1 aux parameter proof");
      if (!aux_param_proof_wire.empty()) {
        aux_param_proof = DecodeAuxRsaParamProof(aux_param_proof_wire, kMaxProofBlobLen);
        has_aux_param_proof = true;
      }
      if (offset != envelope.payload.size()) {
        TECDSA_THROW_ARGUMENT("keygen phase1 payload has trailing bytes");
      }
    }

    if (!ValidateAuxRsaParams(aux_params)) {
      TECDSA_THROW_ARGUMENT("invalid aux RSA parameters");
    }

    if (strict_mode_) {
      const StrictProofVerifierContext context = BuildStrictProofContext(session_id(), envelope.from);
      if (require_aux_param_proof_ && !has_aux_param_proof) {
        TECDSA_THROW_ARGUMENT("missing aux parameter proof in strict mode");
      }
      if (has_aux_param_proof) {
        if (expected_aux_param_proof_profile_.scheme == StrictProofScheme::kUnknown) {
          expected_aux_param_proof_profile_ = aux_param_proof.metadata;
          result_.aux_param_proof_profile = expected_aux_param_proof_profile_;
        }
        if (!StrictMetadataCompatible(expected_aux_param_proof_profile_, aux_param_proof.metadata)) {
          TECDSA_THROW_ARGUMENT("aux parameter proof metadata is not compatible with strict profile");
        }
        if (!VerifyAuxRsaParamProofStrict(aux_params, aux_param_proof, context)) {
          TECDSA_THROW_ARGUMENT("aux parameter proof verification failed in strict mode");
        }
      }
      strict_phase1_non_legacy_parties_.insert(envelope.from);
    } else if (has_aux_param_proof &&
               !VerifyAuxRsaParamProof(
                   aux_params,
                   aux_param_proof,
                   BuildStrictProofContext(session_id(), envelope.from))) {
      TECDSA_THROW_ARGUMENT("aux parameter proof verification failed");
    }

    phase1_commitments_[envelope.from] = std::move(commitment);
    result_.all_paillier_public[envelope.from] = pub;
    result_.all_aux_rsa_params[envelope.from] = std::move(aux_params);
    if (has_aux_param_proof) {
      result_.all_aux_param_proofs[envelope.from] = std::move(aux_param_proof);
    }
  } catch (const std::exception& ex) {
    Abort(std::string("invalid keygen phase1 payload: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase1();
  return true;
}

bool KeygenSession::HandlePhase2OpenEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("keygen phase2 open message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase2_opens_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const ECPoint y_i = ReadPoint(envelope.payload, &offset);
    const Bytes randomness = ReadSizedField(
        envelope.payload, &offset, kMaxOpenRandomnessLen, "keygen phase2 open randomness");
    const uint32_t commitment_count = ReadU32Be(envelope.payload, &offset);
    if (commitment_count != threshold_ + 1) {
      TECDSA_THROW_ARGUMENT("keygen phase2 commitments count does not match threshold");
    }

    std::vector<ECPoint> commitments;
    commitments.reserve(commitment_count);
    for (uint32_t i = 0; i < commitment_count; ++i) {
      commitments.push_back(ReadPoint(envelope.payload, &offset));
    }

    if (offset != envelope.payload.size()) {
      TECDSA_THROW_ARGUMENT("keygen phase2 open payload has trailing bytes");
    }

    const auto commitment_it = phase1_commitments_.find(envelope.from);
    if (commitment_it == phase1_commitments_.end()) {
      TECDSA_THROW_ARGUMENT("missing phase1 commitment for dealer");
    }

    const Bytes y_i_bytes = EncodePoint(y_i);
    if (!VerifyCommitment(
            kPhase1CommitDomain, y_i_bytes, randomness, commitment_it->second)) {
      TECDSA_THROW_ARGUMENT("phase2 open does not match phase1 commitment");
    }
    if (commitments.empty() || commitments.front() != y_i) {
      TECDSA_THROW_ARGUMENT("phase2 Feldman commitments do not match opened Y_i");
    }

    phase2_open_data_[envelope.from] = Phase2OpenData{
        .y_i = y_i,
        .randomness = randomness,
        .commitments = commitments,
    };

    const auto pending_it = pending_phase2_shares_.find(envelope.from);
    if (pending_it != pending_phase2_shares_.end()) {
      if (!VerifyDealerShareForSelf(envelope.from, pending_it->second)) {
        TECDSA_THROW_ARGUMENT("phase2 Feldman share verification failed");
      }
      phase2_verified_shares_[envelope.from] = pending_it->second;
      pending_phase2_shares_.erase(pending_it);
    }
  } catch (const std::exception& ex) {
    Abort(std::string("invalid keygen phase2 open: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase2();
  return true;
}

bool KeygenSession::HandlePhase2ShareEnvelope(const Envelope& envelope) {
  if (envelope.to != self_id()) {
    Abort("keygen phase2 share message must target receiver directly");
    return false;
  }

  const bool inserted = seen_phase2_shares_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const Scalar share = ReadScalar(envelope.payload, &offset);
    if (offset != envelope.payload.size()) {
      TECDSA_THROW_ARGUMENT("keygen phase2 share payload has trailing bytes");
    }

    if (phase2_open_data_.contains(envelope.from)) {
      if (!VerifyDealerShareForSelf(envelope.from, share)) {
        TECDSA_THROW_ARGUMENT("phase2 Feldman share verification failed");
      }
      phase2_verified_shares_[envelope.from] = share;
    } else {
      pending_phase2_shares_[envelope.from] = share;
    }
  } catch (const std::exception& ex) {
    Abort(std::string("invalid keygen phase2 share: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase2();
  return true;
}

bool KeygenSession::HandlePhase3XiProofEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("keygen phase3 message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase3_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const ECPoint X_i = ReadPoint(envelope.payload, &offset);
    const ECPoint a = ReadPoint(envelope.payload, &offset);
    const Scalar z = ReadScalar(envelope.payload, &offset);

    const SchnorrProof proof{.a = a, .z = z};
    if (!VerifySchnorrProof(envelope.from, X_i, proof)) {
      TECDSA_THROW_ARGUMENT("schnorr proof verification failed");
    }

    const auto pk_it = result_.all_paillier_public.find(envelope.from);
    if (pk_it == result_.all_paillier_public.end()) {
      TECDSA_THROW_ARGUMENT("missing Paillier public key for phase3 sender");
    }

    SquareFreeProof square_free_proof;
    bool has_square_free_proof = false;
    if (offset < envelope.payload.size()) {
      const Bytes square_free_proof_wire = ReadSizedField(
          envelope.payload, &offset, kMaxProofFieldLen, "keygen phase3 square-free proof");
      if (!square_free_proof_wire.empty()) {
        square_free_proof = DecodeSquareFreeProof(square_free_proof_wire, kMaxProofBlobLen);
        has_square_free_proof = true;
      }
    }
    if (offset != envelope.payload.size()) {
      TECDSA_THROW_ARGUMENT("keygen phase3 payload has trailing bytes");
    }

    if (strict_mode_) {
      const StrictProofVerifierContext context = BuildStrictProofContext(session_id(), envelope.from);
      if (!has_square_free_proof) {
        TECDSA_THROW_ARGUMENT("missing square-free proof in strict mode");
      }
      if (expected_square_free_proof_profile_.scheme == StrictProofScheme::kUnknown) {
        expected_square_free_proof_profile_ = square_free_proof.metadata;
        result_.square_free_proof_profile = expected_square_free_proof_profile_;
      }
      if (!StrictMetadataCompatible(expected_square_free_proof_profile_, square_free_proof.metadata)) {
        TECDSA_THROW_ARGUMENT("square-free proof metadata is not compatible with strict profile");
      }
      if (!VerifySquareFreeProofGmr98(pk_it->second.n, square_free_proof, context)) {
        TECDSA_THROW_ARGUMENT("square-free proof verification failed in strict mode");
      }
    } else if (has_square_free_proof &&
               !VerifySquareFreeProof(
                   pk_it->second.n,
                   square_free_proof,
                   BuildStrictProofContext(session_id(), envelope.from))) {
      TECDSA_THROW_ARGUMENT("square-free proof verification failed");
    }

    phase3_broadcasts_[envelope.from] = Phase3BroadcastData{.X_i = X_i, .proof = proof};
    result_.all_X_i[envelope.from] = X_i;
    if (has_square_free_proof) {
      result_.all_square_free_proofs[envelope.from] = std::move(square_free_proof);
    }
  } catch (const std::exception& ex) {
    Abort(std::string("invalid keygen phase3 payload: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase3();
  return true;
}

bool KeygenSession::VerifyDealerShareForSelf(PartyIndex dealer, const Scalar& share) const {
  if (share.value() == 0) {
    return false;
  }

  const auto open_it = phase2_open_data_.find(dealer);
  if (open_it == phase2_open_data_.end()) {
    return false;
  }

  const std::vector<ECPoint>& commitments = open_it->second.commitments;
  if (commitments.size() != threshold_ + 1 || commitments.empty()) {
    return false;
  }

  try {
    ECPoint rhs = commitments[0];
    const BigInt& q = Scalar::ModulusQMpInt();
    const BigInt self = BigInt(self_id());
    BigInt power = self.Mod(q);
    for (size_t k = 1; k < commitments.size(); ++k) {
      rhs = rhs.Add(commitments[k].Mul(Scalar(power)));
      power = bigint::NormalizeMod(power * self, q);
    }

    const ECPoint lhs = ECPoint::GeneratorMultiply(share);
    return lhs == rhs;
  } catch (const std::exception&) {
    return false;
  }
}

void KeygenSession::MaybeAdvanceAfterPhase1() {
  if (phase_ != KeygenPhase::kPhase1) {
    return;
  }
  if (seen_phase1_.size() != peers_.size()) {
    return;
  }
  if (phase1_commitments_.size() != participants_.size()) {
    return;
  }
  if (result_.all_paillier_public.size() != participants_.size()) {
    return;
  }
  if (result_.all_aux_rsa_params.size() != participants_.size()) {
    return;
  }
  if (strict_mode_) {
    if (strict_phase1_non_legacy_parties_.size() != participants_.size()) {
      return;
    }
    if (require_aux_param_proof_) {
      if (result_.aux_param_proof_profile.scheme == StrictProofScheme::kUnknown) {
        return;
      }
      if (result_.all_aux_param_proofs.size() != participants_.size()) {
        return;
      }
      for (PartyIndex party : participants_) {
        if (!strict_phase1_non_legacy_parties_.contains(party)) {
          return;
        }
        const auto aux_it = result_.all_aux_rsa_params.find(party);
        const auto aux_pf_it = result_.all_aux_param_proofs.find(party);
        if (aux_it == result_.all_aux_rsa_params.end() ||
            aux_pf_it == result_.all_aux_param_proofs.end()) {
          return;
        }
        if (!StrictMetadataCompatible(result_.aux_param_proof_profile, aux_pf_it->second.metadata)) {
          return;
        }
        const StrictProofVerifierContext context = BuildStrictProofContext(session_id(), party);
        if (!VerifyAuxRsaParamProofStrict(aux_it->second, aux_pf_it->second, context)) {
          return;
        }
      }
    }
  }
  phase_ = KeygenPhase::kPhase2;
}

void KeygenSession::MaybeAdvanceAfterPhase2() {
  if (phase_ != KeygenPhase::kPhase2) {
    return;
  }
  if (!local_phase2_ready_) {
    return;
  }
  if (seen_phase2_opens_.size() != peers_.size()) {
    return;
  }
  if (seen_phase2_shares_.size() != peers_.size()) {
    return;
  }
  if (!pending_phase2_shares_.empty()) {
    return;
  }
  if (phase2_open_data_.size() != participants_.size()) {
    return;
  }
  if (phase2_verified_shares_.size() != participants_.size()) {
    return;
  }

  ComputePhase2Aggregates();
  if (IsTerminal()) {
    return;
  }
  phase_ = KeygenPhase::kPhase3;
}

void KeygenSession::MaybeAdvanceAfterPhase3() {
  if (phase_ != KeygenPhase::kPhase3) {
    return;
  }
  if (!local_phase3_ready_) {
    return;
  }
  if (seen_phase3_.size() != peers_.size()) {
    return;
  }
  if (phase3_broadcasts_.size() != participants_.size()) {
    return;
  }
  if (result_.all_X_i.size() != participants_.size()) {
    return;
  }
  if (strict_mode_) {
    if (result_.square_free_proof_profile.scheme == StrictProofScheme::kUnknown) {
      return;
    }
    if (result_.all_square_free_proofs.size() != participants_.size()) {
      return;
    }
    for (PartyIndex party : participants_) {
      const auto pk_it = result_.all_paillier_public.find(party);
      const auto square_it = result_.all_square_free_proofs.find(party);
      if (pk_it == result_.all_paillier_public.end() ||
          square_it == result_.all_square_free_proofs.end()) {
        return;
      }
      if (!StrictMetadataCompatible(result_.square_free_proof_profile, square_it->second.metadata)) {
        return;
      }
      const StrictProofVerifierContext context = BuildStrictProofContext(session_id(), party);
      if (!VerifySquareFreeProofGmr98(pk_it->second.n, square_it->second, context)) {
        return;
      }
    }
  }

  phase_ = KeygenPhase::kCompleted;
  Complete();
}

void KeygenSession::ComputePhase2Aggregates() {
  Scalar x_sum;
  for (const auto& [dealer, share] : phase2_verified_shares_) {
    (void)dealer;
    x_sum = x_sum + share;
  }
  if (x_sum.value() == 0) {
    Abort("aggregated local share is zero");
    return;
  }

  bool first = true;
  ECPoint y_sum;
  for (PartyIndex party : participants_) {
    const auto open_it = phase2_open_data_.find(party);
    if (open_it == phase2_open_data_.end()) {
      Abort("missing phase2 open data");
      return;
    }
    if (first) {
      y_sum = open_it->second.y_i;
      first = false;
      continue;
    }
    try {
      y_sum = y_sum.Add(open_it->second.y_i);
    } catch (const std::exception& ex) {
      Abort(std::string("failed to aggregate keygen public key points: ") + ex.what());
      return;
    }
  }

  result_.x_i = x_sum;
  result_.y = y_sum;
  phase2_aggregates_ready_ = true;
}

SchnorrProof KeygenSession::BuildSchnorrProof(const ECPoint& statement,
                                              const Scalar& witness) const {
  if (witness.value() == 0) {
    TECDSA_THROW_ARGUMENT("schnorr witness must be non-zero");
  }

  while (true) {
    const Scalar r = RandomNonZeroScalar();
    const ECPoint a = ECPoint::GeneratorMultiply(r);
    const Scalar e = BuildSchnorrChallenge(session_id(), self_id(), statement, a);
    const Scalar z = r + (e * witness);
    if (z.value() == 0) {
      continue;
    }
    return SchnorrProof{.a = a, .z = z};
  }
}

bool KeygenSession::VerifySchnorrProof(PartyIndex prover_id,
                                       const ECPoint& statement,
                                       const SchnorrProof& proof) const {
  if (proof.z.value() == 0) {
    return false;
  }

  try {
    const Scalar e = BuildSchnorrChallenge(session_id(), prover_id, statement, proof.a);
    const ECPoint lhs = ECPoint::GeneratorMultiply(proof.z);

    ECPoint rhs = proof.a;
    if (e.value() != 0) {
      rhs = rhs.Add(statement.Mul(e));
    }
    return lhs == rhs;
  } catch (const std::exception&) {
    return false;
  }
}

}  // namespace tecdsa

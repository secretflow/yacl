#pragma once

#include <optional>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/crypto/ec_point.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/paillier.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/scalar.h"
#include "yacl/crypto/experimental/threshold_ecdsa/crypto/strict_proofs.h"
#include "yacl/crypto/experimental/threshold_ecdsa/net/envelope.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/session.h"

namespace tecdsa {

enum class SignPhase : uint32_t {
  kPhase1 = 1,
  kPhase2 = 2,
  kPhase3 = 3,
  kPhase4 = 4,
  kPhase5 = 5,
  kCompleted = 6,
};

enum class SignPhase5Stage : uint32_t {
  kPhase5A = 1,
  kPhase5B = 2,
  kPhase5C = 3,
  kPhase5D = 4,
  kPhase5E = 5,
  kCompleted = 6,
};

enum class SignMessageType : uint32_t {
  kPhase1 = 2001,
  kPhase2 = 2002,
  kPhase2Response = 2010,
  kPhase3 = 2003,
  kPhase4 = 2004,
  kPhase5A = 2005,
  kPhase5B = 2006,
  kPhase5C = 2007,
  kPhase5D = 2008,
  kPhase5E = 2009,
  kAbort = 2099,
};

struct SignSessionConfig {
  using AuxRsaParams = tecdsa::AuxRsaParams;
  using SquareFreeProof = tecdsa::SquareFreeProof;
  using AuxRsaParamProof = tecdsa::AuxRsaParamProof;

  Bytes session_id;
  Bytes keygen_session_id;
  PartyIndex self_id = 0;
  std::vector<PartyIndex> participants;
  std::chrono::milliseconds timeout = std::chrono::seconds(30);

  Scalar x_i;
  ECPoint y;
  std::unordered_map<PartyIndex, ECPoint> all_X_i;
  std::unordered_map<PartyIndex, PaillierPublicKey> all_paillier_public;
  std::unordered_map<PartyIndex, AuxRsaParams> all_aux_rsa_params;
  std::unordered_map<PartyIndex, SquareFreeProof> all_square_free_proofs;
  std::unordered_map<PartyIndex, AuxRsaParamProof> all_aux_param_proofs;
  ProofMetadata square_free_proof_profile;
  ProofMetadata aux_param_proof_profile;
  std::shared_ptr<PaillierProvider> local_paillier;
  Bytes msg32;
  bool strict_mode = true;
  bool require_aux_param_proof = false;

  std::optional<Scalar> fixed_k_i;
  std::optional<Scalar> fixed_gamma_i;
};

struct SignResult {
  Scalar r;
  Scalar s;
  ECPoint R;

  Scalar local_w_i;
  std::unordered_map<PartyIndex, Scalar> lagrange_coefficients;
  std::unordered_map<PartyIndex, Scalar> w_shares;
  std::unordered_map<PartyIndex, ECPoint> W_points;
};

class SignSession : public Session {
 public:
  explicit SignSession(SignSessionConfig cfg);

  SignPhase phase() const;
  SignPhase5Stage phase5_stage() const;
  size_t received_peer_count_in_phase() const;

  Envelope BuildPhase1CommitEnvelope();
  std::vector<Envelope> BuildPhase2MtaEnvelopes();
  Envelope BuildPhase3DeltaEnvelope();
  Envelope BuildPhase4OpenGammaEnvelope();
  Envelope BuildPhase5ACommitEnvelope();
  Envelope BuildPhase5BOpenEnvelope();
  Envelope BuildPhase5CCommitEnvelope();
  Envelope BuildPhase5DOpenEnvelope();
  Envelope BuildPhase5ERevealEnvelope();

  bool HandleEnvelope(const Envelope& envelope);
  Envelope MakePhaseBroadcastEnvelope(const Bytes& payload) const;
  bool PollTimeout(std::chrono::steady_clock::time_point now =
                       std::chrono::steady_clock::now());

  bool HasResult() const;
  const SignResult& result() const;

  static uint32_t MessageTypeForPhase(SignPhase phase);
  static uint32_t MessageTypeForPhase5Stage(SignPhase5Stage stage);
  static uint32_t Phase2ResponseMessageType();

 private:
  struct SchnorrProof {
    ECPoint a;
    Scalar z;
  };

  struct VRelationProof {
    ECPoint alpha;
    Scalar t;
    Scalar u;
  };

  enum class MtaType : uint8_t {
    kTimesGamma = 1,
    kTimesW = 2,
  };

  struct Phase2InitiatorInstance {
    PartyIndex responder = 0;
    MtaType type = MtaType::kTimesGamma;
    Bytes instance_id;
    mpz_class c1;
    mpz_class c1_randomness;
    bool response_received = false;
  };

  struct Phase4OpenData {
    ECPoint gamma_i;
    SchnorrProof gamma_proof;
    Bytes randomness;
  };

  struct Phase5BOpenData {
    ECPoint V_i;
    ECPoint A_i;
    SchnorrProof a_schnorr_proof;
    VRelationProof v_relation_proof;
    Bytes randomness;
  };

  struct Phase5DOpenData {
    ECPoint U_i;
    ECPoint T_i;
    Bytes randomness;
  };

  bool HandlePhase1CommitEnvelope(const Envelope& envelope);
  bool HandlePhase2InitEnvelope(const Envelope& envelope);
  bool HandlePhase2ResponseEnvelope(const Envelope& envelope);
  bool HandlePhase3DeltaEnvelope(const Envelope& envelope);
  bool HandlePhase4OpenEnvelope(const Envelope& envelope);
  bool HandlePhase5ACommitEnvelope(const Envelope& envelope);
  bool HandlePhase5BOpenEnvelope(const Envelope& envelope);
  bool HandlePhase5CCommitEnvelope(const Envelope& envelope);
  bool HandlePhase5DOpenEnvelope(const Envelope& envelope);
  bool HandlePhase5ERevealEnvelope(const Envelope& envelope);

  void PrepareResharedSigningShares();
  void PreparePhase1SecretsIfNeeded();
  void InitializePhase2InstancesIfNeeded();
  void MaybeFinalizePhase2AndAdvance();
  void ComputeDeltaInverseAndAdvanceToPhase4();
  void ComputeRAndAdvanceToPhase5();
  void ComputePhase5VAAndAdvanceToStage5C();
  void VerifyPhase5DAndAdvanceToStage5E();
  void FinalizeSignatureAndComplete();

  void MaybeAdvanceAfterPhase1();
  void MaybeAdvanceAfterPhase2();
  void MaybeAdvanceAfterPhase3();
  void MaybeAdvanceAfterPhase4();
  void MaybeAdvanceAfterPhase5A();
  void MaybeAdvanceAfterPhase5B();
  void MaybeAdvanceAfterPhase5C();
  void MaybeAdvanceAfterPhase5D();
  void MaybeAdvanceAfterPhase5E();
  void ClearSensitiveIntermediates();
  void Abort(const std::string& reason);
  void Complete();
  SchnorrProof BuildSchnorrProof(const ECPoint& statement, const Scalar& witness) const;
  bool VerifySchnorrProof(PartyIndex prover_id,
                          const ECPoint& statement,
                          const SchnorrProof& proof) const;
  VRelationProof BuildVRelationProof(const ECPoint& r_statement,
                                     const ECPoint& v_statement,
                                     const Scalar& s_witness,
                                     const Scalar& l_witness) const;
  bool VerifyVRelationProof(PartyIndex prover_id,
                            const ECPoint& r_statement,
                            const ECPoint& v_statement,
                            const VRelationProof& proof) const;

  std::vector<PartyIndex> participants_;
  std::unordered_set<PartyIndex> peers_;
  std::unordered_map<PartyIndex, ECPoint> all_X_i_;
  std::unordered_map<PartyIndex, PaillierPublicKey> all_paillier_public_;
  std::unordered_map<PartyIndex, SignSessionConfig::AuxRsaParams> all_aux_rsa_params_;
  std::unordered_map<PartyIndex, SignSessionConfig::SquareFreeProof> all_square_free_proofs_;
  std::unordered_map<PartyIndex, SignSessionConfig::AuxRsaParamProof> all_aux_param_proofs_;
  ProofMetadata expected_square_free_proof_profile_;
  ProofMetadata expected_aux_param_proof_profile_;
  std::shared_ptr<PaillierProvider> local_paillier_;
  bool strict_mode_ = true;
  bool require_aux_param_proof_ = false;

  Scalar local_x_i_;
  ECPoint public_key_y_;
  Scalar message_scalar_;
  Bytes msg32_;

  std::unordered_map<PartyIndex, Scalar> lagrange_coefficients_;
  std::unordered_map<PartyIndex, Scalar> w_shares_;
  std::unordered_map<PartyIndex, ECPoint> W_points_;
  Scalar local_w_i_;

  bool local_phase1_ready_ = false;
  bool local_phase2_ready_ = false;
  bool local_phase3_ready_ = false;
  bool local_phase4_ready_ = false;
  bool local_phase5a_ready_ = false;
  bool local_phase5b_ready_ = false;
  bool local_phase5c_ready_ = false;
  bool local_phase5d_ready_ = false;
  bool local_phase5e_ready_ = false;

  std::unordered_set<PartyIndex> seen_phase1_;
  std::unordered_set<PartyIndex> seen_phase2_;
  std::unordered_set<PartyIndex> seen_phase3_;
  std::unordered_set<PartyIndex> seen_phase4_;
  std::unordered_set<PartyIndex> seen_phase5a_;
  std::unordered_set<PartyIndex> seen_phase5b_;
  std::unordered_set<PartyIndex> seen_phase5c_;
  std::unordered_set<PartyIndex> seen_phase5d_;
  std::unordered_set<PartyIndex> seen_phase5e_;

  std::unordered_map<PartyIndex, Bytes> phase1_commitments_;
  std::vector<Envelope> phase2_outbox_;
  bool phase2_instances_initialized_ = false;
  std::unordered_map<std::string, Phase2InitiatorInstance> phase2_initiator_instances_;
  std::unordered_map<std::string, std::string> phase2_responder_requests_seen_;
  Scalar phase2_mta_initiator_sum_;
  Scalar phase2_mta_responder_sum_;
  Scalar phase2_mtawc_initiator_sum_;
  Scalar phase2_mtawc_responder_sum_;
  std::unordered_map<PartyIndex, Scalar> phase3_delta_shares_;
  std::unordered_map<PartyIndex, Phase4OpenData> phase4_open_data_;
  std::unordered_map<PartyIndex, Bytes> phase5a_commitments_;
  std::unordered_map<PartyIndex, Phase5BOpenData> phase5b_open_data_;
  std::unordered_map<PartyIndex, Bytes> phase5c_commitments_;
  std::unordered_map<PartyIndex, Phase5DOpenData> phase5d_open_data_;
  std::unordered_map<PartyIndex, Scalar> phase5e_revealed_s_;

  Scalar local_k_i_;
  Scalar local_gamma_i_;
  ECPoint local_Gamma_i_;
  Bytes local_phase1_randomness_;
  Bytes local_phase1_commitment_;

  Scalar local_delta_i_;
  Scalar local_sigma_i_;
  Scalar delta_;
  Scalar delta_inv_;

  ECPoint Gamma_;
  ECPoint R_;
  Scalar r_;

  Scalar local_s_i_;
  Scalar local_l_i_;
  Scalar local_rho_i_;
  ECPoint local_V_i_;
  ECPoint local_A_i_;
  Bytes local_phase5a_randomness_;
  Bytes local_phase5a_commitment_;

  ECPoint V_;
  ECPoint A_;
  ECPoint local_U_i_;
  ECPoint local_T_i_;
  Bytes local_phase5c_randomness_;
  Bytes local_phase5c_commitment_;

  Scalar s_;
  SignResult result_;
  bool has_result_ = false;

  std::optional<Scalar> fixed_k_i_;
  std::optional<Scalar> fixed_gamma_i_;

  SignPhase phase_ = SignPhase::kPhase1;
  SignPhase5Stage phase5_stage_ = SignPhase5Stage::kPhase5A;
};

}  // namespace tecdsa

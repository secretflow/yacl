#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "yacl/crypto/experimental/threshold_ecdsa/common/thread_pool.h"
#include "yacl/crypto/experimental/threshold_ecdsa/protocol/sign_session.h"

namespace tecdsa::sign_internal {

inline constexpr size_t kCommitmentLen = 32;
inline constexpr size_t kPointCompressedLen = 33;
inline constexpr size_t kScalarLen = 32;
inline constexpr size_t kMaxOpenRandomnessLen = 1024;
inline constexpr size_t kMtaInstanceIdLen = 16;
inline constexpr size_t kMaxMpIntEncodedLen = 8192;
inline constexpr char kPhase1CommitDomain[] = "GG2019/sign/phase1";
inline constexpr char kPhase5ACommitDomain[] = "GG2019/sign/phase5A";
inline constexpr char kPhase5CCommitDomain[] = "GG2019/sign/phase5C";
inline constexpr char kSchnorrProofId[] = "GG2019/Schnorr/v1";
inline constexpr char kVRelationProofId[] = "GG2019/VRel/v1";
inline constexpr char kA1RangeProofId[] = "GG2019/A1Range/v1";
inline constexpr char kA2MtAwcProofId[] = "GG2019/A2MtAwc/v1";
inline constexpr char kA3MtAProofId[] = "GG2019/A3MtA/v1";
inline constexpr char kCurveName[] = "secp256k1";

using AuxRsaParams = SignSessionConfig::AuxRsaParams;

struct MtaProofContext {
  Bytes session_id;
  PartyIndex initiator_id = 0;
  PartyIndex responder_id = 0;
  Bytes mta_instance_id;
};

struct A1RangeProof {
  BigInt z;
  BigInt u;
  BigInt w;
  BigInt s;
  BigInt s1;
  BigInt s2;
};

struct A2MtAwcProof {
  ECPoint u;
  BigInt z = BigInt(0);
  BigInt z2 = BigInt(0);
  BigInt t = BigInt(0);
  BigInt v = BigInt(0);
  BigInt w = BigInt(0);
  BigInt s = BigInt(0);
  BigInt s1 = BigInt(0);
  BigInt s2 = BigInt(0);
  BigInt t1 = BigInt(0);
  BigInt t2 = BigInt(0);
};

struct A3MtAProof {
  BigInt z = BigInt(0);
  BigInt z2 = BigInt(0);
  BigInt t = BigInt(0);
  BigInt v = BigInt(0);
  BigInt w = BigInt(0);
  BigInt s = BigInt(0);
  BigInt s1 = BigInt(0);
  BigInt s2 = BigInt(0);
  BigInt t1 = BigInt(0);
  BigInt t2 = BigInt(0);
};

void ValidateParticipantsOrThrow(const std::vector<PartyIndex>& participants,
                                 PartyIndex self_id);

std::unordered_set<PartyIndex> BuildPeerSet(const std::vector<PartyIndex>& participants,
                                            PartyIndex self_id);

void AppendU32Be(uint32_t value, Bytes* out);
uint32_t ReadU32Be(std::span<const uint8_t> input, size_t* offset);
void AppendSizedField(std::span<const uint8_t> field, Bytes* out);
Bytes ReadSizedField(std::span<const uint8_t> input,
                     size_t* offset,
                     size_t max_len,
                     const char* field_name);

void AppendPoint(const ECPoint& point, Bytes* out);
ECPoint ReadPoint(std::span<const uint8_t> input, size_t* offset);
void AppendScalar(const Scalar& scalar, Bytes* out);
Scalar ReadScalar(std::span<const uint8_t> input, size_t* offset);
void AppendMpIntField(const BigInt& value, Bytes* out);
BigInt ReadMpIntField(std::span<const uint8_t> input,
                      size_t* offset,
                      size_t max_len,
                      const char* field_name);

std::string BytesToKey(const Bytes& bytes);
std::string MakeResponderRequestKey(PartyIndex initiator, uint8_t type_code);

BigInt RandomBelow(const BigInt& upper_exclusive);
BigInt SampleZnStar(const BigInt& modulus_n);
bool IsZnStarElement(const BigInt& value, const BigInt& modulus);
void ValidateAuxRsaParamsOrThrow(const AuxRsaParams& params);

const BigInt& QPow3();
const BigInt& QPow5();
const BigInt& QPow7();
const BigInt& MinPaillierModulusQ8();

StrictProofVerifierContext BuildKeygenProofContext(const Bytes& keygen_session_id,
                                                   PartyIndex prover_id);
bool StrictMetadataCompatible(const ProofMetadata& expected,
                              const ProofMetadata& candidate);

BigInt NormalizeMod(const BigInt& value, const BigInt& modulus);
BigInt MulMod(const BigInt& lhs, const BigInt& rhs, const BigInt& modulus);
BigInt PowMod(const BigInt& base, const BigInt& exp, const BigInt& modulus);
std::optional<BigInt> InvertMod(const BigInt& value, const BigInt& modulus);
bool IsInRange(const BigInt& value, const BigInt& modulus);

Bytes ExportFixedWidth(const BigInt& value, size_t width);
const Bytes& CurveNameBytes();
const Bytes& ModulusQBytes();

ThreadPool& Phase2ThreadPool();

Scalar BuildA1RangeChallenge(const MtaProofContext& ctx,
                             const BigInt& n,
                             const BigInt& gamma,
                             const AuxRsaParams& aux,
                             const BigInt& c,
                             const BigInt& z,
                             const BigInt& u,
                             const BigInt& w);

Scalar BuildA2MtAwcChallenge(const MtaProofContext& ctx,
                             const BigInt& n,
                             const BigInt& gamma,
                             const AuxRsaParams& aux,
                             const BigInt& c1,
                             const BigInt& c2,
                             const ECPoint& statement_x,
                             const A2MtAwcProof& proof);

Scalar BuildA3MtAChallenge(const MtaProofContext& ctx,
                           const BigInt& n,
                           const BigInt& gamma,
                           const AuxRsaParams& aux,
                           const BigInt& c1,
                           const BigInt& c2,
                           const A3MtAProof& proof);

A1RangeProof ProveA1Range(const MtaProofContext& ctx,
                          const BigInt& n,
                          const AuxRsaParams& verifier_aux,
                          const BigInt& c,
                          const BigInt& witness_m,
                          const BigInt& witness_r);

bool VerifyA1Range(const MtaProofContext& ctx,
                   const BigInt& n,
                   const AuxRsaParams& verifier_aux,
                   const BigInt& c,
                   const A1RangeProof& proof);

A2MtAwcProof ProveA2MtAwc(const MtaProofContext& ctx,
                          const BigInt& n,
                          const AuxRsaParams& verifier_aux,
                          const BigInt& c1,
                          const BigInt& c2,
                          const ECPoint& statement_x,
                          const BigInt& witness_x,
                          const BigInt& witness_y,
                          const BigInt& witness_r);

bool VerifyA2MtAwc(const MtaProofContext& ctx,
                   const BigInt& n,
                   const AuxRsaParams& verifier_aux,
                   const BigInt& c1,
                   const BigInt& c2,
                   const ECPoint& statement_x,
                   const A2MtAwcProof& proof);

A3MtAProof ProveA3MtA(const MtaProofContext& ctx,
                      const BigInt& n,
                      const AuxRsaParams& verifier_aux,
                      const BigInt& c1,
                      const BigInt& c2,
                      const BigInt& witness_x,
                      const BigInt& witness_y,
                      const BigInt& witness_r);

bool VerifyA3MtA(const MtaProofContext& ctx,
                 const BigInt& n,
                 const AuxRsaParams& verifier_aux,
                 const BigInt& c1,
                 const BigInt& c2,
                 const A3MtAProof& proof);

void AppendA1RangeProof(const A1RangeProof& proof, Bytes* out);
A1RangeProof ReadA1RangeProof(std::span<const uint8_t> input, size_t* offset);

void AppendA2MtAwcProof(const A2MtAwcProof& proof, Bytes* out);
A2MtAwcProof ReadA2MtAwcProof(std::span<const uint8_t> input, size_t* offset);

void AppendA3MtAProof(const A3MtAProof& proof, Bytes* out);
A3MtAProof ReadA3MtAProof(std::span<const uint8_t> input, size_t* offset);

Bytes RandomMtaInstanceId();
Scalar RandomNonZeroScalar();
BigInt NormalizeModQ(const BigInt& value);
std::optional<Scalar> InvertScalar(const Scalar& scalar);
bool IsHighScalar(const Scalar& scalar);

std::unordered_map<PartyIndex, Scalar> ComputeLagrangeAtZero(
    const std::vector<PartyIndex>& participants);

ECPoint SumPointsOrThrow(const std::vector<ECPoint>& points);
Bytes SerializePointPair(const ECPoint& first, const ECPoint& second);
Scalar XCoordinateModQ(const ECPoint& point);

Scalar BuildSchnorrChallenge(const Bytes& session_id,
                             PartyIndex party_id,
                             const ECPoint& statement,
                             const ECPoint& a);

Scalar BuildVRelationChallenge(const Bytes& session_id,
                               PartyIndex party_id,
                               const ECPoint& r_statement,
                               const ECPoint& v_statement,
                               const ECPoint& alpha);

ECPoint BuildRGeneratorLinearCombination(const ECPoint& r_base,
                                         const Scalar& r_multiplier,
                                         const Scalar& g_multiplier);

}  // namespace tecdsa::sign_internal

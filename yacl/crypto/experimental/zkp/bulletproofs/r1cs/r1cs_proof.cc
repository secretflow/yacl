// Copyright 2025 @yangjucai.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "yacl/crypto/experimental/zkp/bulletproofs/r1cs/r1cs_proof.h"

#include <cstring>

#include "yacl/base/exception.h"
#include "yacl/crypto/experimental/zkp/bulletproofs/util.h"

namespace examples::zkp {

namespace {

// constexpr constants
constexpr uint8_t ONE_PHASE_COMMITMENTS = 0;
constexpr uint8_t TWO_PHASE_COMMITMENTS = 1;

constexpr size_t SCALAR_SIZE = 32;           // 32-byte scalars
constexpr size_t NUM_SCALARS = 3;            // t_x, t_x_blinding, e_blinding
constexpr size_t NUM_ONE_PHASE_COMMITS = 3;  // A_I1, A_O1, S1
constexpr size_t NUM_TWO_PHASE_COMMITS = 6;  // A_I1, A_O1, S1, A_I2, A_O2, S2
constexpr size_t NUM_T_COMMITS = 5;          // T_1, T_3, T_4, T_5, T_6
constexpr size_t VERSION_BYTE_SIZE = 1;

void WriteToBuffer(char** ptr, const yacl::Buffer& data) {
  std::memcpy(*ptr, data.data(), data.size());
  *ptr += data.size();
}
}  // namespace

bool R1CSProof::MissingPhase2Commitments(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
  return curve->IsInfinity(A_I2) && curve->IsInfinity(A_O2) &&
         curve->IsInfinity(S2);
}

yacl::Buffer R1CSProof::ToBytes(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
  size_t point_size = curve->GetSerializeLength();
  size_t ipp_size = ipp_proof.SerializedSize(curve);

  bool is_one_phase = MissingPhase2Commitments(curve);
  size_t num_phase_commits =
      is_one_phase ? NUM_ONE_PHASE_COMMITS : NUM_TWO_PHASE_COMMITS;

  size_t total_size = VERSION_BYTE_SIZE + num_phase_commits * point_size +
                      NUM_T_COMMITS * point_size + NUM_SCALARS * SCALAR_SIZE +
                      ipp_size;

  yacl::Buffer buf(total_size);
  char* ptr = buf.data<char>();

  // Write version byte
  uint8_t version =
      is_one_phase ? ONE_PHASE_COMMITMENTS : TWO_PHASE_COMMITMENTS;
  std::memcpy(ptr, &version, VERSION_BYTE_SIZE);
  ptr += VERSION_BYTE_SIZE;

  // Write commitments
  WriteToBuffer(&ptr, curve->SerializePoint(A_I1));
  WriteToBuffer(&ptr, curve->SerializePoint(A_O1));
  WriteToBuffer(&ptr, curve->SerializePoint(S1));
  if (!is_one_phase) {
    WriteToBuffer(&ptr, curve->SerializePoint(A_I2));
    WriteToBuffer(&ptr, curve->SerializePoint(A_O2));
    WriteToBuffer(&ptr, curve->SerializePoint(S2));
  }
  WriteToBuffer(&ptr, curve->SerializePoint(T_1));
  WriteToBuffer(&ptr, curve->SerializePoint(T_3));
  WriteToBuffer(&ptr, curve->SerializePoint(T_4));
  WriteToBuffer(&ptr, curve->SerializePoint(T_5));
  WriteToBuffer(&ptr, curve->SerializePoint(T_6));

  // Write scalars
  WriteToBuffer(&ptr, t_x.ToBytes(SCALAR_SIZE, yacl::Endian::little));
  WriteToBuffer(&ptr, t_x_blinding.ToBytes(SCALAR_SIZE, yacl::Endian::little));
  WriteToBuffer(&ptr, e_blinding.ToBytes(SCALAR_SIZE, yacl::Endian::little));

  // Write IPP proof
  WriteToBuffer(&ptr, ipp_proof.ToBytes(curve));

  YACL_ENFORCE(ptr == buf.data<char>() + total_size,
               "R1CSProof serialization size mismatch");

  return buf;
}

R1CSProof R1CSProof::FromBytes(
    const yacl::ByteContainerView& bytes,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
  YACL_ENFORCE(bytes.size() >= VERSION_BYTE_SIZE,
               "R1CSProof format error: too short for version byte");

  uint8_t version = bytes[0];
  yacl::ByteContainerView slice(bytes.data() + VERSION_BYTE_SIZE,
                                bytes.size() - VERSION_BYTE_SIZE);

  size_t point_size = curve->GetSerializeLength();

  size_t min_num_points = (version == ONE_PHASE_COMMITMENTS)
                              ? (NUM_ONE_PHASE_COMMITS + NUM_T_COMMITS)
                              : (NUM_TWO_PHASE_COMMITS + NUM_T_COMMITS);
  size_t min_len = min_num_points * point_size + NUM_SCALARS * SCALAR_SIZE;
  YACL_ENFORCE(slice.size() >= min_len,
               "R1CSProof format error: slice too short for version");

  size_t offset = 0;

  auto read_point = [&](size_t& offset) {
    auto point = curve->DeserializePoint(slice.subspan(offset, point_size));
    offset += point_size;
    return point;
  };
  auto read_scalar = [&](size_t& offset) {
    yacl::math::MPInt s;
    s.FromMagBytes(slice.subspan(offset, SCALAR_SIZE), yacl::Endian::little);
    offset += SCALAR_SIZE;
    return s;
  };

  R1CSProof proof;

  proof.A_I1 = read_point(offset);
  proof.A_O1 = read_point(offset);
  proof.S1 = read_point(offset);

  if (version == ONE_PHASE_COMMITMENTS) {
    proof.A_I2 = curve->MulBase(yacl::math::MPInt(0));
    proof.A_O2 = curve->MulBase(yacl::math::MPInt(0));
    proof.S2 = curve->MulBase(yacl::math::MPInt(0));
  } else {
    proof.A_I2 = read_point(offset);
    proof.A_O2 = read_point(offset);
    proof.S2 = read_point(offset);
  }

  proof.T_1 = read_point(offset);
  proof.T_3 = read_point(offset);
  proof.T_4 = read_point(offset);
  proof.T_5 = read_point(offset);
  proof.T_6 = read_point(offset);

  proof.t_x = read_scalar(offset);
  proof.t_x_blinding = read_scalar(offset);
  proof.e_blinding = read_scalar(offset);

  size_t remaining_size = slice.size() - offset;
  proof.ipp_proof = InnerProductProof::FromBytes(
      slice.subspan(offset, remaining_size), curve);

  return proof;
}

}  // namespace examples::zkp
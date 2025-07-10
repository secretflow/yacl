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
constexpr uint8_t ONE_PHASE_COMMITMENTS = 0;
constexpr uint8_t TWO_PHASE_COMMITMENTS = 1;

// Helper to write a buffer into another buffer and advance the pointer
void WriteToBuffer(char** ptr, const yacl::Buffer& data) {
    std::memcpy(*ptr, data.data(), data.size());
    *ptr += data.size();
}
} // namespace

bool R1CSProof::MissingPhase2Commitments(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
    return curve->IsInfinity(A_I2) && curve->IsInfinity(A_O2) && curve->IsInfinity(S2);
}

yacl::Buffer R1CSProof::ToBytes(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
    size_t point_size = curve->GetSerializeLength();
    size_t scalar_size = 32; // Assuming 32-byte scalars
    size_t ipp_size = ipp_proof.SerializedSize(curve);

    bool is_one_phase = MissingPhase2Commitments(curve);
    size_t num_phase_commits = is_one_phase ? 3 : 6;

    size_t total_size = 1 + // version byte
                        num_phase_commits * point_size + // A/S commitments
                        5 * point_size + // T commitments
                        3 * scalar_size + // t_x, t_x_blinding, e_blinding
                        ipp_size;
    
    yacl::Buffer buf(total_size);
    char* ptr = buf.data<char>();
    
    // Write version byte
    uint8_t version = is_one_phase ? ONE_PHASE_COMMITMENTS : TWO_PHASE_COMMITMENTS;
    std::memcpy(ptr, &version, 1);
    ptr++;
    
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
    WriteToBuffer(&ptr, t_x.ToBytes(scalar_size, yacl::Endian::little));
    WriteToBuffer(&ptr, t_x_blinding.ToBytes(scalar_size, yacl::Endian::little));
    WriteToBuffer(&ptr, e_blinding.ToBytes(scalar_size, yacl::Endian::little));

    // Write IPP proof
    WriteToBuffer(&ptr, ipp_proof.ToBytes(curve));

    YACL_ENFORCE(ptr == buf.data<char>() + total_size, "R1CSProof serialization size mismatch");

    return buf;
}

R1CSProof R1CSProof::FromBytes(const yacl::ByteContainerView& bytes,
                               const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
    YACL_ENFORCE(bytes.size() >= 1, "R1CSProof format error: too short for version byte");
    
    uint8_t version = bytes[0];
    yacl::ByteContainerView slice(bytes.data() + 1, bytes.size() - 1);

    size_t point_size = curve->GetSerializeLength();
    size_t scalar_size = 32;
    
    size_t min_num_points = (version == ONE_PHASE_COMMITMENTS) ? 8 : 11;
    size_t min_len = min_num_points * point_size + 3 * scalar_size;
    YACL_ENFORCE(slice.size() >= min_len, "R1CSProof format error: slice too short for version");

    const char* ptr = reinterpret_cast<const char*>(slice.data());
    
    auto read_point = [&](const char** p) {
        auto point = curve->DeserializePoint({*p, point_size});
        *p += point_size;
        return point;
    };
    auto read_scalar = [&](const char** p) {
        yacl::math::MPInt s;
        s.FromMagBytes({*p, scalar_size}, yacl::Endian::little);
        *p += scalar_size;
        return s;
    };

    R1CSProof proof;

    proof.A_I1 = read_point(&ptr);
    proof.A_O1 = read_point(&ptr);
    proof.S1 = read_point(&ptr);

    if (version == ONE_PHASE_COMMITMENTS) {
        proof.A_I2 = curve->MulBase(yacl::math::MPInt(0));
        proof.A_O2 = curve->MulBase(yacl::math::MPInt(0));
        proof.S2 = curve->MulBase(yacl::math::MPInt(0));
    } else {
        proof.A_I2 = read_point(&ptr);
        proof.A_O2 = read_point(&ptr);
        proof.S2 = read_point(&ptr);
    }
    
    proof.T_1 = read_point(&ptr);
    proof.T_3 = read_point(&ptr);
    proof.T_4 = read_point(&ptr);
    proof.T_5 = read_point(&ptr);
    proof.T_6 = read_point(&ptr);

    proof.t_x = read_scalar(&ptr);
    proof.t_x_blinding = read_scalar(&ptr);
    proof.e_blinding = read_scalar(&ptr);

    size_t remaining_size = slice.size() - (ptr - reinterpret_cast<const char*>(slice.data()));
    proof.ipp_proof = InnerProductProof::FromBytes({ptr, remaining_size}, curve);

    return proof;
}

} // namespace examples::zkp
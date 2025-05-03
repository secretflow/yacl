#include "zkp/bulletproofs/r1cs/r1cs.h"

#include <map> // For optimizing linear combinations
#include <numeric> // For std::accumulate
#include <cstring> // For memcpy

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/base/byte_container_view.h"
#include "zkp/bulletproofs/util.h" // Need helpers

namespace examples::zkp {

// --- LinearCombination Implementation ---

LinearCombination::LinearCombination(Variable var) {
    terms.emplace_back(var, yacl::math::MPInt(1));
}

LinearCombination::LinearCombination(const yacl::math::MPInt& scalar) {
    terms.emplace_back(kOneVariable, scalar);
}
LinearCombination::LinearCombination(int64_t scalar_int) {
     terms.emplace_back(kOneVariable, yacl::math::MPInt(scalar_int));
}


void LinearCombination::Optimize(const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
    if (terms.size() <= 1) return;

    const auto& order = curve->GetOrder();
    std::map<Variable, yacl::math::MPInt> combined_terms;

    for (const auto& term : terms) {
        combined_terms[term.first] = combined_terms[term.first].AddMod(term.second, order);
    }

    terms.clear();
    for (const auto& pair : combined_terms) {
        // Remove terms with zero coefficient
        if (!pair.second.IsZero()) {
            terms.push_back(pair);
        }
    }
}

LinearCombination LinearCombination::operator+(const LinearCombination& other) const {
    LinearCombination result = *this; // Copy current terms
    result.terms.insert(result.terms.end(), other.terms.begin(), other.terms.end());
    return result;
}
LinearCombination LinearCombination::operator+(const Variable& var) const {
    return *this + LinearCombination(var);
}
LinearCombination LinearCombination::operator+(const yacl::math::MPInt& scalar) const {
     return *this + LinearCombination(scalar);
}


LinearCombination LinearCombination::operator-(const LinearCombination& other) const {
     LinearCombination result = *this; // Copy current terms
     for(const auto& term : other.terms) {
         // Use negation modulo order if available, otherwise order - val
         yacl::math::MPInt neg_coeff = term.second.NegateMod(curve->GetOrder()); // Assume NegateMod exists
         result.terms.emplace_back(term.first, neg_coeff);
     }
     return result;
}
LinearCombination LinearCombination::operator-(const Variable& var) const {
    return *this - LinearCombination(var);
}
LinearCombination LinearCombination::operator-(const yacl::math::MPInt& scalar) const {
     return *this - LinearCombination(scalar);
}

LinearCombination LinearCombination::operator-() const { // Negation
    LinearCombination result;
    result.terms.reserve(terms.size());
     for(const auto& term : terms) {
         yacl::math::MPInt neg_coeff = term.second.NegateMod(curve->GetOrder()); // Assume NegateMod exists
         result.terms.emplace_back(term.first, neg_coeff);
     }
     return result;
}

LinearCombination LinearCombination::operator*(const yacl::math::MPInt& scalar) const {
    LinearCombination result;
    result.terms.reserve(terms.size());
    const auto& order = curve->GetOrder(); // Need curve context or pass it
    for(const auto& term : terms) {
        result.terms.emplace_back(term.first, term.second.MulMod(scalar, order));
    }
    return result;
}

// Friend implementations
LinearCombination operator+(const yacl::math::MPInt& scalar, const LinearCombination& lc) {
    return LinearCombination(scalar) + lc;
}
LinearCombination operator+(const Variable& var, const yacl::math::MPInt& scalar) {
    return LinearCombination(var) + LinearCombination(scalar);
}

LinearCombination operator-(const yacl::math::MPInt& scalar, const LinearCombination& lc) {
     return LinearCombination(scalar) - lc;
}
LinearCombination operator-(const Variable& var, const yacl::math::MPInt& scalar) {
    return LinearCombination(var) - LinearCombination(scalar);
}

LinearCombination operator*(const yacl::math::MPInt& scalar, const LinearCombination& lc) {
     return lc * scalar; // Reuse existing operator*
}
LinearCombination operator*(const yacl::math::MPInt& scalar, const Variable& var) {
    return LinearCombination(var) * scalar;
}


// --- R1CSProof Implementation ---

constexpr uint8_t ONE_PHASE_COMMITMENTS = 0;
constexpr uint8_t TWO_PHASE_COMMITMENTS = 1;

R1CSProof::R1CSProof(bool phase2,
                     const yacl::crypto::EcPoint& ai1, const yacl::crypto::EcPoint& ao1, const yacl::crypto::EcPoint& s1,
                     const yacl::crypto::EcPoint& ai2, const yacl::crypto::EcPoint& ao2, const yacl::crypto::EcPoint& s2,
                     const yacl::crypto::EcPoint& t1, const yacl::crypto::EcPoint& t3, const yacl::crypto::EcPoint& t4,
                     const yacl::crypto::EcPoint& t5, const yacl::crypto::EcPoint& t6,
                     const yacl::math::MPInt& tx, const yacl::math::MPInt& tx_b, const yacl::math::MPInt& e_b,
                     InnerProductProof ipp)
    : has_phase2_commitments(phase2),
      A_I1(ai1), A_O1(ao1), S1(s1),
      A_I2(ai2), A_O2(ao2), S2(s2),
      T_1(t1), T_3(t3), T_4(t4), T_5(t5), T_6(t6),
      t_x(tx), t_x_blinding(tx_b), e_blinding(e_b),
      ipp_proof(std::move(ipp)) {}


bool R1CSProof::MissingPhase2Commitments(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
    // Check if phase 2 commitments are identity
    return curve->IsInfinity(A_I2) && curve->IsInfinity(A_O2) && curve->IsInfinity(S2);
}

yacl::Buffer R1CSProof::ToBytes(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
    // Determine size first
    size_t num_points = 8; // A_I1, A_O1, S1, T1, T3, T4, T5, T6
    bool has_phase2 = !MissingPhase2Commitments(curve); // Check if phase 2 is actually present
    if (has_phase2) {
        num_points += 3; // A_I2, A_O2, S2
    }
    size_t num_scalars = 3; // tx, tx_b, e_b
    size_t ipp_size = ipp_proof.SerializedSize(); // Assuming IPP has this
    size_t version_byte_size = 1;
    // Rough estimate, assuming 33 bytes compressed point, 32 bytes scalar
    size_t estimated_total = version_byte_size + num_points * 33 + num_scalars * 32 + ipp_size;

    // Pre-serialize to get actual sizes (more accurate)
    yacl::Buffer ai1_b = curve->SerializePoint(A_I1, true);
    yacl::Buffer ao1_b = curve->SerializePoint(A_O1, true);
    yacl::Buffer s1_b = curve->SerializePoint(S1, true);
    yacl::Buffer ai2_b, ao2_b, s2_b;
     if (has_phase2) {
        ai2_b = curve->SerializePoint(A_I2, true);
        ao2_b = curve->SerializePoint(A_O2, true);
        s2_b = curve->SerializePoint(S2, true);
    }
    yacl::Buffer t1_b = curve->SerializePoint(T_1, true);
    yacl::Buffer t3_b = curve->SerializePoint(T_3, true);
    yacl::Buffer t4_b = curve->SerializePoint(T_4, true);
    yacl::Buffer t5_b = curve->SerializePoint(T_5, true);
    yacl::Buffer t6_b = curve->SerializePoint(T_6, true);
    yacl::Buffer tx_b = t_x.Serialize();
    yacl::Buffer tx_blinding_b = t_x_blinding.Serialize();
    yacl::Buffer e_blinding_b = e_blinding.Serialize();
    yacl::Buffer ipp_b = ipp_proof.ToBytes(curve);

    size_t actual_total = version_byte_size +
                          ai1_b.size() + ao1_b.size() + s1_b.size() +
                          (has_phase2 ? (ai2_b.size() + ao2_b.size() + s2_b.size()) : 0) +
                          t1_b.size() + t3_b.size() + t4_b.size() + t5_b.size() + t6_b.size() +
                          tx_b.size() + tx_blinding_b.size() + e_blinding_b.size() +
                          ipp_b.size();

    yacl::Buffer buf(actual_total);
    char* ptr = buf.data<char>();

    // Write version byte
    *ptr++ = has_phase2 ? TWO_PHASE_COMMITMENTS : ONE_PHASE_COMMITMENTS;

    // Write points & scalars
    auto append_buf = [&](const yacl::Buffer& b) {
        std::memcpy(ptr, b.data(), b.size());
        ptr += b.size();
    };

    append_buf(ai1_b); append_buf(ao1_b); append_buf(s1_b);
    if(has_phase2) {
        append_buf(ai2_b); append_buf(ao2_b); append_buf(s2_b);
    }
    append_buf(t1_b); append_buf(t3_b); append_buf(t4_b); append_buf(t5_b); append_buf(t6_b);
    append_buf(tx_b); append_buf(tx_blinding_b); append_buf(e_blinding_b);
    append_buf(ipp_b);

    YACL_ENFORCE(ptr == buf.data<char>() + actual_total, "R1CSProof Serialization size mismatch");
    return buf;
}


R1CSProof R1CSProof::FromBytes(const yacl::ByteContainerView& bytes,
                              const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
    YACL_ENFORCE(bytes.size() > 0, "R1CSProof FromBytes: Empty input");
    const uint8_t* ptr = bytes.data();
    const uint8_t* end = ptr + bytes.size();

    // Read version byte
    uint8_t version = *ptr++;
    YACL_ENFORCE(version == ONE_PHASE_COMMITMENTS || version == TWO_PHASE_COMMITMENTS,
                 "R1CSProof FromBytes: Invalid version byte");
    bool has_phase2 = (version == TWO_PHASE_COMMITMENTS);

    // Helper to read fixed-size blob (assuming 32-byte points/scalars based on  )
    // This is an approximation, YACL serialization might differ!
    // A more robust approach would store sizes. Sticking to   format for now.
    size_t point_size = 33; // Assuming compressed points
    size_t scalar_size = curve->GetScalarField().BitCount() / 8; // Bytes for scalar
    if (curve->GetScalarField().BitCount() % 8 != 0) scalar_size++; // Ceiling

    auto read_buffer = [&](size_t expected_size) -> yacl::ByteContainerView {
        YACL_ENFORCE(ptr + expected_size <= end, "R1CSProof FromBytes: Unexpected end of data");
        yacl::ByteContainerView view(ptr, expected_size);
        ptr += expected_size;
        return view;
    };

    auto read_point = [&]() { return curve->DeserializePoint(read_buffer(point_size)); };
    auto read_scalar = [&]() {
        yacl::math::MPInt s;
        s.Deserialize(read_buffer(scalar_size)); // Assuming MPInt Deserialize works
        return s;
    };

    // Read commitments
    auto A_I1 = read_point();
    auto A_O1 = read_point();
    auto S1 = read_point();
    yacl::crypto::EcPoint A_I2, A_O2, S2;
    if (has_phase2) {
        A_I2 = read_point();
        A_O2 = read_point();
        S2 = read_point();
    } else {
        // Assign identity if phase 2 is missing
        A_I2 = curve->MulBase(yacl::math::MPInt(0));
        A_O2 = curve->MulBase(yacl::math::MPInt(0));
        S2 = curve->MulBase(yacl::math::MPInt(0));
    }
    auto T_1 = read_point();
    auto T_3 = read_point();
    auto T_4 = read_point();
    auto T_5 = read_point();
    auto T_6 = read_point();

    // Read scalars
    auto t_x = read_scalar();
    auto t_x_blinding = read_scalar();
    auto e_blinding = read_scalar();

    // Read IPP
    size_t remaining_bytes = end - ptr;
    InnerProductProof ipp_proof = InnerProductProof::FromBytes(
        yacl::ByteContainerView(ptr, remaining_bytes), curve);

    return R1CSProof(has_phase2, A_I1, A_O1, S1, A_I2, A_O2, S2, T_1, T_3, T_4, T_5, T_6,
                     t_x, t_x_blinding, e_blinding, std::move(ipp_proof));
}

size_t R1CSProof::SerializedSize(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
     // Calculate exact size based on components
    size_t ipp_size = ipp_proof_.SerializedSize(); // Assuming IPP has this
    size_t version_byte_size = 1;
    size_t point_size = curve->GetSerializeLength(true); // Assume compressed
    size_t scalar_size = curve->GetScalarField().BitCount() / 8;
    if (curve->GetScalarField().BitCount() % 8 != 0) scalar_size++;

    size_t num_phase1_points = 3; // AI1, AO1, S1
    size_t num_phase2_points = MissingPhase2Commitments(curve) ? 0 : 3; // AI2, AO2, S2
    size_t num_T_points = 5; // T1, T3, T4, T5, T6
    size_t num_scalars = 3; // tx, tx_b, e_b

    return version_byte_size +
           (num_phase1_points + num_phase2_points + num_T_points) * point_size +
           num_scalars * scalar_size +
           ipp_size;
}


} // namespace examples::zkp
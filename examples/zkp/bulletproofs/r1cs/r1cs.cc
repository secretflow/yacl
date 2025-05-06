#include "zkp/bulletproofs/r1cs/r1cs.h"

#include <map>
#include <numeric>
#include <cstring> // For memcpy
#include <vector>

#include "yacl/base/byte_container_view.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "zkp/bulletproofs/util.h" // For helpers


namespace examples::zkp {

// --- LinearCombination Implementation ---

LinearCombination::LinearCombination(Variable var) {
    terms.emplace_back(var, yacl::math::MPInt(1));
}

LinearCombination::LinearCombination(const yacl::math::MPInt& scalar) {
    // Optimization: Don't add if scalar is zero
    if (!scalar.IsZero()) {
        terms.emplace_back(kOneVariable, scalar);
    }
}

LinearCombination::LinearCombination(int64_t scalar_int) {
     yacl::math::MPInt scalar(scalar_int);
     if (!scalar.IsZero()) {
         terms.emplace_back(kOneVariable, std::move(scalar));
     }
}


void LinearCombination::Optimize(const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
    if (terms.size() <= 1) return;

    const auto& order = curve->GetOrder();
    // Use std::map which keeps keys sorted, automatically combining terms
    std::map<Variable, yacl::math::MPInt> combined_terms;

    for (const auto& term : terms) {
        // Ensure coefficient is reduced modulo order before adding
        yacl::math::MPInt current_coeff = term.second.Mod(order);
        auto it = combined_terms.find(term.first);
        if (it == combined_terms.end()) {
            // Only insert if non-zero
            if (!current_coeff.IsZero()) {
                combined_terms.emplace(term.first, std::move(current_coeff));
            }
        } else {
            it->second = it->second.AddMod(current_coeff, order);
            // Remove if sum becomes zero
            if (it->second.IsZero()) {
                combined_terms.erase(it);
            }
        }
    }

    terms.clear();
    terms.reserve(combined_terms.size());
    for (const auto& pair : combined_terms) {
        // Map iterator ensures we only have non-zero terms here
        terms.push_back(pair);
    }
}

LinearCombination& LinearCombination::operator+=(const LinearCombination& other) {
    terms.insert(terms.end(), other.terms.begin(), other.terms.end());
    // Optimization could be called here if desired
    return *this;
}
LinearCombination& LinearCombination::operator+=(const Variable& var) {
     terms.emplace_back(var, yacl::math::MPInt(1));
     return *this;
}
LinearCombination& LinearCombination::operator+=(const yacl::math::MPInt& scalar) {
    if (!scalar.IsZero()) {
        terms.emplace_back(kOneVariable, scalar);
    }
    return *this;
}


LinearCombination& LinearCombination::operator-=(const LinearCombination& other) {
     for(const auto& term : other.terms) {
         // Assume MPInt has NegateMod or implement as order - val
         yacl::math::MPInt neg_coeff = yacl::math::MPInt(0).SubMod(term.second, curve->GetOrder()); // Need curve->GetOrder()
         // If NegateMod needs order:
         // yacl::math::MPInt neg_coeff = term.second.NegateMod(curve->GetOrder());
         // Or manually:
         // yacl::math::MPInt neg_coeff = curve->GetOrder().SubMod(term.second, curve->GetOrder());
         terms.emplace_back(term.first, std::move(neg_coeff));
     }
     return *this;
}
LinearCombination& LinearCombination::operator-=(const Variable& var) {
     terms.emplace_back(var, yacl::math::MPInt(-1)); // Add -1 coefficient
     return *this;
}
LinearCombination& LinearCombination::operator-=(const yacl::math::MPInt& scalar) {
     if (!scalar.IsZero()) {
         terms.emplace_back(kOneVariable, yacl::math::MPInt(0).SubMod(scalar, curve->GetOrder())); // Need curve context for order
     }
     return *this;
}

LinearCombination LinearCombination::operator+(const LinearCombination& other) const {
    LinearCombination result = *this;
    result += other;
    return result;
}
LinearCombination LinearCombination::operator+(const Variable& var) const {
    LinearCombination result = *this;
    result += var;
    return result;
}
LinearCombination LinearCombination::operator+(const yacl::math::MPInt& scalar) const {
     LinearCombination result = *this;
     result += scalar;
     return result;
}


LinearCombination LinearCombination::operator-(const LinearCombination& other) const {
     LinearCombination result = *this;
     result -= other;
     return result;
}
LinearCombination LinearCombination::operator-(const Variable& var) const {
    LinearCombination result = *this;
    result -= var;
    return result;
}
LinearCombination LinearCombination::operator-(const yacl::math::MPInt& scalar) const {
     LinearCombination result = *this;
     result -= scalar;
     return result;
}

LinearCombination LinearCombination::operator-() const { // Negation
    LinearCombination result;
    result.terms.reserve(terms.size());
     for(const auto& term : terms) {
         // Need curve context if NegateMod requires it
         yacl::math::MPInt neg_coeff = yacl::math::MPInt(0).SubMod(term.second, curve->GetOrder());
         result.terms.emplace_back(term.first, std::move(neg_coeff));
     }
     return result;
}

LinearCombination LinearCombination::operator*(const yacl::math::MPInt& scalar) const {
    LinearCombination result;
    result.terms.reserve(terms.size());
    // Need curve context for order if scalar can be >= order
    // const auto& order = curve->GetOrder();
    for(const auto& term : terms) {
        yacl::math::MPInt new_coeff = term.second.MulMod(scalar, curve->GetOrder()); // Need order
        if (!new_coeff.IsZero()) { // Don't add zero terms
             result.terms.emplace_back(term.first, std::move(new_coeff));
        }
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
LinearCombination operator*(const Variable& var, const yacl::math::MPInt& scalar) {
     return LinearCombination(var) * scalar;
}


// --- R1CSProof Implementation ---

constexpr uint8_t ONE_PHASE_COMMITMENTS_TAG = 0;
constexpr uint8_t TWO_PHASE_COMMITMENTS_TAG = 1;

R1CSProof::R1CSProof(
    const bool& has_phase2, const yacl::crypto::EcPoint& ai1, const yacl::crypto::EcPoint& ao1, const yacl::crypto::EcPoint& s1,
    const yacl::crypto::EcPoint& ai2, const yacl::crypto::EcPoint& ao2, const yacl::crypto::EcPoint& s2,
    const yacl::crypto::EcPoint& t1, const yacl::crypto::EcPoint& t3, const yacl::crypto::EcPoint& t4,
    const yacl::crypto::EcPoint& t5, const yacl::crypto::EcPoint& t6,
    const yacl::math::MPInt& tx, const yacl::math::MPInt& tx_b, const yacl::math::MPInt& e_b,
    InnerProductProof ipp)
    : has_phase2(has_phase2), A_I1(ai1), A_O1(ao1), S1(s1),
      A_I2(ai2), A_O2(ao2), S2(s2),
      T_1(t1), T_3(t3), T_4(t4), T_5(t5), T_6(t6),
      t_x(tx), t_x_blinding(tx_b), e_blinding(e_b),
      ipp_proof(std::move(ipp)) {} // Assume IPP is movable


bool R1CSProof::MissingPhase2Commitments(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
    // Check if phase 2 commitments are identity
    return curve->IsInfinity(A_I2) && curve->IsInfinity(A_O2) && curve->IsInfinity(S2);
}

yacl::Buffer R1CSProof::ToBytes(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
    bool missing_phase2 = MissingPhase2Commitments(curve);
    size_t ipp_bytes_size = ipp_proof.SerializedSize(); // Needs IPP implementation

    // Use fixed sizes matching Rust (assuming 32-byte compressed points/scalars)
    // Requires YACL to support fixed-size serialization or manual conversion.
    // Using variable size with prefix for now as it's simpler with current YACL Buffer.
    // This WILL NOT match Rust byte-for-byte.
    // Reverting to variable size serialization:
    yacl::Buffer ai1_b = curve->SerializePoint(A_I1);
    yacl::Buffer ao1_b = curve->SerializePoint(A_O1);
    yacl::Buffer s1_b = curve->SerializePoint(S1);
    yacl::Buffer ai2_b, ao2_b, s2_b;
     if (!missing_phase2) {
        ai2_b = curve->SerializePoint(A_I2);
        ao2_b = curve->SerializePoint(A_O2);
        s2_b = curve->SerializePoint(S2);
    }
    yacl::Buffer t1_b = curve->SerializePoint(T_1);
    yacl::Buffer t3_b = curve->SerializePoint(T_3);
    yacl::Buffer t4_b = curve->SerializePoint(T_4);
    yacl::Buffer t5_b = curve->SerializePoint(T_5);
    yacl::Buffer t6_b = curve->SerializePoint(T_6);
    yacl::Buffer tx_b = t_x.Serialize();
    yacl::Buffer tx_blinding_b = t_x_blinding.Serialize();
    yacl::Buffer e_blinding_b = e_blinding.Serialize();
    yacl::Buffer ipp_b = ipp_proof.ToBytes(curve); // Assumes IPP has ToBytes

    size_t num_items = 1 + (missing_phase2 ? 11 : 14) + 1; // Version + points/scalars + IPP
    size_t header_size = num_items * sizeof(size_t); // Size prefix for each item

    size_t total_data_size = ai1_b.size() + ao1_b.size() + s1_b.size() +
                          (!missing_phase2 ? (ai2_b.size() + ao2_b.size() + s2_b.size()) : 0) +
                          t1_b.size() + t3_b.size() + t4_b.size() + t5_b.size() + t6_b.size() +
                          tx_b.size() + tx_blinding_b.size() + e_blinding_b.size() +
                          ipp_b.size();

    yacl::Buffer buf(1 + header_size + total_data_size); // 1 for version byte
    char* ptr = buf.data<char>();

    // Write version byte
    *ptr++ = missing_phase2 ? ONE_PHASE_COMMITMENTS_TAG : TWO_PHASE_COMMITMENTS_TAG;

    auto write_sized_data = [&](const yacl::Buffer& data) {
        size_t size = data.size();
        std::memcpy(ptr, &size, sizeof(size_t));
        ptr += sizeof(size_t);
        std::memcpy(ptr, data.data(), size);
        ptr += size;
    };

    write_sized_data(ai1_b); write_sized_data(ao1_b); write_sized_data(s1_b);
    if(!missing_phase2) {
        write_sized_data(ai2_b); write_sized_data(ao2_b); write_sized_data(s2_b);
    }
    write_sized_data(t1_b); write_sized_data(t3_b); write_sized_data(t4_b);
    write_sized_data(t5_b); write_sized_data(t6_b);
    write_sized_data(tx_b); write_sized_data(tx_blinding_b); write_sized_data(e_blinding_b);
    write_sized_data(ipp_b); // Write IPP last

    YACL_ENFORCE(ptr == buf.data<char>() + buf.size(), "R1CSProof Serialization size mismatch");
    return buf;
}


R1CSProof R1CSProof::FromBytes(const yacl::ByteContainerView& bytes,
                              const std::shared_ptr<yacl::crypto::EcGroup>& curve) {
    YACL_ENFORCE(bytes.size() > 0, "R1CSProof FromBytes: Empty input");
    const char* ptr = reinterpret_cast<const char*>(bytes.data());
    const char* end = ptr + bytes.size();

    // Read version byte
    uint8_t version = *ptr++;
    YACL_ENFORCE(version == ONE_PHASE_COMMITMENTS_TAG || version == TWO_PHASE_COMMITMENTS_TAG,
                 "R1CSProof FromBytes: Invalid version byte");
    bool missing_phase2 = (version == ONE_PHASE_COMMITMENTS_TAG);

    // Helper to read size-prefixed data
    auto read_data = [&](const char* name) -> yacl::ByteContainerView {
         if (ptr + sizeof(size_t) > end) {
            throw yacl::Exception(fmt::format("R1CS FromBytes: Not enough data to read size of {}", name));
        }
        size_t size;
        std::memcpy(&size, ptr, sizeof(size_t));
        ptr += sizeof(size_t);
        if (ptr + size > end) {
            throw yacl::Exception(fmt::format("R1CS FromBytes: Not enough data to read {}", name));
        }
        yacl::ByteContainerView data(ptr, size);
        ptr += size;
        return data;
    };

    // Read commitments
    auto A_I1 = curve->DeserializePoint(read_data("A_I1"));
    auto A_O1 = curve->DeserializePoint(read_data("A_O1"));
    auto S1 = curve->DeserializePoint(read_data("S1"));
    yacl::crypto::EcPoint A_I2, A_O2, S2;
    if (!missing_phase2) {
        A_I2 = curve->DeserializePoint(read_data("A_I2"));
        A_O2 = curve->DeserializePoint(read_data("A_O2"));
        S2 = curve->DeserializePoint(read_data("S2"));
    } else {
        A_I2 = curve->MulBase(yacl::math::MPInt(0)); // Identity
        A_O2 = curve->MulBase(yacl::math::MPInt(0));
        S2 = curve->MulBase(yacl::math::MPInt(0));
    }
    auto T_1 = curve->DeserializePoint(read_data("T_1"));
    auto T_3 = curve->DeserializePoint(read_data("T_3"));
    auto T_4 = curve->DeserializePoint(read_data("T_4"));
    auto T_5 = curve->DeserializePoint(read_data("T_5"));
    auto T_6 = curve->DeserializePoint(read_data("T_6"));

    // Read scalars
    yacl::math::MPInt t_x, t_x_blinding, e_blinding;
    t_x.Deserialize(read_data("t_x"));
    t_x_blinding.Deserialize(read_data("t_x_blinding"));
    e_blinding.Deserialize(read_data("e_blinding"));

    // Read IPP (The rest of the buffer)
    InnerProductProof ipp_proof = InnerProductProof::FromBytes(read_data("ipp_proof"), curve);

    return R1CSProof(!missing_phase2, A_I1, A_O1, S1, A_I2, A_O2, S2, T_1, T_3, T_4, T_5, T_6,
                     t_x, t_x_blinding, e_blinding, std::move(ipp_proof));
}

size_t R1CSProof::SerializedSize(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const {
    // Requires calling ToBytes to get exact size due to variable-length serialization
    // This is inefficient. A fixed-size serialization matching Rust would be better.
    // For now, estimate or calculate based on actual components.
    return ToBytes(curve).size(); // Simple but less efficient way
}


} // namespace examples::zkp
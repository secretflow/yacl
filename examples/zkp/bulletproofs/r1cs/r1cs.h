#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <utility>      // For std::pair
#include <functional>   // For std::function
#include <variant>      // Can be used for Variable if preferred
#include <optional>     // For std::optional
#include <map>          // For LC optimization

#include "yacl/base/exception.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"

#include "zkp/bulletproofs/simple_transcript.h"
#include "zkp/bulletproofs/ipa/inner_product_proof.h"

namespace examples::zkp {

// Forward Declarations
class PedersenGens;
class BulletproofGens;
class R1CSProof;
class Prover;
class Verifier;
class RandomizingProver; // Need forward declarations for callbacks
class RandomizingVerifier;

// --- R1CS Error (Simple Exception for now) ---
// Define a specific error class if needed, inheriting from yacl::Exception
// using R1CSError = yacl::Exception; // Example alias

// --- Metrics ---
struct R1CSMetrics {
    size_t multipliers = 0;
    size_t constraints = 0;
    size_t phase_one_constraints = 0;
    size_t phase_two_constraints = 0;
};

// --- Variable ---
enum class VariableType {
    Committed,
    MultiplierLeft,
    MultiplierRight,
    MultiplierOutput,
    One
};

struct Variable {
    VariableType type = VariableType::One;
    size_t index = 0;

    Variable() = default; // Default constructor needed
    Variable(VariableType t, size_t idx) : type(t), index(idx) {}

    bool operator==(const Variable& other) const {
        return type == other.type && index == other.index;
    }
    bool operator<(const Variable& other) const {
        if (type != other.type) {
            // Provide a consistent ordering for map keys
            return static_cast<int>(type) < static_cast<int>(other.type);
        }
        return index < other.index;
    }
};

const Variable kOneVariable = Variable();

// --- LinearCombination ---
class LinearCombination {
public:
    std::vector<std::pair<Variable, yacl::math::MPInt>> terms;
    std::shared_ptr<yacl::crypto::EcGroup> curve;

    LinearCombination() = default;
    LinearCombination(std::shared_ptr<yacl::crypto::EcGroup> curve) : curve(curve) {}
    // Implicit constructors can be useful here
    /* implicit */ LinearCombination(Variable var);
    /* implicit */ LinearCombination(const yacl::math::MPInt& scalar);
    /* implicit */ LinearCombination(int64_t scalar_int);

    // Combine terms with the same variable
    void Optimize(const std::shared_ptr<yacl::crypto::EcGroup>& curve);

    // Operators
    LinearCombination& operator+=(const LinearCombination& other);
    LinearCombination& operator+=(const Variable& var);
    LinearCombination& operator+=(const yacl::math::MPInt& scalar);

    LinearCombination& operator-=(const LinearCombination& other);
    LinearCombination& operator-=(const Variable& var);
    LinearCombination& operator-=(const yacl::math::MPInt& scalar);

    LinearCombination operator+(const LinearCombination& other) const;
    LinearCombination operator+(const Variable& var) const;
    LinearCombination operator+(const yacl::math::MPInt& scalar) const;

    LinearCombination operator-(const LinearCombination& other) const;
    LinearCombination operator-(const Variable& var) const;
    LinearCombination operator-(const yacl::math::MPInt& scalar) const;

    LinearCombination operator-() const;

    LinearCombination operator*(const yacl::math::MPInt& scalar) const;

    // Friend operators
    friend LinearCombination operator+(const yacl::math::MPInt& scalar, const LinearCombination& lc);
    friend LinearCombination operator+(const Variable& var, const yacl::math::MPInt& scalar);
    friend LinearCombination operator-(const yacl::math::MPInt& scalar, const LinearCombination& lc);
    friend LinearCombination operator-(const Variable& var, const yacl::math::MPInt& scalar);
    friend LinearCombination operator*(const yacl::math::MPInt& scalar, const LinearCombination& lc);
    friend LinearCombination operator*(const yacl::math::MPInt& scalar, const Variable& var);
    friend LinearCombination operator*(const Variable& var, const yacl::math::MPInt& scalar);

};


// --- R1CS Proof ---
class R1CSProof {
 public:
    // Phase indicator stored implicitly by checking identity
    // bool has_phase2_commitments = false; // No explicit field needed

    // Commitments (using EcPoint, assume consistent serialization)
    bool has_phase2;
    yacl::crypto::EcPoint A_I1;
    yacl::crypto::EcPoint A_O1;
    yacl::crypto::EcPoint S1;
    yacl::crypto::EcPoint A_I2;
    yacl::crypto::EcPoint A_O2;
    yacl::crypto::EcPoint S2;
    yacl::crypto::EcPoint T_1;
    yacl::crypto::EcPoint T_3;
    yacl::crypto::EcPoint T_4;
    yacl::crypto::EcPoint T_5;
    yacl::crypto::EcPoint T_6;

    // Scalars
    yacl::math::MPInt t_x;
    yacl::math::MPInt t_x_blinding;
    yacl::math::MPInt e_blinding;

    // Inner Product Proof
    InnerProductProof ipp_proof;

    // Default constructor
    R1CSProof() = default;

    // Constructor
    R1CSProof(const bool& has_phase2, const yacl::crypto::EcPoint& ai1, const yacl::crypto::EcPoint& ao1, const yacl::crypto::EcPoint& s1,
              const yacl::crypto::EcPoint& ai2, const yacl::crypto::EcPoint& ao2, const yacl::crypto::EcPoint& s2,
              const yacl::crypto::EcPoint& t1, const yacl::crypto::EcPoint& t3, const yacl::crypto::EcPoint& t4,
              const yacl::crypto::EcPoint& t5, const yacl::crypto::EcPoint& t6,
              const yacl::math::MPInt& tx, const yacl::math::MPInt& tx_b, const yacl::math::MPInt& e_b,
              InnerProductProof ipp);


    // Serialization
    yacl::Buffer ToBytes(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const;
    static R1CSProof FromBytes(const yacl::ByteContainerView& bytes,
                               const std::shared_ptr<yacl::crypto::EcGroup>& curve);
    size_t SerializedSize(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const;

private:
    bool MissingPhase2Commitments(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const;
};


} // namespace examples::zkp
#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <utility> // For std::pair
#include <functional> // For std::function
#include <variant> // Can be used for Variable if preferred

#include "yacl/base/exception.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"

#include "zkp/bulletproofs/simple_transcript.h"
#include "zkp/bulletproofs/inner_product_proof.h"

namespace examples::zkp {

// Forward Declarations
class PedersenGens;
class BulletproofGens;
class R1CSProof;
class Prover;
class Verifier;

// --- Metrics ---
// Matches  ::r1cs::Metrics
struct R1CSMetrics {
    size_t multipliers = 0;
    size_t constraints = 0;
    size_t phase_one_constraints = 0;
    size_t phase_two_constraints = 0;
};

// --- Variable ---
// Matches  ::r1cs::Variable
enum class VariableType {
    Committed,
    MultiplierLeft,
    MultiplierRight,
    MultiplierOutput,
    One // Represents the constant 1 scalar
};

struct Variable {
    VariableType type = VariableType::One; // Default to One? Or make invalid?
    size_t index = 0; // Index for Committed/Multiplier types

    // Constructor for Constant One
    Variable() : type(VariableType::One), index(0) {}
    // Constructor for other types
    Variable(VariableType t, size_t idx) : type(t), index(idx) {}

    // Add equality operator for use in maps or comparisons
    bool operator==(const Variable& other) const {
        return type == other.type && index == other.index;
    }
     // Add less than operator for use in maps
    bool operator<(const Variable& other) const {
        if (type != other.type) {
            return type < other.type;
        }
        return index < other.index;
    }
};

// Special constant variable for One
const Variable kOneVariable = Variable();


// --- LinearCombination ---
// Matches  ::r1cs::LinearCombination
class LinearCombination {
public:
    std::vector<std::pair<Variable, yacl::math::MPInt>> terms;

    LinearCombination() = default;
    explicit LinearCombination(Variable var); // From Variable
    explicit LinearCombination(const yacl::math::MPInt& scalar); // From Scalar -> scalar * One
    explicit LinearCombination(int64_t scalar_int); // From integer

    // Combine terms with the same variable
    // Optional: Call this periodically or at the end to simplify
    void Optimize(const std::shared_ptr<yacl::crypto::EcGroup>& curve);

    // --- Operator Overloads ---
    LinearCombination operator+(const LinearCombination& other) const;
    LinearCombination operator+(const Variable& var) const;
    LinearCombination operator+(const yacl::math::MPInt& scalar) const;

    LinearCombination operator-(const LinearCombination& other) const;
    LinearCombination operator-(const Variable& var) const;
    LinearCombination operator-(const yacl::math::MPInt& scalar) const;

    LinearCombination operator-() const; // Negation

    LinearCombination operator*(const yacl::math::MPInt& scalar) const;

    // Friend functions for scalar * LC and variable arithmetic
    friend LinearCombination operator+(const yacl::math::MPInt& scalar, const LinearCombination& lc);
    friend LinearCombination operator+(const Variable& var, const yacl::math::MPInt& scalar);

    friend LinearCombination operator-(const yacl::math::MPInt& scalar, const LinearCombination& lc);
    friend LinearCombination operator-(const Variable& var, const yacl::math::MPInt& scalar);

    friend LinearCombination operator*(const yacl::math::MPInt& scalar, const LinearCombination& lc);
    friend LinearCombination operator*(const yacl::math::MPInt& scalar, const Variable& var);
};


// --- R1CS Proof ---
// Matches  ::r1cs::R1CSProof
class R1CSProof {
 public:
    // Phase indicator (instead of Option types)
    bool has_phase2_commitments = false;

    // Commitments
    yacl::crypto::EcPoint A_I1; // Using EcPoint, assuming deserialization handles format
    yacl::crypto::EcPoint A_O1;
    yacl::crypto::EcPoint S1;
    yacl::crypto::EcPoint A_I2; // Will be identity if no phase 2
    yacl::crypto::EcPoint A_O2; // Will be identity if no phase 2
    yacl::crypto::EcPoint S2;   // Will be identity if no phase 2
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
    R1CSProof(bool phase2,
              const yacl::crypto::EcPoint& ai1, const yacl::crypto::EcPoint& ao1, const yacl::crypto::EcPoint& s1,
              const yacl::crypto::EcPoint& ai2, const yacl::crypto::EcPoint& ao2, const yacl::crypto::EcPoint& s2,
              const yacl::crypto::EcPoint& t1, const yacl::crypto::EcPoint& t3, const yacl::crypto::EcPoint& t4,
              const yacl::crypto::EcPoint& t5, const yacl::crypto::EcPoint& t6,
              const yacl::math::MPInt& tx, const yacl::math::MPInt& tx_b, const yacl::math::MPInt& e_b,
              InnerProductProof ipp);


    // Serialization
    yacl::Buffer ToBytes(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const;
    static R1CSProof FromBytes(const yacl::ByteContainerView& bytes,
                               const std::shared_ptr<yacl::crypto::EcGroup>& curve);
    size_t SerializedSize(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const; // Estimate or calculate exact

private:
    bool MissingPhase2Commitments(const std::shared_ptr<yacl::crypto::EcGroup>& curve) const;
};


// --- Constraint System Interface (Conceptual - implemented by Prover/Verifier) ---
// We won't define a pure virtual base class, but Prover/Verifier will implement these methods.
/*
class ConstraintSystem {
public:
    virtual ~ConstraintSystem() = default;
    virtual SimpleTranscript& Transcript() = 0;
    virtual std::tuple<Variable, Variable, Variable> Multiply(LinearCombination left, LinearCombination right) = 0;
    virtual Variable Allocate(const std::optional<yacl::math::MPInt>& assignment) = 0; // Use std::optional
    virtual std::tuple<Variable, Variable, Variable> AllocateMultiplier(const std::optional<std::pair<yacl::math::MPInt, yacl::math::MPInt>>& input_assignments) = 0;
    virtual R1CSMetrics GetMetrics() const = 0;
    virtual void Constrain(LinearCombination lc) = 0;
    // Randomization handled internally or via specific methods
};
*/

} // namespace examples::zkp
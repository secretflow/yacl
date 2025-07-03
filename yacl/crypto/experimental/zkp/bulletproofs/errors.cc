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


#include "yacl/crypto/experimental/zkp/bulletproofs/errors.h"

namespace examples::zkp {

// ProofError implementation
std::string ProofError::GetErrorMessage(Code type, const std::string& msg) {
    switch (type) {
        case Code::VerificationError: return "Proof verification failed.";
        case Code::FormatError: return "Proof data could not be parsed: " + msg;
        case Code::WrongNumBlindingFactors: return "Wrong number of blinding factors supplied.";
        case Code::InvalidBitsize: return "Invalid bitsize, must have n = 8,16,32,64.";
        case Code::InvalidAggregation: return "Invalid aggregation size, m must be a power of 2.";
        case Code::InvalidGeneratorsLength: return "Invalid generators size, too few generators for proof";
        case Code::InvalidInputLength: return "Invalid input size, incorrect input length for proof";
        case Code::ProvingError: return "Internal error during proof creation: " + msg;
        case Code::WrongNumBitCommitments: return "Wrong number of bit commitments.";
        case Code::WrongNumPolyCommitments: return "Wrong number of poly commitments.";
        case Code::WrongNumProofShares: return "Wrong number of proof shares.";
        case Code::MalformedProofShares: return "Malformed proof shares from parties: " + msg;
        case Code::MaliciousDealer: return "Dealer gave a malicious challenge value.";
    }
    return "Unknown proof error";
}

// MPCError implementation
std::string MPCError::GetErrorMessage(Code type, const std::string& msg) {
    switch (type) {
        case Code::MaliciousDealer: return "Dealer gave a malicious challenge value.";
        case Code::InvalidBitsize: return "Invalid bitsize, must have n = 8,16,32,64";
        case Code::InvalidAggregation: return "Invalid aggregation size, m must be a power of 2";
        case Code::InvalidGeneratorsLength: return "Invalid generators size, too few generators for proof";
        case Code::WrongNumBitCommitments: return "Wrong number of value commitments";
        case Code::WrongNumPolyCommitments: return "Wrong number of poly commitments";
        case Code::WrongNumProofShares: return "Wrong number of proof shares";
        case Code::MalformedProofShares: return "Malformed proof shares from parties: " + msg;
    }
    return "Unknown MPC error";
}

// R1CSError implementation
std::string R1CSError::GetErrorMessage(Code type, const std::string& msg) {
    switch (type) {
        case Code::InvalidGeneratorsLength: return "Invalid generators size, too few generators for proof";
        case Code::FormatError: return "R1CSProof data could not be parsed.";
        case Code::VerificationError: return "R1CSProof did not verify correctly.";
        case Code::MissingAssignment: return "Variable does not have a value assignment.";
        case Code::GadgetError: return "Gadget error: " + msg;
        case Code::NotImplemented: return "Functionality not implemented: " + msg;
    }
    return "Unknown R1CS error";
}

// Conversion constructors
ProofError::ProofError(const MPCError& mpc_error) : ProofError(Code::ProvingError, mpc_error.what()) {}

R1CSError::R1CSError(const ProofError& proof_error) : R1CSError(Code::VerificationError, proof_error.what()) {
    switch (proof_error.GetCode()) {
        case ProofError::Code::InvalidGeneratorsLength: code_ = Code::InvalidGeneratorsLength; break;
        case ProofError::Code::FormatError: code_ = Code::FormatError; break;
        case ProofError::Code::VerificationError: code_ = Code::VerificationError; break;
        default:
            // Other proof errors are considered internal verification errors in R1CS context
            break;
    }
}

} // namespace examples::zkp
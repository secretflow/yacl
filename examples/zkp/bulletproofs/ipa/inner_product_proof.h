// Copyright 2023 Ant Group Co., Ltd.
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

#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "zkp/bulletproofs/simple_transcript.h"

#include "yacl/base/exception.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/math/mpint/mp_int.h"

namespace examples::zkp {

/**
 * @brief Error codes for Inner Product Proof
 */
enum class ProofError { VerificationError, FormatError };

/**
 * @brief Inner Product Proof
 *
 * This is a proof of knowledge of vectors a and b such that:
 * P = <a,G> + <b,H> + <a,b>Q
 * where G and H are vectors of points, and Q is a point.
 */
class InnerProductProof {
 public:
  /**
   * @brief Default constructor
   */
  InnerProductProof() = default;

  /**
   * @brief Constructor with all parameters
   *
   * @param L_vec Vector of L points
   * @param R_vec Vector of R points
   * @param a Final a value
   * @param b Final b value
   */
  InnerProductProof(std::vector<yacl::crypto::EcPoint> L_vec,
                    std::vector<yacl::crypto::EcPoint> R_vec,
                    yacl::math::MPInt a, yacl::math::MPInt b)
      : L_vec_(std::move(L_vec)),
        R_vec_(std::move(R_vec)),
        a_(std::move(a)),
        b_(std::move(b)) {}

  /**
   * @brief Creates an inner product proof
   *
   * @param transcript The transcript to append the proof to
   * @param curve The elliptic curve to use
   * @param Q The point Q
   * @param G_factors Scalar factors for G points
   * @param H_factors Scalar factors for H points
   * @param G_vec Vector of G points
   * @param H_vec Vector of H points
   * @param a_vec Vector a
   * @param b_vec Vector b
   * @return InnerProductProof The generated proof
   */
  static InnerProductProof Create(
      SimpleTranscript* transcript,
      const std::shared_ptr<yacl::crypto::EcGroup>& curve,
      const yacl::crypto::EcPoint& Q,
      const std::vector<yacl::math::MPInt>& G_factors,
      const std::vector<yacl::math::MPInt>& H_factors,
      std::vector<yacl::crypto::EcPoint> G_vec,
      std::vector<yacl::crypto::EcPoint> H_vec,
      std::vector<yacl::math::MPInt> a_vec,
      std::vector<yacl::math::MPInt> b_vec);

  /**
   * @brief Computes verification scalars for combined multiscalar
   * multiplication
   *
   * @param n Length of the vectors in the original proof
   * @param transcript The transcript to read challenges from
   * @param curve The elliptic curve to use
   * @return std::tuple<...> (challenges_sq, challenges_inv_sq, s)
   */
  std::tuple<std::vector<yacl::math::MPInt>, std::vector<yacl::math::MPInt>,
             std::vector<yacl::math::MPInt>>
  VerificationScalars(
      size_t n, SimpleTranscript* transcript,
      const std::shared_ptr<yacl::crypto::EcGroup>& curve) const;

  /**
   * @brief Verifies the inner product proof
   *
   * @param n Length of the vectors
   * @param transcript The transcript to read challenges from
   * @param curve The elliptic curve to use
   * @param G_factors Scalar factors for G points
   * @param H_factors Scalar factors for H points
   * @param P The commitment P = <a,G> + <b,H> + <a,b>Q
   * @param Q The point Q
   * @param G Vector of G points
   * @param H Vector of H points
   * @return true if the proof verifies, false otherwise
   */
  bool Verify(SimpleTranscript* transcript,
              const std::shared_ptr<yacl::crypto::EcGroup>& curve,
              const std::vector<yacl::math::MPInt>& G_factors,
              const std::vector<yacl::math::MPInt>& H_factors,
              const yacl::crypto::EcPoint& P, const yacl::crypto::EcPoint& Q,
              const std::vector<yacl::crypto::EcPoint>& G,
              const std::vector<yacl::crypto::EcPoint>& H) const;

  /**
   * @brief Returns the size in bytes required to serialize the proof
   *
   * @return size_t The size in bytes
   */
  size_t SerializedSize() const;

  /**
   * @brief Serializes the proof into a byte vector
   *
   * @param curve The elliptic curve to use for point serialization
   * @return std::vector<uint8_t> The serialized proof
   */
  yacl::Buffer ToBytes(
      const std::shared_ptr<yacl::crypto::EcGroup>& curve) const;

  /**
   * @brief Deserializes the proof from a byte array
   *
   * @param bytes The serialized proof
   * @param curve The elliptic curve to use for point deserialization
   * @return InnerProductProof The deserialized proof
   */
  static InnerProductProof FromBytes(
      const yacl::ByteContainerView& bytes,
      const std::shared_ptr<yacl::crypto::EcGroup>& curve);

  yacl::math::MPInt GetA() const { return a_; }
  yacl::math::MPInt GetB() const { return b_; }
  std::vector<yacl::crypto::EcPoint> GetLVec() const { return L_vec_; }
  std::vector<yacl::crypto::EcPoint> GetRVec() const { return R_vec_; }

 private:
  std::vector<yacl::crypto::EcPoint> L_vec_;
  std::vector<yacl::crypto::EcPoint> R_vec_;
  yacl::math::MPInt a_;
  yacl::math::MPInt b_;
};

/**
 * @brief Computes the inner product of two vectors
 *
 * @param a First vector
 * @param b Second vector
 * @return yacl::math::MPInt The inner product <a,b>
 */
yacl::math::MPInt InnerProduct(
    const std::vector<yacl::math::MPInt>& a,
    const std::vector<yacl::math::MPInt>& b,
    const std::shared_ptr<yacl::crypto::EcGroup>& curve);

/**
 * @brief Helper for optimized multi-scalar multiplication
 *
 * @param curve The elliptic curve
 * @param scalars Vector of scalar values
 * @param points Vector of points
 * @return yacl::crypto::EcPoint Result of the multiplication
 */
yacl::crypto::EcPoint MultiScalarMul(
    const std::shared_ptr<yacl::crypto::EcGroup>& curve,
    const std::vector<yacl::math::MPInt>& scalars,
    const std::vector<yacl::crypto::EcPoint>& points);

}  // namespace examples::zkp
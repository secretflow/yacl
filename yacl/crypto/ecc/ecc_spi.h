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

#include <ostream>
#include <string>
#include <utility>
#include <variant>

#include "yacl/base/byte_container_view.h"
#include "yacl/crypto/ecc/curve_meta.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/math/mpint/mp_int.h"
#include "yacl/utils/spi/spi_factory.h"

// ECC usage example:
//   auto curve = ::yacl::crypto::EcGroupFactory::Instance().Create("sm2");
// And now you can perform ecc operations using the 'curve' object.
namespace yacl::crypto {

using yacl::math::MPInt;

enum class HashToCurveStrategy {
  // Default strategy for HashToCurve(method)'s easy usage, dealing with the
  // scene that different libraries support different hash algorithms
  Autonomous,

  // https://eprint.iacr.org/2009/226.pdf
  // Auto select the most suitable algorithm:
  //  - SHA2: select between SHA-224, SHA-256, SHA-384, SHA-512
  //  - SHA3: select between SHA3-224, SHA3-256, SHA3-384, SHA3-512
  //  - SM: Current only support SM3.
  //  - BLAKE3: fast hash
  // Performance: This method is very fast, but it is susceptible to timing
  // attacks.
  TryAndIncrement_SHA2,
  TryAndIncrement_SHA3,
  TryAndIncrement_SM,
  TryAndIncrement_BLAKE3,

  // Just like TryAndIncrement, but use re-hash instead of increment when try
  // fails.
  TryAndRehash_SHA2,
  TryAndRehash_SHA3,
  TryAndRehash_SM,
  TryAndRehash_BLAKE3,

  // Directly output the hash value as the x-coordinate of the point without any
  // verification. And there is no y-coordinate info in output point.

  // The applicable scenarios of this scheme are very limited, and the following
  // requirements must be met:
  //  - The calculation of points on curve depends only on the x-coordinate
  //  - The usage scenario of the curve allows any hash value to be used as the
  //    initial point, even if the point is not on the curve.
  // It is currently known that this strategy can be safely used when curve is
  // Curve25519 and scene is ECDH. Do not choose this strategy for other
  // purpose.
  HashAsPointX_SHA2,
  HashAsPointX_SHA3,
  HashAsPointX_SM,  // Currently only support SM3
  HashAsPointX_BLAKE3,

  // Below is IRTF CFRG hash-to-curve standard (draft):
  // https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/

  // This strategy is a collection of the following methods, and SPI will
  // automatically select the applicable method according to different curves:
  //  - SHA-256_SSWU_NU_
  //  - SHA-384_SSWU_NU_
  //  - SHA-512_SSWU_NU_
  //  - SHA-512_ELL2_NU_
  //  - SHAKE256_ELL2_NU_
  // Performance: This strategy takes 6 times longer than TryAndIncrement on SM2
  // Warning: The output of this strategy is not uniformly distributed on the
  // elliptic curve G.
  EncodeToCurve,  // Not implemented, do not choose me

  // This strategy is a collection of the following methods, and SPI will
  // automatically select the applicable method according to different curves:
  //  - SHA-256_SSWU_RO_
  //  - SHA-384_SSWU_RO_
  //  - SHA-512_SSWU_RO_
  //  - SHA-512_ELL2_RO_
  //  - SHAKE256_ELL2_RO_
  // Performance: This strategy takes 12 times longer than TryAndIncrement on
  // SM2
  HashToCurve,  // Not implemented, do not choose me
};

// Base class of elliptic curve
// Each subclass can implement one or more curve group.
// Elliptic curves over finite field act as an abel group
class EcGroup {
 public:
  virtual ~EcGroup() = default;

  //================================//
  // Elliptic curve meta info query //
  //================================//

  virtual CurveName GetCurveName() const = 0;
  virtual CurveForm GetCurveForm() const = 0;
  virtual FieldType GetFieldType() const = 0;
  // Get the underlying elliptic curve lib name, e.g. openssl
  virtual std::string GetLibraryName() const = 0;

  // The h, cofactor.
  // Cofactor is the number of non-overlapping subgroups of points, which
  // together hold all curve points
  virtual MPInt GetCofactor() const = 0;

  // The field size of curve
  // returns the prime number (GFp) or the polynomial defining the underlying
  // field (GF2m)
  virtual MPInt GetField() const = 0;

  // The n, order of G, s.t. n < p
  // n is the order of the curve (the number of all its points)
  virtual MPInt GetOrder() const = 0;

  // The G, generator
  // Every elliptic curve defines a special pre-defined (constant) EC point
  // called generator point G (base point), which can generate any other point
  // in its subgroup over the elliptic curve by multiplying G by some integer.
  // When G and n are carefully selected, and the cofactor = 1, all possible EC
  // points on the curve (including the special point infinity) can be generated
  // from the generator G by multiplying it by integer in the range [1...n].
  virtual EcPoint GetGenerator() const = 0;

  // Because the fastest known algorithm to solve the ECDLP for key of size k
  // needs sqrt(k) steps, this means that to achieve a k-bit security strength,
  // at least 2*k-bit curve is needed. Thus, 256-bit elliptic curves (where the
  // field size p is 256-bit number) typically provide nearly 128-bit security
  // strength.
  // Warning: This function only returns an approximate security strength.
  // In fact, the actual strength is slightly less than the value returned by
  // GetSecurityStrength(), because the order of the curve (n) is typically less
  // than the fields size (p) and because the curve may have cofactor h > 1 and
  // because the number of steps is not exactly sqrt(k), but is 0.886*sqrt(k).
  // If you want to know the precise security strength, please check
  // http://safecurves.cr.yp.to/rho.html
  // For example, the secp256k1 curve returns 128-bit security, but real is
  // 127.8-bit and Curve25519 also returns 128-bit security, but real is
  // 125.8-bit.
  virtual size_t GetSecurityStrength() const = 0;

  virtual std::string ToString() const = 0;

  //================================//
  //   Elliptic curve computation   //
  //================================//

  // return p1 + p2
  virtual EcPoint Add(const EcPoint &p1, const EcPoint &p2) const = 0;
  virtual void AddInplace(EcPoint *p1, const EcPoint &p2) const = 0;

  // return p1 - p2
  virtual EcPoint Sub(const EcPoint &p1, const EcPoint &p2) const = 0;
  virtual void SubInplace(EcPoint *p1, const EcPoint &p2) const = 0;

  // return p * 2
  virtual EcPoint Double(const EcPoint &p) const = 0;
  virtual void DoubleInplace(EcPoint *p) const = 0;

  // three types of scalar multiplications:
  //
  // - Fixed-Base: when the input point of the scalar multiplication is known at
  // design time
  // - Variable-Base: when the input point of the scalar multiplication is not
  // known in advance
  // - Double-Base: when the protocol actually requires to compute two scalar
  // multiplications and then to add both results. (e.g. 𝑘𝑃+𝑟𝐵)
  // @param scalar: can be < 0
  virtual EcPoint Mul(const EcPoint &point, const MPInt &scalar) const = 0;
  virtual void MulInplace(EcPoint *point, const MPInt &scalar) const = 0;
  // Returns: scalar*G
  virtual EcPoint MulBase(const MPInt &scalar) const = 0;
  // Returns: s1*G + s2*p2
  virtual EcPoint MulDoubleBase(const MPInt &s1, const MPInt &s2,
                                const EcPoint &p2) const = 0;

  // Output: p / s = p * s^-1
  // Please note that not all scalars have inverses
  // An exception will be thrown if the inverse of s does not exist
  virtual EcPoint Div(const EcPoint &point, const MPInt &scalar) const = 0;
  virtual void DivInplace(EcPoint *point, const MPInt &scalar) const = 0;

  // Output: -p
  virtual EcPoint Negate(const EcPoint &point) const = 0;
  virtual void NegateInplace(EcPoint *point) const = 0;

  //================================//
  //     EcPoint helper tools       //
  //================================//

  // Copy and normalize an EcPoint
  // Usage:
  //  1. Make a deep copy of an EcPoint.
  //     > EcPoint ep2 = CopyPoint(ep1);
  //  2. Convert AffinePoint to EcPoint.
  //     > EcPoint ep = CopyPoint(AffinePoint(x, y));
  //     Note: If x, y is not in EC group, then an exception will throw.
  virtual EcPoint CopyPoint(const EcPoint &point) const = 0;

  // Return the byte length of serialized point (not infinity)
  virtual uint64_t GetSerializeLength(PointOctetFormat format) const = 0;
  uint64_t GetSerializeLength() const {
    return GetSerializeLength(PointOctetFormat::Autonomous);
  }

  // Compress and serialize a point
  virtual Buffer SerializePoint(const EcPoint &point,
                                PointOctetFormat format) const = 0;
  Buffer SerializePoint(const EcPoint &point) const {
    return SerializePoint(point, PointOctetFormat::Autonomous);
  }

  virtual void SerializePoint(const EcPoint &point, PointOctetFormat format,
                              Buffer *buf) const = 0;
  void SerializePoint(const EcPoint &point, Buffer *buf) const {
    SerializePoint(point, PointOctetFormat::Autonomous, buf);
  }

  // Serialize to a fixed buf [buf, buf + buf_size]
  virtual void SerializePoint(const EcPoint &point, PointOctetFormat format,
                              uint8_t *buf, uint64_t buf_size) const = 0;

  void SerializePoint(const EcPoint &point, uint8_t *buf,
                      uint64_t buf_size) const {
    return SerializePoint(point, PointOctetFormat::Autonomous, buf, buf_size);
  }

  // Load a point, the format MUST BE same with SerializePoint
  virtual EcPoint DeserializePoint(ByteContainerView buf,
                                   PointOctetFormat format) const = 0;
  EcPoint DeserializePoint(ByteContainerView buf) const {
    return DeserializePoint(buf, PointOctetFormat::Autonomous);
  }

  // Get a human-readable representation of elliptic curve point
  virtual AffinePoint GetAffinePoint(const EcPoint &point) const = 0;

  // Map a string to curve point
  //   Waring! Not all strategies are supported by libs, be care to choose a
  //   valid strategy for specific lib.
  virtual EcPoint HashToCurve(HashToCurveStrategy strategy,
                              std::string_view str) const = 0;
  EcPoint HashToCurve(std::string_view str) {
    // Autonomous strategy is lib's default strategy and will always be valid;
    return HashToCurve(HashToCurveStrategy::Autonomous, str);
  }

  // Get the hash code of EcPoint so that you can store EcPoint in STL
  // associative containers such as std::unordered_map, std::unordered_set, etc.
  // > https://en.cppreference.com/w/cpp/named_req/UnorderedAssociativeContainer
  //
  // Note: C++ specification requires the return type must be std::size_t
  // > https://en.cppreference.com/w/cpp/named_req/Hash
  //
  // Do not modify the value of the point in container, the following code is
  // very dangerous:
  // ``` C++
  // auto p = ec_->GetGenerator();
  // std::unordered_map<EcPoint, int, HashT, EqualT> points_map;
  // for (int i = 0; i < 10; ++i) {
  //   ec_->DoubleInplace(&p);
  //   points_map[p] = i;
  // }
  // ```
  virtual std::size_t HashPoint(const EcPoint &point) const = 0;

  // Check p1 & p2 are equal
  // It is not recommended to directly compare the buffer of EcPoint using
  // "p1 == p2" since EcPoint is a black box, same point may have multiple
  // representations.
  virtual bool PointEqual(const EcPoint &p1, const EcPoint &p2) const = 0;

  // Is point on this curve
  // Every override function in subclass must support EcPoint<AffinePoint>
  // representation.
  virtual bool IsInCurveGroup(const EcPoint &point) const = 0;

  // Is the point at infinity
  virtual bool IsInfinity(const EcPoint &point) const = 0;
};

// Give curve meta, return curve instance.
using EcCreatorT = std::function<std::unique_ptr<EcGroup>(const CurveMeta &)>;
// Give curve meta, return whether curve is supported by this lib.
// True is supported and false is unsupported.
using EcCheckerT = std::function<bool(const CurveMeta &)>;

class EcGroupFactory final : public SpiFactoryBase<EcGroup> {
 public:
  static EcGroupFactory &Instance();

  /// Register an elliptic curve library
  /// \param lib_name library name, e.g. openssl
  /// \param performance the estimated performance of this lib, bigger is
  /// better
  void Register(const std::string &lib_name, uint64_t performance,
                const EcCheckerT &checker, const EcCreatorT &creator);
};

// Please run bazel run
//   > yacl/crypto/ecc/benchmark -c opt -- --curve CURVE_NAME
// to test your lib's performance.
// We assume that the performance of OpenSSL is 100, if your library is better
// than OpenSSL, please increase the 'performance' value.
#define REGISTER_EC_LIBRARY(lib_name, performance, checker, creator)          \
  REGISTER_SPI_LIBRARY_HELPER(EcGroupFactory, lib_name, performance, checker, \
                              creator)

}  // namespace yacl::crypto

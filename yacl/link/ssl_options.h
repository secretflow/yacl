// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <string>

#include "yacl/link/link.pb.h"

namespace yacl::link {

struct CertInfo {
  // Certificate file path
  std::string certificate_path;

  // Private key file path
  std::string private_key_path;
};

struct VerifyOptions {
  // Set the maximum depth of the certificate chain for verification
  // If 0, turn off the verification
  // Default: 0
  int verify_depth{0};

  // Set the trusted CA file to verify the peer's certificate
  // If empty, use the system default CA files
  std::string ca_file_path;
};

struct SSLOptions {
  // Certificate used for authentication
  CertInfo cert;

  // Options used to verify the peer's certificate
  VerifyOptions verify;

  SSLOptions() = default;

  SSLOptions(const SSLOptionsProto& pb) {
    cert.certificate_path = pb.certificate_path();
    cert.private_key_path = pb.private_key_path();

    verify.verify_depth = pb.verify_depth();
    verify.ca_file_path = pb.ca_file_path();
  }
};

}  // namespace yacl::link

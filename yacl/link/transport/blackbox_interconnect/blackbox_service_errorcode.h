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

#include <mutex>
#include <string_view>
#include <unordered_map>

namespace blackbox_interconnect::error_code {

const static std::unordered_map<std::string_view, std::string_view>
    desc_to_code = {
        {"OK", "E0000000000"},
        {"ResourceNotFound", "E0000000404"},
        {"SystemError", "E0000000500"},
        {"ServiceUnreachable", "E0000000503"},
        {"BadRequest", "E0000000400"},
        {"ResourceForbidden", "E0000000403"},
        {"UnknownError", "E0000000520"},
        {"SystemIncompatibale", "E0000000600"},
        {"RequestTimeout", "E0000000601"},
        {"NoServiceInstance", "E0000000602"},
        {"CertificateException", "E0000000603"},
        {"TokenExpired", "E0000000604"},
        {"NodeNetExpired", "E0000000605"},
        {"PeerNetworkForbidden", "E0000000606"},
        {"NetworkError", "E0000000607"},
        {"UnlicensedCall", "E0000000614"},
        {"SignatureInvalid", "E0000000615"},
        {"MessageError", "E0000000616"},
        {"VersionError", "E0000000617"},
        {"NodeNotConnect", "E0000000618"},
        {"UnsupportedUriPath", "E0000000619"},
        {"QueueFull", "E0000000700"},
};

inline std::string Code(std::string_view desc) {
  auto iter = desc_to_code.find(desc);
  if (iter == desc_to_code.end()) {
    return "E0000000520";
  }
  return {iter->second.begin(), iter->second.end()};
}

inline std::string_view Desc(std::string_view code) {
  static std::once_flag once;
  static std::unordered_map<std::string_view, std::string_view> code_to_desc;
  std::call_once(once, [&]() {
    for (const auto &[k, v] : desc_to_code) {
      code_to_desc[v] = k;
    }
  });
  auto iter = code_to_desc.find(code);
  if (iter == code_to_desc.end()) {
    return "UnKnownErrorCode";
  }
  return iter->second;
}

}  // namespace blackbox_interconnect::error_code
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

#include <exception>
#include <filesystem>
#include <string>
#include <vector>

#include "absl/strings/str_split.h"
#include "spdlog/spdlog.h"

#include "yacl/base/exception.h"

#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <sys/syslimits.h>

#define SO_EXT ".dylib"
#else
#define SO_EXT ".so"
#endif

namespace yacl::crypto {

inline std::string GetProviderPath() {
  // first, get the exec path
  std::filesystem::path exe_path;
#ifndef __APPLE__
  exe_path = std::filesystem::canonical("/proc/self/exe");
#else
  std::array<char, PATH_MAX> buf;
  uint32_t bufsize = PATH_MAX;
  auto ret = _NSGetExecutablePath(buf.data(), &bufsize);
  YACL_ENFORCE(ret == 0);

  exe_path = std::filesystem::path(buf.data());
#endif
  auto selfdir_str = exe_path.parent_path().generic_string();

  // persumely, you are using bazel, so split the path in a bazel way
  // HACK: bazel path
  try {
    std::string path1;
    std::string path2;
    std::string path3 =
        fmt::format("/yacl/crypto/ossl-provider/libprov_shared{}", SO_EXT);

    // step 1: determine if target is "cc_test" or "cc_library"
    if (selfdir_str.find("sandbox") != std::string::npos) {
      std::vector<std::string> tmp = absl::StrSplit(selfdir_str, "sandbox");
      path1 = tmp.at(0);
      tmp = absl::StrSplit(selfdir_str, "execroot");
      tmp = absl::StrSplit(tmp.at(1), "bin");
      path2 = tmp.at(0);
    } else {
      std::vector<std::string> tmp = absl::StrSplit(selfdir_str, "execroot");
      path1 = tmp.at(0);
      tmp = absl::StrSplit(tmp.at(1), "bin");
      path2 = tmp.at(0);
    }

    std::string filename =
        fmt::format("{}execroot{}bin{}", path1, path2, path3);
    return filename;
  } catch (std::exception& e) {
    return "";
  }
}

}  // namespace yacl::crypto

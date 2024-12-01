// Copyright 2024 Ant Group Co., Ltd.
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

#include "yacl/examples/primitives/sse/sse.h"

namespace yacl::examples::primitives::sse {

SSE::SSE(int bucket_size, int slot_size, int lambda, int n_lambda,
         const std::string& filename)
    : tset_(bucket_size, slot_size, lambda, n_lambda) {
  initialize(filename);
}

std::string SSE::getKt() { return K_map_["Kt"]; }

// EDBSetup
std::pair<
    std::vector<std::vector<yacl::examples::primitives::sse::TSet::Record>>,
    std::string>
SSE::EDBSetup() {
  processAndUpdateTAndXSet();
  auto [TSet, Kt] = tset_.TSetSetup(T_, keywords_);
  TSet_ = TSet;
  K_map_["Kt"] = Kt;
  return {TSet, Kt};
}

// SaveEDB
std::tuple<std::map<std::string, std::string>,
           std::vector<std::vector<TSet::Record>>,
           std::vector<yacl::crypto::EcPoint>>
SSE::SaveEDB(const std::string& k_map_file, const std::string& tset_file,
             const std::string& xset_file) {
  SaveKeys(K_map_, k_map_file);
  SaveTSet(TSet_, tset_file);
  SaveXSet(XSet_, xset_file, ec_group_);
  return {K_map_, TSet_, XSet_};
}

// LoadEDB
std::tuple<std::map<std::string, std::string>,
           std::vector<std::vector<TSet::Record>>,
           std::vector<yacl::crypto::EcPoint>>
SSE::LoadEDB(const std::string& k_map_file, const std::string& tset_file,
             const std::string& xset_file) {
  K_map_ = LoadKeys(k_map_file);
  TSet_ = LoadTSet(tset_file);
  XSet_ = LoadXSet(xset_file, ec_group_);
  return {K_map_, TSet_, XSet_};
}

// SearchProtocol
std::vector<std::string> SSE::SearchProtocol(
    const std::vector<std::string>& keywords_Search) {
  if (keywords_Search.empty()) {
    return {};
  }
  std::string w1 = keywords_Search[0];
  // Client computes stag
  auto vector_stag = tset_.TSetGetTag(K_map_["Kt"], w1);
  std::string stag = vectorToString(vector_stag);

  // Server computes t ← TSetRetrieve(TSet, stag)
  std::vector<std::pair<std::vector<uint8_t>, std::string>> t =
      tset_.TSetRetrieve(TSet_, stag);
  size_t size = t.size();

  // Client computes xtoken
  std::vector<std::vector<yacl::crypto::EcPoint>> xtoken;
  xtoken.resize(size + 1);
  yacl::crypto::HmacSha256 hmac_F_SSE_Search_Kz(K_map_["Kz"]);
  yacl::crypto::HmacSha256 hmac_F_SSE_Search_Kx(K_map_["Kx"]);
  for (size_t c = 1; c <= size; c++) {
    xtoken[c].resize(keywords_Search.size() + 1);
    for (size_t i = 2; i <= keywords_Search.size(); i++) {
      hmac_F_SSE_Search_Kz.Reset();
      hmac_F_SSE_Search_Kz.Update(w1 + std::to_string(c));
      auto mac_z1 = hmac_F_SSE_Search_Kz.CumulativeMac();
      std::string string_z1 = vectorToString(mac_z1);
      yacl::math::MPInt z1(string_z1);
      z1 = z1.Mod(ec_group_->GetOrder());

      hmac_F_SSE_Search_Kx.Reset();
      hmac_F_SSE_Search_Kx.Update(keywords_Search[i - 1]);
      auto mac_for_xtag_search = hmac_F_SSE_Search_Kx.CumulativeMac();
      std::string string_for_xtag_search = vectorToString(mac_for_xtag_search);
      yacl::math::MPInt for_xtag_search(string_for_xtag_search);
      for_xtag_search = for_xtag_search.Mod(ec_group_->GetOrder());

      auto for_ecc_search = for_xtag_search.MulMod(z1, ec_group_->GetOrder());
      xtoken[c][i] = ec_group_->MulBase(for_ecc_search);
    }
  }

  // Server computes xtoken
  std::cout << "Output t: " << std::endl;
  std::vector<std::vector<uint8_t>> E;
  bool found = false;
  for (size_t c = 1; c <= size; c++) {
    auto [e, y_string] = t[c - 1];
    yacl::math::MPInt y(y_string);

    bool allInXSet = true;
    for (size_t i = 2; i <= keywords_Search.size(); i++) {
      auto xtag = ec_group_->Mul(xtoken[c][i], y);
      if (!isInXSet(ec_group_, xtag, XSet_)) {
        allInXSet = false;
        break;
      }
    }
    if (allInXSet) {
      E.push_back(e);
      found = true;
    }
  }

  if (!found) {
    std::cout << "No match found." << std::endl;
    return {};
  }

  // Client computes Ke ← Dec(Ks, w1)
  std::vector<std::string> results;
  yacl::crypto::HmacSha256 hmac_F_SSE_Search_Ks(K_map_["Ks"]);
  hmac_F_SSE_Search_Ks.Reset();
  hmac_F_SSE_Search_Ks.Update(w1);
  auto Ke_mac = hmac_F_SSE_Search_Ks.CumulativeMac();
  uint128_t Ke = convert_to_uint128(Ke_mac);
  for (const auto& e : E) {
    std::vector<uint8_t> ind = aes_ctr_decrypt(e, Ke, 0);
    std::string ind_string(ind.begin(), ind.end());
    std::cout << "Found match: " << ind_string << std::endl;
    results.push_back(ind_string);
  }

  return results;
}

SSE::~SSE() { ec_group_.reset(); }

// ? private functions

bool SSE::isInXSet(const std::unique_ptr<yacl::crypto::EcGroup>& ec_group,
                   const yacl::crypto::EcPoint& xtag,
                   const std::vector<yacl::crypto::EcPoint>& XSet) {
  for (const auto& xtag_in_XSet : XSet) {
    auto affine_point = ec_group->GetAffinePoint(xtag_in_XSet);
    if (ec_group->PointEqual(xtag, xtag_in_XSet)) {
      return true;
    }
  }
  return false;
}

// 初始化密钥，curve等参数
void SSE::initialize(const std::string& filename) {
  auto [keywords, keyValuePairs, reverseIndex] = processAndSaveCSV(filename);
  keywords_ = keywords;
  keyValuePairs_ = keyValuePairs;
  reverseIndex_ = reverseIndex;

  K_map_["Ks"] = "This is Ks";
  K_map_["Kx"] = "This is Kx";
  K_map_["Ki"] = "This is Ki";
  K_map_["Kz"] = "This is Kz";

  const auto& curve = yacl::crypto::GetCurveMetaByName("secp224r1");
  ec_group_ = yacl::crypto::openssl::OpensslGroup::Create(curve);
}

// 主功能函数：计算并更新 T 和 XSet
void SSE::processAndUpdateTAndXSet() {
  yacl::crypto::HmacSha256 hmac_F_SSE_Ks(K_map_["Ks"]);
  yacl::crypto::HmacSha256 hmac_F_SSE_Kx(K_map_["Kx"]);
  yacl::crypto::HmacSha256 hmac_F_SSE_Ki(K_map_["Ki"]);
  yacl::crypto::HmacSha256 hmac_F_SSE_Kz(K_map_["Kz"]);

  for (const auto& keyword : keywords_) {
    auto mac_Ke = hmac_F_SSE_Ks.Reset().Update(keyword).CumulativeMac();
    uint128_t Ke = convert_to_uint128(mac_Ke);

    auto mac_for_xtag = hmac_F_SSE_Kx.Reset().Update(keyword).CumulativeMac();
    std::string string_for_xtag = vectorToString(mac_for_xtag);
    yacl::math::MPInt for_xtag(string_for_xtag);
    for_xtag = for_xtag.Mod(ec_group_->GetOrder());

    std::vector<std::string> inds = fetchKeysByValue(reverseIndex_, keyword);
    std::vector<std::pair<std::vector<uint8_t>, std::string>> t;
    size_t c = 1;
    for (const auto& ind : inds) {
      // xind
      auto mac_xind = hmac_F_SSE_Ki.Reset().Update(ind).CumulativeMac();
      std::string string_xind = vectorToString(mac_xind);
      yacl::math::MPInt xind(string_xind);
      xind = xind.Mod(ec_group_->GetOrder());

      // z
      auto mac_z = hmac_F_SSE_Kz.Reset()
                       .Update(keyword + std::to_string(c))
                       .CumulativeMac();
      std::string string_z = vectorToString(mac_z);
      yacl::math::MPInt z(string_z);
      z = z.Mod(ec_group_->GetOrder());

      // Invert_z
      yacl::math::MPInt Invert_z = z.InvertMod(ec_group_->GetOrder());
      // y
      yacl::math::MPInt y = xind.MulMod(Invert_z, ec_group_->GetOrder());

      // append (e, y) to t.
      std::vector<uint8_t> ind_vector(ind.begin(), ind.end());
      std::vector<uint8_t> e = aes_ctr_encrypt(ind_vector, Ke, 0);
      t.push_back(std::make_pair(e, y.ToString()));

      // add xtag to XSet.
      auto for_ecc = for_xtag.MulMod(xind, ec_group_->GetOrder());
      auto xtag = ec_group_->MulBase(for_ecc);
      XSet_.push_back(xtag);

      c++;
    }
    T_[keyword] = t;
  }
}

// 整合后的函数：读取CSV文件、处理键值对并保存到数据库
std::tuple<std::vector<std::string>,
           std::vector<std::pair<std::string, std::string>>,
           std::unordered_map<std::string, std::vector<std::string>>>
SSE::processAndSaveCSV(const std::string& file_path) {
  // 存储键值对
  std::vector<std::pair<std::string, std::string>> keyValuePairs;

  // 创建输入流
  std::unique_ptr<yacl::io::InputStream> in(
      new yacl::io::FileInputStream(file_path));

  // 定义CSV读取选项
  yacl::io::ReaderOptions read_options;
  read_options.batch_size = 1;  // 每次读取一行
  read_options.column_reader = false;
  read_options.use_header_order = true;

  // 定义文件架构
  read_options.file_schema.feature_names = {"ID",
                                            "age",
                                            "workclass",
                                            "fnlwgt",
                                            "education",
                                            "education_num",
                                            "marital_status",
                                            "occupation",
                                            "relationship",
                                            "race",
                                            "gender",
                                            "capital_gain",
                                            "capital_loss",
                                            "hours_per_week",
                                            "native_country"};
  read_options.file_schema.feature_types.resize(15, yacl::io::Schema::STRING);

  // 创建CSV读取器
  auto reader =
      std::make_shared<yacl::io::CsvReader>(read_options, std::move(in));
  reader->Init();

  // 读取CSV文件并处理为键值对
  yacl::io::ColumnVectorBatch batch_dataset;
  while (reader->Next(&batch_dataset)) {
    for (size_t i = 0; i < batch_dataset.Shape().rows; ++i) {
      std::string id = batch_dataset.At<std::string>(i, 0);  // 获取ID列的值
      for (size_t j = 1; j < batch_dataset.Shape().cols; ++j) {
        std::string key = read_options.file_schema.feature_names[j];
        std::string value = batch_dataset.At<std::string>(i, j);
        keyValuePairs.emplace_back(id, key + "=" + value);
      }
    }
  }

  // 反向索引（从值到键的映）
  std::unordered_map<std::string, std::vector<std::string>> reverseIndex;

  // 存储键值对并生成关键字列表
  std::set<std::string> keywords_set;
  for (const auto& pair : keyValuePairs) {
    keywords_set.insert(pair.second);  // 收集所有的关键字
    reverseIndex[pair.second].push_back(pair.first);  // 更新反向索引
  }

  // 将唯一关键字转化为 vector
  std::vector<std::string> keywords(keywords_set.begin(), keywords_set.end());

  // 返回包含关键字和反向索引的 pair
  return {keywords, keyValuePairs, reverseIndex};
}

// 将 HMAC 结果转换为 uint128_t
uint128_t SSE::convert_to_uint128(const std::vector<uint8_t>& mac) {
  uint128_t result = 0;
  std::memcpy(&result, mac.data(), std::min(mac.size(), sizeof(result)));
  return result;
}

// std::vector<uint8_t> 转换为std::string
std::string SSE::vectorToString(const std::vector<uint8_t>& vec) {
  std::string result;
  for (auto& byte : vec) {
    result += std::to_string(static_cast<int>(byte));
  }
  return result;
}

// 通过值获取对应的多个键
std::vector<std::string> SSE::fetchKeysByValue(
    const std::unordered_map<std::string, std::vector<std::string>>&
        reverseIndex,
    const std::string& value) {
  std::vector<std::string> keys;
  auto it = reverseIndex.find(value);
  if (it != reverseIndex.end()) {
    for (const auto& key : it->second) {
      keys.push_back(key);
    }
  } else {
    std::cerr << "No keys found for value: " << value << std::endl;
  }
  return keys;
}

// AES-CTR 加密函数
std::vector<uint8_t> SSE::aes_ctr_encrypt(const std::vector<uint8_t>& plaintext,
                                          const uint128_t& key,
                                          const uint128_t& iv) {
  yacl::crypto::SymmetricCrypto crypto(
      yacl::crypto::SymmetricCrypto::CryptoType::AES128_CTR, key, iv);
  std::vector<uint8_t> ciphertext(plaintext.size());
  crypto.Encrypt(absl::MakeConstSpan(plaintext), absl::MakeSpan(ciphertext));
  return ciphertext;
}

// AES-CTR 解密函数
std::vector<uint8_t> SSE::aes_ctr_decrypt(
    const std::vector<uint8_t>& ciphertext, const uint128_t& key,
    const uint128_t& iv) {
  yacl::crypto::SymmetricCrypto crypto(
      yacl::crypto::SymmetricCrypto::CryptoType::AES128_CTR, key, iv);
  std::vector<uint8_t> plaintext(ciphertext.size());
  crypto.Decrypt(absl::MakeConstSpan(ciphertext), absl::MakeSpan(plaintext));
  return plaintext;
}

void SSE::SaveKeys(const std::map<std::string, std::string>& K_map,
                   const std::string& file_path) {
  std::ofstream K_file(file_path, std::ios::binary);
  if (K_file.is_open()) {
    // 遍历 map，将键和值写入文件
    for (const auto& pair : K_map) {
      // 写入键和值的长度，然后写入实际内容
      size_t key_size = pair.first.size();
      size_t value_size = pair.second.size();
      K_file.write(reinterpret_cast<const char*>(&key_size),
                   sizeof(size_t));                // 写入键的长度
      K_file.write(pair.first.c_str(), key_size);  // 写入键
      K_file.write(reinterpret_cast<const char*>(&value_size),
                   sizeof(size_t));                   // 写入值的长度
      K_file.write(pair.second.c_str(), value_size);  // 写入值
    }
    K_file.close();
    std::cout << "密钥成功写入文件：" << file_path << std::endl;
  } else {
    std::cerr << "无法打开文件 " << file_path << " 进行写入。" << std::endl;
  }
}

void SSE::SaveTSet(
    const std::vector<
        std::vector<yacl::examples::primitives::sse::TSet::Record>>& TSet,
    const std::string& file_path) {
  std::ofstream tset_file(file_path, std::ios::binary);

  if (tset_file.is_open()) {
    // 遍历 TSet 中的每个 bucket
    for (const auto& bucket : TSet) {
      size_t bucket_size = bucket.size();
      tset_file.write(reinterpret_cast<const char*>(&bucket_size),
                      sizeof(size_t));  // 写入 bucket 的大小

      // 遍历每个 bucket 中的 entry
      for (const auto& entry : bucket) {
        size_t entry_size = entry.value.size();
        tset_file.write(reinterpret_cast<const char*>(&entry_size),
                        sizeof(size_t));  // 写入 entry 的大小
        tset_file.write(reinterpret_cast<const char*>(entry.value.data()),
                        entry_size);  // 写入 entry 的内容
      }
    }

    tset_file.close();
    std::cout << "TSet 已成功写入文件：" << file_path << std::endl;
  } else {
    std::cerr << "无法打开文件 " << file_path << " 进行写入。" << std::endl;
  }
}

void SSE::SaveXSet(const std::vector<yacl::crypto::EcPoint>& XSet,
                   const std::string& file_path,
                   const std::unique_ptr<yacl::crypto::EcGroup>& ec_group) {
  std::ofstream xset_file(file_path, std::ios::binary);

  if (xset_file.is_open()) {
    // 写入XSet的大小
    size_t xset_size = XSet.size();
    xset_file.write(reinterpret_cast<const char*>(&xset_size), sizeof(size_t));

    // 遍历每个点并写入其坐标
    for (const auto& point : XSet) {
      auto affine_point = ec_group->GetAffinePoint(point);
      std::string x_str = affine_point.x.ToString();
      std::string y_str = affine_point.y.ToString();

      // 写入x坐标
      size_t x_size = x_str.size();
      xset_file.write(reinterpret_cast<const char*>(&x_size), sizeof(size_t));
      xset_file.write(x_str.c_str(), x_size);

      // 写入y坐标
      size_t y_size = y_str.size();
      xset_file.write(reinterpret_cast<const char*>(&y_size), sizeof(size_t));
      xset_file.write(y_str.c_str(), y_size);
    }

    xset_file.close();
    std::cout << "XSet 已成功写入文件：" << file_path << std::endl;
  } else {
    std::cerr << "无法打开文件 " << file_path << " 进行写入。" << std::endl;
  }
}

std::map<std::string, std::string> SSE::LoadKeys(const std::string& file_path) {
  std::ifstream K_file_read(file_path, std::ios::binary);
  std::map<std::string, std::string> K_map_read;

  if (K_file_read.is_open()) {
    while (K_file_read.peek() != EOF) {
      size_t key_size, value_size;

      // 读取键的长度和内容
      K_file_read.read(reinterpret_cast<char*>(&key_size), sizeof(size_t));
      std::string key(key_size, '\0');
      K_file_read.read(&key[0], key_size);

      // 读取值的长度和内容
      K_file_read.read(reinterpret_cast<char*>(&value_size), sizeof(size_t));
      std::string value(value_size, '\0');
      K_file_read.read(&value[0], value_size);

      K_map_read[key] = value;
    }
    K_file_read.close();
    std::cout << "密钥已成功从文件读取。" << std::endl;
  } else {
    std::cerr << "无法打开文件 " << file_path << " 进行读取。" << std::endl;
  }

  return K_map_read;
}

std::vector<std::vector<yacl::examples::primitives::sse::TSet::Record>>
SSE::LoadTSet(const std::string& file_path) {
  std::ifstream tset_file(file_path, std::ios::binary);
  std::vector<std::vector<yacl::examples::primitives::sse::TSet::Record>> TSet;
  while (tset_file.good()) {
    size_t bucket_size;
    tset_file.read(reinterpret_cast<char*>(&bucket_size), sizeof(size_t));
    if (!tset_file.good()) break;  // 检查是否到达文件末尾

    std::vector<yacl::examples::primitives::sse::TSet::Record> bucket;
    for (size_t i = 0; i < bucket_size; i++) {
      yacl::examples::primitives::sse::TSet::Record entry;
      size_t entry_size;
      tset_file.read(reinterpret_cast<char*>(&entry_size), sizeof(size_t));
      entry.value.resize(entry_size);
      tset_file.read(reinterpret_cast<char*>(entry.value.data()), entry_size);
      bucket.push_back(entry);
    }
    TSet.push_back(bucket);
  }
  return TSet;
}

std::vector<yacl::crypto::EcPoint> SSE::LoadXSet(
    const std::string& file_path,
    const std::unique_ptr<yacl::crypto::EcGroup>& ec_group) {
  std::ifstream xset_file(file_path, std::ios::binary);
  std::vector<yacl::crypto::EcPoint> XSet;
  size_t xset_size;
  xset_file.read(reinterpret_cast<char*>(&xset_size), sizeof(size_t));

  for (size_t i = 0; i < xset_size; i++) {
    // 读取x坐标
    size_t x_size;
    xset_file.read(reinterpret_cast<char*>(&x_size), sizeof(size_t));
    std::string x_str(x_size, '\0');
    xset_file.read(&x_str[0], x_size);

    // 读取y坐标
    size_t y_size;
    xset_file.read(reinterpret_cast<char*>(&y_size), sizeof(size_t));
    std::string y_str(y_size, '\0');
    xset_file.read(&y_str[0], y_size);

    // 从字符串构造MPInt
    yacl::math::MPInt x(x_str);
    yacl::math::MPInt y(y_str);

    yacl::crypto::AffinePoint affine_point{x, y};
    XSet.push_back(ec_group->CopyPoint(affine_point));
  }
  return XSet;
}

}  // namespace yacl::examples::primitives::sse

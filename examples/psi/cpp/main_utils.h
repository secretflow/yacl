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

#include <filesystem>
#include <string>
#include <vector>

#include "yacl/base/exception.h"
#include "yacl/io/rw/csv_reader.h"
#include "yacl/io/rw/schema.h"
#include "yacl/io/stream/file_io.h"
#include "yacl/io/stream/interface.h"
#include "yacl/link/context.h"
#include "yacl/link/factory.h"

inline std::vector<std::string> LoadCsv(const std::string& file_path) {
  // File input stream
  auto in = std::unique_ptr<yacl::io::InputStream>(
      new yacl::io::FileInputStream(file_path));

  // Read csv file
  yacl::io::ReaderOptions reader_ops;

  // We only want to read the "ID" column
  reader_ops.file_schema = {{/* target colum type */ yacl::io::Schema::STRING},
                            {/* target column */ "ID"}};
  auto csv_reader = yacl::io::CsvReader(reader_ops, std::move(in));
  csv_reader.Init();

  // Read in batch
  std::vector<std::string> out;
  yacl::io::ColumnVectorBatch col_batch;
  while (csv_reader.Next(&col_batch)) {
    auto target_column = col_batch.Pop<std::string>(0);
    out.insert(out.end(), target_column.begin(), target_column.end());
  }
  col_batch.Clear();

  return out;
}
inline std::vector<std::string> LoadCsv(int rank) {
  YACL_ENFORCE(rank == 0 || rank == 1);
  std::string file_path = fmt::format("{}/psi/data/data_{}.csv",
                                      std::filesystem::current_path().string(),
                                      rank == 0 ? "a" : "b");
  return LoadCsv(file_path);
}

inline std::shared_ptr<yacl::link::Context> SetupLink(int my_rank) {
  size_t world_size = 2;
  yacl::link::ContextDesc ctx_desc;

  for (size_t rank = 0; rank < world_size; rank++) {
    const auto id = fmt::format("id-{}", rank);
    const auto host = fmt::format("127.0.0.1:{}", 10086 + rank);
    ctx_desc.parties.emplace_back(id, host);
  }
  auto lctx = yacl::link::FactoryBrpc().CreateContext(ctx_desc, my_rank);
  lctx->ConnectToMesh();

  return lctx;
}

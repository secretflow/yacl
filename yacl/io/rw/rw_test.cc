// Copyright 2022 Ant Group Co., Ltd.
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

#include <cmath>
#include <filesystem>
#include <random>

#include "absl/strings/str_split.h"
#include "fmt/format.h"
#include "gflags/gflags.h"
#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/io/rw/csv_reader.h"
#include "yacl/io/rw/csv_writer.h"
#include "yacl/io/rw/schema.h"
#include "yacl/io/stream/file_io.h"
#include "yacl/utils/elapsed_timer.h"

namespace yacl::io {

DEFINE_string(large_file_test, "", "");

class IOTest : public ::testing::Test {};

// how to use reader / writer.
TEST(RW, test) {
  // in this case, we steamingly read from input & write into other file.
  {
    // How to build a csv reader.
    // build inputstream.
    std::unique_ptr<InputStream> in(
        new FileInputStream("yacl/io/test/data/perfect_logit_a.csv"));

    // define csv reader
    ReaderOptions read_options;
    read_options.batch_size = 509;
    // in this case, read by row.
    read_options.column_reader = false;
    // output batch's cols follow csv file header's order.
    read_options.use_header_order = true;
    // count lines during init.
    read_options.row_reader_count_lines = true;
    // use_header_order == true, so Next(&batch) return batch by header's order.
    // even feature_names is out of order as below.
    // feature names
    read_options.file_schema.feature_names = {"x6", "id1", "x1", "x3",
                                              "x4", "x7",  "x5", "x8",
                                              "x9", "x10", "y",  "x2"};
    // feild types.
    read_options.file_schema.feature_types.resize(12, Schema::FLOAT);
    read_options.file_schema.feature_types[1] = Schema::STRING;
    read_options.file_schema.feature_types[10] = Schema::DOUBLE;

    // build reader
    auto reader = std::make_shared<CsvReader>(read_options, std::move(in));
    reader->Init();
    // row_reader_count_lines == true, so we can get rows before first scan.
    EXPECT_EQ(10000, reader->Rows());

    // How to build a csv writer.
    // build outputstream.
    std::unique_ptr<OutputStream> out(new FileOutputStream("test.csv"));

    // define csv writer
    WriterOptions writer_options;
    // reader return Next(&batch) batch by csv file header's order.
    // so we define out put header as input.
    writer_options.file_schema.feature_names = {"id1", "x1", "x2",  "x3",
                                                "x4",  "x5", "x6",  "x7",
                                                "x8",  "x9", "x10", "y"};
    writer_options.file_schema.feature_types.resize(12, Schema::FLOAT);
    writer_options.file_schema.feature_types[0] = Schema::STRING;
    // let Y be double
    writer_options.file_schema.feature_types[11] = Schema::DOUBLE;

    // build writer
    auto writer = std::make_shared<CsvWriter>(writer_options, std::move(out));
    writer->Init();

    // NOW, streaming
    size_t batch_row_count = 0;
    ColumnVectorBatch batch_dataset;
    while (reader->Next(&batch_dataset)) {
      batch_row_count += batch_dataset.Shape().rows;
      writer->Add(batch_dataset);
    }
    // !!! PLS Call Close before release Writer !!!
    writer->Close();
    EXPECT_EQ(batch_row_count, 10000);
    // reach EOF
    // in column_reader == false mode. rows is available now.
    size_t rows = reader->Rows();
    EXPECT_EQ(10000, rows);
    EXPECT_EQ(12, reader->Cols());
    EXPECT_NE(rows, std::numeric_limits<size_t>::max());
    // let try seek back, then read other batch.
    reader->Seek(3000);
    reader->Next(&batch_dataset);
    EXPECT_EQ(batch_dataset.Shape().rows, 509);
    EXPECT_EQ(batch_dataset.Shape().cols, 12);
    // we can read data by (row, col) directly, no need convert to eigen.
    EXPECT_EQ("user3001", batch_dataset.At<std::string>(0, 0));
    EXPECT_NEAR(0.404875, batch_dataset.At<float>(0, 1), 1e-07);

    // Spawn new row reader .
    auto spawn_reader = reader->Spawn();
    EXPECT_EQ(spawn_reader->Rows(), reader->Rows());
    EXPECT_EQ(spawn_reader->Tell(), reader->Tell());
    EXPECT_EQ(spawn_reader->Headers(), reader->Headers());

    spawn_reader->Next(&batch_dataset);
    EXPECT_EQ(batch_dataset.Shape().rows, 509);
    EXPECT_EQ(batch_dataset.Shape().cols, 12);

    EXPECT_EQ("user3510", batch_dataset.At<std::string>(0, 0));
    EXPECT_NEAR(-0.67803686857, batch_dataset.At<float>(0, 1), 1e-07);

    // override global batch size
    spawn_reader->Next(701, &batch_dataset);
    EXPECT_EQ(batch_dataset.Shape().rows, 701);
    EXPECT_EQ(batch_dataset.Shape().cols, 12);
  }
  // now let try read csv file by col.
  {
    // build inputstream.
    std::unique_ptr<InputStream> in(new FileInputStream("test.csv"));

    // define csv reader
    ReaderOptions read_options;
    // batch_size is ignored in col read mode
    // read_options.batch_size = 500;
    // in this case, read by col.
    read_options.column_reader = true;
    // use file_schema define order, not file head order.
    read_options.use_header_order = false;
    // use_header_order == false,
    // so Next(&batch) return batch by file_schema's order as below.
    // feature names
    read_options.file_schema.feature_names = {"y",  "id1", "x6",  "x1",
                                              "x3", "x4",  "x7",  "x5",
                                              "x8", "x9",  "x10", "x2"};
    // feild types.
    read_options.file_schema.feature_types.resize(12, Schema::FLOAT);
    // feature_types must match feature_names
    read_options.file_schema.feature_types[1] = Schema::STRING;
    // let Y be double
    read_options.file_schema.feature_types[0] = Schema::DOUBLE;
    // build reader
    auto reader = std::make_shared<CsvReader>(read_options, std::move(in));
    reader->Init();

    // in col reader, rows is available after build even before reach EOF.
    size_t rows2 = reader->Rows();
    EXPECT_EQ(rows2, 10000);

    ColumnVectorBatch batch_dataset;
    // use_header_order == false, so first col return from next is y label as
    // feature_names's order.
    EXPECT_EQ(reader->Next(&batch_dataset), true);
    EXPECT_EQ(rows2, batch_dataset.Shape().rows);
    EXPECT_EQ(1, batch_dataset.Shape().cols);
    // id1 col.
    EXPECT_EQ(reader->Next(&batch_dataset), true);
    EXPECT_EQ(rows2, batch_dataset.Shape().rows);
    EXPECT_EQ(1, batch_dataset.Shape().cols);
    EXPECT_EQ("user1", batch_dataset.At<std::string>(0, 0));
    EXPECT_EQ("user10000", batch_dataset.At<std::string>(rows2 - 1, 0));
    // x6 col.
    EXPECT_EQ(reader->Next(&batch_dataset), true);
    EXPECT_EQ(rows2, batch_dataset.Shape().rows);
    EXPECT_EQ(1, batch_dataset.Shape().cols);

    reader->Seek(1);
    // read id1 again.
    EXPECT_EQ(reader->Next(&batch_dataset), true);
    EXPECT_EQ(rows2, batch_dataset.Shape().rows);
    EXPECT_EQ(1, batch_dataset.Shape().cols);
    EXPECT_EQ("user1", batch_dataset.At<std::string>(0, 0));
    EXPECT_EQ("user10000", batch_dataset.At<std::string>(rows2 - 1, 0));

    // Spawn new col reader .
    auto spawn_reader = reader->Spawn();
    EXPECT_EQ(spawn_reader->Rows(), reader->Rows());
    EXPECT_EQ(spawn_reader->Tell(), reader->Tell());
    EXPECT_EQ(spawn_reader->Headers(), reader->Headers());
    reader.reset();  // delete old reader. but keep mmap data.

    // x6
    EXPECT_EQ(spawn_reader->Next(&batch_dataset), true);
    EXPECT_EQ(rows2, batch_dataset.Shape().rows);
    EXPECT_EQ(1, batch_dataset.Shape().cols);

    // seek & read again. make sure mmap dir still readable
    spawn_reader->Seek(1);
    EXPECT_EQ(spawn_reader->Next(&batch_dataset), true);
    EXPECT_EQ(rows2, batch_dataset.Shape().rows);
    EXPECT_EQ(1, batch_dataset.Shape().cols);
    EXPECT_EQ("user1", batch_dataset.At<std::string>(0, 0));
    EXPECT_EQ("user10000", batch_dataset.At<std::string>(rows2 - 1, 0));

    spawn_reader->Seek(11);
    EXPECT_EQ(spawn_reader->Next(&batch_dataset), true);
    EXPECT_EQ(rows2, batch_dataset.Shape().rows);
    EXPECT_EQ(1, batch_dataset.Shape().cols);

    spawn_reader->Seek(0);
    // read all  12 cols.
    EXPECT_EQ(spawn_reader->Next(12, &batch_dataset), true);
    EXPECT_EQ(rows2, batch_dataset.Shape().rows);
    EXPECT_EQ(12, batch_dataset.Shape().cols);
    EXPECT_EQ("user1", batch_dataset.At<std::string>(0, 1));
    EXPECT_EQ("user10000", batch_dataset.At<std::string>(rows2 - 1, 1));

    spawn_reader->Seek(10);
    EXPECT_EQ(spawn_reader->Next(12, &batch_dataset), true);
    EXPECT_EQ(rows2, batch_dataset.Shape().rows);
    EXPECT_EQ(2, batch_dataset.Shape().cols);

    EXPECT_EQ(spawn_reader->Next(12, &batch_dataset), false);

    spawn_reader->Seek(2);
    EXPECT_EQ(spawn_reader->Next(5, &batch_dataset), true);
    EXPECT_EQ(rows2, batch_dataset.Shape().rows);
    EXPECT_EQ(5, batch_dataset.Shape().cols);
  }
}

TEST(RW, empty_reader) {
  {
    // row reader.
    // if file_schema.feature_names empty, reader do nothing but count lines.
    std::unique_ptr<InputStream> in(
        new FileInputStream("yacl/io/test/data/perfect_logit_a.csv"));

    ReaderOptions read_options;
    read_options.batch_size = 509;
    read_options.column_reader = false;
    // empty feature names
    read_options.file_schema.feature_names = {};
    read_options.file_schema.feature_types.resize(0);

    // build reader
    auto reader = std::make_shared<CsvReader>(read_options, std::move(in));
    reader->Init();

    // streaming read
    size_t batch_row_count = 0;
    ColumnVectorBatch batch_dataset;
    while (reader->Next(&batch_dataset)) {
      batch_row_count += batch_dataset.Shape().rows;
      EXPECT_EQ(0, batch_dataset.Shape().cols);
    }
    // reach EOF
    EXPECT_EQ(batch_row_count, 10000);
  }
  {
    std::unique_ptr<InputStream> in(
        new FileInputStream("yacl/io/test/data/perfect_logit_a.csv"));

    ReaderOptions read_options;
    read_options.batch_size = 1;
    read_options.column_reader = true;
    // empty feature names
    read_options.file_schema.feature_names = {};
    read_options.file_schema.feature_types.resize(0);
    // col reader do not support empty feature_names.
    auto reader = std::make_shared<CsvReader>(read_options, std::move(in));
    EXPECT_THROW(reader->Init(), yacl::Exception);
  }
}

DEFINE_uint64(rows, 0, "");
DEFINE_string(feature_names, "", "");
DEFINE_int64(string_col_index, -1, "");

TEST(LARGE, test) {
  if (!FLAGS_large_file_test.size()) {
    return;
  }

  yacl::ElapsedTimer timer;

  Schema file_schema;
  std::vector<std::string> feature_names =
      absl::StrSplit(FLAGS_feature_names, ",");
  file_schema.feature_names = feature_names;
  file_schema.feature_types.resize(feature_names.size(), Schema::FLOAT);
  if (FLAGS_string_col_index != -1) {
    file_schema.feature_types[FLAGS_string_col_index] = Schema::STRING;
  }

  // build reader row
  std::unique_ptr<InputStream> in_1(new FileInputStream(FLAGS_large_file_test));

  ReaderOptions reader_options_1;
  reader_options_1.file_schema = file_schema;
  reader_options_1.batch_size = 9859;
  reader_options_1.column_reader = false;
  reader_options_1.use_header_order = true;
  auto reader_row =
      std::make_shared<CsvReader>(reader_options_1, std::move(in_1));
  reader_row->Init();

  std::cout << "build row reader time: " << timer.CountSec() << "\n";
  timer.Restart();

  // build writer
  std::unique_ptr<OutputStream> out(new FileOutputStream("test.csv"));

  WriterOptions writer_options;
  writer_options.file_schema = file_schema;
  auto writer = std::make_shared<CsvWriter>(writer_options, std::move(out));
  writer->Init();

  std::cout << "build writer time: " << timer.CountSec() << "\n";
  timer.Restart();

  // NOW, streaming
  size_t batch_row_count = 0;
  {
    ColumnVectorBatch batch_dataset;
    while (reader_row->Next(&batch_dataset)) {
      batch_row_count += batch_dataset.Shape().rows;
      writer->Add(batch_dataset);
    }
  }

  EXPECT_EQ(batch_row_count, FLAGS_rows);

  EXPECT_EQ(FLAGS_rows, reader_row->Rows());
  // !!! PLS Call Close before release Writer !!!
  writer->Close();
  writer.reset();

  std::cout << "streaming time: " << timer.CountSec() << "\n";
  timer.Restart();

  // build reader col
  std::unique_ptr<InputStream> in_2(new FileInputStream("test.csv"));

  ReaderOptions reader_options_2;
  reader_options_2.column_reader = true;
  reader_options_2.use_header_order = true;
  reader_options_2.file_schema = file_schema;
  auto reader_col =
      std::make_shared<CsvReader>(reader_options_2, std::move(in_2));
  reader_col->Init();

  std::cout << "build col reader time: " << timer.CountSec() << "\n";
  timer.Restart();

  EXPECT_EQ(FLAGS_rows, reader_col->Rows());

  ColumnVectorBatch batch_dataset_col;

  EXPECT_EQ(reader_col->Next(&batch_dataset_col), true);
  EXPECT_EQ(FLAGS_rows, batch_dataset_col.Shape().rows);
  EXPECT_EQ(1, batch_dataset_col.Shape().cols);

  size_t test_count = std::ceil(std::log(FLAGS_rows) * 10);
  std::random_device rd;
  while (test_count--) {
    ColumnVectorBatch batch_dataset_row;
    size_t rand_index = rd() % FLAGS_rows;
    reader_row->Seek(rand_index);
    reader_row->Next(&batch_dataset_row);
    EXPECT_LT(0, batch_dataset_row.Shape().rows);
    if (FLAGS_string_col_index == 0) {
      EXPECT_EQ(batch_dataset_row.At<std::string>(0, 0),
                batch_dataset_col.At<std::string>(rand_index, 0));
    } else {
      EXPECT_NEAR(batch_dataset_row.At<float>(0, 0),
                  batch_dataset_col.At<float>(rand_index, 0), 1e-07);
    }
  }
  std::cout << "rand test time: " << timer.CountSec() << "\n";
  timer.Restart();

  EXPECT_EQ(reader_col->Next(&batch_dataset_col), true);
  std::cout << "load one col time: " << timer.CountSec() << "\n";
  timer.Restart();

  [[maybe_unused]] float total = 0;
  const auto& col = batch_dataset_col.Col<float>(0);
  for (const auto& f : col) {
    total += f;
  }
  // EXPECT_LT(0, total);
  std::cout << "read col by vector time: " << timer.CountSec() << "\n";
  timer.Restart();

  EXPECT_EQ(reader_col->Next(&batch_dataset_col), true);
  std::cout << "load one col time: " << timer.CountSec() << "\n";
  timer.Restart();

  total = 0;
  for (size_t i = 0; i < FLAGS_rows; i++) {
    total += batch_dataset_col.At<float>(i, 0);
  }
  // EXPECT_LT(0, total);
  std::cout << "read col by index time: " << timer.CountSec() << "\n";
}

}  // namespace yacl::io
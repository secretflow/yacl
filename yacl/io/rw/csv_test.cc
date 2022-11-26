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

#include <cstdint>
#include <ctime>
#include <filesystem>

#include "fmt/format.h"
#include "gtest/gtest.h"

#include "yacl/base/exception.h"
#include "yacl/io/rw/csv_reader.h"
#include "yacl/io/rw/csv_writer.h"
#include "yacl/io/rw/schema.h"
#include "yacl/io/stream/file_io.h"
#include "yacl/io/stream/mem_io.h"

namespace yacl::io {

class IOTest : public ::testing::Test {};

TEST(CSV, test1) {
  std::string input(R"TEXT(id , f2 , f3 , f4 , f5 , label
u1, 2  , 3  , 4  , 5  , 1
u2, 22 , 23 , 24 , 25 , 0
u3, 1e-300 , 0 , 0 , -inf , inf
)TEXT");

  {  // reader
    std::unique_ptr<InputStream> in(new MemInputStream(input));
    Schema s;
    s.feature_types = {Schema::STRING, Schema::FLOAT,  Schema::FLOAT,
                       Schema::FLOAT,  Schema::DOUBLE, Schema::DOUBLE};
    s.feature_names = {"id", "f2", "f4", "f3", "f5", "label"};

    ReaderOptions r_ops;
    r_ops.file_schema = s;
    r_ops.batch_size = 1;
    r_ops.use_header_order = true;

    CsvReader reader(r_ops, std::move(in));
    reader.Init();
    EXPECT_EQ(reader.Tell(), 0);
    EXPECT_EQ(reader.Rows(), std::numeric_limits<size_t>::max());

    EXPECT_EQ(reader.GetLength(), input.size());
    EXPECT_EQ(reader.Tellg(), 31);

    ColumnVectorBatch batch;
    EXPECT_EQ(reader.Next(&batch), true);
    EXPECT_EQ(reader.Tell(), 1);
    EXPECT_EQ(reader.Rows(), std::numeric_limits<size_t>::max());
    EXPECT_EQ(batch.Shape().rows, 1);
    EXPECT_EQ(batch.Shape().cols, 6);
    EXPECT_EQ(batch.At<float>(0, 2), 3);
    EXPECT_EQ(batch.At<float>(0, 3), 4);
    EXPECT_EQ(batch.At<double>(0, 5), 1);
    EXPECT_EQ(batch.At<std::string>(0, 0), "u1");
    EXPECT_EQ(reader.Tellg(), 57);

    EXPECT_EQ(reader.Next(&batch), true);
    EXPECT_EQ(reader.Tell(), 2);
    EXPECT_EQ(reader.Rows(), std::numeric_limits<size_t>::max());
    EXPECT_EQ(batch.Shape().rows, 1);
    EXPECT_EQ(batch.Shape().cols, 6);
    EXPECT_EQ(batch.At<float>(0, 2), 23);
    EXPECT_EQ(batch.At<float>(0, 3), 24);
    EXPECT_EQ(batch.At<double>(0, 5), 0);
    EXPECT_EQ(batch.At<std::string>(0, 0), "u2");
    EXPECT_EQ(reader.Tellg(), 83);

    EXPECT_EQ(reader.Next(&batch), true);
    EXPECT_EQ(reader.Tell(), 3);
    EXPECT_EQ(reader.Rows(), std::numeric_limits<size_t>::max());
    EXPECT_EQ(batch.Shape().rows, 1);
    EXPECT_EQ(batch.Shape().cols, 6);
    EXPECT_EQ(batch.At<float>(0, 1), 0);  // overflow to 0.
    // inf & -inf
    EXPECT_EQ(batch.At<double>(0, 4), -std::numeric_limits<double>::infinity());
    EXPECT_EQ(batch.At<double>(0, 5), std::numeric_limits<double>::infinity());
    EXPECT_EQ(batch.At<std::string>(0, 0), "u3");
    EXPECT_EQ(reader.Tellg(), 115);

    EXPECT_EQ(reader.Next(&batch), false);
    EXPECT_EQ(reader.Tell(), 3);
    EXPECT_EQ(reader.Rows(), 3);
    EXPECT_EQ(reader.Next(&batch), false);

    reader.Seek(1);
    EXPECT_EQ(reader.Tellg(), 57);

    EXPECT_EQ(reader.Next(&batch), true);
    EXPECT_EQ(reader.Tell(), 2);
    EXPECT_EQ(reader.Rows(), 3);
    EXPECT_EQ(batch.Shape().rows, 1);
    EXPECT_EQ(batch.Shape().cols, 6);
    EXPECT_EQ(batch.At<float>(0, 2), 23);
    EXPECT_EQ(batch.At<float>(0, 3), 24);
    EXPECT_EQ(batch.At<double>(0, 5), 0);
    EXPECT_EQ(batch.At<std::string>(0, 0), "u2");
    EXPECT_EQ(reader.Tellg(), 83);
  }
  {
    ColumnVectorBatch batch;
    {  // reader
      std::unique_ptr<InputStream> in(new MemInputStream(input));
      Schema s;
      s.feature_types = {Schema::STRING, Schema::FLOAT, Schema::FLOAT};
      s.feature_names = {"id", "f2", "label"};
      ReaderOptions r_ops;
      r_ops.file_schema = s;
      r_ops.batch_size = 2;
      r_ops.use_header_order = true;
      CsvReader reader(r_ops, std::move(in));
      reader.Init();

      EXPECT_EQ(reader.Next(&batch), true);
      EXPECT_EQ(batch.Shape().rows, 2);
      EXPECT_EQ(batch.Shape().cols, 3);
    }

    std::string out_buf;
    {  // writer
      std::unique_ptr<OutputStream> out(new MemOutputStream(&out_buf));
      Schema s;
      s.feature_types = {Schema::STRING, Schema::FLOAT, Schema::FLOAT,
                         Schema::DOUBLE};
      s.feature_names = {"id", "f2", "label", "test"};
      WriterOptions w_op;
      w_op.file_schema = s;
      CsvWriter writer(w_op, std::move(out));
      writer.Init();
      EXPECT_EQ(writer.Tellp(), 17);
      std::vector<double> float_test_col(2);
      float_test_col[0] = DBL_TRUE_MIN;
      float_test_col[1] = -std::numeric_limits<double>::infinity();
      batch.AppendCol(std::move(float_test_col));
      writer.Add(batch);
      EXPECT_EQ(writer.Tellp(), 39);
      writer.Close();
    }
    EXPECT_NE(out_buf.find("id,f2,label,test"), std::string::npos);
    {  // reader
      std::unique_ptr<InputStream> in(new MemInputStream(out_buf));
      Schema s;
      s.feature_types = {Schema::STRING, Schema::FLOAT, Schema::FLOAT,
                         Schema::DOUBLE};
      s.feature_names = {"id", "f2", "label", "test"};
      ReaderOptions r_ops;
      r_ops.file_schema = s;
      r_ops.batch_size = 2;
      r_ops.use_header_order = true;
      CsvReader reader(r_ops, std::move(in));
      reader.Init();

      EXPECT_EQ(reader.Next(&batch), true);
      EXPECT_EQ(batch.Shape().rows, 2);
      EXPECT_EQ(batch.Shape().cols, 4);
      EXPECT_EQ(batch.At<float>(0, 1), 2);
      EXPECT_EQ(batch.At<float>(0, 2), 1);
      EXPECT_EQ(batch.At<double>(0, 3), 0);  // DBL_TRUE_MIN -> 0
      EXPECT_EQ(batch.At<double>(1, 3),
                -std::numeric_limits<double>::infinity());
      EXPECT_EQ(batch.At<std::string>(0, 0), "u1");
    }
  }
}

TEST(CSV, test2) {
  std::string input(R"TEXT(id , f2 , f3 , f4 , f5 , label
u1, 2  , 3  , 4  , 5  , 1
u2, 22 , 23 , 24 , 25 , 0
)TEXT");

  {  // reader
    std::unique_ptr<InputStream> in(new MemInputStream(input));
    Schema s;
    s.feature_types = {Schema::STRING, Schema::FLOAT,  Schema::FLOAT,
                       Schema::FLOAT,  Schema::DOUBLE, Schema::DOUBLE};
    s.feature_names = {"id", "f2", "f4", "f3", "f5", "label"};

    ReaderOptions r_ops;
    r_ops.file_schema = s;
    r_ops.batch_size = 1;
    r_ops.column_reader = true;
    r_ops.use_header_order = true;

    CsvReader reader(r_ops, std::move(in));
    reader.Init();
    auto header = reader.Headers();
    EXPECT_EQ(header.size(), 6);
    EXPECT_EQ(header[1], "f2");
    EXPECT_EQ(reader.Rows(), 2);
    EXPECT_EQ(reader.Tell(), 0);
    EXPECT_THROW(reader.Tellg(), yacl::Exception);

    ColumnVectorBatch batch;
    EXPECT_EQ(reader.Next(&batch), true);
    EXPECT_EQ(reader.Tell(), 1);
    EXPECT_EQ(batch.Shape().rows, 2);
    EXPECT_EQ(batch.Shape().cols, 1);
    EXPECT_EQ(batch.At<std::string>(1, 0), "u2");

    EXPECT_EQ(reader.Next(&batch), true);
    EXPECT_EQ(reader.Tell(), 2);
    EXPECT_EQ(batch.Shape().rows, 2);
    EXPECT_EQ(batch.Shape().cols, 1);
    EXPECT_EQ(batch.At<float>(1, 0), 22);

    EXPECT_EQ(reader.Next(&batch), true);
    EXPECT_EQ(reader.Tell(), 3);
    EXPECT_EQ(batch.Shape().rows, 2);
    EXPECT_EQ(batch.Shape().cols, 1);
    EXPECT_EQ(batch.At<float>(1, 0), 23);

    EXPECT_EQ(reader.Next(&batch), true);
    EXPECT_EQ(reader.Tell(), 4);
    EXPECT_EQ(batch.Shape().rows, 2);
    EXPECT_EQ(batch.Shape().cols, 1);
    EXPECT_EQ(batch.At<float>(1, 0), 24);

    EXPECT_EQ(reader.Next(&batch), true);
    EXPECT_EQ(reader.Tell(), 5);
    EXPECT_EQ(batch.Shape().rows, 2);
    EXPECT_EQ(batch.Shape().cols, 1);
    EXPECT_EQ(batch.At<double>(1, 0), 25);

    EXPECT_EQ(reader.Next(&batch), true);
    EXPECT_EQ(reader.Tell(), 6);
    EXPECT_EQ(batch.Shape().rows, 2);
    EXPECT_EQ(batch.Shape().cols, 1);
    EXPECT_EQ(batch.At<double>(1, 0), 0);

    EXPECT_EQ(reader.Next(&batch), false);

    reader.Seek(2);
    EXPECT_EQ(reader.Next(&batch), true);
    EXPECT_EQ(reader.Tell(), 3);
    EXPECT_EQ(batch.Shape().rows, 2);
    EXPECT_EQ(batch.Shape().cols, 1);
    EXPECT_EQ(batch.At<float>(1, 0), 23);
  }
}

TEST(CSV, error_args) {
  std::string input(R"TEXT(id , f2 , f3 , f4 , f5 , label
u1, 2  , 3  , 4  , 5  , 1
u2, 22 , 23 , 24 , 25 , 0
)TEXT");

  {  // error 1
    std::unique_ptr<InputStream> in(new MemInputStream(input));
    Schema s;
    s.feature_types = {Schema::STRING, Schema::FLOAT,  Schema::FLOAT,
                       Schema::FLOAT,  Schema::DOUBLE, Schema::DOUBLE};
    s.feature_names = {"id", "fx", "f4", "f3", "f5", "label"};

    ReaderOptions r_ops;
    r_ops.file_schema = s;
    r_ops.batch_size = 1;
    r_ops.column_reader = true;
    r_ops.use_header_order = true;

    CsvReader reader(r_ops, std::move(in));
    EXPECT_THROW(reader.Init(), yacl::ArgumentError);
  }
}

TEST(CSV, error_format) {
  {  // empty field
    std::string input(R"TEXT(id , , f3 , f4 , f5 , label
u1, 2  , 3  , 4  , 5  , 1
u2, 22 , 23 , 24 , 25 , 0
)TEXT");
    std::unique_ptr<InputStream> in(new MemInputStream(input));
    Schema s;
    s.feature_types = {Schema::STRING, Schema::FLOAT,  Schema::FLOAT,
                       Schema::FLOAT,  Schema::DOUBLE, Schema::DOUBLE};
    s.feature_names = {"id", "f2", "f4", "f3", "f5", "label"};

    ReaderOptions r_ops;
    r_ops.file_schema = s;
    r_ops.batch_size = 1;
    r_ops.column_reader = true;
    r_ops.use_header_order = true;

    CsvReader reader(r_ops, std::move(in));
    EXPECT_THROW(reader.Init(), yacl::InvalidFormat);
  }
  {  // Repeated fields
    std::string input(R"TEXT(id , f2 , f2 , f4 , f5 , label
u1, 2  , 3  , 4  , 5  , 1
u2, 22 , 23 , 24 , 25 , 0
)TEXT");
    std::unique_ptr<InputStream> in(new MemInputStream(input));
    Schema s;
    s.feature_types = {Schema::STRING, Schema::FLOAT,  Schema::FLOAT,
                       Schema::FLOAT,  Schema::DOUBLE, Schema::DOUBLE};
    s.feature_names = {"id", "f2", "f4", "f3", "f5", "label"};

    ReaderOptions r_ops;
    r_ops.file_schema = s;
    r_ops.batch_size = 1;
    r_ops.column_reader = true;
    r_ops.use_header_order = true;

    CsvReader reader(r_ops, std::move(in));
    EXPECT_THROW(reader.Init(), yacl::InvalidFormat);
  }
  {  // col fields size err
    std::string input(R"TEXT(id , f2 , f3 , f4 , f5 , label
u1, 2  , 3  , 4  , 5  , 1, 1
u2, 22 , 23 , 24 , 25 , 0
)TEXT");
    std::unique_ptr<InputStream> in(new MemInputStream(input));
    Schema s;
    s.feature_types = {Schema::STRING, Schema::FLOAT,  Schema::FLOAT,
                       Schema::FLOAT,  Schema::DOUBLE, Schema::DOUBLE};
    s.feature_names = {"id", "f2", "f4", "f3", "f5", "label"};

    ReaderOptions r_ops;
    r_ops.file_schema = s;
    r_ops.batch_size = 1;
    r_ops.column_reader = true;
    r_ops.use_header_order = true;

    CsvReader reader(r_ops, std::move(in));
    EXPECT_THROW(reader.Init(), yacl::InvalidFormat);
  }
  {  // col fields float err
    std::string input(R"TEXT(id , f2 , f3 , f4 , f5 , label
u1, s123  , 3  , 4  , 5  , 1
u2, 22 , 23 , 24 , 25 , 0
)TEXT");
    std::unique_ptr<InputStream> in(new MemInputStream(input));
    Schema s;
    s.feature_types = {Schema::STRING, Schema::FLOAT};
    s.feature_names = {"id", "f2"};

    ReaderOptions r_ops;
    r_ops.file_schema = s;
    r_ops.batch_size = 1;
    r_ops.column_reader = true;
    r_ops.use_header_order = true;

    CsvReader reader(r_ops, std::move(in));
    EXPECT_THROW(reader.Init(), yacl::InvalidFormat);
  }
  {  // col fields double err
    std::string input(R"TEXT(id , f2 , f3 , f4 , f5 , label
u1, s123  , 3  , 4  , 5  , 1
u2, 22 , 23 , 24 , 25 , 0
)TEXT");
    std::unique_ptr<InputStream> in(new MemInputStream(input));
    Schema s;
    s.feature_types = {Schema::STRING, Schema::DOUBLE};
    s.feature_names = {"id", "f2"};

    ReaderOptions r_ops;
    r_ops.file_schema = s;
    r_ops.batch_size = 1;
    r_ops.column_reader = true;
    r_ops.use_header_order = true;

    CsvReader reader(r_ops, std::move(in));
    EXPECT_THROW(reader.Init(), yacl::InvalidFormat);
  }

  {  // row fields size err
    std::string input(R"TEXT(id , f2 , f3 , f4 , f5 , label
u1, 2  , 3  , 4  , 5  , 1, 1
u2, 22 , 23 , 24 , 25 , 0
)TEXT");
    std::unique_ptr<InputStream> in(new MemInputStream(input));
    Schema s;
    s.feature_types = {Schema::STRING, Schema::FLOAT,  Schema::FLOAT,
                       Schema::FLOAT,  Schema::DOUBLE, Schema::DOUBLE};
    s.feature_names = {"id", "f2", "f4", "f3", "f5", "label"};

    ReaderOptions r_ops;
    r_ops.file_schema = s;
    r_ops.batch_size = 1;
    r_ops.column_reader = false;
    r_ops.use_header_order = true;

    CsvReader reader(r_ops, std::move(in));
    reader.Init();
    ColumnVectorBatch data;
    EXPECT_THROW(reader.Next(&data), yacl::InvalidFormat);
  }
  {  // row fields float err
    std::string input(R"TEXT(id , f2 , f3 , f4 , f5 , label
u1, s1d23  , 3  , 4  , 5  , 1
u2, 22 , 23 , 24 , 25 , 0
)TEXT");
    std::unique_ptr<InputStream> in(new MemInputStream(input));
    Schema s;
    s.feature_types = {Schema::STRING, Schema::FLOAT};
    s.feature_names = {"id", "f2"};

    ReaderOptions r_ops;
    r_ops.file_schema = s;
    r_ops.batch_size = 1;
    r_ops.column_reader = false;
    r_ops.use_header_order = true;

    CsvReader reader(r_ops, std::move(in));
    reader.Init();
    ColumnVectorBatch data;
    EXPECT_THROW(reader.Next(&data), yacl::InvalidFormat);
  }
  {  // row fields double err
    std::string input(R"TEXT(id , f2 , f3 , f4 , f5 , label
u1, s1d23  , 3  , 4  , 5  , 1
u2, 22 , 23 , 24 , 25 , 0
)TEXT");
    std::unique_ptr<InputStream> in(new MemInputStream(input));
    Schema s;
    s.feature_types = {Schema::STRING, Schema::DOUBLE};
    s.feature_names = {"id", "f2"};

    ReaderOptions r_ops;
    r_ops.file_schema = s;
    r_ops.batch_size = 1;
    r_ops.column_reader = false;
    r_ops.use_header_order = true;

    CsvReader reader(r_ops, std::move(in));
    reader.Init();
    ColumnVectorBatch data;
    EXPECT_THROW(reader.Next(&data), yacl::InvalidFormat);
  }
}

TEST(BATCH, test) {
  {
    FloatColumnVector col;
    col.resize(10, 1);
    const auto data_prt = col.data();
    ColumnVectorBatch batch;
    batch.AppendCol(std::move(col));
    // yes, it's really move & perfect forwarding
    EXPECT_EQ(0, col.size());
    EXPECT_EQ(data_prt, batch.Col<float>(0).data());
    batch.At<float>(0, 0) = 42;
    auto poped = batch.Pop<float>(0);
    EXPECT_EQ(data_prt, poped.data());
    EXPECT_EQ(ColumnVectorBatch::Dimension({10, 0}), batch.Shape());
    EXPECT_EQ(42, poped[0]);
  }

  {
    FloatColumnVector col;
    col.resize(10, 1);
    const auto data_prt = col.data();
    ColumnVectorBatch batch;
    ColumnType c(std::move(col));
    batch.AppendCol(std::move(c));
    // yes, it's really move & perfect forwarding
    EXPECT_EQ(0, col.size());
    EXPECT_EQ(data_prt, batch.Col<float>(0).data());
    auto poped = batch.Pop<float>(0);
    EXPECT_EQ(data_prt, poped.data());
    EXPECT_EQ(ColumnVectorBatch::Dimension({10, 0}), batch.Shape());
  }
}

}  // namespace yacl::io
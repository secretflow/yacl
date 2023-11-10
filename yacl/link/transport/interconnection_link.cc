// Copyright 2019 Ant Group Co., Ltd.
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

#include "yacl/link/transport/interconnection_link.h"

#include <exception>
#include <memory>
#include <utility>

#include "absl/strings/match.h"
#include "fmt/ostream.h"
#include "spdlog/spdlog.h"

#include "yacl/base/exception.h"

#include "interconnection/link/transport.pb.h"

namespace brpc::policy {

DECLARE_int32(h2_client_stream_window_size);

}

namespace yacl::link::transport {

void ThrowLinkErrorByBrpcCntl(const brpc::Controller& cntl) {
  int code = cntl.ErrorCode();
  int http_code = 0;
  if (code == brpc::EHTTP) {
    http_code = cntl.http_response().status_code();
  }
  const auto& response_header = cntl.http_response();
  std::string http_headers;
  constexpr size_t kMaxResponsePrefix = 20;
  std::string http_response;
  if (cntl.has_http_request()) {
    for (auto it = response_header.HeaderBegin();
         it != response_header.HeaderEnd(); ++it) {
      http_headers += fmt::format("[{}]:[{}];", it->first, it->second);
    }
    http_response =
        cntl.response_attachment().to_string().substr(0, kMaxResponsePrefix);
  }

  YACL_THROW_LINK_ERROR(code, http_code,
                        "cntl ErrorCode '{}', http status code '{}', response "
                        "header '{}', response body '{}', error msg '{}'",
                        code, http_code, http_headers, http_response,
                        cntl.ErrorText());
}

namespace ic = org::interconnection;
namespace ic_pb = org::interconnection::link;

std::unique_ptr<::google::protobuf::Message>
InterconnectionLink::PackMonoRequest(const std::string& key,
                                     ByteContainerView value) const {
  auto request = std::make_unique<ic_pb::PushRequest>();
  {
    request->set_sender_rank(self_rank_);
    request->set_key(key);
    request->set_value(value.data(), value.size());
    request->set_trans_type(ic_pb::TransType::MONO);
  }
  return request;
}

std::unique_ptr<::google::protobuf::Message>
InterconnectionLink::PackChunkedRequest(const std::string& key,
                                        ByteContainerView value, size_t offset,
                                        size_t total_length) const {
  auto request = std::make_unique<ic_pb::PushRequest>();
  {
    request->set_sender_rank(self_rank_);
    request->set_key(key);
    request->set_value(value.data(), value.size());
    request->set_trans_type(ic_pb::TransType::CHUNKED);
    request->mutable_chunk_info()->set_chunk_offset(offset);
    request->mutable_chunk_info()->set_message_length(total_length);
  }
  return request;
}

void InterconnectionLink::UnpackMonoRequest(
    const ::google::protobuf::Message& request, std::string* key,
    ByteContainerView* value) const {
  YACL_ENFORCE(key != nullptr, "key should not be null");
  YACL_ENFORCE(value != nullptr, "value should not be null");
  auto real_request = static_cast<const ic_pb::PushRequest*>(&request);
  *key = real_request->key();
  *value = real_request->value();
}

void InterconnectionLink::UnpackChunckRequest(
    const ::google::protobuf::Message& request, std::string* key,
    ByteContainerView* value, size_t* offset, size_t* total_length) const {
  YACL_ENFORCE(key != nullptr, "key should not be null");
  YACL_ENFORCE(value != nullptr, "value should not be null");
  YACL_ENFORCE(offset != nullptr, "offset should not be null");
  YACL_ENFORCE(total_length != nullptr, "total_length should not be null");

  auto real_request = static_cast<const ic_pb::PushRequest*>(&request);
  *key = real_request->key();
  *value = real_request->value();
  *offset = real_request->chunk_info().chunk_offset();
  *total_length = real_request->chunk_info().message_length();
}

void InterconnectionLink::FillResponseOk(
    const ::google::protobuf::Message& /*request*/,
    ::google::protobuf::Message* response) const {
  YACL_ENFORCE(response != nullptr, "response should not be null");

  auto real_response = static_cast<ic_pb::PushResponse*>(response);
  real_response->mutable_header()->set_error_code(ic::ErrorCode::OK);
  real_response->mutable_header()->set_error_msg("");
}

void InterconnectionLink::FillResponseError(
    const ::google::protobuf::Message& request,
    ::google::protobuf::Message* response) const {
  YACL_ENFORCE(response != nullptr, "response should not be null");

  auto real_response = static_cast<ic_pb::PushResponse*>(response);
  auto real_request = static_cast<const ic_pb::PushRequest*>(&request);

  real_response->mutable_header()->set_error_code(
      ic::ErrorCode::INVALID_REQUEST);
  real_response->mutable_header()->set_error_msg(fmt::format(
      "Error: trans type={}, from rank={}",
      TransType_Name(real_request->trans_type()), real_request->sender_rank()));
}

bool InterconnectionLink::IsChunkedRequest(
    const ::google::protobuf::Message& request) const {
  return static_cast<const ic_pb::PushRequest*>(&request)->trans_type() ==
         ic_pb::TransType::CHUNKED;
}

bool InterconnectionLink::IsMonoRequest(
    const ::google::protobuf::Message& request) const {
  return static_cast<const ic_pb::PushRequest*>(&request)->trans_type() ==
         ic_pb::TransType::MONO;
}

auto InterconnectionLink::MakeOptions(
    Options& default_opt, uint32_t http_timeout_ms,
    uint32_t http_max_payload_bytes, const std::string& brpc_channel_protocol,
    const std::string& brpc_channel_connection_type) -> Options {
  auto opts = default_opt;
  if (http_timeout_ms != 0) {
    opts.http_timeout_ms = http_timeout_ms;
  }
  if (http_max_payload_bytes != 0) {
    opts.http_max_payload_bytes = http_max_payload_bytes;
  }
  if (!brpc_channel_protocol.empty()) {
    opts.channel_protocol = brpc_channel_protocol;
  }

  if (absl::StartsWith(opts.channel_protocol, "h2")) {
    YACL_ENFORCE(opts.http_max_payload_bytes > 4096,
                 "http_max_payload_bytes is too small");
    YACL_ENFORCE(
        opts.http_max_payload_bytes < std::numeric_limits<int32_t>::max(),
        "http_max_payload_bytes is too large");
    // if use h2 protocol (h2 or h2:grpc), need to change h2 window size too,
    // use http_max_payload_bytes as h2's window size, then reserve 4kb buffer
    // for protobuf header
    brpc::policy::FLAGS_h2_client_stream_window_size =
        static_cast<int32_t>(opts.http_max_payload_bytes);
    opts.http_max_payload_bytes -= 4096;
  }

  if (!brpc_channel_connection_type.empty()) {
    opts.channel_connection_type = brpc_channel_connection_type;
  }

  return opts;
}

}  // namespace yacl::link::transport

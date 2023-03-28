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

#include <functional>
#include <iostream>
#include <map>

namespace yacl::utils {

template <typename T>
class SegmentTree {
 public:
  SegmentTree() = default;
  ~SegmentTree() = default;

  bool Insert(const T& item) {
    if (segments_.empty()) {
      segments_.insert({item, item + 1});
      return true;
    }

    // first key <= item
    auto current = segments_.upper_bound(item);
    if (current == segments_.begin()) {
      current = segments_.end();
    } else {
      current = std::prev(current);
    }

    if (current == segments_.end() || item > current->second) {
      // new segment
      current = segments_.insert({item, item + 1}).first;
    } else if (item == current->second) {
      // expend exist segment
      current->second = item + 1;
    } else {
      // exist item
      return false;
    }

    // try merge segment
    if (current != segments_.begin()) {
      auto prev = std::prev(current);
      if (prev->second == current->first) {
        prev->second = current->second;
        segments_.erase(current);
        current = prev;
      }
    }

    auto next = std::next(current);
    if (next != segments_.end() && next->first == current->second) {
      current->second = next->second;
      segments_.erase(next);
    }

    return true;
  }

  bool Contains(const T& item) const {
    if (segments_.empty()) {
      return false;
    }

    // first key <= item
    auto current = segments_.upper_bound(item);
    if (current == segments_.begin()) {
      current = segments_.end();
    } else {
      current = std::prev(current);
    }

    if (current == segments_.end() || item >= current->second) {
      return false;
    }

    return true;
  }

  size_t SegmentsCount() const { return segments_.size(); }

  std::vector<std::pair<T, T>> GetSegments() const {
    std::vector<std::pair<T, T>> ret;
    ret.reserve(segments_.size());

    for (const auto& p : segments_) {
      ret.push_back({p.first, p.second});
    }

    return ret;
  }

 private:
  // segments for [key, value)
  std::map<T, T> segments_;
};

}  // namespace yacl::utils
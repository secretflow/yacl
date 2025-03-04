# Copyright 2024 Ant Group Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ecdh_psi_pybind.libs import EcdhPsiCC

class EcdhPsi:

    def __init__(self):
        self.cc_impl = EcdhPsiCC()

    def mask_strs(self, x):
        return self.cc_impl.MaskStrings(x);

    def mask_ec_points_and_hash_to_u128(self, x):
        return self.cc_impl.MaskEcPointsAndHashToU128(x);

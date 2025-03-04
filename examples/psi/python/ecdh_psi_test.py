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

from ecdh_psi import EcdhPsi
import unittest

def intersection_idx(lst1, lst2):
    ret_list = []
    for item in list(set(lst1) & set(lst2)):
        ret_list.append(lst1.index(item))
    return ret_list

class EcdhTest(unittest.TestCase):

    def test_full(self):
        alice = EcdhPsi()
        bob = EcdhPsi()

        alice_data = [str(i) for i in range(0, 4)]
        bob_data = [str(i) for i in range(3, 7)]

        alice_masked_data = alice.mask_strs(alice_data)
        bob_masked_data = bob.mask_strs(bob_data)

        bob_final_data = alice.mask_ec_points_and_hash_to_u128(bob_masked_data)
        alice_final_data = bob.mask_ec_points_and_hash_to_u128(alice_masked_data)

        check = intersection_idx(alice_data, bob_data)
        result = intersection_idx(alice_final_data, bob_final_data)

        for i in range(len(check)):
            self.assertTrue(check[i] == result[i])

if __name__ == "__main__":
    unittest.main()

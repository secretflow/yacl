// Copyright 2023 Ant Group Co., Ltd. #
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

import static org.junit.Assert.*;

import java.util.Arrays;
import org.junit.Test;

public class EcdhPsiTest {
  @Test
  public void load_test() {
    new EcdhPsi(); // should not throw any error
  }

  @Test
  public void ecdh_psi_test() {
    EcdhPsi alice = new EcdhPsi();
    EcdhPsi bob = new EcdhPsi();

    // the generated ec keys by two difference instances should not be the same
    assertEquals(alice.GetEcKey().length, bob.GetEcKey().length);
    assertFalse(Arrays.equals(alice.GetEcKey(), bob.GetEcKey()));

    int n = 4;
    assertTrue(n > 3); // at least one intersection
    String[] x = create_range_items(0, n); // alice's data
    String[] y = create_range_items(3, n); // bob's data

    // -------------------
    // Protocol execution
    // -------------------
    byte[][] x_mask = alice.MaskStrings(x); // x_points = H(x) ^ {alice_sk}
    byte[][] y_mask = bob.MaskStrings(y); // y_points = H(y) ^ {bob_sk}

    byte[][] x_final = bob.MaskEcPointAndHashTo128(x_mask);
    byte[][] y_final = alice.MaskEcPointAndHashTo128(y_mask);

    // -------------------
    // Check
    // -------------------
    for (int i = 0; i < n - 3; ++i) {
      assertTrue(bytes_to_hex_string(x_final[3 + i]).equals(bytes_to_hex_string(y_final[i])));
    }
  }

  private String bytes_to_hex_string(byte[] in) {
    StringBuilder sb = new StringBuilder();
    for (byte b : in) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  private String[] create_range_items(int begin, int size) {
    String[] ret = new String[size];

    for (int i = 0; i < size; i++) {
      ret[i] = Integer.toString(begin + i);
    }
    return ret;
  }
}

// Copyright 2024 Ant Group Co., Ltd. #
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

import com.github.fmeum.rules_jni.RulesJni;
import java.lang.annotation.Native;

public class EcdhPsi {
  static {
    RulesJni.loadLibrary("ecdh_psi_jni", EcdhPsi.class);
  }

  // Constructor
  EcdhPsi() {
    ec_key_ = jni_ecc_keygen();
    inited_ = true;
  }

  public byte[][] MaskStrings(String[] in) {
    if (!this.inited_) {
      throw new IllegalArgumentException("EcdhPsi instance has not been inited");
    }
    return jni_mask_strings(in, this.GetEcKey());
  }

  public byte[][] MaskEcPointAndHashTo128(byte[][] in) {
    if (!this.inited_) {
      throw new IllegalArgumentException("EcdhPsi instance has not been inited");
    }
    return jni_mask_ec_point_and_hash_to_u128(in, this.GetEcKey());
  }

  byte[] GetEcKey() {
    return ec_key_;
  }

  private byte[] ec_key_;
  private boolean inited_ = false;

  // ----------------------------
  // Native Functions Declaration
  // ----------------------------
  //
  // NOTE the gerenated c header (*.h) file could be found at
  // bazel-bin/examples/psi/java/EcdhPsi.hdrs.h/EcdhPsi.h

  public static native byte[] jni_ecc_keygen();

  public static native byte[][] jni_mask_strings(String[] in, byte[] ec_key);

  public static native byte[][] jni_mask_ec_point_and_hash_to_u128(byte[][] in, byte[] ec_key);
}

// Copyright 2026 Ant Group Co., Ltd.
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

#include <iostream>
#include <stdexcept>

#include "sign_flow_test_shared.h"

int main() {
  using namespace tecdsa::sign_flow_test;

  try {
    TestStage4SignConstructorRejectsSmallPaillierModulus();
    TestStage6SignConstructorRejectsMissingKeygenProofArtifacts();
    TestStage6SignConstructorRejectsInvalidKeygenProofArtifacts();
    TestStage6MalformedPhase2InitProofPayloadAbortsResponder();
    TestStage6MalformedPhase2ResponseProofPayloadAbortsInitiator();
    TestStage4Phase2InitUsesResponderOwnedAuxParams();
    TestStage4Phase2ResponseUsesInitiatorOwnedAuxParams();
    TestM4SignEndToEndProducesVerifiableSignature();
    TestM4Phase5DFailurePreventsPhase5EReveal();
    TestM5Phase2InstanceIdMismatchAborts();
    TestM7TamperedPhase2A1ProofAbortsResponder();
    TestM7TamperedPhase2A3ProofAbortsInitiator();
    TestM7TamperedPhase2A2ProofAbortsInitiator();
    TestM6TamperedPhase4GammaSchnorrAbortsReceiver();
    TestM6TamperedPhase5BASchnorrAbortsReceiver();
    TestM6TamperedPhase5BVRelationAbortsReceiver();
    TestM9TamperedPhase4GammaPointAbortsReceiver();
    TestM9TamperedPhase5ACommitmentAbortsReceiver();
    TestM9TamperedPhase3DeltaShareAbortsAndNoResult();
    TestM9TamperedPhase5BVPointAbortsReceiver();
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << '\n';
    return 1;
  }

  std::cout << "sign_flow_tests passed" << '\n';
  return 0;
}

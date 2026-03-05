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

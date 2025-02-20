#include "bits/stdc++.h"

#include "yacl/io/circuit/bristol_fashion.h"

using namespace std;

void func(yacl::io::BFCircuit cir) {
  cir.ng = 45;
  cout << "func:" << cir.ng << endl;
}

int main() {
  std::string operate;
  std::cin >> operate;

  std::string pth =
      fmt::format("{0}/yacl/io/circuit/data/{1}.txt",
                  std::filesystem::current_path().string(), operate);
  yacl::io::CircuitReader reader(pth);
  reader.ReadMeta();
  reader.ReadAllGates();
  std::shared_ptr<yacl::io::BFCircuit> circ_ = reader.StealCirc();

  func(*circ_);

  cout << "origin:" << circ_->ng << endl;

  return 0;
}

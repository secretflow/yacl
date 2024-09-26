// Copyright 2024 Ant Group Co., Ltd.
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

#include "examples/psi/python/ecdh_psi_pybind.h"

#include "pybind11/complex.h"
#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"

#define NO_GIL py::call_guard<py::gil_scoped_release>()

namespace examples::psi {

void BindLibs(py::module& m) {
  // see:
  // https://pybind11.readthedocs.io/en/stable/advanced/cast/strings.html#returning-c-strings-to-python
  // NOTE When a C++ function returns a std::string or char* to a Python caller,
  // pybind11 will assume that the string is valid UTF-8
  py::class_<EcdhPsiPy>(m, "EcdhPsiCC", "The ECDH PSI protocol class")
      .def(py::init<>())
      .def("MaskStrings", &EcdhPsiPy::MaskStrings)
      .def("MaskEcPointsAndHashToU128", &EcdhPsiPy::MaskEcPointsAndHashToU128);
}

PYBIND11_MODULE(ecdh_psi_pybind, m) {
  py::module libs_m = m.def_submodule("libs");
  BindLibs(libs_m);
}

}  // namespace examples::psi

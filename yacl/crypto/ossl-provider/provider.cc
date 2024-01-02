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

#include "yacl/crypto/ossl-provider/rand_impl.h"
#include "yacl/crypto/ossl-provider/version.h"

using FuncPtr = void (*)();

// FIXME(@shanzhu.cjm): Indirect memeory leak
// Declare the function types that yacl provider provides
static const OSSL_ALGORITHM provider_rands[] = {
    {/* algorithm_names */ "Yes", /* Yacl's entropy source */
     /* property_definition */ "provider=yes",
     /* implementations */ yacl_rand_prov_functions,
     /* algorithm_description */ "yacl's self-defined random entropy source"},
    {nullptr, nullptr, nullptr, nullptr}};

/* Parameters we provide to the core */
static const OSSL_PARAM yacl_prov_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END};

// The function that returns the appropriate algorithm table per operation
static const OSSL_ALGORITHM *yacl_prov_operation(ossl_unused void *vprov,
                                                 ossl_unused int operation_id,
                                                 int *no_cache) {
  *no_cache = 0;
  switch (operation_id) {
    case OSSL_OP_RAND: /* Yacl Provider only supports rand operation */
      return provider_rands;
  }
  return nullptr;
}

// provider status function
static int yacl_prov_is_running() { return 1; }

// tear down yacl's entropy source provider
static void yacl_prov_ctx_teardown(ossl_unused void *vprov) {}

static const OSSL_PARAM *yacl_prov_gettable_params(
    ossl_unused const OSSL_PROVIDER *prov) {
  return yacl_prov_param_types;
}

static int yacl_prov_get_params(ossl_unused const OSSL_PROVIDER *provctx,
                                OSSL_PARAM params[]) {
  OSSL_PARAM *p;

  p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
  if (p != nullptr && (OSSL_PARAM_set_utf8_ptr(p, YACL_STR) == 0)) {
    return 0;
  }
  p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
  if (p != nullptr && (OSSL_PARAM_set_utf8_ptr(p, YACL_VERSION_STR) == 0)) {
    return 0;
  }
  p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
  if (p != nullptr &&
      (OSSL_PARAM_set_utf8_ptr(p, YACL_FULL_VERSION_STR) == 0)) {
    return 0;
  }
  p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
  if (p != nullptr && (OSSL_PARAM_set_int(p, yacl_prov_is_running()) == 0)) {
    return 0;
  }
  return 1;
}

// ----------------------
// Setup OpsnSSL Provider
// ----------------------

// the dispatched functions that yacl's entropy source should implement
static const OSSL_DISPATCH yacl_prov_funcs[] = {
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
     reinterpret_cast<FuncPtr>(yacl_prov_gettable_params)},
    {OSSL_FUNC_PROVIDER_GET_PARAMS,
     reinterpret_cast<FuncPtr>(yacl_prov_get_params)},
    {OSSL_FUNC_PROVIDER_TEARDOWN,
     reinterpret_cast<FuncPtr>(yacl_prov_ctx_teardown)},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION,
     reinterpret_cast<FuncPtr>(yacl_prov_operation)},
    {0, nullptr}};

// the provider entry point
int OSSL_provider_init(const OSSL_CORE_HANDLE *core,
                       ossl_unused const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out, void **vprov) {
  /* Could be anything - we don't use it */
  *vprov = (void *)core;

  // init provider functions
  *out = yacl_prov_funcs;

  return 1;
}

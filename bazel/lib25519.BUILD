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

load("@rules_cc//cc:defs.bzl", "cc_library")

genrule(
    name = "crypto_uint64_h",
    srcs = ["inttypes/crypto_uintN.h"],
    outs = ["include-build/crypto_uint64.h"],
    cmd = "sed -e 's/N/64/g' $(<) > $(@)",
)

genrule(
    name = "crypto_verify_c",
    srcs = ["crypto_verify/32/ref/verify.c"],
    outs = ["crypto_verify.c"],
    cmd = "cat $(<) > $(@)",
)

genrule(
    name = "crypto_verify_h",
    outs = ["include-build/crypto_verify.h"],
    cmd = """
cat > $@ << EOF
#ifndef crypto_verify_h
#define crypto_verify_h

#define crypto_verify CRYPTO_NAMESPACE(verify)

#define crypto_verify_32_BYTES 32
#define crypto_verify_BYTES 32

extern int crypto_verify(const unsigned char *,const unsigned char *);

#endif

EOF"""
)

genrule(
    name = "ge25519_unpack_c",
    srcs = ["crypto_multiscalar/ed25519/amd64-maax-p3/ge25519_unpack.c"],
    outs = ["ge25519_unpack.c"],
    cmd = "sed -e 's/crypto_verify_32/crypto_verify/g' $(<) > $(@)",
)

genrule(
    name = "ge25519_sub_h",
    outs = ["include-build/ge25519_sub.h"],
    cmd = """
cat > $@ << EOF
#ifndef ge25519_sub_h
#define ge25519_sub_h

#include "ge25519.h"

#define ge25519_sub         CRYPTO_NAMESPACE(ge25519_sub)

extern void ge25519_sub(ge25519 *r, const ge25519 *p, const ge25519 *q);

#endif

EOF"""
)

genrule(
    name = "ge25519_sub_c",
    outs = ["ge25519_sub.c"],
    cmd = """
cat > $@ << EOF
#include "ge25519_sub.h"

void ge25519_sub(ge25519 *r, const ge25519 *p, const ge25519 *q)
{
  ge25519_p3 qneg;
  fe25519_neg(&qneg.x,&q->x);
  fe25519_neg(&qneg.t,&q->t);
  qneg.y = q->y;
  qneg.z = q->z;
  ge25519_add(r,p,&qneg);
}

EOF"""
)

genrule(
    name = "ge25519_scalarmult_h",
    outs = ["include-build/ge25519_scalarmult.h"],
    cmd = """
cat > $@ << EOF
#ifndef ge25519_scalarmult_h
#define ge25519_scalarmult_h

#include "ge25519.h"

#define ge25519_scalarmult         CRYPTO_NAMESPACE(ge25519_scalarmult)

extern void ge25519_scalarmult(ge25519 *r, const ge25519 *p, const sc25519 *s);

#endif

EOF"""
)

genrule(
    name = "ge25519_scalarmult_c",
    outs = ["ge25519_scalarmult.c"],
    cmd = """
cat > $@ << EOF
#include "ge25519_scalarmult.h"
#include "ge25519_sub.h"

// warning: these constants are not encapsulated
#define P_WINDOWSIZE 5
#define P_MULTIPLES (1<<(P_WINDOWSIZE-2))
static void ge25519_p3_0(ge25519_p3 *r)
{
  fe25519_setint(&r->x,0);
  fe25519_setint(&r->y,1);
  fe25519_setint(&r->z,1);
  fe25519_setint(&r->t,0);
}
static void ge25519_multi_scalarmult_precompute(ge25519_p3 *cP, const ge25519_p3 *P, unsigned long long multiples)
{
  __attribute__ ((aligned(32))) ge25519_p3 twoP;
  ge25519_double(&twoP,P);
  cP[0] = *P;
  for (long long i = 0;i < multiples-1;++i)
    ge25519_add(&cP[i+1],&twoP,&cP[i]);
}
static void ge25519_multi_scalarmult_process(ge25519_p3 *r, const signed char nslide[256], const ge25519_p3 cP[P_MULTIPLES])
{
  int maybenonzero = 0;
  ge25519_p3_0(r);
  for (long long i = 255;i >= 0;--i) {
    if (maybenonzero)
      ge25519_double(r,r);
    signed char c = nslide[i];
    if (c != 0) {
      maybenonzero = 1;
      if (c > 0)
        ge25519_add(r,r,&cP[c/2]);
      else
        ge25519_sub(r,r,&cP[-c/2]);
    }
  }
}
void ge25519_scalarmult(ge25519 *r, const ge25519 *p, const sc25519 *s) {
  signed char nslide[256];
  ge25519_p3 cP[P_MULTIPLES]; /* P,3P,5P,7P,9P,11P,13P,15P */
  sc25519_slide(nslide,s,P_WINDOWSIZE);
  ge25519_multi_scalarmult_precompute(cP,p,P_MULTIPLES);
  ge25519_multi_scalarmult_process(r,nslide,cP);
}

EOF"""
)

genrule(
    name = "ge25519_is_on_curve_h",
    outs = ["include-build/ge25519_is_on_curve.h"],
    cmd = """
cat > $@ << EOF
#ifndef ge25519_is_on_curve_h
#define ge25519_is_on_curve_h

#include "ge25519.h"

#define ge25519_is_on_curve         CRYPTO_NAMESPACE(ge25519_is_on_curve)

extern int ge25519_is_on_curve(const ge25519 *p);

#endif

EOF"""
)

genrule(
    name = "ge25519_is_on_curve_c",
    outs = ["ge25519_is_on_curve.c"],
    cmd = """
cat > $@ << EOF
#include "ge25519_is_on_curve.h"

/* d */
static const fe25519 ecd = {{0x75EB4DCA135978A3, 0x00700A4D4141D8AB, 0x8CC740797779E898, 0x52036CEE2B6FFE73}};

static const fe25519 zero = {{0,0,0,0}};

int ge25519_is_on_curve(const ge25519_p3 *p)
{
  fe25519 x2;
  fe25519 y2;
  fe25519 z2;
  fe25519 z4;
  fe25519 t0;
  fe25519 t1;

  fe25519_square(&x2, &p->x);
  fe25519_square(&y2, &p->y);
  fe25519_square(&z2, &p->z);
  fe25519_sub(&t0, &y2, &x2);
  fe25519_mul(&t0, &t0, &z2);

  fe25519_mul(&t1, &x2, &y2);
  fe25519_mul(&t1, &t1, &ecd);
  fe25519_square(&z4, &z2);
  fe25519_add(&t1, &t1, &z4);
  fe25519_sub(&t0, &t0, &t1);

  return fe25519_iseq_vartime(&t0, &zero) != 0;
}

EOF"""
)

cc_library(
    name = "25519",
    srcs = [
        "crypto_multiscalar/ed25519/amd64-maax-p3/fe25519_add.S",
        "crypto_multiscalar/ed25519/amd64-maax-p3/fe25519_freeze.S",
        "crypto_multiscalar/ed25519/amd64-maax-p3/fe25519_getparity.c",
        "crypto_multiscalar/ed25519/amd64-maax-p3/fe25519_iseq.c",
        "crypto_multiscalar/ed25519/amd64-maax-p3/fe25519_mul.S",
        "crypto_multiscalar/ed25519/amd64-maax-p3/fe25519_neg.c",
        "crypto_multiscalar/ed25519/amd64-maax-p3/fe25519_pack.c",
        "crypto_multiscalar/ed25519/amd64-maax-p3/fe25519_unpack.c",
        "crypto_multiscalar/ed25519/amd64-maax-p3/fe25519_setint.c",
        "crypto_multiscalar/ed25519/amd64-maax-p3/fe25519_sub.S",
        "crypto_multiscalar/ed25519/amd64-maax-p3/fe25519_pow2523.c",  # referenced by ge25519_unpack
        "crypto_multiscalar/ed25519/amd64-maax-p3/ge25519_add.S",
        "crypto_multiscalar/ed25519/amd64-maax-p3/ge25519_double.S",
        "crypto_multiscalar/ed25519/amd64-maax-p3/sc25519_from32bytes.c",
        "crypto_multiscalar/ed25519/amd64-maax-p3/sc25519_to32bytes.c",
        "crypto_multiscalar/ed25519/amd64-maax-p3/sc25519_slide.c",
        "crypto_multiscalar/ed25519/amd64-maax-p3/shared-consts.c",
        "crypto_pow/inv25519/amd64-maax/fe25519_invert.c",
        "crypto_pow/inv25519/amd64-maax/fe25519_nsquare.S",
        "crypto_pow/inv25519/amd64-maax/fe25519_square.S",
        "crypto_nG/merged25519/amd64-maax/fe25519_cmov.c",
        "crypto_nG/merged25519/amd64-maax/ge25519_base.S",
        "crypto_nG/merged25519/amd64-maax/ge25519_scalarmult_base.c",
        "crypto_nG/merged25519/amd64-maax/sc25519_window4.c",
        "crypto_nG/merged25519/amd64-maax/shared-base-data.c",
        "crypto_mGnP/ed25519/amd64-maax/ge25519_pack.c",
        "crypto_verify.c",
        "ge25519_sub.c",
        "ge25519_unpack.c",
        "ge25519_scalarmult.c",
        "ge25519_is_on_curve.c",
        "include-build/crypto_asm_hidden.h",
        "include-build/crypto_uint64.h",
        "include-build/crypto_verify.h",
    ],
    hdrs = [
        "crypto_multiscalar/ed25519/amd64-maax-p3/sc25519.h",
        "crypto_multiscalar/ed25519/amd64-maax-p3/ge25519_unpack.h",
        "crypto_nG/merged25519/amd64-maax/fe25519.h",
        "crypto_nG/merged25519/amd64-maax/ge25519.h",
        "crypto_nG/merged25519/amd64-maax/ge25519_base_niels.data",
        "include-build/ge25519_sub.h",
        "include-build/ge25519_scalarmult.h",
        "include-build/ge25519_is_on_curve.h",
    ],
    includes = [
        "crypto_multiscalar/ed25519/amd64-maax-p3",
        "crypto_nG/merged25519/amd64-maax",
        "include-build",
    ],
    defines = [
        "CRYPTO_NAMESPACE(name)=crypto_##name",
        "_CRYPTO_NAMESPACE(name)=_crypto_##name",
        "CRYPTO_SHARED_NAMESPACE(name)=crypto_shared_##name",
        "_CRYPTO_SHARED_NAMESPACE(name)=_crypto_shared_##name",
    ],
    copts = ["-fvisibility=hidden"],
    visibility = ["//visibility:public"],
    linkstatic = True,
)
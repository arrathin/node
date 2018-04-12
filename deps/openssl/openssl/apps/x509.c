/* apps/x509.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "\x54\x68\x69\x73\x20\x70\x72\x6f\x64\x75\x63\x74\x20\x69\x6e\x63\x6c\x75\x64\x65\x73\x20\x73\x6f\x66\x74\x77\x61\x72\x65\x20\x77\x72\x69\x74\x74\x65\x6e\x20\x62\x79\x20\x54\x69\x6d\x20\x48\x75\x64\x73\x6f\x6e\x20\x28\x74\x6a\x68\x40\x63\x72\x79\x70\x74\x73\x6f\x66\x74\x2e\x63\x6f\x6d\x29"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef OPENSSL_NO_STDIO
# define APPS_WIN16
#endif
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
# include <openssl/dsa.h>
#endif

#undef PROG
#define PROG x509_main

#undef POSTFIX
#define POSTFIX "\x2e\x73\x72\x6c"
#define DEF_DAYS        30

static const char *x509_usage[] = {
    "\x75\x73\x61\x67\x65\x3a\x20\x78\x35\x30\x39\x20\x61\x72\x67\x73\xa",
    "\x20\x2d\x69\x6e\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x20\x20\x2d\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20\x64\x65\x66\x61\x75\x6c\x74\x20\x50\x45\x4d\x20\x28\x6f\x6e\x65\x20\x6f\x66\x20\x44\x45\x52\x2c\x20\x4e\x45\x54\x20\x6f\x72\x20\x50\x45\x4d\x29\xa",
    "\x20\x2d\x6f\x75\x74\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x20\x2d\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20\x64\x65\x66\x61\x75\x6c\x74\x20\x50\x45\x4d\x20\x28\x6f\x6e\x65\x20\x6f\x66\x20\x44\x45\x52\x2c\x20\x4e\x45\x54\x20\x6f\x72\x20\x50\x45\x4d\x29\xa",
    "\x20\x2d\x6b\x65\x79\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20\x64\x65\x66\x61\x75\x6c\x74\x20\x50\x45\x4d\xa",
    "\x20\x2d\x43\x41\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x20\x20\x2d\x20\x43\x41\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20\x64\x65\x66\x61\x75\x6c\x74\x20\x50\x45\x4d\xa",
    "\x20\x2d\x43\x41\x6b\x65\x79\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x2d\x20\x43\x41\x20\x6b\x65\x79\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20\x64\x65\x66\x61\x75\x6c\x74\x20\x50\x45\x4d\xa",
    "\x20\x2d\x69\x6e\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x2d\x20\x64\x65\x66\x61\x75\x6c\x74\x20\x73\x74\x64\x69\x6e\xa",
    "\x20\x2d\x6f\x75\x74\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x2d\x20\x64\x65\x66\x61\x75\x6c\x74\x20\x73\x74\x64\x6f\x75\x74\xa",
    "\x20\x2d\x70\x61\x73\x73\x69\x6e\x20\x61\x72\x67\x20\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x20\x73\x6f\x75\x72\x63\x65\xa",
    "\x20\x2d\x73\x65\x72\x69\x61\x6c\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x73\x65\x72\x69\x61\x6c\x20\x6e\x75\x6d\x62\x65\x72\x20\x76\x61\x6c\x75\x65\xa",
    "\x20\x2d\x73\x75\x62\x6a\x65\x63\x74\x5f\x68\x61\x73\x68\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x73\x75\x62\x6a\x65\x63\x74\x20\x68\x61\x73\x68\x20\x76\x61\x6c\x75\x65\xa",
#ifndef OPENSSL_NO_MD5
    "\x20\x2d\x73\x75\x62\x6a\x65\x63\x74\x5f\x68\x61\x73\x68\x5f\x6f\x6c\x64\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x6f\x6c\x64\x2d\x73\x74\x79\x6c\x65\x20\x28\x4d\x44\x35\x29\x20\x73\x75\x62\x6a\x65\x63\x74\x20\x68\x61\x73\x68\x20\x76\x61\x6c\x75\x65\xa",
#endif
    "\x20\x2d\x69\x73\x73\x75\x65\x72\x5f\x68\x61\x73\x68\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x69\x73\x73\x75\x65\x72\x20\x68\x61\x73\x68\x20\x76\x61\x6c\x75\x65\xa",
#ifndef OPENSSL_NO_MD5
    "\x20\x2d\x69\x73\x73\x75\x65\x72\x5f\x68\x61\x73\x68\x5f\x6f\x6c\x64\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x6f\x6c\x64\x2d\x73\x74\x79\x6c\x65\x20\x28\x4d\x44\x35\x29\x20\x69\x73\x73\x75\x65\x72\x20\x68\x61\x73\x68\x20\x76\x61\x6c\x75\x65\xa",
#endif
    "\x20\x2d\x68\x61\x73\x68\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x73\x79\x6e\x6f\x6e\x79\x6d\x20\x66\x6f\x72\x20\x2d\x73\x75\x62\x6a\x65\x63\x74\x5f\x68\x61\x73\x68\xa",
    "\x20\x2d\x73\x75\x62\x6a\x65\x63\x74\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x73\x75\x62\x6a\x65\x63\x74\x20\x44\x4e\xa",
    "\x20\x2d\x69\x73\x73\x75\x65\x72\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x69\x73\x73\x75\x65\x72\x20\x44\x4e\xa",
    "\x20\x2d\x65\x6d\x61\x69\x6c\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x65\x6d\x61\x69\x6c\x20\x61\x64\x64\x72\x65\x73\x73\x28\x65\x73\x29\xa",
    "\x20\x2d\x73\x74\x61\x72\x74\x64\x61\x74\x65\x20\x20\x20\x20\x20\x20\x2d\x20\x6e\x6f\x74\x42\x65\x66\x6f\x72\x65\x20\x66\x69\x65\x6c\x64\xa",
    "\x20\x2d\x65\x6e\x64\x64\x61\x74\x65\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x6e\x6f\x74\x41\x66\x74\x65\x72\x20\x66\x69\x65\x6c\x64\xa",
    "\x20\x2d\x70\x75\x72\x70\x6f\x73\x65\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x6f\x75\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x70\x75\x72\x70\x6f\x73\x65\x73\xa",
    "\x20\x2d\x64\x61\x74\x65\x73\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x62\x6f\x74\x68\x20\x42\x65\x66\x6f\x72\x65\x20\x61\x6e\x64\x20\x41\x66\x74\x65\x72\x20\x64\x61\x74\x65\x73\xa",
    "\x20\x2d\x6d\x6f\x64\x75\x6c\x75\x73\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x74\x68\x65\x20\x52\x53\x41\x20\x6b\x65\x79\x20\x6d\x6f\x64\x75\x6c\x75\x73\xa",
    "\x20\x2d\x70\x75\x62\x6b\x65\x79\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x6f\x75\x74\x70\x75\x74\x20\x74\x68\x65\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\xa",
    "\x20\x2d\x66\x69\x6e\x67\x65\x72\x70\x72\x69\x6e\x74\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x74\x68\x65\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x66\x69\x6e\x67\x65\x72\x70\x72\x69\x6e\x74\xa",
    "\x20\x2d\x61\x6c\x69\x61\x73\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x6f\x75\x74\x70\x75\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x61\x6c\x69\x61\x73\xa",
    "\x20\x2d\x6e\x6f\x6f\x75\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x6e\x6f\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x6f\x75\x74\x70\x75\x74\xa",
    "\x20\x2d\x6f\x63\x73\x70\x69\x64\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x4f\x43\x53\x50\x20\x68\x61\x73\x68\x20\x76\x61\x6c\x75\x65\x73\x20\x66\x6f\x72\x20\x74\x68\x65\x20\x73\x75\x62\x6a\x65\x63\x74\x20\x6e\x61\x6d\x65\x20\x61\x6e\x64\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\xa",
    "\x20\x2d\x6f\x63\x73\x70\x5f\x75\x72\x69\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x4f\x43\x53\x50\x20\x52\x65\x73\x70\x6f\x6e\x64\x65\x72\x20\x55\x52\x4c\x28\x73\x29\xa",
    "\x20\x2d\x74\x72\x75\x73\x74\x6f\x75\x74\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x6f\x75\x74\x70\x75\x74\x20\x61\x20\x22\x74\x72\x75\x73\x74\x65\x64\x22\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\xa",
    "\x20\x2d\x63\x6c\x72\x74\x72\x75\x73\x74\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x63\x6c\x65\x61\x72\x20\x61\x6c\x6c\x20\x74\x72\x75\x73\x74\x65\x64\x20\x70\x75\x72\x70\x6f\x73\x65\x73\xa",
    "\x20\x2d\x63\x6c\x72\x72\x65\x6a\x65\x63\x74\x20\x20\x20\x20\x20\x20\x2d\x20\x63\x6c\x65\x61\x72\x20\x61\x6c\x6c\x20\x72\x65\x6a\x65\x63\x74\x65\x64\x20\x70\x75\x72\x70\x6f\x73\x65\x73\xa",
    "\x20\x2d\x61\x64\x64\x74\x72\x75\x73\x74\x20\x61\x72\x67\x20\x20\x20\x2d\x20\x74\x72\x75\x73\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x66\x6f\x72\x20\x61\x20\x67\x69\x76\x65\x6e\x20\x70\x75\x72\x70\x6f\x73\x65\xa",
    "\x20\x2d\x61\x64\x64\x72\x65\x6a\x65\x63\x74\x20\x61\x72\x67\x20\x20\x2d\x20\x72\x65\x6a\x65\x63\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x66\x6f\x72\x20\x61\x20\x67\x69\x76\x65\x6e\x20\x70\x75\x72\x70\x6f\x73\x65\xa",
    "\x20\x2d\x73\x65\x74\x61\x6c\x69\x61\x73\x20\x61\x72\x67\x20\x20\x20\x2d\x20\x73\x65\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x61\x6c\x69\x61\x73\xa",
    "\x20\x2d\x64\x61\x79\x73\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x48\x6f\x77\x20\x6c\x6f\x6e\x67\x20\x74\x69\x6c\x6c\x20\x65\x78\x70\x69\x72\x79\x20\x6f\x66\x20\x61\x20\x73\x69\x67\x6e\x65\x64\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x2d\x20\x64\x65\x66\x20\x33\x30\x20\x64\x61\x79\x73\xa",
    "\x20\x2d\x63\x68\x65\x63\x6b\x65\x6e\x64\x20\x61\x72\x67\x20\x20\x20\x2d\x20\x63\x68\x65\x63\x6b\x20\x77\x68\x65\x74\x68\x65\x72\x20\x74\x68\x65\x20\x63\x65\x72\x74\x20\x65\x78\x70\x69\x72\x65\x73\x20\x69\x6e\x20\x74\x68\x65\x20\x6e\x65\x78\x74\x20\x61\x72\x67\x20\x73\x65\x63\x6f\x6e\x64\x73\xa",
    "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x78\x69\x74\x20\x31\x20\x69\x66\x20\x73\x6f\x2c\x20\x30\x20\x69\x66\x20\x6e\x6f\x74\xa",
    "\x20\x2d\x73\x69\x67\x6e\x6b\x65\x79\x20\x61\x72\x67\x20\x20\x20\x20\x2d\x20\x73\x65\x6c\x66\x20\x73\x69\x67\x6e\x20\x63\x65\x72\x74\x20\x77\x69\x74\x68\x20\x61\x72\x67\xa",
    "\x20\x2d\x78\x35\x30\x39\x74\x6f\x72\x65\x71\x20\x20\x20\x20\x20\x20\x2d\x20\x6f\x75\x74\x70\x75\x74\x20\x61\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x20\x72\x65\x71\x75\x65\x73\x74\x20\x6f\x62\x6a\x65\x63\x74\xa",
    "\x20\x2d\x72\x65\x71\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x69\x6e\x70\x75\x74\x20\x69\x73\x20\x61\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x72\x65\x71\x75\x65\x73\x74\x2c\x20\x73\x69\x67\x6e\x20\x61\x6e\x64\x20\x6f\x75\x74\x70\x75\x74\x2e\xa",
    "\x20\x2d\x43\x41\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x73\x65\x74\x20\x74\x68\x65\x20\x43\x41\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x2c\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x50\x45\x4d\x20\x66\x6f\x72\x6d\x61\x74\x2e\xa",
    "\x20\x2d\x43\x41\x6b\x65\x79\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x2d\x20\x73\x65\x74\x20\x74\x68\x65\x20\x43\x41\x20\x6b\x65\x79\x2c\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x50\x45\x4d\x20\x66\x6f\x72\x6d\x61\x74\xa",
    "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6d\x69\x73\x73\x69\x6e\x67\x2c\x20\x69\x74\x20\x69\x73\x20\x61\x73\x73\x75\x6d\x65\x64\x20\x74\x6f\x20\x62\x65\x20\x69\x6e\x20\x74\x68\x65\x20\x43\x41\x20\x66\x69\x6c\x65\x2e\xa",
    "\x20\x2d\x43\x41\x63\x72\x65\x61\x74\x65\x73\x65\x72\x69\x61\x6c\x20\x2d\x20\x63\x72\x65\x61\x74\x65\x20\x73\x65\x72\x69\x61\x6c\x20\x6e\x75\x6d\x62\x65\x72\x20\x66\x69\x6c\x65\x20\x69\x66\x20\x69\x74\x20\x64\x6f\x65\x73\x20\x6e\x6f\x74\x20\x65\x78\x69\x73\x74\xa",
    "\x20\x2d\x43\x41\x73\x65\x72\x69\x61\x6c\x20\x61\x72\x67\x20\x20\x20\x2d\x20\x73\x65\x72\x69\x61\x6c\x20\x66\x69\x6c\x65\xa",
    "\x20\x2d\x73\x65\x74\x5f\x73\x65\x72\x69\x61\x6c\x20\x20\x20\x20\x20\x2d\x20\x73\x65\x72\x69\x61\x6c\x20\x6e\x75\x6d\x62\x65\x72\x20\x74\x6f\x20\x75\x73\x65\xa",
    "\x20\x2d\x74\x65\x78\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x74\x68\x65\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x69\x6e\x20\x74\x65\x78\x74\x20\x66\x6f\x72\x6d\xa",
    "\x20\x2d\x43\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x6f\x75\x74\x20\x43\x20\x63\x6f\x64\x65\x20\x66\x6f\x72\x6d\x73\xa",
    "\x20\x2d\x6d\x64\x32\x2f\x2d\x6d\x64\x35\x2f\x2d\x73\x68\x61\x31\x2f\x2d\x6d\x64\x63\x32\x20\x2d\x20\x64\x69\x67\x65\x73\x74\x20\x74\x6f\x20\x75\x73\x65\xa",
    "\x20\x2d\x65\x78\x74\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x63\x6f\x6e\x66\x69\x67\x75\x72\x61\x74\x69\x6f\x6e\x20\x66\x69\x6c\x65\x20\x77\x69\x74\x68\x20\x58\x35\x30\x39\x56\x33\x20\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73\x20\x74\x6f\x20\x61\x64\x64\xa",
    "\x20\x2d\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73\x20\x20\x20\x20\x20\x2d\x20\x73\x65\x63\x74\x69\x6f\x6e\x20\x66\x72\x6f\x6d\x20\x63\x6f\x6e\x66\x69\x67\x20\x66\x69\x6c\x65\x20\x77\x69\x74\x68\x20\x58\x35\x30\x39\x56\x33\x20\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73\x20\x74\x6f\x20\x61\x64\x64\xa",
    "\x20\x2d\x63\x6c\x72\x65\x78\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x64\x65\x6c\x65\x74\x65\x20\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73\x20\x62\x65\x66\x6f\x72\x65\x20\x73\x69\x67\x6e\x69\x6e\x67\x20\x61\x6e\x64\x20\x69\x6e\x70\x75\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\xa",
    "\x20\x2d\x6e\x61\x6d\x65\x6f\x70\x74\x20\x61\x72\x67\x20\x20\x20\x20\x2d\x20\x76\x61\x72\x69\x6f\x75\x73\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x6e\x61\x6d\x65\x20\x6f\x70\x74\x69\x6f\x6e\x73\xa",
#ifndef OPENSSL_NO_ENGINE
    "\x20\x2d\x65\x6e\x67\x69\x6e\x65\x20\x65\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x65\x2c\x20\x70\x6f\x73\x73\x69\x62\x6c\x79\x20\x61\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20\x64\x65\x76\x69\x63\x65\x2e\xa",
#endif
    "\x20\x2d\x63\x65\x72\x74\x6f\x70\x74\x20\x61\x72\x67\x20\x20\x20\x20\x2d\x20\x76\x61\x72\x69\x6f\x75\x73\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x74\x65\x78\x74\x20\x6f\x70\x74\x69\x6f\x6e\x73\xa",
    "\x20\x2d\x63\x68\x65\x63\x6b\x68\x6f\x73\x74\x20\x68\x6f\x73\x74\x20\x2d\x20\x63\x68\x65\x63\x6b\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x6d\x61\x74\x63\x68\x65\x73\x20\x22\x68\x6f\x73\x74\x22\xa",
    "\x20\x2d\x63\x68\x65\x63\x6b\x65\x6d\x61\x69\x6c\x20\x65\x6d\x61\x69\x6c\x20\x2d\x20\x63\x68\x65\x63\x6b\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x6d\x61\x74\x63\x68\x65\x73\x20\x22\x65\x6d\x61\x69\x6c\x22\xa",
    "\x20\x2d\x63\x68\x65\x63\x6b\x69\x70\x20\x69\x70\x61\x64\x64\x72\x20\x2d\x20\x63\x68\x65\x63\x6b\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x6d\x61\x74\x63\x68\x65\x73\x20\x22\x69\x70\x61\x64\x64\x72\x22\xa",
    NULL
};

static int MS_CALLBACK callb(int ok, X509_STORE_CTX *ctx);
static int sign(X509 *x, EVP_PKEY *pkey, int days, int clrext,
                const EVP_MD *digest, CONF *conf, char *section);
static int x509_certify(X509_STORE *ctx, char *CAfile, const EVP_MD *digest,
                        X509 *x, X509 *xca, EVP_PKEY *pkey,
                        STACK_OF(OPENSSL_STRING) *sigopts, char *serial,
                        int create, int days, int clrext, CONF *conf,
                        char *section, ASN1_INTEGER *sno);
static int purpose_print(BIO *bio, X509 *cert, X509_PURPOSE *pt);
static int reqfile = 0;
#ifdef OPENSSL_SSL_DEBUG_BROKEN_PROTOCOL
static int force_version = 2;
#endif

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    ENGINE *e = NULL;
    int ret = 1;
    X509_REQ *req = NULL;
    X509 *x = NULL, *xca = NULL;
    ASN1_OBJECT *objtmp;
    STACK_OF(OPENSSL_STRING) *sigopts = NULL;
    EVP_PKEY *Upkey = NULL, *CApkey = NULL, *fkey = NULL;
    ASN1_INTEGER *sno = NULL;
    int i, num, badops = 0, badsig = 0;
    BIO *out = NULL;
    BIO *STDout = NULL;
    STACK_OF(ASN1_OBJECT) *trust = NULL, *reject = NULL;
    int informat, outformat, keyformat, CAformat, CAkeyformat;
    char *infile = NULL, *outfile = NULL, *keyfile = NULL, *CAfile = NULL;
    char *CAkeyfile = NULL, *CAserial = NULL;
    char *fkeyfile = NULL;
    char *alias = NULL;
    int text = 0, serial = 0, subject = 0, issuer = 0, startdate =
        0, enddate = 0;
    int next_serial = 0;
    int subject_hash = 0, issuer_hash = 0, ocspid = 0;
#ifndef OPENSSL_NO_MD5
    int subject_hash_old = 0, issuer_hash_old = 0;
#endif
    int noout = 0, sign_flag = 0, CA_flag = 0, CA_createserial = 0, email = 0;
    int ocsp_uri = 0;
    int trustout = 0, clrtrust = 0, clrreject = 0, aliasout = 0, clrext = 0;
    int C = 0;
    int x509req = 0, days = DEF_DAYS, modulus = 0, pubkey = 0;
    int pprint = 0;
    const char **pp;
    X509_STORE *ctx = NULL;
    X509_REQ *rq = NULL;
    int fingerprint = 0;
    char buf[256];
    const EVP_MD *md_alg, *digest = NULL;
    CONF *extconf = NULL;
    char *extsect = NULL, *extfile = NULL, *passin = NULL, *passargin = NULL;
    int need_rand = 0;
    int checkend = 0, checkoffset = 0;
    unsigned long nmflag = 0, certflag = 0;
    char *checkhost = NULL;
    char *checkemail = NULL;
    char *checkip = NULL;
    char *engine = NULL;

    reqfile = 0;

    apps_startup();

    if (bio_err == NULL)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!load_config(bio_err, NULL))
        goto end;
    STDout = BIO_new_fp(stdout, BIO_NOCLOSE);
#ifdef OPENSSL_SYS_VMS
    {
        BIO *tmpbio = BIO_new(BIO_f_linebuffer());
        STDout = BIO_push(tmpbio, STDout);
    }
#endif

    informat = FORMAT_PEM;
    outformat = FORMAT_PEM;
    keyformat = FORMAT_PEM;
    CAformat = FORMAT_PEM;
    CAkeyformat = FORMAT_PEM;

    ctx = X509_STORE_new();
    if (ctx == NULL)
        goto end;
    X509_STORE_set_verify_cb(ctx, callb);

    argc--;
    argv++;
    num = 0;
    while (argc >= 1) {
        if (strcmp(*argv, "\x2d\x69\x6e\x66\x6f\x72\x6d") == 0) {
            if (--argc < 1)
                goto bad;
            informat = str2fmt(*(++argv));
        } else if (strcmp(*argv, "\x2d\x6f\x75\x74\x66\x6f\x72\x6d") == 0) {
            if (--argc < 1)
                goto bad;
            outformat = str2fmt(*(++argv));
        } else if (strcmp(*argv, "\x2d\x6b\x65\x79\x66\x6f\x72\x6d") == 0) {
            if (--argc < 1)
                goto bad;
            keyformat = str2fmt(*(++argv));
        } else if (strcmp(*argv, "\x2d\x72\x65\x71") == 0) {
            reqfile = 1;
            need_rand = 1;
        } else if (strcmp(*argv, "\x2d\x43\x41\x66\x6f\x72\x6d") == 0) {
            if (--argc < 1)
                goto bad;
            CAformat = str2fmt(*(++argv));
        } else if (strcmp(*argv, "\x2d\x43\x41\x6b\x65\x79\x66\x6f\x72\x6d") == 0) {
            if (--argc < 1)
                goto bad;
            CAkeyformat = str2fmt(*(++argv));
        } else if (strcmp(*argv, "\x2d\x73\x69\x67\x6f\x70\x74") == 0) {
            if (--argc < 1)
                goto bad;
            if (!sigopts)
                sigopts = sk_OPENSSL_STRING_new_null();
            if (!sigopts || !sk_OPENSSL_STRING_push(sigopts, *(++argv)))
                goto bad;
        }
#ifdef OPENSSL_SSL_DEBUG_BROKEN_PROTOCOL
        else if (strcmp(*argv, "\x2d\x66\x6f\x72\x63\x65\x5f\x76\x65\x72\x73\x69\x6f\x6e") == 0) {
            if (--argc < 1)
                goto bad;
            force_version = atoi(*(++argv)) - 1;
        }
#endif
        else if (strcmp(*argv, "\x2d\x64\x61\x79\x73") == 0) {
            if (--argc < 1)
                goto bad;
            days = atoi(*(++argv));
            if (days == 0) {
                BIO_printf(bio_err, "\x62\x61\x64\x20\x6e\x75\x6d\x62\x65\x72\x20\x6f\x66\x20\x64\x61\x79\x73\xa");
                goto bad;
            }
        } else if (strcmp(*argv, "\x2d\x70\x61\x73\x73\x69\x6e") == 0) {
            if (--argc < 1)
                goto bad;
            passargin = *(++argv);
        } else if (strcmp(*argv, "\x2d\x65\x78\x74\x66\x69\x6c\x65") == 0) {
            if (--argc < 1)
                goto bad;
            extfile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73") == 0) {
            if (--argc < 1)
                goto bad;
            extsect = *(++argv);
        } else if (strcmp(*argv, "\x2d\x69\x6e") == 0) {
            if (--argc < 1)
                goto bad;
            infile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6f\x75\x74") == 0) {
            if (--argc < 1)
                goto bad;
            outfile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x73\x69\x67\x6e\x6b\x65\x79") == 0) {
            if (--argc < 1)
                goto bad;
            keyfile = *(++argv);
            sign_flag = ++num;
            need_rand = 1;
        } else if (strcmp(*argv, "\x2d\x43\x41") == 0) {
            if (--argc < 1)
                goto bad;
            CAfile = *(++argv);
            CA_flag = ++num;
            need_rand = 1;
        } else if (strcmp(*argv, "\x2d\x43\x41\x6b\x65\x79") == 0) {
            if (--argc < 1)
                goto bad;
            CAkeyfile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x43\x41\x73\x65\x72\x69\x61\x6c") == 0) {
            if (--argc < 1)
                goto bad;
            CAserial = *(++argv);
        } else if (strcmp(*argv, "\x2d\x73\x65\x74\x5f\x73\x65\x72\x69\x61\x6c") == 0) {
            if (--argc < 1)
                goto bad;
            if (!(sno = s2i_ASN1_INTEGER(NULL, *(++argv))))
                goto bad;
        } else if (strcmp(*argv, "\x2d\x66\x6f\x72\x63\x65\x5f\x70\x75\x62\x6b\x65\x79") == 0) {
            if (--argc < 1)
                goto bad;
            fkeyfile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x61\x64\x64\x74\x72\x75\x73\x74") == 0) {
            if (--argc < 1)
                goto bad;
            if (!(objtmp = OBJ_txt2obj(*(++argv), 0))) {
                BIO_printf(bio_err, "\x49\x6e\x76\x61\x6c\x69\x64\x20\x74\x72\x75\x73\x74\x20\x6f\x62\x6a\x65\x63\x74\x20\x76\x61\x6c\x75\x65\x20\x25\x73\xa", *argv);
                goto bad;
            }
            if (!trust)
                trust = sk_ASN1_OBJECT_new_null();
            sk_ASN1_OBJECT_push(trust, objtmp);
            trustout = 1;
        } else if (strcmp(*argv, "\x2d\x61\x64\x64\x72\x65\x6a\x65\x63\x74") == 0) {
            if (--argc < 1)
                goto bad;
            if (!(objtmp = OBJ_txt2obj(*(++argv), 0))) {
                BIO_printf(bio_err,
                           "\x49\x6e\x76\x61\x6c\x69\x64\x20\x72\x65\x6a\x65\x63\x74\x20\x6f\x62\x6a\x65\x63\x74\x20\x76\x61\x6c\x75\x65\x20\x25\x73\xa", *argv);
                goto bad;
            }
            if (!reject)
                reject = sk_ASN1_OBJECT_new_null();
            sk_ASN1_OBJECT_push(reject, objtmp);
            trustout = 1;
        } else if (strcmp(*argv, "\x2d\x73\x65\x74\x61\x6c\x69\x61\x73") == 0) {
            if (--argc < 1)
                goto bad;
            alias = *(++argv);
            trustout = 1;
        } else if (strcmp(*argv, "\x2d\x63\x65\x72\x74\x6f\x70\x74") == 0) {
            if (--argc < 1)
                goto bad;
            if (!set_cert_ex(&certflag, *(++argv)))
                goto bad;
        } else if (strcmp(*argv, "\x2d\x6e\x61\x6d\x65\x6f\x70\x74") == 0) {
            if (--argc < 1)
                goto bad;
            if (!set_name_ex(&nmflag, *(++argv)))
                goto bad;
        }
#ifndef OPENSSL_NO_ENGINE
        else if (strcmp(*argv, "\x2d\x65\x6e\x67\x69\x6e\x65") == 0) {
            if (--argc < 1)
                goto bad;
            engine = *(++argv);
        }
#endif
        else if (strcmp(*argv, "\x2d\x43") == 0)
            C = ++num;
        else if (strcmp(*argv, "\x2d\x65\x6d\x61\x69\x6c") == 0)
            email = ++num;
        else if (strcmp(*argv, "\x2d\x6f\x63\x73\x70\x5f\x75\x72\x69") == 0)
            ocsp_uri = ++num;
        else if (strcmp(*argv, "\x2d\x73\x65\x72\x69\x61\x6c") == 0)
            serial = ++num;
        else if (strcmp(*argv, "\x2d\x6e\x65\x78\x74\x5f\x73\x65\x72\x69\x61\x6c") == 0)
            next_serial = ++num;
        else if (strcmp(*argv, "\x2d\x6d\x6f\x64\x75\x6c\x75\x73") == 0)
            modulus = ++num;
        else if (strcmp(*argv, "\x2d\x70\x75\x62\x6b\x65\x79") == 0)
            pubkey = ++num;
        else if (strcmp(*argv, "\x2d\x78\x35\x30\x39\x74\x6f\x72\x65\x71") == 0)
            x509req = ++num;
        else if (strcmp(*argv, "\x2d\x74\x65\x78\x74") == 0)
            text = ++num;
        else if (strcmp(*argv, "\x2d\x68\x61\x73\x68") == 0
                 || strcmp(*argv, "\x2d\x73\x75\x62\x6a\x65\x63\x74\x5f\x68\x61\x73\x68") == 0)
            subject_hash = ++num;
#ifndef OPENSSL_NO_MD5
        else if (strcmp(*argv, "\x2d\x73\x75\x62\x6a\x65\x63\x74\x5f\x68\x61\x73\x68\x5f\x6f\x6c\x64") == 0)
            subject_hash_old = ++num;
#endif
        else if (strcmp(*argv, "\x2d\x69\x73\x73\x75\x65\x72\x5f\x68\x61\x73\x68") == 0)
            issuer_hash = ++num;
#ifndef OPENSSL_NO_MD5
        else if (strcmp(*argv, "\x2d\x69\x73\x73\x75\x65\x72\x5f\x68\x61\x73\x68\x5f\x6f\x6c\x64") == 0)
            issuer_hash_old = ++num;
#endif
        else if (strcmp(*argv, "\x2d\x73\x75\x62\x6a\x65\x63\x74") == 0)
            subject = ++num;
        else if (strcmp(*argv, "\x2d\x69\x73\x73\x75\x65\x72") == 0)
            issuer = ++num;
        else if (strcmp(*argv, "\x2d\x66\x69\x6e\x67\x65\x72\x70\x72\x69\x6e\x74") == 0)
            fingerprint = ++num;
        else if (strcmp(*argv, "\x2d\x64\x61\x74\x65\x73") == 0) {
            startdate = ++num;
            enddate = ++num;
        } else if (strcmp(*argv, "\x2d\x70\x75\x72\x70\x6f\x73\x65") == 0)
            pprint = ++num;
        else if (strcmp(*argv, "\x2d\x73\x74\x61\x72\x74\x64\x61\x74\x65") == 0)
            startdate = ++num;
        else if (strcmp(*argv, "\x2d\x65\x6e\x64\x64\x61\x74\x65") == 0)
            enddate = ++num;
        else if (strcmp(*argv, "\x2d\x63\x68\x65\x63\x6b\x65\x6e\x64") == 0) {
            if (--argc < 1)
                goto bad;
            checkoffset = atoi(*(++argv));
            checkend = 1;
        } else if (strcmp(*argv, "\x2d\x63\x68\x65\x63\x6b\x68\x6f\x73\x74") == 0) {
            if (--argc < 1)
                goto bad;
            checkhost = *(++argv);
        } else if (strcmp(*argv, "\x2d\x63\x68\x65\x63\x6b\x65\x6d\x61\x69\x6c") == 0) {
            if (--argc < 1)
                goto bad;
            checkemail = *(++argv);
        } else if (strcmp(*argv, "\x2d\x63\x68\x65\x63\x6b\x69\x70") == 0) {
            if (--argc < 1)
                goto bad;
            checkip = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6e\x6f\x6f\x75\x74") == 0)
            noout = ++num;
        else if (strcmp(*argv, "\x2d\x74\x72\x75\x73\x74\x6f\x75\x74") == 0)
            trustout = 1;
        else if (strcmp(*argv, "\x2d\x63\x6c\x72\x74\x72\x75\x73\x74") == 0)
            clrtrust = ++num;
        else if (strcmp(*argv, "\x2d\x63\x6c\x72\x72\x65\x6a\x65\x63\x74") == 0)
            clrreject = ++num;
        else if (strcmp(*argv, "\x2d\x61\x6c\x69\x61\x73") == 0)
            aliasout = ++num;
        else if (strcmp(*argv, "\x2d\x43\x41\x63\x72\x65\x61\x74\x65\x73\x65\x72\x69\x61\x6c") == 0)
            CA_createserial = ++num;
        else if (strcmp(*argv, "\x2d\x63\x6c\x72\x65\x78\x74") == 0)
            clrext = 1;
#if 1                           /* stay backwards-compatible with 0.9.5; this
                                 * should go away soon */
        else if (strcmp(*argv, "\x2d\x63\x72\x6c\x65\x78\x74") == 0) {
            BIO_printf(bio_err, "\x75\x73\x65\x20\x2d\x63\x6c\x72\x65\x78\x74\x20\x69\x6e\x73\x74\x65\x61\x64\x20\x6f\x66\x20\x2d\x63\x72\x6c\x65\x78\x74\xa");
            clrext = 1;
        }
#endif
        else if (strcmp(*argv, "\x2d\x6f\x63\x73\x70\x69\x64") == 0)
            ocspid = ++num;
        else if (strcmp(*argv, "\x2d\x62\x61\x64\x73\x69\x67") == 0)
            badsig = 1;
        else if ((md_alg = EVP_get_digestbyname(*argv + 1))) {
            /* ok */
            digest = md_alg;
        } else {
            BIO_printf(bio_err, "\x75\x6e\x6b\x6e\x6f\x77\x6e\x20\x6f\x70\x74\x69\x6f\x6e\x20\x25\x73\xa", *argv);
            badops = 1;
            break;
        }
        argc--;
        argv++;
    }

    if (badops) {
 bad:
        for (pp = x509_usage; (*pp != NULL); pp++)
            BIO_printf(bio_err, "\x25\x73", *pp);
        goto end;
    }
    e = setup_engine(bio_err, engine, 0);

    if (need_rand)
        app_RAND_load_file(NULL, bio_err, 0);

    ERR_load_crypto_strings();

    if (!app_passwd(bio_err, passargin, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\xa");
        goto end;
    }

    if (!X509_STORE_set_default_paths(ctx)) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (fkeyfile) {
        fkey = load_pubkey(bio_err, fkeyfile, keyformat, 0,
                           NULL, e, "\x46\x6f\x72\x63\x65\x64\x20\x6b\x65\x79");
        if (fkey == NULL)
            goto end;
    }

    if ((CAkeyfile == NULL) && (CA_flag) && (CAformat == FORMAT_PEM)) {
        CAkeyfile = CAfile;
    } else if ((CA_flag) && (CAkeyfile == NULL)) {
        BIO_printf(bio_err,
                   "\x6e\x65\x65\x64\x20\x74\x6f\x20\x73\x70\x65\x63\x69\x66\x79\x20\x61\x20\x43\x41\x6b\x65\x79\x20\x69\x66\x20\x75\x73\x69\x6e\x67\x20\x74\x68\x65\x20\x43\x41\x20\x63\x6f\x6d\x6d\x61\x6e\x64\xa");
        goto end;
    }

    if (extfile) {
        long errorline = -1;
        X509V3_CTX ctx2;
        extconf = NCONF_new(NULL);
        if (!NCONF_load(extconf, extfile, &errorline)) {
            if (errorline <= 0)
                BIO_printf(bio_err,
                           "\x65\x72\x72\x6f\x72\x20\x6c\x6f\x61\x64\x69\x6e\x67\x20\x74\x68\x65\x20\x63\x6f\x6e\x66\x69\x67\x20\x66\x69\x6c\x65\x20\x27\x25\x73\x27\xa", extfile);
            else
                BIO_printf(bio_err,
                           "\x65\x72\x72\x6f\x72\x20\x6f\x6e\x20\x6c\x69\x6e\x65\x20\x25\x6c\x64\x20\x6f\x66\x20\x63\x6f\x6e\x66\x69\x67\x20\x66\x69\x6c\x65\x20\x27\x25\x73\x27\xa",
                           errorline, extfile);
            goto end;
        }
        if (!extsect) {
            extsect = NCONF_get_string(extconf, "\x64\x65\x66\x61\x75\x6c\x74", "\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73");
            if (!extsect) {
                ERR_clear_error();
                extsect = "\x64\x65\x66\x61\x75\x6c\x74";
            }
        }
        X509V3_set_ctx_test(&ctx2);
        X509V3_set_nconf(&ctx2, extconf);
        if (!X509V3_EXT_add_nconf(extconf, &ctx2, extsect, NULL)) {
            BIO_printf(bio_err,
                       "\x45\x72\x72\x6f\x72\x20\x4c\x6f\x61\x64\x69\x6e\x67\x20\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x20\x73\x65\x63\x74\x69\x6f\x6e\x20\x25\x73\xa", extsect);
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (reqfile) {
        EVP_PKEY *pkey;
        BIO *in;

        if (!sign_flag && !CA_flag) {
            BIO_printf(bio_err, "\x57\x65\x20\x6e\x65\x65\x64\x20\x61\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x74\x6f\x20\x73\x69\x67\x6e\x20\x77\x69\x74\x68\xa");
            goto end;
        }
        in = BIO_new(BIO_s_file());
        if (in == NULL) {
            ERR_print_errors(bio_err);
            goto end;
        }

        if (infile == NULL)
            BIO_set_fp(in, stdin, BIO_NOCLOSE | BIO_FP_TEXT);
        else {
            if (BIO_read_filename(in, infile) <= 0) {
                perror(infile);
                BIO_free(in);
                goto end;
            }
        }
        req = PEM_read_bio_X509_REQ(in, NULL, NULL, NULL);
        BIO_free(in);

        if (req == NULL) {
            ERR_print_errors(bio_err);
            goto end;
        }

        if ((req->req_info == NULL) ||
            (req->req_info->pubkey == NULL) ||
            (req->req_info->pubkey->public_key == NULL) ||
            (req->req_info->pubkey->public_key->data == NULL)) {
            BIO_printf(bio_err,
                       "\x54\x68\x65\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x72\x65\x71\x75\x65\x73\x74\x20\x61\x70\x70\x65\x61\x72\x73\x20\x74\x6f\x20\x63\x6f\x72\x72\x75\x70\x74\x65\x64\xa");
            BIO_printf(bio_err, "\x49\x74\x20\x64\x6f\x65\x73\x20\x6e\x6f\x74\x20\x63\x6f\x6e\x74\x61\x69\x6e\x20\x61\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\xa");
            goto end;
        }
        if ((pkey = X509_REQ_get_pubkey(req)) == NULL) {
            BIO_printf(bio_err, "\x65\x72\x72\x6f\x72\x20\x75\x6e\x70\x61\x63\x6b\x69\x6e\x67\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\xa");
            goto end;
        }
        i = X509_REQ_verify(req, pkey);
        EVP_PKEY_free(pkey);
        if (i < 0) {
            BIO_printf(bio_err, "\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x76\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x20\x65\x72\x72\x6f\x72\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
        if (i == 0) {
            BIO_printf(bio_err,
                       "\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x64\x69\x64\x20\x6e\x6f\x74\x20\x6d\x61\x74\x63\x68\x20\x74\x68\x65\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x72\x65\x71\x75\x65\x73\x74\xa");
            goto end;
        } else
            BIO_printf(bio_err, "\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x6f\x6b\xa");

        print_name(bio_err, "\x73\x75\x62\x6a\x65\x63\x74\x3d", X509_REQ_get_subject_name(req),
                   nmflag);

        if ((x = X509_new()) == NULL)
            goto end;

        if (sno == NULL) {
            sno = ASN1_INTEGER_new();
            if (!sno || !rand_serial(NULL, sno))
                goto end;
            if (!X509_set_serialNumber(x, sno))
                goto end;
            ASN1_INTEGER_free(sno);
            sno = NULL;
        } else if (!X509_set_serialNumber(x, sno))
            goto end;

        if (!X509_set_issuer_name(x, req->req_info->subject))
            goto end;
        if (!X509_set_subject_name(x, req->req_info->subject))
            goto end;

        X509_gmtime_adj(X509_get_notBefore(x), 0);
        X509_time_adj_ex(X509_get_notAfter(x), days, 0, NULL);
        if (fkey)
            X509_set_pubkey(x, fkey);
        else {
            pkey = X509_REQ_get_pubkey(req);
            X509_set_pubkey(x, pkey);
            EVP_PKEY_free(pkey);
        }
    } else
        x = load_cert(bio_err, infile, informat, NULL, e, "\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65");

    if (x == NULL)
        goto end;
    if (CA_flag) {
        xca = load_cert(bio_err, CAfile, CAformat, NULL, e, "\x43\x41\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65");
        if (xca == NULL)
            goto end;
    }

    if (!noout || text || next_serial) {
        OBJ_create("\x32\x2e\x39\x39\x39\x39\x39\x2e\x33", "\x53\x45\x54\x2e\x65\x78\x33", "\x53\x45\x54\x20\x78\x35\x30\x39\x76\x33\x20\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x20\x33");

        out = BIO_new(BIO_s_file());
        if (out == NULL) {
            ERR_print_errors(bio_err);
            goto end;
        }
        if (outfile == NULL) {
            BIO_set_fp(out, stdout, BIO_NOCLOSE);
#ifdef OPENSSL_SYS_VMS
            {
                BIO *tmpbio = BIO_new(BIO_f_linebuffer());
                out = BIO_push(tmpbio, out);
            }
#endif
        } else {
            if (BIO_write_filename(out, outfile) <= 0) {
                perror(outfile);
                goto end;
            }
        }
    }

    if (alias)
        X509_alias_set1(x, (unsigned char *)alias, -1);

    if (clrtrust)
        X509_trust_clear(x);
    if (clrreject)
        X509_reject_clear(x);

    if (trust) {
        for (i = 0; i < sk_ASN1_OBJECT_num(trust); i++) {
            objtmp = sk_ASN1_OBJECT_value(trust, i);
            X509_add1_trust_object(x, objtmp);
        }
    }

    if (reject) {
        for (i = 0; i < sk_ASN1_OBJECT_num(reject); i++) {
            objtmp = sk_ASN1_OBJECT_value(reject, i);
            X509_add1_reject_object(x, objtmp);
        }
    }

    if (num) {
        for (i = 1; i <= num; i++) {
            if (issuer == i) {
                print_name(STDout, "\x69\x73\x73\x75\x65\x72\x3d\x20",
                           X509_get_issuer_name(x), nmflag);
            } else if (subject == i) {
                print_name(STDout, "\x73\x75\x62\x6a\x65\x63\x74\x3d\x20",
                           X509_get_subject_name(x), nmflag);
            } else if (serial == i) {
                BIO_printf(STDout, "\x73\x65\x72\x69\x61\x6c\x3d");
                i2a_ASN1_INTEGER(STDout, X509_get_serialNumber(x));
                BIO_printf(STDout, "\xa");
            } else if (next_serial == i) {
                BIGNUM *bnser;
                ASN1_INTEGER *ser;
                ser = X509_get_serialNumber(x);
                bnser = ASN1_INTEGER_to_BN(ser, NULL);
                if (!bnser)
                    goto end;
                if (!BN_add_word(bnser, 1))
                    goto end;
                ser = BN_to_ASN1_INTEGER(bnser, NULL);
                if (!ser)
                    goto end;
                BN_free(bnser);
                i2a_ASN1_INTEGER(out, ser);
                ASN1_INTEGER_free(ser);
                BIO_puts(out, "\xa");
            } else if ((email == i) || (ocsp_uri == i)) {
                int j;
                STACK_OF(OPENSSL_STRING) *emlst;
                if (email == i)
                    emlst = X509_get1_email(x);
                else
                    emlst = X509_get1_ocsp(x);
                for (j = 0; j < sk_OPENSSL_STRING_num(emlst); j++)
                    BIO_printf(STDout, "\x25\x73\xa",
                               sk_OPENSSL_STRING_value(emlst, j));
                X509_email_free(emlst);
            } else if (aliasout == i) {
                unsigned char *alstr;
                alstr = X509_alias_get0(x, NULL);
                if (alstr)
                    BIO_printf(STDout, "\x25\x73\xa", alstr);
                else
                    BIO_puts(STDout, "\x3c\x4e\x6f\x20\x41\x6c\x69\x61\x73\x3e\xa");
            } else if (subject_hash == i) {
                BIO_printf(STDout, "\x25\x30\x38\x6c\x78\xa", X509_subject_name_hash(x));
            }
#ifndef OPENSSL_NO_MD5
            else if (subject_hash_old == i) {
                BIO_printf(STDout, "\x25\x30\x38\x6c\x78\xa", X509_subject_name_hash_old(x));
            }
#endif
            else if (issuer_hash == i) {
                BIO_printf(STDout, "\x25\x30\x38\x6c\x78\xa", X509_issuer_name_hash(x));
            }
#ifndef OPENSSL_NO_MD5
            else if (issuer_hash_old == i) {
                BIO_printf(STDout, "\x25\x30\x38\x6c\x78\xa", X509_issuer_name_hash_old(x));
            }
#endif
            else if (pprint == i) {
                X509_PURPOSE *ptmp;
                int j;
                BIO_printf(STDout, "\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x70\x75\x72\x70\x6f\x73\x65\x73\x3a\xa");
                for (j = 0; j < X509_PURPOSE_get_count(); j++) {
                    ptmp = X509_PURPOSE_get0(j);
                    purpose_print(STDout, x, ptmp);
                }
            } else if (modulus == i) {
                EVP_PKEY *pkey;

                pkey = X509_get_pubkey(x);
                if (pkey == NULL) {
                    BIO_printf(bio_err, "\x4d\x6f\x64\x75\x6c\x75\x73\x3d\x75\x6e\x61\x76\x61\x69\x6c\x61\x62\x6c\x65\xa");
                    ERR_print_errors(bio_err);
                    goto end;
                }
                BIO_printf(STDout, "\x4d\x6f\x64\x75\x6c\x75\x73\x3d");
#ifndef OPENSSL_NO_RSA
                if (pkey->type == EVP_PKEY_RSA)
                    BN_print(STDout, pkey->pkey.rsa->n);
                else
#endif
#ifndef OPENSSL_NO_DSA
                if (pkey->type == EVP_PKEY_DSA)
                    BN_print(STDout, pkey->pkey.dsa->pub_key);
                else
#endif
                    BIO_printf(STDout, "\x57\x72\x6f\x6e\x67\x20\x41\x6c\x67\x6f\x72\x69\x74\x68\x6d\x20\x74\x79\x70\x65");
                BIO_printf(STDout, "\xa");
                EVP_PKEY_free(pkey);
            } else if (pubkey == i) {
                EVP_PKEY *pkey;

                pkey = X509_get_pubkey(x);
                if (pkey == NULL) {
                    BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\xa");
                    ERR_print_errors(bio_err);
                    goto end;
                }
                PEM_write_bio_PUBKEY(STDout, pkey);
                EVP_PKEY_free(pkey);
            } else if (C == i) {
                unsigned char *d;
                char *m;
                int y, z;

                X509_NAME_oneline(X509_get_subject_name(x), buf, sizeof(buf));
                BIO_printf(STDout, "\x2f\x2a\x20\x73\x75\x62\x6a\x65\x63\x74\x3a\x25\x73\x20\x2a\x2f\xa", buf);
                m = X509_NAME_oneline(X509_get_issuer_name(x), buf,
                                      sizeof(buf));
                BIO_printf(STDout, "\x2f\x2a\x20\x69\x73\x73\x75\x65\x72\x20\x3a\x25\x73\x20\x2a\x2f\xa", buf);

                z = i2d_X509(x, NULL);
                m = OPENSSL_malloc(z);
                if (!m) {
                    BIO_printf(bio_err, "\x4f\x75\x74\x20\x6f\x66\x20\x6d\x65\x6d\x6f\x72\x79\xa");
                    ERR_print_errors(bio_err);
                    goto end;
                }

                d = (unsigned char *)m;
                z = i2d_X509_NAME(X509_get_subject_name(x), &d);
                BIO_printf(STDout, "\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x63\x68\x61\x72\x20\x58\x58\x58\x5f\x73\x75\x62\x6a\x65\x63\x74\x5f\x6e\x61\x6d\x65\x5b\x25\x64\x5d\x3d\x7b\xa",
                           z);
                d = (unsigned char *)m;
                for (y = 0; y < z; y++) {
                    BIO_printf(STDout, "\x30\x78\x25\x30\x32\x58\x2c", d[y]);
                    if ((y & 0x0f) == 0x0f)
                        BIO_printf(STDout, "\xa");
                }
                if (y % 16 != 0)
                    BIO_printf(STDout, "\xa");
                BIO_printf(STDout, "\x7d\x3b\xa");

                z = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), &d);
                BIO_printf(STDout, "\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x63\x68\x61\x72\x20\x58\x58\x58\x5f\x70\x75\x62\x6c\x69\x63\x5f\x6b\x65\x79\x5b\x25\x64\x5d\x3d\x7b\xa", z);
                d = (unsigned char *)m;
                for (y = 0; y < z; y++) {
                    BIO_printf(STDout, "\x30\x78\x25\x30\x32\x58\x2c", d[y]);
                    if ((y & 0x0f) == 0x0f)
                        BIO_printf(STDout, "\xa");
                }
                if (y % 16 != 0)
                    BIO_printf(STDout, "\xa");
                BIO_printf(STDout, "\x7d\x3b\xa");

                z = i2d_X509(x, &d);
                BIO_printf(STDout, "\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x63\x68\x61\x72\x20\x58\x58\x58\x5f\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x5b\x25\x64\x5d\x3d\x7b\xa",
                           z);
                d = (unsigned char *)m;
                for (y = 0; y < z; y++) {
                    BIO_printf(STDout, "\x30\x78\x25\x30\x32\x58\x2c", d[y]);
                    if ((y & 0x0f) == 0x0f)
                        BIO_printf(STDout, "\xa");
                }
                if (y % 16 != 0)
                    BIO_printf(STDout, "\xa");
                BIO_printf(STDout, "\x7d\x3b\xa");

                OPENSSL_free(m);
            } else if (text == i) {
                X509_print_ex(STDout, x, nmflag, certflag);
            } else if (startdate == i) {
                BIO_puts(STDout, "\x6e\x6f\x74\x42\x65\x66\x6f\x72\x65\x3d");
                ASN1_TIME_print(STDout, X509_get_notBefore(x));
                BIO_puts(STDout, "\xa");
            } else if (enddate == i) {
                BIO_puts(STDout, "\x6e\x6f\x74\x41\x66\x74\x65\x72\x3d");
                ASN1_TIME_print(STDout, X509_get_notAfter(x));
                BIO_puts(STDout, "\xa");
            } else if (fingerprint == i) {
                int j;
                unsigned int n;
                unsigned char md[EVP_MAX_MD_SIZE];
                const EVP_MD *fdig = digest;

                if (!fdig)
                    fdig = EVP_sha1();

                if (!X509_digest(x, fdig, md, &n)) {
                    BIO_printf(bio_err, "\x6f\x75\x74\x20\x6f\x66\x20\x6d\x65\x6d\x6f\x72\x79\xa");
                    goto end;
                }
                BIO_printf(STDout, "\x25\x73\x20\x46\x69\x6e\x67\x65\x72\x70\x72\x69\x6e\x74\x3d",
                           OBJ_nid2sn(EVP_MD_type(fdig)));
                for (j = 0; j < (int)n; j++) {
                    BIO_printf(STDout, "\x25\x30\x32\x58\x25\x63", md[j], (j + 1 == (int)n)
                               ? '\xa' : '\x3a');
                }
            }

            /* should be in the library */
            else if ((sign_flag == i) && (x509req == 0)) {
                BIO_printf(bio_err, "\x47\x65\x74\x74\x69\x6e\x67\x20\x50\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\xa");
                if (Upkey == NULL) {
                    Upkey = load_key(bio_err,
                                     keyfile, keyformat, 0,
                                     passin, e, "\x50\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79");
                    if (Upkey == NULL)
                        goto end;
                }

                assert(need_rand);
                if (!sign(x, Upkey, days, clrext, digest, extconf, extsect))
                    goto end;
            } else if (CA_flag == i) {
                BIO_printf(bio_err, "\x47\x65\x74\x74\x69\x6e\x67\x20\x43\x41\x20\x50\x72\x69\x76\x61\x74\x65\x20\x4b\x65\x79\xa");
                if (CAkeyfile != NULL) {
                    CApkey = load_key(bio_err,
                                      CAkeyfile, CAkeyformat,
                                      0, passin, e, "\x43\x41\x20\x50\x72\x69\x76\x61\x74\x65\x20\x4b\x65\x79");
                    if (CApkey == NULL)
                        goto end;
                }

                assert(need_rand);
                if (!x509_certify(ctx, CAfile, digest, x, xca,
                                  CApkey, sigopts,
                                  CAserial, CA_createserial, days, clrext,
                                  extconf, extsect, sno))
                    goto end;
            } else if (x509req == i) {
                EVP_PKEY *pk;

                BIO_printf(bio_err, "\x47\x65\x74\x74\x69\x6e\x67\x20\x72\x65\x71\x75\x65\x73\x74\x20\x50\x72\x69\x76\x61\x74\x65\x20\x4b\x65\x79\xa");
                if (keyfile == NULL) {
                    BIO_printf(bio_err, "\x6e\x6f\x20\x72\x65\x71\x75\x65\x73\x74\x20\x6b\x65\x79\x20\x66\x69\x6c\x65\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
                    goto end;
                } else {
                    pk = load_key(bio_err,
                                  keyfile, keyformat, 0,
                                  passin, e, "\x72\x65\x71\x75\x65\x73\x74\x20\x6b\x65\x79");
                    if (pk == NULL)
                        goto end;
                }

                BIO_printf(bio_err, "\x47\x65\x6e\x65\x72\x61\x74\x69\x6e\x67\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x72\x65\x71\x75\x65\x73\x74\xa");

                rq = X509_to_X509_REQ(x, pk, digest);
                EVP_PKEY_free(pk);
                if (rq == NULL) {
                    ERR_print_errors(bio_err);
                    goto end;
                }
                if (!noout) {
                    X509_REQ_print(out, rq);
                    PEM_write_bio_X509_REQ(out, rq);
                }
                noout = 1;
            } else if (ocspid == i) {
                X509_ocspid_print(out, x);
            }
        }
    }

    if (checkend) {
        time_t tcheck = time(NULL) + checkoffset;

        if (X509_cmp_time(X509_get_notAfter(x), &tcheck) < 0) {
            BIO_printf(out, "\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x77\x69\x6c\x6c\x20\x65\x78\x70\x69\x72\x65\xa");
            ret = 1;
        } else {
            BIO_printf(out, "\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x77\x69\x6c\x6c\x20\x6e\x6f\x74\x20\x65\x78\x70\x69\x72\x65\xa");
            ret = 0;
        }
        goto end;
    }

    print_cert_checks(STDout, x, checkhost, checkemail, checkip);

    if (noout) {
        ret = 0;
        goto end;
    }

    if (badsig)
        x->signature->data[x->signature->length - 1] ^= 0x1;

    if (outformat == FORMAT_ASN1)
        i = i2d_X509_bio(out, x);
    else if (outformat == FORMAT_PEM) {
        if (trustout)
            i = PEM_write_bio_X509_AUX(out, x);
        else
            i = PEM_write_bio_X509(out, x);
    } else if (outformat == FORMAT_NETSCAPE) {
        NETSCAPE_X509 nx;
        ASN1_OCTET_STRING hdr;

        hdr.data = (unsigned char *)NETSCAPE_CERT_HDR;
        hdr.length = strlen(NETSCAPE_CERT_HDR);
        nx.header = &hdr;
        nx.cert = x;

        i = ASN1_item_i2d_bio(ASN1_ITEM_rptr(NETSCAPE_X509), out, &nx);
    } else {
        BIO_printf(bio_err, "\x62\x61\x64\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20\x6f\x75\x74\x66\x69\x6c\x65\xa");
        goto end;
    }
    if (!i) {
        BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x77\x72\x69\x74\x65\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\xa");
        ERR_print_errors(bio_err);
        goto end;
    }
    ret = 0;
 end:
    if (need_rand)
        app_RAND_write_file(NULL, bio_err);
    OBJ_cleanup();
    NCONF_free(extconf);
    BIO_free_all(out);
    BIO_free_all(STDout);
    X509_STORE_free(ctx);
    X509_REQ_free(req);
    X509_free(x);
    X509_free(xca);
    EVP_PKEY_free(Upkey);
    EVP_PKEY_free(CApkey);
    EVP_PKEY_free(fkey);
    if (sigopts)
        sk_OPENSSL_STRING_free(sigopts);
    X509_REQ_free(rq);
    ASN1_INTEGER_free(sno);
    sk_ASN1_OBJECT_pop_free(trust, ASN1_OBJECT_free);
    sk_ASN1_OBJECT_pop_free(reject, ASN1_OBJECT_free);
    release_engine(e);
    if (passin)
        OPENSSL_free(passin);
    apps_shutdown();
    OPENSSL_EXIT(ret);
}

static ASN1_INTEGER *x509_load_serial(char *CAfile, char *serialfile,
                                      int create)
{
    char *buf = NULL, *p;
    ASN1_INTEGER *bs = NULL;
    BIGNUM *serial = NULL;
    size_t len;

    len = ((serialfile == NULL)
           ? (strlen(CAfile) + strlen(POSTFIX) + 1)
           : (strlen(serialfile))) + 1;
    buf = OPENSSL_malloc(len);
    if (buf == NULL) {
        BIO_printf(bio_err, "\x6f\x75\x74\x20\x6f\x66\x20\x6d\x65\x6d\xa");
        goto end;
    }
    if (serialfile == NULL) {
        BUF_strlcpy(buf, CAfile, len);
        for (p = buf; *p; p++)
            if (*p == '\x2e') {
                *p = '\x0';
                break;
            }
        BUF_strlcat(buf, POSTFIX, len);
    } else
        BUF_strlcpy(buf, serialfile, len);

    serial = load_serial(buf, create, NULL);
    if (serial == NULL)
        goto end;

    if (!BN_add_word(serial, 1)) {
        BIO_printf(bio_err, "\x61\x64\x64\x5f\x77\x6f\x72\x64\x20\x66\x61\x69\x6c\x75\x72\x65\xa");
        goto end;
    }

    if (!save_serial(buf, NULL, serial, &bs))
        goto end;

 end:
    if (buf)
        OPENSSL_free(buf);
    BN_free(serial);
    return bs;
}

static int x509_certify(X509_STORE *ctx, char *CAfile, const EVP_MD *digest,
                        X509 *x, X509 *xca, EVP_PKEY *pkey,
                        STACK_OF(OPENSSL_STRING) *sigopts,
                        char *serialfile, int create,
                        int days, int clrext, CONF *conf, char *section,
                        ASN1_INTEGER *sno)
{
    int ret = 0;
    ASN1_INTEGER *bs = NULL;
    X509_STORE_CTX xsc;
    EVP_PKEY *upkey;

    upkey = X509_get_pubkey(xca);
    if (upkey == NULL)  {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x6f\x62\x74\x61\x69\x6e\x69\x6e\x67\x20\x43\x41\x20\x58\x35\x30\x39\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\xa");
        goto end;
    }
    EVP_PKEY_copy_parameters(upkey, pkey);
    EVP_PKEY_free(upkey);

    if (!X509_STORE_CTX_init(&xsc, ctx, x, NULL)) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x69\x6e\x69\x74\x69\x61\x6c\x69\x73\x69\x6e\x67\x20\x58\x35\x30\x39\x20\x73\x74\x6f\x72\x65\xa");
        goto end;
    }
    if (sno)
        bs = sno;
    else if (!(bs = x509_load_serial(CAfile, serialfile, create)))
        goto end;

/*      if (!X509_STORE_add_cert(ctx,x)) goto end;*/

    /*
     * NOTE: this certificate can/should be self signed, unless it was a
     * certificate request in which case it is not.
     */
    X509_STORE_CTX_set_cert(&xsc, x);
    X509_STORE_CTX_set_flags(&xsc, X509_V_FLAG_CHECK_SS_SIGNATURE);
    if (!reqfile && X509_verify_cert(&xsc) <= 0)
        goto end;

    if (!X509_check_private_key(xca, pkey)) {
        BIO_printf(bio_err,
                   "\x43\x41\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x61\x6e\x64\x20\x43\x41\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x64\x6f\x20\x6e\x6f\x74\x20\x6d\x61\x74\x63\x68\xa");
        goto end;
    }

    if (!X509_set_issuer_name(x, X509_get_subject_name(xca)))
        goto end;
    if (!X509_set_serialNumber(x, bs))
        goto end;

    if (X509_gmtime_adj(X509_get_notBefore(x), 0L) == NULL)
        goto end;

    /* hardwired expired */
    if (X509_time_adj_ex(X509_get_notAfter(x), days, 0, NULL) == NULL)
        goto end;

    if (clrext) {
        while (X509_get_ext_count(x) > 0)
            X509_delete_ext(x, 0);
    }

    if (conf) {
        X509V3_CTX ctx2;
#ifdef OPENSSL_SSL_DEBUG_BROKEN_PROTOCOL
        X509_set_version(x, force_version);
#else
        X509_set_version(x, 2); /* version 3 certificate */
#endif
        X509V3_set_ctx(&ctx2, xca, x, NULL, NULL, 0);
        X509V3_set_nconf(&ctx2, conf);
        if (!X509V3_EXT_add_nconf(conf, &ctx2, section, x))
            goto end;
    }

    if (!do_X509_sign(bio_err, x, pkey, digest, sigopts))
        goto end;
    ret = 1;
 end:
    X509_STORE_CTX_cleanup(&xsc);
    if (!ret)
        ERR_print_errors(bio_err);
    if (!sno)
        ASN1_INTEGER_free(bs);
    return ret;
}

static int MS_CALLBACK callb(int ok, X509_STORE_CTX *ctx)
{
    int err;
    X509 *err_cert;

    /*
     * it is ok to use a self signed certificate This case will catch both
     * the initial ok == 0 and the final ok == 1 calls to this function
     */
    err = X509_STORE_CTX_get_error(ctx);
    if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
        return 1;

    /*
     * BAD we should have gotten an error.  Normally if everything worked
     * X509_STORE_CTX_get_error(ctx) will still be set to
     * DEPTH_ZERO_SELF_....
     */
    if (ok) {
        BIO_printf(bio_err,
                   "\x65\x72\x72\x6f\x72\x20\x77\x69\x74\x68\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x74\x6f\x20\x62\x65\x20\x63\x65\x72\x74\x69\x66\x69\x65\x64\x20\x2d\x20\x73\x68\x6f\x75\x6c\x64\x20\x62\x65\x20\x73\x65\x6c\x66\x20\x73\x69\x67\x6e\x65\x64\xa");
        return 0;
    } else {
        err_cert = X509_STORE_CTX_get_current_cert(ctx);
        print_name(bio_err, NULL, X509_get_subject_name(err_cert), 0);
        BIO_printf(bio_err,
                   "\x65\x72\x72\x6f\x72\x20\x77\x69\x74\x68\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x2d\x20\x65\x72\x72\x6f\x72\x20\x25\x64\x20\x61\x74\x20\x64\x65\x70\x74\x68\x20\x25\x64\xa\x25\x73\xa", err,
                   X509_STORE_CTX_get_error_depth(ctx),
                   X509_verify_cert_error_string(err));
        return 1;
    }
}

/* self sign */
static int sign(X509 *x, EVP_PKEY *pkey, int days, int clrext,
                const EVP_MD *digest, CONF *conf, char *section)
{

    EVP_PKEY *pktmp;

    pktmp = X509_get_pubkey(x);
    if (pktmp == NULL)
        goto err;
    EVP_PKEY_copy_parameters(pktmp, pkey);
    EVP_PKEY_save_parameters(pktmp, 1);
    EVP_PKEY_free(pktmp);

    if (!X509_set_issuer_name(x, X509_get_subject_name(x)))
        goto err;
    if (X509_gmtime_adj(X509_get_notBefore(x), 0) == NULL)
        goto err;

    if (X509_time_adj_ex(X509_get_notAfter(x), days, 0, NULL) == NULL)
        goto err;

    if (!X509_set_pubkey(x, pkey))
        goto err;
    if (clrext) {
        while (X509_get_ext_count(x) > 0)
            X509_delete_ext(x, 0);
    }
    if (conf) {
        X509V3_CTX ctx;
#ifdef OPENSSL_SSL_DEBUG_BROKEN_PROTOCOL
        X509_set_version(x, force_version);
#else
        X509_set_version(x, 2); /* version 3 certificate */
#endif
        X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
        X509V3_set_nconf(&ctx, conf);
        if (!X509V3_EXT_add_nconf(conf, &ctx, section, x))
            goto err;
    }
    if (!X509_sign(x, pkey, digest))
        goto err;
    return 1;
 err:
    ERR_print_errors(bio_err);
    return 0;
}

static int purpose_print(BIO *bio, X509 *cert, X509_PURPOSE *pt)
{
    int id, i, idret;
    char *pname;
    id = X509_PURPOSE_get_id(pt);
    pname = X509_PURPOSE_get0_name(pt);
    for (i = 0; i < 2; i++) {
        idret = X509_check_purpose(cert, id, i);
        BIO_printf(bio, "\x25\x73\x25\x73\x20\x3a\x20", pname, i ? "\x20\x43\x41" : "");
        if (idret == 1)
            BIO_printf(bio, "\x59\x65\x73\xa");
        else if (idret == 0)
            BIO_printf(bio, "\x4e\x6f\xa");
        else
            BIO_printf(bio, "\x59\x65\x73\x20\x28\x57\x41\x52\x4e\x49\x4e\x47\x20\x63\x6f\x64\x65\x3d\x25\x64\x29\xa", idret);
    }
    return 1;
}

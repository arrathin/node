/* apps/s_client.c */
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
/* ====================================================================
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "\x4f\x70\x65\x6e\x53\x53\x4c\x20\x54\x6f\x6f\x6c\x6b\x69\x74" and "\x4f\x70\x65\x6e\x53\x53\x4c\x20\x50\x72\x6f\x6a\x65\x63\x74" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "\x4f\x70\x65\x6e\x53\x53\x4c"
 *    nor may "\x4f\x70\x65\x6e\x53\x53\x4c" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("\x43\x6f\x6e\x74\x72\x69\x62\x75\x74\x69\x6f\x6e") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "\x50\x53\x4b" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "\x41\x53\x20\x49\x53" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/e_os2.h>
#ifdef OPENSSL_NO_STDIO
# define APPS_WIN16
#endif

/*
 * With IPv6, it looks like Digital has mixed up the proper order of
 * recursive header file inclusion, resulting in the compiler complaining
 * that u_int isn't defined, but only if _POSIX_C_SOURCE is defined, which is
 * needed to have fileno() declared correctly...  So let's define u_int
 */
#if defined(OPENSSL_SYS_VMS_DECC) && !defined(__U_INT)
# define __U_INT
typedef unsigned int u_int;
#endif

#define USE_SOCKETS
#include "apps.h"
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ocsp.h>
#include <openssl/bn.h>
#ifndef OPENSSL_NO_SRP
# include <openssl/srp.h>
#endif
#include "s_apps.h"
#include "timeouts.h"

#if (defined(OPENSSL_SYS_VMS) && __VMS_VER < 70000000)
/* FIONBIO used as a switch to enable ioctl, and that isn't in VMS < 7.0 */
# undef FIONBIO
#endif

#if defined(OPENSSL_SYS_BEOS_R5)
# include <fcntl.h>
#endif

/* Use Windows API with STD_INPUT_HANDLE when checking for input?
   Don't look at OPENSSL_SYS_MSDOS for this, since it is always defined if
   OPENSSL_SYS_WINDOWS is defined */
#if defined(OPENSSL_SYS_WINDOWS) && !defined(OPENSSL_SYS_WINCE) && defined(STD_INPUT_HANDLE)
#define OPENSSL_USE_STD_INPUT_HANDLE
#endif

#undef PROG
#define PROG    s_client_main

/*
 * #define SSL_HOST_NAME "www.netscape.com"
 */
/*
 * #define SSL_HOST_NAME "\x31\x39\x33\x2e\x31\x31\x38\x2e\x31\x38\x37\x2e\x31\x30\x32"
 */
#define SSL_HOST_NAME   "\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74"

/* no default cert. */
/*
 * #define TEST_CERT "\x63\x6c\x69\x65\x6e\x74\x2e\x70\x65\x6d"
 */

#undef BUFSIZZ
#define BUFSIZZ 1024*8

extern int verify_depth;
extern int verify_error;
extern int verify_return_error;
extern int verify_quiet;

#ifdef FIONBIO
static int c_nbio = 0;
#endif
static int c_Pause = 0;
static int c_debug = 0;
#ifndef OPENSSL_NO_TLSEXT
static int c_tlsextdebug = 0;
static int c_status_req = 0;
#endif
static int c_msg = 0;
static int c_showcerts = 0;

static char *keymatexportlabel = NULL;
static int keymatexportlen = 20;

static void sc_usage(void);
static void print_stuff(BIO *berr, SSL *con, int full);
#ifndef OPENSSL_NO_TLSEXT
static int ocsp_resp_cb(SSL *s, void *arg);
#endif
static BIO *bio_c_out = NULL;
static BIO *bio_c_msg = NULL;
static int c_quiet = 0;
static int c_ign_eof = 0;
static int c_brief = 0;
static int c_no_rand_screen = 0;

#ifndef OPENSSL_NO_PSK
/* Default PSK identity and key */
static char *psk_identity = "\x43\x6c\x69\x65\x6e\x74\x5f\x69\x64\x65\x6e\x74\x69\x74\x79";
/*
 * char *psk_key=NULL; by default PSK is not used
 */

static unsigned int psk_client_cb(SSL *ssl, const char *hint, char *identity,
                                  unsigned int max_identity_len,
                                  unsigned char *psk,
                                  unsigned int max_psk_len)
{
    int ret;
    long key_len;
    unsigned char *key;

    if (c_debug)
        BIO_printf(bio_c_out, "\x70\x73\x6b\x5f\x63\x6c\x69\x65\x6e\x74\x5f\x63\x62\xa");
    if (!hint) {
        /* no ServerKeyExchange message */
        if (c_debug)
            BIO_printf(bio_c_out,
                       "\x4e\x55\x4c\x4c\x20\x72\x65\x63\x65\x69\x76\x65\x64\x20\x50\x53\x4b\x20\x69\x64\x65\x6e\x74\x69\x74\x79\x20\x68\x69\x6e\x74\x2c\x20\x63\x6f\x6e\x74\x69\x6e\x75\x69\x6e\x67\x20\x61\x6e\x79\x77\x61\x79\xa");
    } else if (c_debug)
        BIO_printf(bio_c_out, "\x52\x65\x63\x65\x69\x76\x65\x64\x20\x50\x53\x4b\x20\x69\x64\x65\x6e\x74\x69\x74\x79\x20\x68\x69\x6e\x74\x20\x27\x25\x73\x27\xa", hint);

    /*
     * lookup PSK identity and PSK key based on the given identity hint here
     */
    ret = BIO_snprintf(identity, max_identity_len, "\x25\x73", psk_identity);
    if (ret < 0 || (unsigned int)ret > max_identity_len)
        goto out_err;
    if (c_debug)
        BIO_printf(bio_c_out, "\x63\x72\x65\x61\x74\x65\x64\x20\x69\x64\x65\x6e\x74\x69\x74\x79\x20\x27\x25\x73\x27\x20\x6c\x65\x6e\x3d\x25\x64\xa", identity,
                   ret);

    /* convert the PSK key to binary */
    key = string_to_hex(psk_key, &key_len);
    if (key == NULL) {
        BIO_printf(bio_err, "\x43\x6f\x75\x6c\x64\x20\x6e\x6f\x74\x20\x63\x6f\x6e\x76\x65\x72\x74\x20\x50\x53\x4b\x20\x6b\x65\x79\x20\x27\x25\x73\x27\x20\x74\x6f\x20\x62\x75\x66\x66\x65\x72\xa",
                   psk_key);
        return 0;
    }
    if ((unsigned long)key_len > (unsigned long)max_psk_len) {
        BIO_printf(bio_err,
                   "\x70\x73\x6b\x20\x62\x75\x66\x66\x65\x72\x20\x6f\x66\x20\x63\x61\x6c\x6c\x62\x61\x63\x6b\x20\x69\x73\x20\x74\x6f\x6f\x20\x73\x6d\x61\x6c\x6c\x20\x28\x25\x64\x29\x20\x66\x6f\x72\x20\x6b\x65\x79\x20\x28\x25\x6c\x64\x29\xa",
                   max_psk_len, key_len);
        OPENSSL_free(key);
        return 0;
    }

    memcpy(psk, key, key_len);
    OPENSSL_free(key);

    if (c_debug)
        BIO_printf(bio_c_out, "\x63\x72\x65\x61\x74\x65\x64\x20\x50\x53\x4b\x20\x6c\x65\x6e\x3d\x25\x6c\x64\xa", key_len);

    return key_len;
 out_err:
    if (c_debug)
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x69\x6e\x20\x50\x53\x4b\x20\x63\x6c\x69\x65\x6e\x74\x20\x63\x61\x6c\x6c\x62\x61\x63\x6b\xa");
    return 0;
}
#endif

static void sc_usage(void)
{
    BIO_printf(bio_err, "\x75\x73\x61\x67\x65\x3a\x20\x73\x5f\x63\x6c\x69\x65\x6e\x74\x20\x61\x72\x67\x73\xa");
    BIO_printf(bio_err, "\xa");
    BIO_printf(bio_err, "\x20\x2d\x68\x6f\x73\x74\x20\x68\x6f\x73\x74\x20\x20\x20\x20\x20\x2d\x20\x75\x73\x65\x20\x2d\x63\x6f\x6e\x6e\x65\x63\x74\x20\x69\x6e\x73\x74\x65\x61\x64\xa");
    BIO_printf(bio_err, "\x20\x2d\x70\x6f\x72\x74\x20\x70\x6f\x72\x74\x20\x20\x20\x20\x20\x2d\x20\x75\x73\x65\x20\x2d\x63\x6f\x6e\x6e\x65\x63\x74\x20\x69\x6e\x73\x74\x65\x61\x64\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x63\x6f\x6e\x6e\x65\x63\x74\x20\x68\x6f\x73\x74\x3a\x70\x6f\x72\x74\x20\x2d\x20\x77\x68\x6f\x20\x74\x6f\x20\x63\x6f\x6e\x6e\x65\x63\x74\x20\x74\x6f\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x20\x69\x73\x20\x25\x73\x3a\x25\x73\x29\xa",
               SSL_HOST_NAME, PORT_STR);
    BIO_printf(bio_err,
               "\x20\x2d\x76\x65\x72\x69\x66\x79\x5f\x68\x6f\x73\x74\x6e\x61\x6d\x65\x20\x68\x6f\x73\x74\x20\x2d\x20\x63\x68\x65\x63\x6b\x20\x70\x65\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x6d\x61\x74\x63\x68\x65\x73\x20\x22\x68\x6f\x73\x74\x22\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x76\x65\x72\x69\x66\x79\x5f\x65\x6d\x61\x69\x6c\x20\x65\x6d\x61\x69\x6c\x20\x2d\x20\x63\x68\x65\x63\x6b\x20\x70\x65\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x6d\x61\x74\x63\x68\x65\x73\x20\x22\x65\x6d\x61\x69\x6c\x22\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x76\x65\x72\x69\x66\x79\x5f\x69\x70\x20\x69\x70\x61\x64\x64\x72\x20\x2d\x20\x63\x68\x65\x63\x6b\x20\x70\x65\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x6d\x61\x74\x63\x68\x65\x73\x20\x22\x69\x70\x61\x64\x64\x72\x22\xa");

    BIO_printf(bio_err,
               "\x20\x2d\x76\x65\x72\x69\x66\x79\x20\x61\x72\x67\x20\x20\x20\x2d\x20\x74\x75\x72\x6e\x20\x6f\x6e\x20\x70\x65\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x76\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x76\x65\x72\x69\x66\x79\x5f\x72\x65\x74\x75\x72\x6e\x5f\x65\x72\x72\x6f\x72\x20\x2d\x20\x72\x65\x74\x75\x72\x6e\x20\x76\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x20\x65\x72\x72\x6f\x72\x73\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x63\x65\x72\x74\x20\x61\x72\x67\x20\x20\x20\x20\x20\x2d\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x66\x69\x6c\x65\x20\x74\x6f\x20\x75\x73\x65\x2c\x20\x50\x45\x4d\x20\x66\x6f\x72\x6d\x61\x74\x20\x61\x73\x73\x75\x6d\x65\x64\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x63\x65\x72\x74\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x2d\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x66\x6f\x72\x6d\x61\x74\x20\x28\x50\x45\x4d\x20\x6f\x72\x20\x44\x45\x52\x29\x20\x50\x45\x4d\x20\x64\x65\x66\x61\x75\x6c\x74\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x6b\x65\x79\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x2d\x20\x50\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x66\x69\x6c\x65\x20\x74\x6f\x20\x75\x73\x65\x2c\x20\x69\x6e\x20\x63\x65\x72\x74\x20\x66\x69\x6c\x65\x20\x69\x66\xa");
    BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6e\x6f\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x62\x75\x74\x20\x63\x65\x72\x74\x20\x66\x69\x6c\x65\x20\x69\x73\x2e\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x6b\x65\x79\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x2d\x20\x6b\x65\x79\x20\x66\x6f\x72\x6d\x61\x74\x20\x28\x50\x45\x4d\x20\x6f\x72\x20\x44\x45\x52\x29\x20\x50\x45\x4d\x20\x64\x65\x66\x61\x75\x6c\x74\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x70\x61\x73\x73\x20\x61\x72\x67\x20\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x66\x69\x6c\x65\x20\x70\x61\x73\x73\x20\x70\x68\x72\x61\x73\x65\x20\x73\x6f\x75\x72\x63\x65\xa");
    BIO_printf(bio_err, "\x20\x2d\x43\x41\x70\x61\x74\x68\x20\x61\x72\x67\x20\x20\x20\x2d\x20\x50\x45\x4d\x20\x66\x6f\x72\x6d\x61\x74\x20\x64\x69\x72\x65\x63\x74\x6f\x72\x79\x20\x6f\x66\x20\x43\x41\x27\x73\xa");
    BIO_printf(bio_err, "\x20\x2d\x43\x41\x66\x69\x6c\x65\x20\x61\x72\x67\x20\x20\x20\x2d\x20\x50\x45\x4d\x20\x66\x6f\x72\x6d\x61\x74\x20\x66\x69\x6c\x65\x20\x6f\x66\x20\x43\x41\x27\x73\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x6e\x6f\x5f\x61\x6c\x74\x5f\x63\x68\x61\x69\x6e\x73\x20\x2d\x20\x6f\x6e\x6c\x79\x20\x65\x76\x65\x72\x20\x75\x73\x65\x20\x74\x68\x65\x20\x66\x69\x72\x73\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x63\x68\x61\x69\x6e\x20\x66\x6f\x75\x6e\x64\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x72\x65\x63\x6f\x6e\x6e\x65\x63\x74\x20\x20\x20\x20\x2d\x20\x44\x72\x6f\x70\x20\x61\x6e\x64\x20\x72\x65\x2d\x6d\x61\x6b\x65\x20\x74\x68\x65\x20\x63\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x20\x77\x69\x74\x68\x20\x74\x68\x65\x20\x73\x61\x6d\x65\x20\x53\x65\x73\x73\x69\x6f\x6e\x2d\x49\x44\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x70\x61\x75\x73\x65\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x73\x6c\x65\x65\x70\x28\x31\x29\x20\x61\x66\x74\x65\x72\x20\x65\x61\x63\x68\x20\x72\x65\x61\x64\x28\x32\x29\x20\x61\x6e\x64\x20\x77\x72\x69\x74\x65\x28\x32\x29\x20\x73\x79\x73\x74\x65\x6d\x20\x63\x61\x6c\x6c\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x70\x72\x65\x78\x69\x74\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x73\x65\x73\x73\x69\x6f\x6e\x20\x69\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e\x20\x65\x76\x65\x6e\x20\x6f\x6e\x20\x63\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x20\x66\x61\x69\x6c\x75\x72\x65\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x73\x68\x6f\x77\x63\x65\x72\x74\x73\x20\x20\x20\x20\x2d\x20\x73\x68\x6f\x77\x20\x61\x6c\x6c\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x69\x6e\x20\x74\x68\x65\x20\x63\x68\x61\x69\x6e\xa");
    BIO_printf(bio_err, "\x20\x2d\x64\x65\x62\x75\x67\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x65\x78\x74\x72\x61\x20\x6f\x75\x74\x70\x75\x74\xa");
#ifdef WATT32
    BIO_printf(bio_err, "\x20\x2d\x77\x64\x65\x62\x75\x67\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x57\x41\x54\x54\x2d\x33\x32\x20\x74\x63\x70\x20\x64\x65\x62\x75\x67\x67\x69\x6e\x67\xa");
#endif
    BIO_printf(bio_err, "\x20\x2d\x6d\x73\x67\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x53\x68\x6f\x77\x20\x70\x72\x6f\x74\x6f\x63\x6f\x6c\x20\x6d\x65\x73\x73\x61\x67\x65\x73\xa");
    BIO_printf(bio_err, "\x20\x2d\x6e\x62\x69\x6f\x5f\x74\x65\x73\x74\x20\x20\x20\x20\x2d\x20\x6d\x6f\x72\x65\x20\x73\x73\x6c\x20\x70\x72\x6f\x74\x6f\x63\x6f\x6c\x20\x74\x65\x73\x74\x69\x6e\x67\xa");
    BIO_printf(bio_err, "\x20\x2d\x73\x74\x61\x74\x65\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x70\x72\x69\x6e\x74\x20\x74\x68\x65\x20\x27\x73\x73\x6c\x27\x20\x73\x74\x61\x74\x65\x73\xa");
#ifdef FIONBIO
    BIO_printf(bio_err, "\x20\x2d\x6e\x62\x69\x6f\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x52\x75\x6e\x20\x77\x69\x74\x68\x20\x6e\x6f\x6e\x2d\x62\x6c\x6f\x63\x6b\x69\x6e\x67\x20\x49\x4f\xa");
#endif
    BIO_printf(bio_err,
               "\x20\x2d\x63\x72\x6c\x66\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x63\x6f\x6e\x76\x65\x72\x74\x20\x4c\x46\x20\x66\x72\x6f\x6d\x20\x74\x65\x72\x6d\x69\x6e\x61\x6c\x20\x69\x6e\x74\x6f\x20\x43\x52\x4c\x46\xa");
    BIO_printf(bio_err, "\x20\x2d\x71\x75\x69\x65\x74\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x6e\x6f\x20\x73\x5f\x63\x6c\x69\x65\x6e\x74\x20\x6f\x75\x74\x70\x75\x74\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x69\x67\x6e\x5f\x65\x6f\x66\x20\x20\x20\x20\x20\x20\x2d\x20\x69\x67\x6e\x6f\x72\x65\x20\x69\x6e\x70\x75\x74\x20\x65\x6f\x66\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x20\x77\x68\x65\x6e\x20\x2d\x71\x75\x69\x65\x74\x29\xa");
    BIO_printf(bio_err, "\x20\x2d\x6e\x6f\x5f\x69\x67\x6e\x5f\x65\x6f\x66\x20\x20\x20\x2d\x20\x64\x6f\x6e\x27\x74\x20\x69\x67\x6e\x6f\x72\x65\x20\x69\x6e\x70\x75\x74\x20\x65\x6f\x66\xa");
#ifndef OPENSSL_NO_PSK
    BIO_printf(bio_err, "\x20\x2d\x70\x73\x6b\x5f\x69\x64\x65\x6e\x74\x69\x74\x79\x20\x61\x72\x67\x20\x2d\x20\x50\x53\x4b\x20\x69\x64\x65\x6e\x74\x69\x74\x79\xa");
    BIO_printf(bio_err, "\x20\x2d\x70\x73\x6b\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x2d\x20\x50\x53\x4b\x20\x69\x6e\x20\x68\x65\x78\x20\x28\x77\x69\x74\x68\x6f\x75\x74\x20\x30\x78\x29\xa");
# ifndef OPENSSL_NO_JPAKE
    BIO_printf(bio_err, "\x20\x2d\x6a\x70\x61\x6b\x65\x20\x61\x72\x67\x20\x20\x20\x20\x2d\x20\x4a\x50\x41\x4b\x45\x20\x73\x65\x63\x72\x65\x74\x20\x74\x6f\x20\x75\x73\x65\xa");
# endif
#endif
#ifndef OPENSSL_NO_SRP
    BIO_printf(bio_err,
               "\x20\x2d\x73\x72\x70\x75\x73\x65\x72\x20\x75\x73\x65\x72\x20\x20\x20\x20\x20\x2d\x20\x53\x52\x50\x20\x61\x75\x74\x68\x65\x6e\x74\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x20\x66\x6f\x72\x20\x27\x75\x73\x65\x72\x27\xa");
    BIO_printf(bio_err, "\x20\x2d\x73\x72\x70\x70\x61\x73\x73\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x2d\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x20\x66\x6f\x72\x20\x27\x75\x73\x65\x72\x27\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x73\x72\x70\x5f\x6c\x61\x74\x65\x75\x73\x65\x72\x20\x20\x20\x20\x20\x2d\x20\x53\x52\x50\x20\x75\x73\x65\x72\x6e\x61\x6d\x65\x20\x69\x6e\x74\x6f\x20\x73\x65\x63\x6f\x6e\x64\x20\x43\x6c\x69\x65\x6e\x74\x48\x65\x6c\x6c\x6f\x20\x6d\x65\x73\x73\x61\x67\x65\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x73\x72\x70\x5f\x6d\x6f\x72\x65\x67\x72\x6f\x75\x70\x73\x20\x20\x20\x2d\x20\x54\x6f\x6c\x65\x72\x61\x74\x65\x20\x6f\x74\x68\x65\x72\x20\x74\x68\x61\x6e\x20\x74\x68\x65\x20\x6b\x6e\x6f\x77\x6e\x20\x67\x20\x4e\x20\x76\x61\x6c\x75\x65\x73\x2e\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x73\x72\x70\x5f\x73\x74\x72\x65\x6e\x67\x74\x68\x20\x69\x6e\x74\x20\x2d\x20\x6d\x69\x6e\x69\x6d\x61\x6c\x20\x6c\x65\x6e\x67\x74\x68\x20\x69\x6e\x20\x62\x69\x74\x73\x20\x66\x6f\x72\x20\x4e\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x20\x25\x64\x29\x2e\xa",
               SRP_MINIMAL_N);
#endif
    BIO_printf(bio_err, "\x20\x2d\x73\x73\x6c\x32\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x6a\x75\x73\x74\x20\x75\x73\x65\x20\x53\x53\x4c\x76\x32\xa");
#ifndef OPENSSL_NO_SSL3_METHOD
    BIO_printf(bio_err, "\x20\x2d\x73\x73\x6c\x33\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x6a\x75\x73\x74\x20\x75\x73\x65\x20\x53\x53\x4c\x76\x33\xa");
#endif
    BIO_printf(bio_err, "\x20\x2d\x74\x6c\x73\x31\x5f\x32\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x6a\x75\x73\x74\x20\x75\x73\x65\x20\x54\x4c\x53\x76\x31\x2e\x32\xa");
    BIO_printf(bio_err, "\x20\x2d\x74\x6c\x73\x31\x5f\x31\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x6a\x75\x73\x74\x20\x75\x73\x65\x20\x54\x4c\x53\x76\x31\x2e\x31\xa");
    BIO_printf(bio_err, "\x20\x2d\x74\x6c\x73\x31\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x6a\x75\x73\x74\x20\x75\x73\x65\x20\x54\x4c\x53\x76\x31\xa");
    BIO_printf(bio_err, "\x20\x2d\x64\x74\x6c\x73\x31\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x6a\x75\x73\x74\x20\x75\x73\x65\x20\x44\x54\x4c\x53\x76\x31\xa");
    BIO_printf(bio_err, "\x20\x2d\x66\x61\x6c\x6c\x62\x61\x63\x6b\x5f\x73\x63\x73\x76\x20\x2d\x20\x73\x65\x6e\x64\x20\x54\x4c\x53\x5f\x46\x41\x4c\x4c\x42\x41\x43\x4b\x5f\x53\x43\x53\x56\xa");
    BIO_printf(bio_err, "\x20\x2d\x6d\x74\x75\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x73\x65\x74\x20\x74\x68\x65\x20\x6c\x69\x6e\x6b\x20\x6c\x61\x79\x65\x72\x20\x4d\x54\x55\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x6e\x6f\x5f\x74\x6c\x73\x31\x5f\x32\x2f\x2d\x6e\x6f\x5f\x74\x6c\x73\x31\x5f\x31\x2f\x2d\x6e\x6f\x5f\x74\x6c\x73\x31\x2f\x2d\x6e\x6f\x5f\x73\x73\x6c\x33\x2f\x2d\x6e\x6f\x5f\x73\x73\x6c\x32\x20\x2d\x20\x74\x75\x72\x6e\x20\x6f\x66\x66\x20\x74\x68\x61\x74\x20\x70\x72\x6f\x74\x6f\x63\x6f\x6c\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x62\x75\x67\x73\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x53\x77\x69\x74\x63\x68\x20\x6f\x6e\x20\x61\x6c\x6c\x20\x53\x53\x4c\x20\x69\x6d\x70\x6c\x65\x6d\x65\x6e\x74\x61\x74\x69\x6f\x6e\x20\x62\x75\x67\x20\x77\x6f\x72\x6b\x61\x72\x6f\x75\x6e\x64\x73\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x63\x69\x70\x68\x65\x72\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x70\x72\x65\x66\x65\x72\x72\x65\x64\x20\x63\x69\x70\x68\x65\x72\x20\x74\x6f\x20\x75\x73\x65\x2c\x20\x75\x73\x65\x20\x74\x68\x65\x20\x27\x6f\x70\x65\x6e\x73\x73\x6c\x20\x63\x69\x70\x68\x65\x72\x73\x27\xa");
    BIO_printf(bio_err,
               "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x63\x6f\x6d\x6d\x61\x6e\x64\x20\x74\x6f\x20\x73\x65\x65\x20\x77\x68\x61\x74\x20\x69\x73\x20\x61\x76\x61\x69\x6c\x61\x62\x6c\x65\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x73\x74\x61\x72\x74\x74\x6c\x73\x20\x70\x72\x6f\x74\x20\x2d\x20\x75\x73\x65\x20\x74\x68\x65\x20\x53\x54\x41\x52\x54\x54\x4c\x53\x20\x63\x6f\x6d\x6d\x61\x6e\x64\x20\x62\x65\x66\x6f\x72\x65\x20\x73\x74\x61\x72\x74\x69\x6e\x67\x20\x54\x4c\x53\xa");
    BIO_printf(bio_err,
               "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x66\x6f\x72\x20\x74\x68\x6f\x73\x65\x20\x70\x72\x6f\x74\x6f\x63\x6f\x6c\x73\x20\x74\x68\x61\x74\x20\x73\x75\x70\x70\x6f\x72\x74\x20\x69\x74\x2c\x20\x77\x68\x65\x72\x65\xa");
    BIO_printf(bio_err,
               "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x27\x70\x72\x6f\x74\x27\x20\x64\x65\x66\x69\x6e\x65\x73\x20\x77\x68\x69\x63\x68\x20\x6f\x6e\x65\x20\x74\x6f\x20\x61\x73\x73\x75\x6d\x65\x2e\x20\x20\x43\x75\x72\x72\x65\x6e\x74\x6c\x79\x2c\xa");
    BIO_printf(bio_err,
               "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6f\x6e\x6c\x79\x20\x22\x73\x6d\x74\x70\x22\x2c\x20\x22\x70\x6f\x70\x33\x22\x2c\x20\x22\x69\x6d\x61\x70\x22\x2c\x20\x22\x66\x74\x70\x22\x20\x61\x6e\x64\x20\x22\x78\x6d\x70\x70\x22\xa");
    BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x61\x72\x65\x20\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x2e\xa");
#ifndef OPENSSL_NO_ENGINE
    BIO_printf(bio_err,
               "\x20\x2d\x65\x6e\x67\x69\x6e\x65\x20\x69\x64\x20\x20\x20\x20\x2d\x20\x49\x6e\x69\x74\x69\x61\x6c\x69\x73\x65\x20\x61\x6e\x64\x20\x75\x73\x65\x20\x74\x68\x65\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x65\x6e\x67\x69\x6e\x65\xa");
#endif
    BIO_printf(bio_err, "\x20\x2d\x72\x61\x6e\x64\x20\x66\x69\x6c\x65\x25\x63\x66\x69\x6c\x65\x25\x63\x2e\x2e\x2e\xa", LIST_SEPARATOR_CHAR,
               LIST_SEPARATOR_CHAR);
    BIO_printf(bio_err, "\x20\x2d\x73\x65\x73\x73\x5f\x6f\x75\x74\x20\x61\x72\x67\x20\x2d\x20\x66\x69\x6c\x65\x20\x74\x6f\x20\x77\x72\x69\x74\x65\x20\x53\x53\x4c\x20\x73\x65\x73\x73\x69\x6f\x6e\x20\x74\x6f\xa");
    BIO_printf(bio_err, "\x20\x2d\x73\x65\x73\x73\x5f\x69\x6e\x20\x61\x72\x67\x20\x20\x2d\x20\x66\x69\x6c\x65\x20\x74\x6f\x20\x72\x65\x61\x64\x20\x53\x53\x4c\x20\x73\x65\x73\x73\x69\x6f\x6e\x20\x66\x72\x6f\x6d\xa");
#ifndef OPENSSL_NO_TLSEXT
    BIO_printf(bio_err,
               "\x20\x2d\x73\x65\x72\x76\x65\x72\x6e\x61\x6d\x65\x20\x68\x6f\x73\x74\x20\x20\x2d\x20\x53\x65\x74\x20\x54\x4c\x53\x20\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x20\x73\x65\x72\x76\x65\x72\x6e\x61\x6d\x65\x20\x69\x6e\x20\x43\x6c\x69\x65\x6e\x74\x48\x65\x6c\x6c\x6f\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x74\x6c\x73\x65\x78\x74\x64\x65\x62\x75\x67\x20\x20\x20\x20\x20\x20\x2d\x20\x68\x65\x78\x20\x64\x75\x6d\x70\x20\x6f\x66\x20\x61\x6c\x6c\x20\x54\x4c\x53\x20\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73\x20\x72\x65\x63\x65\x69\x76\x65\x64\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x73\x74\x61\x74\x75\x73\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x72\x65\x71\x75\x65\x73\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x73\x74\x61\x74\x75\x73\x20\x66\x72\x6f\x6d\x20\x73\x65\x72\x76\x65\x72\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x6e\x6f\x5f\x74\x69\x63\x6b\x65\x74\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x64\x69\x73\x61\x62\x6c\x65\x20\x75\x73\x65\x20\x6f\x66\x20\x52\x46\x43\x34\x35\x30\x37\x62\x69\x73\x20\x73\x65\x73\x73\x69\x6f\x6e\x20\x74\x69\x63\x6b\x65\x74\x73\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x73\x65\x72\x76\x65\x72\x69\x6e\x66\x6f\x20\x74\x79\x70\x65\x73\x20\x2d\x20\x73\x65\x6e\x64\x20\x65\x6d\x70\x74\x79\x20\x43\x6c\x69\x65\x6e\x74\x48\x65\x6c\x6c\x6f\x20\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73\x20\x28\x63\x6f\x6d\x6d\x61\x2d\x73\x65\x70\x61\x72\x61\x74\x65\x64\x20\x6e\x75\x6d\x62\x65\x72\x73\x29\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x63\x75\x72\x76\x65\x73\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x45\x6c\x6c\x69\x70\x74\x69\x63\x20\x63\x75\x72\x76\x65\x73\x20\x74\x6f\x20\x61\x64\x76\x65\x72\x74\x69\x73\x65\x20\x28\x63\x6f\x6c\x6f\x6e\x2d\x73\x65\x70\x61\x72\x61\x74\x65\x64\x20\x6c\x69\x73\x74\x29\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x73\x69\x67\x61\x6c\x67\x73\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x2d\x20\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x73\x20\x74\x6f\x20\x73\x75\x70\x70\x6f\x72\x74\x20\x28\x63\x6f\x6c\x6f\x6e\x2d\x73\x65\x70\x61\x72\x61\x74\x65\x64\x20\x6c\x69\x73\x74\x29\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x63\x6c\x69\x65\x6e\x74\x5f\x73\x69\x67\x61\x6c\x67\x73\x20\x61\x72\x67\x20\x2d\x20\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x73\x20\x74\x6f\x20\x73\x75\x70\x70\x6f\x72\x74\x20\x66\x6f\x72\x20\x63\x6c\x69\x65\x6e\x74\xa");
    BIO_printf(bio_err,
               "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x61\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x69\x6f\x6e\x20\x28\x63\x6f\x6c\x6f\x6e\x2d\x73\x65\x70\x61\x72\x61\x74\x65\x64\x20\x6c\x69\x73\x74\x29\xa");
#endif
#ifndef OPENSSL_NO_NEXTPROTONEG
    BIO_printf(bio_err,
               "\x20\x2d\x6e\x65\x78\x74\x70\x72\x6f\x74\x6f\x6e\x65\x67\x20\x61\x72\x67\x20\x2d\x20\x65\x6e\x61\x62\x6c\x65\x20\x4e\x50\x4e\x20\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x2c\x20\x63\x6f\x6e\x73\x69\x64\x65\x72\x69\x6e\x67\x20\x6e\x61\x6d\x65\x64\x20\x70\x72\x6f\x74\x6f\x63\x6f\x6c\x73\x20\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x20\x28\x63\x6f\x6d\x6d\x61\x2d\x73\x65\x70\x61\x72\x61\x74\x65\x64\x20\x6c\x69\x73\x74\x29\xa");
#endif
    BIO_printf(bio_err,
               "\x20\x2d\x61\x6c\x70\x6e\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x65\x6e\x61\x62\x6c\x65\x20\x41\x4c\x50\x4e\x20\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x2c\x20\x63\x6f\x6e\x73\x69\x64\x65\x72\x69\x6e\x67\x20\x6e\x61\x6d\x65\x64\x20\x70\x72\x6f\x74\x6f\x63\x6f\x6c\x73\x20\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x20\x28\x63\x6f\x6d\x6d\x61\x2d\x73\x65\x70\x61\x72\x61\x74\x65\x64\x20\x6c\x69\x73\x74\x29\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x6c\x65\x67\x61\x63\x79\x5f\x72\x65\x6e\x65\x67\x6f\x74\x69\x61\x74\x69\x6f\x6e\x20\x2d\x20\x65\x6e\x61\x62\x6c\x65\x20\x75\x73\x65\x20\x6f\x66\x20\x6c\x65\x67\x61\x63\x79\x20\x72\x65\x6e\x65\x67\x6f\x74\x69\x61\x74\x69\x6f\x6e\x20\x28\x64\x61\x6e\x67\x65\x72\x6f\x75\x73\x29\xa");
#ifndef OPENSSL_NO_SRTP
    BIO_printf(bio_err,
               "\x20\x2d\x75\x73\x65\x5f\x73\x72\x74\x70\x20\x70\x72\x6f\x66\x69\x6c\x65\x73\x20\x2d\x20\x4f\x66\x66\x65\x72\x20\x53\x52\x54\x50\x20\x6b\x65\x79\x20\x6d\x61\x6e\x61\x67\x65\x6d\x65\x6e\x74\x20\x77\x69\x74\x68\x20\x61\x20\x63\x6f\x6c\x6f\x6e\x2d\x73\x65\x70\x61\x72\x61\x74\x65\x64\x20\x70\x72\x6f\x66\x69\x6c\x65\x20\x6c\x69\x73\x74\xa");
#endif
    BIO_printf(bio_err,
               "\x20\x2d\x6b\x65\x79\x6d\x61\x74\x65\x78\x70\x6f\x72\x74\x20\x6c\x61\x62\x65\x6c\x20\x20\x20\x2d\x20\x45\x78\x70\x6f\x72\x74\x20\x6b\x65\x79\x69\x6e\x67\x20\x6d\x61\x74\x65\x72\x69\x61\x6c\x20\x75\x73\x69\x6e\x67\x20\x6c\x61\x62\x65\x6c\xa");
    BIO_printf(bio_err,
               "\x20\x2d\x6b\x65\x79\x6d\x61\x74\x65\x78\x70\x6f\x72\x74\x6c\x65\x6e\x20\x6c\x65\x6e\x20\x20\x2d\x20\x45\x78\x70\x6f\x72\x74\x20\x6c\x65\x6e\x20\x62\x79\x74\x65\x73\x20\x6f\x66\x20\x6b\x65\x79\x69\x6e\x67\x20\x6d\x61\x74\x65\x72\x69\x61\x6c\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x20\x32\x30\x29\xa");
#ifdef OPENSSL_SYS_WINDOWS
    BIO_printf(bio_err,
               "\x20\x2d\x6e\x6f\x5f\x72\x61\x6e\x64\x5f\x73\x63\x72\x65\x65\x6e\x20\x20\x2d\x20\x44\x6f\x20\x6e\x6f\x74\x20\x75\x73\x65\x20\x52\x41\x4e\x44\x5f\x73\x63\x72\x65\x65\x6e\x28\x29\x20\x74\x6f\x20\x69\x6e\x69\x74\x69\x61\x6c\x69\x7a\x65\x20\x72\x61\x6e\x64\x6f\x6d\x20\x73\x74\x61\x74\x65\xa");
#endif
}

#ifndef OPENSSL_NO_TLSEXT

/* This is a context that we pass to callbacks */
typedef struct tlsextctx_st {
    BIO *biodebug;
    int ack;
} tlsextctx;

static int MS_CALLBACK ssl_servername_cb(SSL *s, int *ad, void *arg)
{
    tlsextctx *p = (tlsextctx *) arg;
    const char *hn = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    if (SSL_get_servername_type(s) != -1)
        p->ack = !SSL_session_reused(s) && hn != NULL;
    else
        BIO_printf(bio_err, "\x43\x61\x6e\x27\x74\x20\x75\x73\x65\x20\x53\x53\x4c\x5f\x67\x65\x74\x5f\x73\x65\x72\x76\x65\x72\x6e\x61\x6d\x65\xa");

    return SSL_TLSEXT_ERR_OK;
}

# ifndef OPENSSL_NO_SRP

/* This is a context that we pass to all callbacks */
typedef struct srp_arg_st {
    char *srppassin;
    char *srplogin;
    int msg;                    /* copy from c_msg */
    int debug;                  /* copy from c_debug */
    int amp;                    /* allow more groups */
    int strength /* minimal size for N */ ;
} SRP_ARG;

#  define SRP_NUMBER_ITERATIONS_FOR_PRIME 64

static int srp_Verify_N_and_g(BIGNUM *N, BIGNUM *g)
{
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *r = BN_new();
    int ret =
        g != NULL && N != NULL && bn_ctx != NULL && BN_is_odd(N) &&
        BN_is_prime_ex(N, SRP_NUMBER_ITERATIONS_FOR_PRIME, bn_ctx, NULL) &&
        p != NULL && BN_rshift1(p, N) &&
        /* p = (N-1)/2 */
        BN_is_prime_ex(p, SRP_NUMBER_ITERATIONS_FOR_PRIME, bn_ctx, NULL) &&
        r != NULL &&
        /* verify g^((N-1)/2) == -1 (mod N) */
        BN_mod_exp(r, g, p, N, bn_ctx) &&
        BN_add_word(r, 1) && BN_cmp(r, N) == 0;

    if (r)
        BN_free(r);
    if (p)
        BN_free(p);
    if (bn_ctx)
        BN_CTX_free(bn_ctx);
    return ret;
}

/*-
 * This callback is used here for two purposes:
 * - extended debugging
 * - making some primality tests for unknown groups
 * The callback is only called for a non default group.
 *
 * An application does not need the call back at all if
 * only the stanard groups are used.  In real life situations,
 * client and server already share well known groups,
 * thus there is no need to verify them.
 * Furthermore, in case that a server actually proposes a group that
 * is not one of those defined in RFC 5054, it is more appropriate
 * to add the group to a static list and then compare since
 * primality tests are rather cpu consuming.
 */

static int MS_CALLBACK ssl_srp_verify_param_cb(SSL *s, void *arg)
{
    SRP_ARG *srp_arg = (SRP_ARG *)arg;
    BIGNUM *N = NULL, *g = NULL;
    if (!(N = SSL_get_srp_N(s)) || !(g = SSL_get_srp_g(s)))
        return 0;
    if (srp_arg->debug || srp_arg->msg || srp_arg->amp == 1) {
        BIO_printf(bio_err, "\x53\x52\x50\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x3a\xa");
        BIO_printf(bio_err, "\x9\x4e\x3d");
        BN_print(bio_err, N);
        BIO_printf(bio_err, "\xa\x9\x67\x3d");
        BN_print(bio_err, g);
        BIO_printf(bio_err, "\xa");
    }

    if (SRP_check_known_gN_param(g, N))
        return 1;

    if (srp_arg->amp == 1) {
        if (srp_arg->debug)
            BIO_printf(bio_err,
                       "\x53\x52\x50\x20\x70\x61\x72\x61\x6d\x20\x4e\x20\x61\x6e\x64\x20\x67\x20\x61\x72\x65\x20\x6e\x6f\x74\x20\x6b\x6e\x6f\x77\x6e\x20\x70\x61\x72\x61\x6d\x73\x2c\x20\x67\x6f\x69\x6e\x67\x20\x74\x6f\x20\x63\x68\x65\x63\x6b\x20\x64\x65\x65\x70\x65\x72\x2e\xa");

        /*
         * The srp_moregroups is a real debugging feature. Implementors
         * should rather add the value to the known ones. The minimal size
         * has already been tested.
         */
        if (BN_num_bits(g) <= BN_BITS && srp_Verify_N_and_g(N, g))
            return 1;
    }
    BIO_printf(bio_err, "\x53\x52\x50\x20\x70\x61\x72\x61\x6d\x20\x4e\x20\x61\x6e\x64\x20\x67\x20\x72\x65\x6a\x65\x63\x74\x65\x64\x2e\xa");
    return 0;
}

#  define PWD_STRLEN 1024

static char *MS_CALLBACK ssl_give_srp_client_pwd_cb(SSL *s, void *arg)
{
    SRP_ARG *srp_arg = (SRP_ARG *)arg;
    char *pass = (char *)OPENSSL_malloc(PWD_STRLEN + 1);
    PW_CB_DATA cb_tmp;
    int l;

    if (!pass) {
        BIO_printf(bio_err, "\x4d\x61\x6c\x6c\x6f\x63\x20\x66\x61\x69\x6c\x75\x72\x65\xa");
        return NULL;
    }

    cb_tmp.password = (char *)srp_arg->srppassin;
    cb_tmp.prompt_info = "\x53\x52\x50\x20\x75\x73\x65\x72";
    if ((l = password_callback(pass, PWD_STRLEN, 0, &cb_tmp)) < 0) {
        BIO_printf(bio_err, "\x43\x61\x6e\x27\x74\x20\x72\x65\x61\x64\x20\x50\x61\x73\x73\x77\x6f\x72\x64\xa");
        OPENSSL_free(pass);
        return NULL;
    }
    *(pass + l) = '\x0';

    return pass;
}

# endif
# ifndef OPENSSL_NO_SRTP
char *srtp_profiles = NULL;
# endif

# ifndef OPENSSL_NO_NEXTPROTONEG
/* This the context that we pass to next_proto_cb */
typedef struct tlsextnextprotoctx_st {
    unsigned char *data;
    unsigned short len;
    int status;
} tlsextnextprotoctx;

static tlsextnextprotoctx next_proto;

static int next_proto_cb(SSL *s, unsigned char **out, unsigned char *outlen,
                         const unsigned char *in, unsigned int inlen,
                         void *arg)
{
    tlsextnextprotoctx *ctx = arg;

    if (!c_quiet) {
        /* We can assume that |in| is syntactically valid. */
        unsigned i;
        BIO_printf(bio_c_out, "\x50\x72\x6f\x74\x6f\x63\x6f\x6c\x73\x20\x61\x64\x76\x65\x72\x74\x69\x73\x65\x64\x20\x62\x79\x20\x73\x65\x72\x76\x65\x72\x3a\x20");
        for (i = 0; i < inlen;) {
            if (i)
                BIO_write(bio_c_out, "\x2c\x20", 2);
            BIO_write(bio_c_out, &in[i + 1], in[i]);
            i += in[i] + 1;
        }
        BIO_write(bio_c_out, "\xa", 1);
    }

    ctx->status =
        SSL_select_next_proto(out, outlen, in, inlen, ctx->data, ctx->len);
    return SSL_TLSEXT_ERR_OK;
}
# endif                         /* ndef OPENSSL_NO_NEXTPROTONEG */

static int serverinfo_cli_parse_cb(SSL *s, unsigned int ext_type,
                                   const unsigned char *in, size_t inlen,
                                   int *al, void *arg)
{
    char pem_name[100];
    unsigned char ext_buf[4 + 65536];

    /* Reconstruct the type/len fields prior to extension data */
    inlen &= 0xffff; /* for formal memcpy correctness */
    ext_buf[0] = (unsigned char)(ext_type >> 8);
    ext_buf[1] = (unsigned char)(ext_type);
    ext_buf[2] = (unsigned char)(inlen >> 8);
    ext_buf[3] = (unsigned char)(inlen);
    memcpy(ext_buf + 4, in, inlen);

    BIO_snprintf(pem_name, sizeof(pem_name), "\x53\x45\x52\x56\x45\x52\x49\x4e\x46\x4f\x20\x46\x4f\x52\x20\x45\x58\x54\x45\x4e\x53\x49\x4f\x4e\x20\x25\x64",
                 ext_type);
    PEM_write_bio(bio_c_out, pem_name, "", ext_buf, 4 + inlen);
    return 1;
}

#endif

enum {
    PROTO_OFF = 0,
    PROTO_SMTP,
    PROTO_POP3,
    PROTO_IMAP,
    PROTO_FTP,
    PROTO_XMPP
};

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    int build_chain = 0;
    SSL *con = NULL;
#ifndef OPENSSL_NO_KRB5
    KSSL_CTX *kctx;
#endif
    int s, k, width, state = 0;
    char *cbuf = NULL, *sbuf = NULL, *mbuf = NULL;
    int cbuf_len, cbuf_off;
    int sbuf_len, sbuf_off;
    fd_set readfds, writefds;
    short port = PORT;
    int full_log = 1;
    char *host = SSL_HOST_NAME;
    char *cert_file = NULL, *key_file = NULL, *chain_file = NULL;
    int cert_format = FORMAT_PEM, key_format = FORMAT_PEM;
    char *passarg = NULL, *pass = NULL;
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;
    STACK_OF(X509) *chain = NULL;
    char *CApath = NULL, *CAfile = NULL;
    char *chCApath = NULL, *chCAfile = NULL;
    char *vfyCApath = NULL, *vfyCAfile = NULL;
    int reconnect = 0, badop = 0, verify = SSL_VERIFY_NONE;
    int crlf = 0;
    int write_tty, read_tty, write_ssl, read_ssl, tty_on, ssl_pending;
    SSL_CTX *ctx = NULL;
    int ret = 1, in_init = 1, i, nbio_test = 0;
    int starttls_proto = PROTO_OFF;
    int prexit = 0;
    X509_VERIFY_PARAM *vpm = NULL;
    int badarg = 0;
    const SSL_METHOD *meth = NULL;
    int socket_type = SOCK_STREAM;
    BIO *sbio;
    char *inrand = NULL;
    int mbuf_len = 0;
    struct timeval timeout, *timeoutp;
    char *engine_id = NULL;
    ENGINE *e = NULL;
#ifndef OPENSSL_NO_ENGINE
    char *ssl_client_engine_id = NULL;
    ENGINE *ssl_client_engine = NULL;
#endif
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS) || defined(OPENSSL_SYS_NETWARE) || defined(OPENSSL_SYS_BEOS_R5)
    struct timeval tv;
# if defined(OPENSSL_SYS_BEOS_R5)
    int stdin_set = 0;
# endif
#endif
#ifndef OPENSSL_NO_TLSEXT
    char *servername = NULL;
    tlsextctx tlsextcbp = { NULL, 0 };
# ifndef OPENSSL_NO_NEXTPROTONEG
    const char *next_proto_neg_in = NULL;
# endif
    const char *alpn_in = NULL;
# define MAX_SI_TYPES 100
    unsigned short serverinfo_types[MAX_SI_TYPES];
    int serverinfo_types_count = 0;
#endif
    char *sess_in = NULL;
    char *sess_out = NULL;
    struct sockaddr peer;
    int peerlen = sizeof(peer);
    int fallback_scsv = 0;
    int enable_timeouts = 0;
    long socket_mtu = 0;
#ifndef OPENSSL_NO_JPAKE
    static char *jpake_secret = NULL;
# define no_jpake !jpake_secret
#else
# define no_jpake 1
#endif
#ifndef OPENSSL_NO_SRP
    char *srppass = NULL;
    int srp_lateuser = 0;
    SRP_ARG srp_arg = { NULL, NULL, 0, 0, 0, 1024 };
#endif
    SSL_EXCERT *exc = NULL;

    SSL_CONF_CTX *cctx = NULL;
    STACK_OF(OPENSSL_STRING) *ssl_args = NULL;

    char *crl_file = NULL;
    int crl_format = FORMAT_PEM;
    int crl_download = 0;
    STACK_OF(X509_CRL) *crls = NULL;
    int prot_opt = 0, no_prot_opt = 0;

    meth = SSLv23_client_method();

    apps_startup();
    c_Pause = 0;
    c_quiet = 0;
    c_ign_eof = 0;
    c_debug = 0;
    c_msg = 0;
    c_showcerts = 0;

    if (bio_err == NULL)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!load_config(bio_err, NULL))
        goto end;

    cctx = SSL_CONF_CTX_new();
    if (!cctx)
        goto end;
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CLIENT);
    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CMDLINE);

    if (((cbuf = OPENSSL_malloc(BUFSIZZ)) == NULL) ||
        ((sbuf = OPENSSL_malloc(BUFSIZZ)) == NULL) ||
        ((mbuf = OPENSSL_malloc(BUFSIZZ)) == NULL)) {
        BIO_printf(bio_err, "\x6f\x75\x74\x20\x6f\x66\x20\x6d\x65\x6d\x6f\x72\x79\xa");
        goto end;
    }

    verify_depth = 0;
    verify_error = X509_V_OK;
#ifdef FIONBIO
    c_nbio = 0;
#endif

    argc--;
    argv++;
    while (argc >= 1) {
        if (strcmp(*argv, "\x2d\x68\x6f\x73\x74") == 0) {
            if (--argc < 1)
                goto bad;
            host = *(++argv);
        } else if (strcmp(*argv, "\x2d\x70\x6f\x72\x74") == 0) {
            if (--argc < 1)
                goto bad;
            port = atoi(*(++argv));
            if (port == 0)
                goto bad;
        } else if (strcmp(*argv, "\x2d\x63\x6f\x6e\x6e\x65\x63\x74") == 0) {
            if (--argc < 1)
                goto bad;
            if (!extract_host_port(*(++argv), &host, NULL, &port))
                goto bad;
        } else if (strcmp(*argv, "\x2d\x76\x65\x72\x69\x66\x79") == 0) {
            verify = SSL_VERIFY_PEER;
            if (--argc < 1)
                goto bad;
            verify_depth = atoi(*(++argv));
            if (!c_quiet)
                BIO_printf(bio_err, "\x76\x65\x72\x69\x66\x79\x20\x64\x65\x70\x74\x68\x20\x69\x73\x20\x25\x64\xa", verify_depth);
        } else if (strcmp(*argv, "\x2d\x63\x65\x72\x74") == 0) {
            if (--argc < 1)
                goto bad;
            cert_file = *(++argv);
        } else if (strcmp(*argv, "\x2d\x43\x52\x4c") == 0) {
            if (--argc < 1)
                goto bad;
            crl_file = *(++argv);
        } else if (strcmp(*argv, "\x2d\x63\x72\x6c\x5f\x64\x6f\x77\x6e\x6c\x6f\x61\x64") == 0)
            crl_download = 1;
        else if (strcmp(*argv, "\x2d\x73\x65\x73\x73\x5f\x6f\x75\x74") == 0) {
            if (--argc < 1)
                goto bad;
            sess_out = *(++argv);
        } else if (strcmp(*argv, "\x2d\x73\x65\x73\x73\x5f\x69\x6e") == 0) {
            if (--argc < 1)
                goto bad;
            sess_in = *(++argv);
        } else if (strcmp(*argv, "\x2d\x63\x65\x72\x74\x66\x6f\x72\x6d") == 0) {
            if (--argc < 1)
                goto bad;
            cert_format = str2fmt(*(++argv));
        } else if (strcmp(*argv, "\x2d\x43\x52\x4c\x66\x6f\x72\x6d") == 0) {
            if (--argc < 1)
                goto bad;
            crl_format = str2fmt(*(++argv));
        } else if (args_verify(&argv, &argc, &badarg, bio_err, &vpm)) {
            if (badarg)
                goto bad;
            continue;
        } else if (strcmp(*argv, "\x2d\x76\x65\x72\x69\x66\x79\x5f\x72\x65\x74\x75\x72\x6e\x5f\x65\x72\x72\x6f\x72") == 0)
            verify_return_error = 1;
        else if (strcmp(*argv, "\x2d\x76\x65\x72\x69\x66\x79\x5f\x71\x75\x69\x65\x74") == 0)
            verify_quiet = 1;
        else if (strcmp(*argv, "\x2d\x62\x72\x69\x65\x66") == 0) {
            c_brief = 1;
            verify_quiet = 1;
            c_quiet = 1;
        } else if (args_excert(&argv, &argc, &badarg, bio_err, &exc)) {
            if (badarg)
                goto bad;
            continue;
        } else if (args_ssl(&argv, &argc, cctx, &badarg, bio_err, &ssl_args,
                            &no_prot_opt)) {
            if (badarg)
                goto bad;
            continue;
        } else if (strcmp(*argv, "\x2d\x70\x72\x65\x78\x69\x74") == 0)
            prexit = 1;
        else if (strcmp(*argv, "\x2d\x63\x72\x6c\x66") == 0)
            crlf = 1;
        else if (strcmp(*argv, "\x2d\x71\x75\x69\x65\x74") == 0) {
            c_quiet = 1;
            c_ign_eof = 1;
        } else if (strcmp(*argv, "\x2d\x69\x67\x6e\x5f\x65\x6f\x66") == 0)
            c_ign_eof = 1;
        else if (strcmp(*argv, "\x2d\x6e\x6f\x5f\x69\x67\x6e\x5f\x65\x6f\x66") == 0)
            c_ign_eof = 0;
        else if (strcmp(*argv, "\x2d\x70\x61\x75\x73\x65") == 0)
            c_Pause = 1;
        else if (strcmp(*argv, "\x2d\x64\x65\x62\x75\x67") == 0)
            c_debug = 1;
#ifndef OPENSSL_NO_TLSEXT
        else if (strcmp(*argv, "\x2d\x74\x6c\x73\x65\x78\x74\x64\x65\x62\x75\x67") == 0)
            c_tlsextdebug = 1;
        else if (strcmp(*argv, "\x2d\x73\x74\x61\x74\x75\x73") == 0)
            c_status_req = 1;
#endif
#ifdef WATT32
        else if (strcmp(*argv, "\x2d\x77\x64\x65\x62\x75\x67") == 0)
            dbug_init();
#endif
        else if (strcmp(*argv, "\x2d\x6d\x73\x67") == 0)
            c_msg = 1;
        else if (strcmp(*argv, "\x2d\x6d\x73\x67\x66\x69\x6c\x65") == 0) {
            if (--argc < 1)
                goto bad;
            bio_c_msg = BIO_new_file(*(++argv), "\x77");
        }
#ifndef OPENSSL_NO_SSL_TRACE
        else if (strcmp(*argv, "\x2d\x74\x72\x61\x63\x65") == 0)
            c_msg = 2;
#endif
        else if (strcmp(*argv, "\x2d\x73\x68\x6f\x77\x63\x65\x72\x74\x73") == 0)
            c_showcerts = 1;
        else if (strcmp(*argv, "\x2d\x6e\x62\x69\x6f\x5f\x74\x65\x73\x74") == 0)
            nbio_test = 1;
        else if (strcmp(*argv, "\x2d\x73\x74\x61\x74\x65") == 0)
            state = 1;
#ifndef OPENSSL_NO_PSK
        else if (strcmp(*argv, "\x2d\x70\x73\x6b\x5f\x69\x64\x65\x6e\x74\x69\x74\x79") == 0) {
            if (--argc < 1)
                goto bad;
            psk_identity = *(++argv);
        } else if (strcmp(*argv, "\x2d\x70\x73\x6b") == 0) {
            size_t j;

            if (--argc < 1)
                goto bad;
            psk_key = *(++argv);
            for (j = 0; j < strlen(psk_key); j++) {
                if (isxdigit((unsigned char)psk_key[j]))
                    continue;
                BIO_printf(bio_err, "\x4e\x6f\x74\x20\x61\x20\x68\x65\x78\x20\x6e\x75\x6d\x62\x65\x72\x20\x27\x25\x73\x27\xa", *argv);
                goto bad;
            }
        }
#endif
#ifndef OPENSSL_NO_SRP
        else if (strcmp(*argv, "\x2d\x73\x72\x70\x75\x73\x65\x72") == 0) {
            if (--argc < 1)
                goto bad;
            srp_arg.srplogin = *(++argv);
            meth = TLSv1_client_method();
        } else if (strcmp(*argv, "\x2d\x73\x72\x70\x70\x61\x73\x73") == 0) {
            if (--argc < 1)
                goto bad;
            srppass = *(++argv);
            meth = TLSv1_client_method();
        } else if (strcmp(*argv, "\x2d\x73\x72\x70\x5f\x73\x74\x72\x65\x6e\x67\x74\x68") == 0) {
            if (--argc < 1)
                goto bad;
            srp_arg.strength = atoi(*(++argv));
            BIO_printf(bio_err, "\x53\x52\x50\x20\x6d\x69\x6e\x69\x6d\x61\x6c\x20\x6c\x65\x6e\x67\x74\x68\x20\x66\x6f\x72\x20\x4e\x20\x69\x73\x20\x25\x64\xa",
                       srp_arg.strength);
            meth = TLSv1_client_method();
        } else if (strcmp(*argv, "\x2d\x73\x72\x70\x5f\x6c\x61\x74\x65\x75\x73\x65\x72") == 0) {
            srp_lateuser = 1;
            meth = TLSv1_client_method();
        } else if (strcmp(*argv, "\x2d\x73\x72\x70\x5f\x6d\x6f\x72\x65\x67\x72\x6f\x75\x70\x73") == 0) {
            srp_arg.amp = 1;
            meth = TLSv1_client_method();
        }
#endif
#ifndef OPENSSL_NO_SSL2
        else if (strcmp(*argv, "\x2d\x73\x73\x6c\x32") == 0) {
            meth = SSLv2_client_method();
            prot_opt++;
        }
#endif
#ifndef OPENSSL_NO_SSL3_METHOD
        else if (strcmp(*argv, "\x2d\x73\x73\x6c\x33") == 0) {
            meth = SSLv3_client_method();
            prot_opt++;
        }
#endif
#ifndef OPENSSL_NO_TLS1
        else if (strcmp(*argv, "\x2d\x74\x6c\x73\x31\x5f\x32") == 0) {
            meth = TLSv1_2_client_method();
            prot_opt++;
        } else if (strcmp(*argv, "\x2d\x74\x6c\x73\x31\x5f\x31") == 0) {
            meth = TLSv1_1_client_method();
            prot_opt++;
        } else if (strcmp(*argv, "\x2d\x74\x6c\x73\x31") == 0) {
            meth = TLSv1_client_method();
            prot_opt++;
        }
#endif
#ifndef OPENSSL_NO_DTLS1
        else if (strcmp(*argv, "\x2d\x64\x74\x6c\x73") == 0) {
            meth = DTLS_client_method();
            socket_type = SOCK_DGRAM;
            prot_opt++;
        } else if (strcmp(*argv, "\x2d\x64\x74\x6c\x73\x31") == 0) {
            meth = DTLSv1_client_method();
            socket_type = SOCK_DGRAM;
            prot_opt++;
        } else if (strcmp(*argv, "\x2d\x64\x74\x6c\x73\x31\x5f\x32") == 0) {
            meth = DTLSv1_2_client_method();
            socket_type = SOCK_DGRAM;
            prot_opt++;
        } else if (strcmp(*argv, "\x2d\x74\x69\x6d\x65\x6f\x75\x74") == 0)
            enable_timeouts = 1;
        else if (strcmp(*argv, "\x2d\x6d\x74\x75") == 0) {
            if (--argc < 1)
                goto bad;
            socket_mtu = atol(*(++argv));
        }
#endif
        else if (strcmp(*argv, "\x2d\x66\x61\x6c\x6c\x62\x61\x63\x6b\x5f\x73\x63\x73\x76") == 0) {
            fallback_scsv = 1;
        } else if (strcmp(*argv, "\x2d\x6b\x65\x79\x66\x6f\x72\x6d") == 0) {
            if (--argc < 1)
                goto bad;
            key_format = str2fmt(*(++argv));
        } else if (strcmp(*argv, "\x2d\x70\x61\x73\x73") == 0) {
            if (--argc < 1)
                goto bad;
            passarg = *(++argv);
        } else if (strcmp(*argv, "\x2d\x63\x65\x72\x74\x5f\x63\x68\x61\x69\x6e") == 0) {
            if (--argc < 1)
                goto bad;
            chain_file = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6b\x65\x79") == 0) {
            if (--argc < 1)
                goto bad;
            key_file = *(++argv);
        } else if (strcmp(*argv, "\x2d\x72\x65\x63\x6f\x6e\x6e\x65\x63\x74") == 0) {
            reconnect = 5;
        } else if (strcmp(*argv, "\x2d\x43\x41\x70\x61\x74\x68") == 0) {
            if (--argc < 1)
                goto bad;
            CApath = *(++argv);
        } else if (strcmp(*argv, "\x2d\x63\x68\x61\x69\x6e\x43\x41\x70\x61\x74\x68") == 0) {
            if (--argc < 1)
                goto bad;
            chCApath = *(++argv);
        } else if (strcmp(*argv, "\x2d\x76\x65\x72\x69\x66\x79\x43\x41\x70\x61\x74\x68") == 0) {
            if (--argc < 1)
                goto bad;
            vfyCApath = *(++argv);
        } else if (strcmp(*argv, "\x2d\x62\x75\x69\x6c\x64\x5f\x63\x68\x61\x69\x6e") == 0)
            build_chain = 1;
        else if (strcmp(*argv, "\x2d\x43\x41\x66\x69\x6c\x65") == 0) {
            if (--argc < 1)
                goto bad;
            CAfile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x63\x68\x61\x69\x6e\x43\x41\x66\x69\x6c\x65") == 0) {
            if (--argc < 1)
                goto bad;
            chCAfile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x76\x65\x72\x69\x66\x79\x43\x41\x66\x69\x6c\x65") == 0) {
            if (--argc < 1)
                goto bad;
            vfyCAfile = *(++argv);
        }
#ifndef OPENSSL_NO_TLSEXT
# ifndef OPENSSL_NO_NEXTPROTONEG
        else if (strcmp(*argv, "\x2d\x6e\x65\x78\x74\x70\x72\x6f\x74\x6f\x6e\x65\x67") == 0) {
            if (--argc < 1)
                goto bad;
            next_proto_neg_in = *(++argv);
        }
# endif
        else if (strcmp(*argv, "\x2d\x61\x6c\x70\x6e") == 0) {
            if (--argc < 1)
                goto bad;
            alpn_in = *(++argv);
        } else if (strcmp(*argv, "\x2d\x73\x65\x72\x76\x65\x72\x69\x6e\x66\x6f") == 0) {
            char *c;
            int start = 0;
            int len;

            if (--argc < 1)
                goto bad;
            c = *(++argv);
            serverinfo_types_count = 0;
            len = strlen(c);
            for (i = 0; i <= len; ++i) {
                if (i == len || c[i] == '\x2c') {
                    serverinfo_types[serverinfo_types_count]
                        = atoi(c + start);
                    serverinfo_types_count++;
                    start = i + 1;
                }
                if (serverinfo_types_count == MAX_SI_TYPES)
                    break;
            }
        }
#endif
#ifdef FIONBIO
        else if (strcmp(*argv, "\x2d\x6e\x62\x69\x6f") == 0) {
            c_nbio = 1;
        }
#endif
        else if (strcmp(*argv, "\x2d\x73\x74\x61\x72\x74\x74\x6c\x73") == 0) {
            if (--argc < 1)
                goto bad;
            ++argv;
            if (strcmp(*argv, "\x73\x6d\x74\x70") == 0)
                starttls_proto = PROTO_SMTP;
            else if (strcmp(*argv, "\x70\x6f\x70\x33") == 0)
                starttls_proto = PROTO_POP3;
            else if (strcmp(*argv, "\x69\x6d\x61\x70") == 0)
                starttls_proto = PROTO_IMAP;
            else if (strcmp(*argv, "\x66\x74\x70") == 0)
                starttls_proto = PROTO_FTP;
            else if (strcmp(*argv, "\x78\x6d\x70\x70") == 0)
                starttls_proto = PROTO_XMPP;
            else
                goto bad;
        }
#ifndef OPENSSL_NO_ENGINE
        else if (strcmp(*argv, "\x2d\x65\x6e\x67\x69\x6e\x65") == 0) {
            if (--argc < 1)
                goto bad;
            engine_id = *(++argv);
        } else if (strcmp(*argv, "\x2d\x73\x73\x6c\x5f\x63\x6c\x69\x65\x6e\x74\x5f\x65\x6e\x67\x69\x6e\x65") == 0) {
            if (--argc < 1)
                goto bad;
            ssl_client_engine_id = *(++argv);
        }
#endif
        else if (strcmp(*argv, "\x2d\x72\x61\x6e\x64") == 0) {
            if (--argc < 1)
                goto bad;
            inrand = *(++argv);
        }
#ifndef OPENSSL_NO_TLSEXT
        else if (strcmp(*argv, "\x2d\x73\x65\x72\x76\x65\x72\x6e\x61\x6d\x65") == 0) {
            if (--argc < 1)
                goto bad;
            servername = *(++argv);
            /* meth=TLSv1_client_method(); */
        }
#endif
#ifndef OPENSSL_NO_JPAKE
        else if (strcmp(*argv, "\x2d\x6a\x70\x61\x6b\x65") == 0) {
            if (--argc < 1)
                goto bad;
            jpake_secret = *++argv;
        }
#endif
#ifndef OPENSSL_NO_SRTP
        else if (strcmp(*argv, "\x2d\x75\x73\x65\x5f\x73\x72\x74\x70") == 0) {
            if (--argc < 1)
                goto bad;
            srtp_profiles = *(++argv);
        }
#endif
        else if (strcmp(*argv, "\x2d\x6b\x65\x79\x6d\x61\x74\x65\x78\x70\x6f\x72\x74") == 0) {
            if (--argc < 1)
                goto bad;
            keymatexportlabel = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6b\x65\x79\x6d\x61\x74\x65\x78\x70\x6f\x72\x74\x6c\x65\x6e") == 0) {
            if (--argc < 1)
                goto bad;
            keymatexportlen = atoi(*(++argv));
            if (keymatexportlen == 0)
                goto bad;
#ifdef OPENSSL_SYS_WINDOWS
        } else if (strcmp(*argv, "\x2d\x6e\x6f\x5f\x72\x61\x6e\x64\x5f\x73\x63\x72\x65\x65\x6e") == 0) {
          c_no_rand_screen = 1;
#endif
        } else {
            BIO_printf(bio_err, "\x75\x6e\x6b\x6e\x6f\x77\x6e\x20\x6f\x70\x74\x69\x6f\x6e\x20\x25\x73\xa", *argv);
            badop = 1;
            break;
        }
        argc--;
        argv++;
    }
    if (badop) {
 bad:
        sc_usage();
        goto end;
    }
#if !defined(OPENSSL_NO_JPAKE) && !defined(OPENSSL_NO_PSK)
    if (jpake_secret) {
        if (psk_key) {
            BIO_printf(bio_err, "\x43\x61\x6e\x27\x74\x20\x75\x73\x65\x20\x4a\x50\x41\x4b\x45\x20\x61\x6e\x64\x20\x50\x53\x4b\x20\x74\x6f\x67\x65\x74\x68\x65\x72\xa");
            goto end;
        }
        psk_identity = "\x4a\x50\x41\x4b\x45";
    }
#endif

    if (prot_opt > 1) {
        BIO_printf(bio_err, "\x43\x61\x6e\x6e\x6f\x74\x20\x73\x75\x70\x70\x6c\x79\x20\x6d\x75\x6c\x74\x69\x70\x6c\x65\x20\x70\x72\x6f\x74\x6f\x63\x6f\x6c\x20\x66\x6c\x61\x67\x73\xa");
        goto end;
    }

    if (prot_opt == 1 && no_prot_opt) {
        BIO_printf(bio_err, "\x43\x61\x6e\x6e\x6f\x74\x20\x73\x75\x70\x70\x6c\x79\x20\x62\x6f\x74\x68\x20\x61\x20\x70\x72\x6f\x74\x6f\x63\x6f\x6c\x20\x66\x6c\x61\x67\x20\x61\x6e\x64\x20"
                            "\x22\x2d\x6e\x6f\x5f\x3c\x70\x72\x6f\x74\x3e\x22\xa");
        goto end;
    }

    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

#if !defined(OPENSSL_NO_TLSEXT) && !defined(OPENSSL_NO_NEXTPROTONEG)
    next_proto.status = -1;
    if (next_proto_neg_in) {
        next_proto.data =
            next_protos_parse(&next_proto.len, next_proto_neg_in);
        if (next_proto.data == NULL) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x70\x61\x72\x73\x69\x6e\x67\x20\x2d\x6e\x65\x78\x74\x70\x72\x6f\x74\x6f\x6e\x65\x67\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\xa");
            goto end;
        }
    } else
        next_proto.data = NULL;
#endif

    e = setup_engine(bio_err, engine_id, 1);
#ifndef OPENSSL_NO_ENGINE
    if (ssl_client_engine_id) {
        ssl_client_engine = ENGINE_by_id(ssl_client_engine_id);
        if (!ssl_client_engine) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x63\x6c\x69\x65\x6e\x74\x20\x61\x75\x74\x68\x20\x65\x6e\x67\x69\x6e\x65\xa");
            goto end;
        }
    }
#endif
    if (!app_passwd(bio_err, passarg, NULL, &pass, NULL)) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\xa");
        goto end;
    }

    if (key_file == NULL)
        key_file = cert_file;

    if (key_file) {

        key = load_key(bio_err, key_file, key_format, 0, pass, e,
                       "\x63\x6c\x69\x65\x6e\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x66\x69\x6c\x65");
        if (!key) {
            ERR_print_errors(bio_err);
            goto end;
        }

    }

    if (cert_file) {
        cert = load_cert(bio_err, cert_file, cert_format,
                         NULL, e, "\x63\x6c\x69\x65\x6e\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x66\x69\x6c\x65");

        if (!cert) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (chain_file) {
        chain = load_certs(bio_err, chain_file, FORMAT_PEM,
                           NULL, e, "\x63\x6c\x69\x65\x6e\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x63\x68\x61\x69\x6e");
        if (!chain)
            goto end;
    }

    if (crl_file) {
        X509_CRL *crl;
        crl = load_crl(crl_file, crl_format);
        if (!crl) {
            BIO_puts(bio_err, "\x45\x72\x72\x6f\x72\x20\x6c\x6f\x61\x64\x69\x6e\x67\x20\x43\x52\x4c\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
        crls = sk_X509_CRL_new_null();
        if (!crls || !sk_X509_CRL_push(crls, crl)) {
            BIO_puts(bio_err, "\x45\x72\x72\x6f\x72\x20\x61\x64\x64\x69\x6e\x67\x20\x43\x52\x4c\xa");
            ERR_print_errors(bio_err);
            X509_CRL_free(crl);
            goto end;
        }
    }

    if (!load_excert(&exc, bio_err))
        goto end;

    if (!app_RAND_load_file(NULL, bio_err, ++c_no_rand_screen) && inrand == NULL
        && !RAND_status()) {
        BIO_printf(bio_err,
                   "\x77\x61\x72\x6e\x69\x6e\x67\x2c\x20\x6e\x6f\x74\x20\x6d\x75\x63\x68\x20\x65\x78\x74\x72\x61\x20\x72\x61\x6e\x64\x6f\x6d\x20\x64\x61\x74\x61\x2c\x20\x63\x6f\x6e\x73\x69\x64\x65\x72\x20\x75\x73\x69\x6e\x67\x20\x74\x68\x65\x20\x2d\x72\x61\x6e\x64\x20\x6f\x70\x74\x69\x6f\x6e\xa");
    }
    if (inrand != NULL)
        BIO_printf(bio_err, "\x25\x6c\x64\x20\x73\x65\x6d\x69\x2d\x72\x61\x6e\x64\x6f\x6d\x20\x62\x79\x74\x65\x73\x20\x6c\x6f\x61\x64\x65\x64\xa",
                   app_RAND_load_files(inrand));

    if (bio_c_out == NULL) {
        if (c_quiet && !c_debug) {
            bio_c_out = BIO_new(BIO_s_null());
            if (c_msg && !bio_c_msg)
                bio_c_msg = BIO_new_fp(stdout, BIO_NOCLOSE);
        } else {
            if (bio_c_out == NULL)
                bio_c_out = BIO_new_fp(stdout, BIO_NOCLOSE);
        }
    }
#ifndef OPENSSL_NO_SRP
    if (!app_passwd(bio_err, srppass, NULL, &srp_arg.srppassin, NULL)) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\xa");
        goto end;
    }
#endif

    ctx = SSL_CTX_new(meth);
    if (ctx == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (vpm)
        SSL_CTX_set1_param(ctx, vpm);

    if (!args_ssl_call(ctx, bio_err, cctx, ssl_args, 1, no_jpake)) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (!ssl_load_stores(ctx, vfyCApath, vfyCAfile, chCApath, chCAfile,
                         crls, crl_download)) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x6c\x6f\x61\x64\x69\x6e\x67\x20\x73\x74\x6f\x72\x65\x20\x6c\x6f\x63\x61\x74\x69\x6f\x6e\x73\xa");
        ERR_print_errors(bio_err);
        goto end;
    }
#ifndef OPENSSL_NO_ENGINE
    if (ssl_client_engine) {
        if (!SSL_CTX_set_client_cert_engine(ctx, ssl_client_engine)) {
            BIO_puts(bio_err, "\x45\x72\x72\x6f\x72\x20\x73\x65\x74\x74\x69\x6e\x67\x20\x63\x6c\x69\x65\x6e\x74\x20\x61\x75\x74\x68\x20\x65\x6e\x67\x69\x6e\x65\xa");
            ERR_print_errors(bio_err);
            ENGINE_free(ssl_client_engine);
            goto end;
        }
        ENGINE_free(ssl_client_engine);
    }
#endif

#ifndef OPENSSL_NO_PSK
# ifdef OPENSSL_NO_JPAKE
    if (psk_key != NULL)
# else
    if (psk_key != NULL || jpake_secret)
# endif
    {
        if (c_debug)
            BIO_printf(bio_c_out,
                       "\x50\x53\x4b\x20\x6b\x65\x79\x20\x67\x69\x76\x65\x6e\x20\x6f\x72\x20\x4a\x50\x41\x4b\x45\x20\x69\x6e\x20\x75\x73\x65\x2c\x20\x73\x65\x74\x74\x69\x6e\x67\x20\x63\x6c\x69\x65\x6e\x74\x20\x63\x61\x6c\x6c\x62\x61\x63\x6b\xa");
        SSL_CTX_set_psk_client_callback(ctx, psk_client_cb);
    }
#endif
#ifndef OPENSSL_NO_SRTP
    if (srtp_profiles != NULL)
        SSL_CTX_set_tlsext_use_srtp(ctx, srtp_profiles);
#endif
    if (exc)
        ssl_ctx_set_excert(ctx, exc);

#if !defined(OPENSSL_NO_TLSEXT)
# if !defined(OPENSSL_NO_NEXTPROTONEG)
    if (next_proto.data)
        SSL_CTX_set_next_proto_select_cb(ctx, next_proto_cb, &next_proto);
# endif
    if (alpn_in) {
        unsigned short alpn_len;
        unsigned char *alpn = next_protos_parse(&alpn_len, alpn_in);

        if (alpn == NULL) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x70\x61\x72\x73\x69\x6e\x67\x20\x2d\x61\x6c\x70\x6e\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\xa");
            goto end;
        }
        SSL_CTX_set_alpn_protos(ctx, alpn, alpn_len);
        OPENSSL_free(alpn);
    }
#endif
#ifndef OPENSSL_NO_TLSEXT
    for (i = 0; i < serverinfo_types_count; i++) {
        SSL_CTX_add_client_custom_ext(ctx,
                                      serverinfo_types[i],
                                      NULL, NULL, NULL,
                                      serverinfo_cli_parse_cb, NULL);
    }
#endif

    if (state)
        SSL_CTX_set_info_callback(ctx, apps_ssl_info_callback);
#if 0
    else
        SSL_CTX_set_cipher_list(ctx, getenv("\x53\x53\x4c\x5f\x43\x49\x50\x48\x45\x52"));
#endif

    SSL_CTX_set_verify(ctx, verify, verify_callback);

    if ((CAfile || CApath)
        && !SSL_CTX_load_verify_locations(ctx, CAfile, CApath)) {
        ERR_print_errors(bio_err);
    }
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        ERR_print_errors(bio_err);
    }

    ssl_ctx_add_crls(ctx, crls, crl_download);
    if (!set_cert_key_stuff(ctx, cert, key, chain, build_chain))
        goto end;

#ifndef OPENSSL_NO_TLSEXT
    if (servername != NULL) {
        tlsextcbp.biodebug = bio_err;
        SSL_CTX_set_tlsext_servername_callback(ctx, ssl_servername_cb);
        SSL_CTX_set_tlsext_servername_arg(ctx, &tlsextcbp);
    }
# ifndef OPENSSL_NO_SRP
    if (srp_arg.srplogin) {
        if (!srp_lateuser && !SSL_CTX_set_srp_username(ctx, srp_arg.srplogin)) {
            BIO_printf(bio_err, "\x55\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x73\x65\x74\x20\x53\x52\x50\x20\x75\x73\x65\x72\x6e\x61\x6d\x65\xa");
            goto end;
        }
        srp_arg.msg = c_msg;
        srp_arg.debug = c_debug;
        SSL_CTX_set_srp_cb_arg(ctx, &srp_arg);
        SSL_CTX_set_srp_client_pwd_callback(ctx, ssl_give_srp_client_pwd_cb);
        SSL_CTX_set_srp_strength(ctx, srp_arg.strength);
        if (c_msg || c_debug || srp_arg.amp == 0)
            SSL_CTX_set_srp_verify_param_callback(ctx,
                                                  ssl_srp_verify_param_cb);
    }
# endif
#endif

    con = SSL_new(ctx);
    if (sess_in) {
        SSL_SESSION *sess;
        BIO *stmp = BIO_new_file(sess_in, "\x72");
        if (!stmp) {
            BIO_printf(bio_err, "\x43\x61\x6e\x27\x74\x20\x6f\x70\x65\x6e\x20\x73\x65\x73\x73\x69\x6f\x6e\x20\x66\x69\x6c\x65\x20\x25\x73\xa", sess_in);
            ERR_print_errors(bio_err);
            goto end;
        }
        sess = PEM_read_bio_SSL_SESSION(stmp, NULL, 0, NULL);
        BIO_free(stmp);
        if (!sess) {
            BIO_printf(bio_err, "\x43\x61\x6e\x27\x74\x20\x6f\x70\x65\x6e\x20\x73\x65\x73\x73\x69\x6f\x6e\x20\x66\x69\x6c\x65\x20\x25\x73\xa", sess_in);
            ERR_print_errors(bio_err);
            goto end;
        }
        SSL_set_session(con, sess);
        SSL_SESSION_free(sess);
    }

    if (fallback_scsv)
        SSL_set_mode(con, SSL_MODE_SEND_FALLBACK_SCSV);

#ifndef OPENSSL_NO_TLSEXT
    if (servername != NULL) {
        if (!SSL_set_tlsext_host_name(con, servername)) {
            BIO_printf(bio_err, "\x55\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x73\x65\x74\x20\x54\x4c\x53\x20\x73\x65\x72\x76\x65\x72\x6e\x61\x6d\x65\x20\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x2e\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
    }
#endif
#ifndef OPENSSL_NO_KRB5
    if (con && (kctx = kssl_ctx_new()) != NULL) {
        SSL_set0_kssl_ctx(con, kctx);
        kssl_ctx_setstring(kctx, KSSL_SERVER, host);
    }
#endif                          /* OPENSSL_NO_KRB5 */
/*      SSL_set_cipher_list(con,"\x52\x43\x34\x2d\x4d\x44\x35"); */
#if 0
# ifdef TLSEXT_TYPE_opaque_prf_input
    SSL_set_tlsext_opaque_prf_input(con, "\x54\x65\x73\x74\x20\x63\x6c\x69\x65\x6e\x74", 11);
# endif
#endif

 re_start:

    if (init_client(&s, host, port, socket_type) == 0) {
        BIO_printf(bio_err, "\x63\x6f\x6e\x6e\x65\x63\x74\x3a\x65\x72\x72\x6e\x6f\x3d\x25\x64\xa", get_last_socket_error());
        SHUTDOWN(s);
        goto end;
    }
    BIO_printf(bio_c_out, "\x43\x4f\x4e\x4e\x45\x43\x54\x45\x44\x28\x25\x30\x38\x58\x29\xa", s);

#ifdef FIONBIO
    if (c_nbio) {
        unsigned long l = 1;
        BIO_printf(bio_c_out, "\x74\x75\x72\x6e\x69\x6e\x67\x20\x6f\x6e\x20\x6e\x6f\x6e\x20\x62\x6c\x6f\x63\x6b\x69\x6e\x67\x20\x69\x6f\xa");
        if (BIO_socket_ioctl(s, FIONBIO, &l) < 0) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }
#endif
    if (c_Pause & 0x01)
        SSL_set_debug(con, 1);

    if (socket_type == SOCK_DGRAM) {

        sbio = BIO_new_dgram(s, BIO_NOCLOSE);
        if (getsockname(s, &peer, (void *)&peerlen) < 0) {
            BIO_printf(bio_err, "\x67\x65\x74\x73\x6f\x63\x6b\x6e\x61\x6d\x65\x3a\x65\x72\x72\x6e\x6f\x3d\x25\x64\xa",
                       get_last_socket_error());
            SHUTDOWN(s);
            goto end;
        }

        (void)BIO_ctrl_set_connected(sbio, 1, &peer);

        if (enable_timeouts) {
            timeout.tv_sec = 0;
            timeout.tv_usec = DGRAM_RCV_TIMEOUT;
            BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

            timeout.tv_sec = 0;
            timeout.tv_usec = DGRAM_SND_TIMEOUT;
            BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &timeout);
        }

        if (socket_mtu) {
            if (socket_mtu < DTLS_get_link_min_mtu(con)) {
                BIO_printf(bio_err, "\x4d\x54\x55\x20\x74\x6f\x6f\x20\x73\x6d\x61\x6c\x6c\x2e\x20\x4d\x75\x73\x74\x20\x62\x65\x20\x61\x74\x20\x6c\x65\x61\x73\x74\x20\x25\x6c\x64\xa",
                           DTLS_get_link_min_mtu(con));
                BIO_free(sbio);
                goto shut;
            }
            SSL_set_options(con, SSL_OP_NO_QUERY_MTU);
            if (!DTLS_set_link_mtu(con, socket_mtu)) {
                BIO_printf(bio_err, "\x46\x61\x69\x6c\x65\x64\x20\x74\x6f\x20\x73\x65\x74\x20\x4d\x54\x55\xa");
                BIO_free(sbio);
                goto shut;
            }
        } else
            /* want to do MTU discovery */
            BIO_ctrl(sbio, BIO_CTRL_DGRAM_MTU_DISCOVER, 0, NULL);
    } else
        sbio = BIO_new_socket(s, BIO_NOCLOSE);

    if (nbio_test) {
        BIO *test;

        test = BIO_new(BIO_f_nbio_test());
        sbio = BIO_push(test, sbio);
    }

    if (c_debug) {
        SSL_set_debug(con, 1);
        BIO_set_callback(sbio, bio_dump_callback);
        BIO_set_callback_arg(sbio, (char *)bio_c_out);
    }
    if (c_msg) {
#ifndef OPENSSL_NO_SSL_TRACE
        if (c_msg == 2)
            SSL_set_msg_callback(con, SSL_trace);
        else
#endif
            SSL_set_msg_callback(con, msg_cb);
        SSL_set_msg_callback_arg(con, bio_c_msg ? bio_c_msg : bio_c_out);
    }
#ifndef OPENSSL_NO_TLSEXT
    if (c_tlsextdebug) {
        SSL_set_tlsext_debug_callback(con, tlsext_cb);
        SSL_set_tlsext_debug_arg(con, bio_c_out);
    }
    if (c_status_req) {
        SSL_set_tlsext_status_type(con, TLSEXT_STATUSTYPE_ocsp);
        SSL_CTX_set_tlsext_status_cb(ctx, ocsp_resp_cb);
        SSL_CTX_set_tlsext_status_arg(ctx, bio_c_out);
# if 0
        {
            STACK_OF(OCSP_RESPID) *ids = sk_OCSP_RESPID_new_null();
            OCSP_RESPID *id = OCSP_RESPID_new();
            id->value.byKey = ASN1_OCTET_STRING_new();
            id->type = V_OCSP_RESPID_KEY;
            ASN1_STRING_set(id->value.byKey, "\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64", -1);
            sk_OCSP_RESPID_push(ids, id);
            SSL_set_tlsext_status_ids(con, ids);
        }
# endif
    }
#endif
#ifndef OPENSSL_NO_JPAKE
    if (jpake_secret)
        jpake_client_auth(bio_c_out, sbio, jpake_secret);
#endif

    SSL_set_bio(con, sbio, sbio);
    SSL_set_connect_state(con);

    /* ok, lets connect */
    if (fileno_stdin() > SSL_get_fd(con))
        width = fileno_stdin() + 1;
    else
        width = SSL_get_fd(con) + 1;

    read_tty = 1;
    write_tty = 0;
    tty_on = 0;
    read_ssl = 1;
    write_ssl = 1;

    cbuf_len = 0;
    cbuf_off = 0;
    sbuf_len = 0;
    sbuf_off = 0;

    /* This is an ugly hack that does a lot of assumptions */
    /*
     * We do have to handle multi-line responses which may come in a single
     * packet or not. We therefore have to use BIO_gets() which does need a
     * buffering BIO. So during the initial chitchat we do push a buffering
     * BIO into the chain that is removed again later on to not disturb the
     * rest of the s_client operation.
     */
    if (starttls_proto == PROTO_SMTP) {
        int foundit = 0;
        BIO *fbio = BIO_new(BIO_f_buffer());
        BIO_push(fbio, sbio);
        /* wait for multi-line response to end from SMTP */
        do {
            mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
        }
        while (mbuf_len > 3 && mbuf[3] == '\x2d');
        /* STARTTLS command requires EHLO... */
        BIO_printf(fbio, "\x45\x48\x4c\x4f\x20\x6f\x70\x65\x6e\x73\x73\x6c\x2e\x63\x6c\x69\x65\x6e\x74\x2e\x6e\x65\x74\xd\xa");
        (void)BIO_flush(fbio);
        /* wait for multi-line response to end EHLO SMTP response */
        do {
            mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
            if (strstr(mbuf, "\x53\x54\x41\x52\x54\x54\x4c\x53"))
                foundit = 1;
        }
        while (mbuf_len > 3 && mbuf[3] == '\x2d');
        (void)BIO_flush(fbio);
        BIO_pop(fbio);
        BIO_free(fbio);
        if (!foundit)
            BIO_printf(bio_err,
                       "\x64\x69\x64\x6e\x27\x74\x20\x66\x6f\x75\x6e\x64\x20\x73\x74\x61\x72\x74\x74\x6c\x73\x20\x69\x6e\x20\x73\x65\x72\x76\x65\x72\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\x2c"
                       "\x20\x74\x72\x79\x20\x61\x6e\x79\x77\x61\x79\x2e\x2e\x2e\xa");
        BIO_printf(sbio, "\x53\x54\x41\x52\x54\x54\x4c\x53\xd\xa");
        BIO_read(sbio, sbuf, BUFSIZZ);
    } else if (starttls_proto == PROTO_POP3) {
        BIO_read(sbio, mbuf, BUFSIZZ);
        BIO_printf(sbio, "\x53\x54\x4c\x53\xd\xa");
        BIO_read(sbio, sbuf, BUFSIZZ);
    } else if (starttls_proto == PROTO_IMAP) {
        int foundit = 0;
        BIO *fbio = BIO_new(BIO_f_buffer());
        BIO_push(fbio, sbio);
        BIO_gets(fbio, mbuf, BUFSIZZ);
        /* STARTTLS command requires CAPABILITY... */
        BIO_printf(fbio, "\x2e\x20\x43\x41\x50\x41\x42\x49\x4c\x49\x54\x59\xd\xa");
        (void)BIO_flush(fbio);
        /* wait for multi-line CAPABILITY response */
        do {
            mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
            if (strstr(mbuf, "\x53\x54\x41\x52\x54\x54\x4c\x53"))
                foundit = 1;
        }
        while (mbuf_len > 3 && mbuf[0] != '\x2e');
        (void)BIO_flush(fbio);
        BIO_pop(fbio);
        BIO_free(fbio);
        if (!foundit)
            BIO_printf(bio_err,
                       "\x64\x69\x64\x6e\x27\x74\x20\x66\x6f\x75\x6e\x64\x20\x53\x54\x41\x52\x54\x54\x4c\x53\x20\x69\x6e\x20\x73\x65\x72\x76\x65\x72\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\x2c"
                       "\x20\x74\x72\x79\x20\x61\x6e\x79\x77\x61\x79\x2e\x2e\x2e\xa");
        BIO_printf(sbio, "\x2e\x20\x53\x54\x41\x52\x54\x54\x4c\x53\xd\xa");
        BIO_read(sbio, sbuf, BUFSIZZ);
    } else if (starttls_proto == PROTO_FTP) {
        BIO *fbio = BIO_new(BIO_f_buffer());
        BIO_push(fbio, sbio);
        /* wait for multi-line response to end from FTP */
        do {
            mbuf_len = BIO_gets(fbio, mbuf, BUFSIZZ);
        }
        while (mbuf_len > 3 && mbuf[3] == '\x2d');
        (void)BIO_flush(fbio);
        BIO_pop(fbio);
        BIO_free(fbio);
        BIO_printf(sbio, "\x41\x55\x54\x48\x20\x54\x4c\x53\xd\xa");
        BIO_read(sbio, sbuf, BUFSIZZ);
    }
    if (starttls_proto == PROTO_XMPP) {
        int seen = 0;
        BIO_printf(sbio, "\x3c\x73\x74\x72\x65\x61\x6d\x3a\x73\x74\x72\x65\x61\x6d\x20"
                   "\x78\x6d\x6c\x6e\x73\x3a\x73\x74\x72\x65\x61\x6d\x3d\x27\x68\x74\x74\x70\x3a\x2f\x2f\x65\x74\x68\x65\x72\x78\x2e\x6a\x61\x62\x62\x65\x72\x2e\x6f\x72\x67\x2f\x73\x74\x72\x65\x61\x6d\x73\x27\x20"
                   "\x78\x6d\x6c\x6e\x73\x3d\x27\x6a\x61\x62\x62\x65\x72\x3a\x63\x6c\x69\x65\x6e\x74\x27\x20\x74\x6f\x3d\x27\x25\x73\x27\x20\x76\x65\x72\x73\x69\x6f\x6e\x3d\x27\x31\x2e\x30\x27\x3e", host);
        seen = BIO_read(sbio, mbuf, BUFSIZZ);
        mbuf[seen] = 0;
        while (!strstr
               (mbuf, "\x3c\x73\x74\x61\x72\x74\x74\x6c\x73\x20\x78\x6d\x6c\x6e\x73\x3d\x27\x75\x72\x6e\x3a\x69\x65\x74\x66\x3a\x70\x61\x72\x61\x6d\x73\x3a\x78\x6d\x6c\x3a\x6e\x73\x3a\x78\x6d\x70\x70\x2d\x74\x6c\x73\x27")) {
            if (strstr(mbuf, "\x2f\x73\x74\x72\x65\x61\x6d\x3a\x66\x65\x61\x74\x75\x72\x65\x73\x3e"))
                goto shut;
            seen = BIO_read(sbio, mbuf, BUFSIZZ);
            if (seen <= 0)
                goto shut;
            mbuf[seen] = 0;
        }
        BIO_printf(sbio,
                   "\x3c\x73\x74\x61\x72\x74\x74\x6c\x73\x20\x78\x6d\x6c\x6e\x73\x3d\x27\x75\x72\x6e\x3a\x69\x65\x74\x66\x3a\x70\x61\x72\x61\x6d\x73\x3a\x78\x6d\x6c\x3a\x6e\x73\x3a\x78\x6d\x70\x70\x2d\x74\x6c\x73\x27\x2f\x3e");
        seen = BIO_read(sbio, sbuf, BUFSIZZ);
        sbuf[seen] = 0;
        if (!strstr(sbuf, "\x3c\x70\x72\x6f\x63\x65\x65\x64"))
            goto shut;
        mbuf[0] = 0;
    }

    for (;;) {
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);

        if ((SSL_version(con) == DTLS1_VERSION) &&
            DTLSv1_get_timeout(con, &timeout))
            timeoutp = &timeout;
        else
            timeoutp = NULL;

        if (SSL_in_init(con) && !SSL_total_renegotiations(con)) {
            in_init = 1;
            tty_on = 0;
        } else {
            tty_on = 1;
            if (in_init) {
                in_init = 0;
#if 0                           /* This test doesn't really work as intended
                                 * (needs to be fixed) */
# ifndef OPENSSL_NO_TLSEXT
                if (servername != NULL && !SSL_session_reused(con)) {
                    BIO_printf(bio_c_out,
                               "\x53\x65\x72\x76\x65\x72\x20\x64\x69\x64\x20\x25\x73\x61\x63\x6b\x6e\x6f\x77\x6c\x65\x64\x67\x65\x20\x73\x65\x72\x76\x65\x72\x6e\x61\x6d\x65\x20\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x2e\xa",
                               tlsextcbp.ack ? "" : "\x6e\x6f\x74\x20");
                }
# endif
#endif
                if (sess_out) {
                    BIO *stmp = BIO_new_file(sess_out, "\x77");
                    if (stmp) {
                        PEM_write_bio_SSL_SESSION(stmp, SSL_get_session(con));
                        BIO_free(stmp);
                    } else
                        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x77\x72\x69\x74\x69\x6e\x67\x20\x73\x65\x73\x73\x69\x6f\x6e\x20\x66\x69\x6c\x65\x20\x25\x73\xa",
                                   sess_out);
                }
                if (c_brief) {
                    BIO_puts(bio_err, "\x43\x4f\x4e\x4e\x45\x43\x54\x49\x4f\x4e\x20\x45\x53\x54\x41\x42\x4c\x49\x53\x48\x45\x44\xa");
                    print_ssl_summary(bio_err, con);
                }

                print_stuff(bio_c_out, con, full_log);
                if (full_log > 0)
                    full_log--;

                if (starttls_proto) {
                    BIO_printf(bio_err, "\x25\x73", mbuf);
                    /* We don't need to know any more */
                    starttls_proto = PROTO_OFF;
                }

                if (reconnect) {
                    reconnect--;
                    BIO_printf(bio_c_out,
                               "\x64\x72\x6f\x70\x20\x63\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x20\x61\x6e\x64\x20\x74\x68\x65\x6e\x20\x72\x65\x63\x6f\x6e\x6e\x65\x63\x74\xa");
                    SSL_shutdown(con);
                    SSL_set_connect_state(con);
                    SHUTDOWN(SSL_get_fd(con));
                    goto re_start;
                }
            }
        }

        ssl_pending = read_ssl && SSL_pending(con);

        if (!ssl_pending) {
#if !defined(OPENSSL_SYS_WINDOWS) && !defined(OPENSSL_SYS_MSDOS) && !defined(OPENSSL_SYS_NETWARE) && !defined (OPENSSL_SYS_BEOS_R5)
            if (tty_on) {
                if (read_tty)
                    openssl_fdset(fileno_stdin(), &readfds);
#if !defined(OPENSSL_SYS_VMS)
                if (write_tty)
                    openssl_fdset(fileno_stdout(), &writefds);
#endif
            }
            if (read_ssl)
                openssl_fdset(SSL_get_fd(con), &readfds);
            if (write_ssl)
                openssl_fdset(SSL_get_fd(con), &writefds);
#else
            if (!tty_on || !write_tty) {
                if (read_ssl)
                    openssl_fdset(SSL_get_fd(con), &readfds);
                if (write_ssl)
                    openssl_fdset(SSL_get_fd(con), &writefds);
            }
#endif
/*-         printf("mode tty(%d %d%d) ssl(%d%d)\n",
                    tty_on,read_tty,write_tty,read_ssl,write_ssl);*/

            /*
             * Note: under VMS with SOCKETSHR the second parameter is
             * currently of type (int *) whereas under other systems it is
             * (void *) if you don't have a cast it will choke the compiler:
             * if you do have a cast then you can either go for (int *) or
             * (void *).
             */
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS)
            /*
             * Under Windows/DOS we make the assumption that we can always
             * write to the tty: therefore if we need to write to the tty we
             * just fall through. Otherwise we timeout the select every
             * second and see if there are any keypresses. Note: this is a
             * hack, in a proper Windows application we wouldn't do this.
             */
            i = 0;
            if (!write_tty) {
                if (read_tty) {
                    tv.tv_sec = 1;
                    tv.tv_usec = 0;
                    i = select(width, (void *)&readfds, (void *)&writefds,
                               NULL, &tv);
#if defined(OPENSSL_USE_STD_INPUT_HANDLE)
                    if (!i && (!((_kbhit())
                                 || (WAIT_OBJECT_0 ==
                                     WaitForSingleObject(GetStdHandle
                                                         (STD_INPUT_HANDLE),
                                                         0)))
                               || !read_tty))
                        continue;
#else
                    if(!i && (!_kbhit() || !read_tty) ) continue;
# endif
                } else
                    i = select(width, (void *)&readfds, (void *)&writefds,
                               NULL, timeoutp);
            }
#elif defined(OPENSSL_SYS_NETWARE)
            if (!write_tty) {
                if (read_tty) {
                    tv.tv_sec = 1;
                    tv.tv_usec = 0;
                    i = select(width, (void *)&readfds, (void *)&writefds,
                               NULL, &tv);
                } else
                    i = select(width, (void *)&readfds, (void *)&writefds,
                               NULL, timeoutp);
            }
#elif defined(OPENSSL_SYS_BEOS_R5)
            /* Under BeOS-R5 the situation is similar to DOS */
            i = 0;
            stdin_set = 0;
            (void)fcntl(fileno_stdin(), F_SETFL, O_NONBLOCK);
            if (!write_tty) {
                if (read_tty) {
                    tv.tv_sec = 1;
                    tv.tv_usec = 0;
                    i = select(width, (void *)&readfds, (void *)&writefds,
                               NULL, &tv);
                    if (read(fileno_stdin(), sbuf, 0) >= 0)
                        stdin_set = 1;
                    if (!i && (stdin_set != 1 || !read_tty))
                        continue;
                } else
                    i = select(width, (void *)&readfds, (void *)&writefds,
                               NULL, timeoutp);
            }
            (void)fcntl(fileno_stdin(), F_SETFL, 0);
#else
            i = select(width, (void *)&readfds, (void *)&writefds,
                       NULL, timeoutp);
#endif
            if (i < 0) {
                BIO_printf(bio_err, "\x62\x61\x64\x20\x73\x65\x6c\x65\x63\x74\x20\x25\x64\xa",
                           get_last_socket_error());
                goto shut;
                /* goto end; */
            }
        }

        if ((SSL_version(con) == DTLS1_VERSION)
            && DTLSv1_handle_timeout(con) > 0) {
            BIO_printf(bio_err, "\x54\x49\x4d\x45\x4f\x55\x54\x20\x6f\x63\x63\x75\x72\x65\x64\xa");
        }

        if (!ssl_pending && FD_ISSET(SSL_get_fd(con), &writefds)) {
            k = SSL_write(con, &(cbuf[cbuf_off]), (unsigned int)cbuf_len);
            switch (SSL_get_error(con, k)) {
            case SSL_ERROR_NONE:
                cbuf_off += k;
                cbuf_len -= k;
                if (k <= 0)
                    goto end;
                /* we have done a  write(con,NULL,0); */
                if (cbuf_len <= 0) {
                    read_tty = 1;
                    write_ssl = 0;
                } else {        /* if (cbuf_len > 0) */

                    read_tty = 0;
                    write_ssl = 1;
                }
                break;
            case SSL_ERROR_WANT_WRITE:
                BIO_printf(bio_c_out, "\x77\x72\x69\x74\x65\x20\x57\x20\x42\x4c\x4f\x43\x4b\xa");
                write_ssl = 1;
                read_tty = 0;
                break;
            case SSL_ERROR_WANT_READ:
                BIO_printf(bio_c_out, "\x77\x72\x69\x74\x65\x20\x52\x20\x42\x4c\x4f\x43\x4b\xa");
                write_tty = 0;
                read_ssl = 1;
                write_ssl = 0;
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                BIO_printf(bio_c_out, "\x77\x72\x69\x74\x65\x20\x58\x20\x42\x4c\x4f\x43\x4b\xa");
                break;
            case SSL_ERROR_ZERO_RETURN:
                if (cbuf_len != 0) {
                    BIO_printf(bio_c_out, "\x73\x68\x75\x74\x64\x6f\x77\x6e\xa");
                    ret = 0;
                    goto shut;
                } else {
                    read_tty = 1;
                    write_ssl = 0;
                    break;
                }

            case SSL_ERROR_SYSCALL:
                if ((k != 0) || (cbuf_len != 0)) {
                    BIO_printf(bio_err, "\x77\x72\x69\x74\x65\x3a\x65\x72\x72\x6e\x6f\x3d\x25\x64\xa",
                               get_last_socket_error());
                    goto shut;
                } else {
                    read_tty = 1;
                    write_ssl = 0;
                }
                break;
            case SSL_ERROR_SSL:
                ERR_print_errors(bio_err);
                goto shut;
            }
        }
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS) || defined(OPENSSL_SYS_NETWARE) || defined(OPENSSL_SYS_BEOS_R5) || defined(OPENSSL_SYS_VMS)
        /* Assume Windows/DOS/BeOS can always write */
        else if (!ssl_pending && write_tty)
#else
        else if (!ssl_pending && FD_ISSET(fileno_stdout(), &writefds))
#endif
        {
#ifdef CHARSET_EBCDIC
            ascii2ebcdic(&(sbuf[sbuf_off]), &(sbuf[sbuf_off]), sbuf_len);
#endif
            i = raw_write_stdout(&(sbuf[sbuf_off]), sbuf_len);

            if (i <= 0) {
                BIO_printf(bio_c_out, "\x44\x4f\x4e\x45\xa");
                ret = 0;
                goto shut;
                /* goto end; */
            }

            sbuf_len -= i;;
            sbuf_off += i;
            if (sbuf_len <= 0) {
                read_ssl = 1;
                write_tty = 0;
            }
        } else if (ssl_pending || FD_ISSET(SSL_get_fd(con), &readfds)) {
#ifdef RENEG
            {
                static int iiii;
                if (++iiii == 52) {
                    SSL_renegotiate(con);
                    iiii = 0;
                }
            }
#endif
#if 1
            k = SSL_read(con, sbuf, 1024 /* BUFSIZZ */ );
#else
/* Demo for pending and peek :-) */
            k = SSL_read(con, sbuf, 16);
            {
                char zbuf[10240];
                printf("\x72\x65\x61\x64\x3d\x25\x64\x20\x70\x65\x6e\x64\x69\x6e\x67\x3d\x25\x64\x20\x70\x65\x65\x6b\x3d\x25\x64\xa", k, SSL_pending(con),
                       SSL_peek(con, zbuf, 10240));
            }
#endif

            switch (SSL_get_error(con, k)) {
            case SSL_ERROR_NONE:
                if (k <= 0)
                    goto end;
                sbuf_off = 0;
                sbuf_len = k;

                read_ssl = 0;
                write_tty = 1;
                break;
            case SSL_ERROR_WANT_WRITE:
                BIO_printf(bio_c_out, "\x72\x65\x61\x64\x20\x57\x20\x42\x4c\x4f\x43\x4b\xa");
                write_ssl = 1;
                read_tty = 0;
                break;
            case SSL_ERROR_WANT_READ:
                BIO_printf(bio_c_out, "\x72\x65\x61\x64\x20\x52\x20\x42\x4c\x4f\x43\x4b\xa");
                write_tty = 0;
                read_ssl = 1;
                if ((read_tty == 0) && (write_ssl == 0))
                    write_ssl = 1;
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                BIO_printf(bio_c_out, "\x72\x65\x61\x64\x20\x58\x20\x42\x4c\x4f\x43\x4b\xa");
                break;
            case SSL_ERROR_SYSCALL:
                ret = get_last_socket_error();
                if (c_brief)
                    BIO_puts(bio_err, "\x43\x4f\x4e\x4e\x45\x43\x54\x49\x4f\x4e\x20\x43\x4c\x4f\x53\x45\x44\x20\x42\x59\x20\x53\x45\x52\x56\x45\x52\xa");
                else
                    BIO_printf(bio_err, "\x72\x65\x61\x64\x3a\x65\x72\x72\x6e\x6f\x3d\x25\x64\xa", ret);
                goto shut;
            case SSL_ERROR_ZERO_RETURN:
                BIO_printf(bio_c_out, "\x63\x6c\x6f\x73\x65\x64\xa");
                ret = 0;
                goto shut;
            case SSL_ERROR_SSL:
                ERR_print_errors(bio_err);
                goto shut;
                /* break; */
            }
        }
#if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_MSDOS)
#if defined(OPENSSL_USE_STD_INPUT_HANDLE)
        else if ((_kbhit())
                 || (WAIT_OBJECT_0 ==
                     WaitForSingleObject(GetStdHandle(STD_INPUT_HANDLE), 0)))
#else
        else if (_kbhit())
# endif
#elif defined (OPENSSL_SYS_NETWARE)
        else if (_kbhit())
#elif defined(OPENSSL_SYS_BEOS_R5)
        else if (stdin_set)
#else
        else if (FD_ISSET(fileno_stdin(), &readfds))
#endif
        {
            if (crlf) {
                int j, lf_num;

                i = raw_read_stdin(cbuf, BUFSIZZ / 2);
                lf_num = 0;
                /* both loops are skipped when i <= 0 */
                for (j = 0; j < i; j++)
                    if (cbuf[j] == '\xa')
                        lf_num++;
                for (j = i - 1; j >= 0; j--) {
                    cbuf[j + lf_num] = cbuf[j];
                    if (cbuf[j] == '\xa') {
                        lf_num--;
                        i++;
                        cbuf[j + lf_num] = '\xd';
                    }
                }
                assert(lf_num == 0);
            } else
                i = raw_read_stdin(cbuf, BUFSIZZ);

            if ((!c_ign_eof) && ((i <= 0) || (cbuf[0] == '\x51'))) {
                BIO_printf(bio_err, "\x44\x4f\x4e\x45\xa");
                ret = 0;
                goto shut;
            }

            if ((!c_ign_eof) && (cbuf[0] == '\x52')) {
                BIO_printf(bio_err, "\x52\x45\x4e\x45\x47\x4f\x54\x49\x41\x54\x49\x4e\x47\xa");
                SSL_renegotiate(con);
                cbuf_len = 0;
            }
#ifndef OPENSSL_NO_HEARTBEATS
            else if ((!c_ign_eof) && (cbuf[0] == '\x42')) {
                BIO_printf(bio_err, "\x48\x45\x41\x52\x54\x42\x45\x41\x54\x49\x4e\x47\xa");
                SSL_heartbeat(con);
                cbuf_len = 0;
            }
#endif
            else {
                cbuf_len = i;
                cbuf_off = 0;
#ifdef CHARSET_EBCDIC
                ebcdic2ascii(cbuf, cbuf, i);
#endif
            }

            write_ssl = 1;
            read_tty = 0;
        }
    }

    ret = 0;
 shut:
    if (in_init)
        print_stuff(bio_c_out, con, full_log);
    SSL_shutdown(con);
    SHUTDOWN(SSL_get_fd(con));
 end:
    if (con != NULL) {
        if (prexit != 0)
            print_stuff(bio_c_out, con, 1);
        SSL_free(con);
    }
#if !defined(OPENSSL_NO_TLSEXT) && !defined(OPENSSL_NO_NEXTPROTONEG)
    if (next_proto.data)
        OPENSSL_free(next_proto.data);
#endif
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    if (cert)
        X509_free(cert);
    if (crls)
        sk_X509_CRL_pop_free(crls, X509_CRL_free);
    if (key)
        EVP_PKEY_free(key);
    if (chain)
        sk_X509_pop_free(chain, X509_free);
    if (pass)
        OPENSSL_free(pass);
#ifndef OPENSSL_NO_SRP
    OPENSSL_free(srp_arg.srppassin);
#endif
    if (vpm)
        X509_VERIFY_PARAM_free(vpm);
    ssl_excert_free(exc);
    if (ssl_args)
        sk_OPENSSL_STRING_free(ssl_args);
    if (cctx)
        SSL_CONF_CTX_free(cctx);
#ifndef OPENSSL_NO_JPAKE
    if (jpake_secret && psk_key)
        OPENSSL_free(psk_key);
#endif
    if (cbuf != NULL) {
        OPENSSL_cleanse(cbuf, BUFSIZZ);
        OPENSSL_free(cbuf);
    }
    if (sbuf != NULL) {
        OPENSSL_cleanse(sbuf, BUFSIZZ);
        OPENSSL_free(sbuf);
    }
    if (mbuf != NULL) {
        OPENSSL_cleanse(mbuf, BUFSIZZ);
        OPENSSL_free(mbuf);
    }
    release_engine(e);
    if (bio_c_out != NULL) {
        BIO_free(bio_c_out);
        bio_c_out = NULL;
    }
    if (bio_c_msg != NULL) {
        BIO_free(bio_c_msg);
        bio_c_msg = NULL;
    }
    SSL_COMP_free_compression_methods();
    apps_shutdown();
    OPENSSL_EXIT(ret);
}

static void print_stuff(BIO *bio, SSL *s, int full)
{
    X509 *peer = NULL;
    char *p;
    static const char *space = "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20";
    char buf[BUFSIZ];
    STACK_OF(X509) *sk;
    STACK_OF(X509_NAME) *sk2;
    const SSL_CIPHER *c;
    X509_NAME *xn;
    int j, i;
#ifndef OPENSSL_NO_COMP
    const COMP_METHOD *comp, *expansion;
#endif
    unsigned char *exportedkeymat;

    if (full) {
        int got_a_chain = 0;

        sk = SSL_get_peer_cert_chain(s);
        if (sk != NULL) {
            got_a_chain = 1;    /* we don't have it for SSL2 (yet) */

            BIO_printf(bio, "\x2d\x2d\x2d\xaC\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x63\x68\x61\x69\x6e\xa");
            for (i = 0; i < sk_X509_num(sk); i++) {
                X509_NAME_oneline(X509_get_subject_name(sk_X509_value(sk, i)),
                                  buf, sizeof(buf));
                BIO_printf(bio, "\x25\x32\x64\x20\x73\x3a\x25\x73\xa", i, buf);
                X509_NAME_oneline(X509_get_issuer_name(sk_X509_value(sk, i)),
                                  buf, sizeof(buf));
                BIO_printf(bio, "\x20\x20\x20\x69\x3a\x25\x73\xa", buf);
                if (c_showcerts)
                    PEM_write_bio_X509(bio, sk_X509_value(sk, i));
            }
        }

        BIO_printf(bio, "\x2d\x2d\x2d\xa");
        peer = SSL_get_peer_certificate(s);
        if (peer != NULL) {
            BIO_printf(bio, "\x53\x65\x72\x76\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\xa");

            /* Redundant if we showed the whole chain */
            if (!(c_showcerts && got_a_chain))
                PEM_write_bio_X509(bio, peer);
            X509_NAME_oneline(X509_get_subject_name(peer), buf, sizeof(buf));
            BIO_printf(bio, "\x73\x75\x62\x6a\x65\x63\x74\x3d\x25\x73\xa", buf);
            X509_NAME_oneline(X509_get_issuer_name(peer), buf, sizeof(buf));
            BIO_printf(bio, "\x69\x73\x73\x75\x65\x72\x3d\x25\x73\xa", buf);
        } else
            BIO_printf(bio, "\x6e\x6f\x20\x70\x65\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x61\x76\x61\x69\x6c\x61\x62\x6c\x65\xa");

        sk2 = SSL_get_client_CA_list(s);
        if ((sk2 != NULL) && (sk_X509_NAME_num(sk2) > 0)) {
            BIO_printf(bio, "\x2d\x2d\x2d\xaA\x63\x63\x65\x70\x74\x61\x62\x6c\x65\x20\x63\x6c\x69\x65\x6e\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x43\x41\x20\x6e\x61\x6d\x65\x73\xa");
            for (i = 0; i < sk_X509_NAME_num(sk2); i++) {
                xn = sk_X509_NAME_value(sk2, i);
                X509_NAME_oneline(xn, buf, sizeof(buf));
                BIO_write(bio, buf, strlen(buf));
                BIO_write(bio, "\xa", 1);
            }
        } else {
            BIO_printf(bio, "\x2d\x2d\x2d\xa\x4e\x6f\x20\x63\x6c\x69\x65\x6e\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x43\x41\x20\x6e\x61\x6d\x65\x73\x20\x73\x65\x6e\x74\xa");
        }
        p = SSL_get_shared_ciphers(s, buf, sizeof(buf));
        if (p != NULL) {
            /*
             * This works only for SSL 2.  In later protocol versions, the
             * client does not know what other ciphers (in addition to the
             * one to be used in the current connection) the server supports.
             */

            BIO_printf(bio,
                       "\x2d\x2d\x2d\xaC\x69\x70\x68\x65\x72\x73\x20\x63\x6f\x6d\x6d\x6f\x6e\x20\x62\x65\x74\x77\x65\x65\x6e\x20\x62\x6f\x74\x68\x20\x53\x53\x4c\x20\x65\x6e\x64\x70\x6f\x69\x6e\x74\x73\x3a\xa");
            j = i = 0;
            while (*p) {
                if (*p == '\x3a') {
                    BIO_write(bio, space, 15 - j % 25);
                    i++;
                    j = 0;
                    BIO_write(bio, ((i % 3) ? "\x20" : "\xa"), 1);
                } else {
                    BIO_write(bio, p, 1);
                    j++;
                }
                p++;
            }
            BIO_write(bio, "\xa", 1);
        }

        ssl_print_sigalgs(bio, s);
        ssl_print_tmp_key(bio, s);

        BIO_printf(bio,
                   "\x2d\x2d\x2d\xa\x53\x53\x4c\x20\x68\x61\x6e\x64\x73\x68\x61\x6b\x65\x20\x68\x61\x73\x20\x72\x65\x61\x64\x20\x25\x6c\x64\x20\x62\x79\x74\x65\x73\x20\x61\x6e\x64\x20\x77\x72\x69\x74\x74\x65\x6e\x20\x25\x6c\x64\x20\x62\x79\x74\x65\x73\xa",
                   BIO_number_read(SSL_get_rbio(s)),
                   BIO_number_written(SSL_get_wbio(s)));
    }
    BIO_printf(bio, (SSL_cache_hit(s) ? "\x2d\x2d\x2d\xa\x52\x65\x75\x73\x65\x64\x2c\x20" : "\x2d\x2d\x2d\xa\x4e\x65\x77\x2c\x20"));
    c = SSL_get_current_cipher(s);
    BIO_printf(bio, "\x25\x73\x2c\x20\x43\x69\x70\x68\x65\x72\x20\x69\x73\x20\x25\x73\xa",
               SSL_CIPHER_get_version(c), SSL_CIPHER_get_name(c));
    if (peer != NULL) {
        EVP_PKEY *pktmp;
        pktmp = X509_get_pubkey(peer);
        BIO_printf(bio, "\x53\x65\x72\x76\x65\x72\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\x20\x69\x73\x20\x25\x64\x20\x62\x69\x74\xa",
                   EVP_PKEY_bits(pktmp));
        EVP_PKEY_free(pktmp);
    }
    BIO_printf(bio, "\x53\x65\x63\x75\x72\x65\x20\x52\x65\x6e\x65\x67\x6f\x74\x69\x61\x74\x69\x6f\x6e\x20\x49\x53\x25\x73\x20\x73\x75\x70\x70\x6f\x72\x74\x65\x64\xa",
               SSL_get_secure_renegotiation_support(s) ? "" : "\x20\x4e\x4f\x54");
#ifndef OPENSSL_NO_COMP
    comp = SSL_get_current_compression(s);
    expansion = SSL_get_current_expansion(s);
    BIO_printf(bio, "\x43\x6f\x6d\x70\x72\x65\x73\x73\x69\x6f\x6e\x3a\x20\x25\x73\xa",
               comp ? SSL_COMP_get_name(comp) : "\x4e\x4f\x4e\x45");
    BIO_printf(bio, "\x45\x78\x70\x61\x6e\x73\x69\x6f\x6e\x3a\x20\x25\x73\xa",
               expansion ? SSL_COMP_get_name(expansion) : "\x4e\x4f\x4e\x45");
#endif

#ifdef SSL_DEBUG
    {
        /* Print out local port of connection: useful for debugging */
        int sock;
        struct sockaddr_in ladd;
        socklen_t ladd_size = sizeof(ladd);
        sock = SSL_get_fd(s);
        getsockname(sock, (struct sockaddr *)&ladd, &ladd_size);
        BIO_printf(bio_c_out, "\x4c\x4f\x43\x41\x4c\x20\x50\x4f\x52\x54\x20\x69\x73\x20\x25\x75\xa", ntohs(ladd.sin_port));
    }
#endif

#if !defined(OPENSSL_NO_TLSEXT)
# if !defined(OPENSSL_NO_NEXTPROTONEG)
    if (next_proto.status != -1) {
        const unsigned char *proto;
        unsigned int proto_len;
        SSL_get0_next_proto_negotiated(s, &proto, &proto_len);
        BIO_printf(bio, "\x4e\x65\x78\x74\x20\x70\x72\x6f\x74\x6f\x63\x6f\x6c\x3a\x20\x28\x25\x64\x29\x20", next_proto.status);
        BIO_write(bio, proto, proto_len);
        BIO_write(bio, "\xa", 1);
    }
# endif
    {
        const unsigned char *proto;
        unsigned int proto_len;
        SSL_get0_alpn_selected(s, &proto, &proto_len);
        if (proto_len > 0) {
            BIO_printf(bio, "\x41\x4c\x50\x4e\x20\x70\x72\x6f\x74\x6f\x63\x6f\x6c\x3a\x20");
            BIO_write(bio, proto, proto_len);
            BIO_write(bio, "\xa", 1);
        } else
            BIO_printf(bio, "\x4e\x6f\x20\x41\x4c\x50\x4e\x20\x6e\x65\x67\x6f\x74\x69\x61\x74\x65\x64\xa");
    }
#endif

#ifndef OPENSSL_NO_SRTP
    {
        SRTP_PROTECTION_PROFILE *srtp_profile =
            SSL_get_selected_srtp_profile(s);

        if (srtp_profile)
            BIO_printf(bio, "\x53\x52\x54\x50\x20\x45\x78\x74\x65\x6e\x73\x69\x6f\x6e\x20\x6e\x65\x67\x6f\x74\x69\x61\x74\x65\x64\x2c\x20\x70\x72\x6f\x66\x69\x6c\x65\x3d\x25\x73\xa",
                       srtp_profile->name);
    }
#endif

    SSL_SESSION_print(bio, SSL_get_session(s));
    if (keymatexportlabel != NULL) {
        BIO_printf(bio, "\x4b\x65\x79\x69\x6e\x67\x20\x6d\x61\x74\x65\x72\x69\x61\x6c\x20\x65\x78\x70\x6f\x72\x74\x65\x72\x3a\xa");
        BIO_printf(bio, "\x20\x20\x20\x20\x4c\x61\x62\x65\x6c\x3a\x20\x27\x25\x73\x27\xa", keymatexportlabel);
        BIO_printf(bio, "\x20\x20\x20\x20\x4c\x65\x6e\x67\x74\x68\x3a\x20\x25\x69\x20\x62\x79\x74\x65\x73\xa", keymatexportlen);
        exportedkeymat = OPENSSL_malloc(keymatexportlen);
        if (exportedkeymat != NULL) {
            if (!SSL_export_keying_material(s, exportedkeymat,
                                            keymatexportlen,
                                            keymatexportlabel,
                                            strlen(keymatexportlabel),
                                            NULL, 0, 0)) {
                BIO_printf(bio, "\x20\x20\x20\x20\x45\x72\x72\x6f\x72\xa");
            } else {
                BIO_printf(bio, "\x20\x20\x20\x20\x4b\x65\x79\x69\x6e\x67\x20\x6d\x61\x74\x65\x72\x69\x61\x6c\x3a\x20");
                for (i = 0; i < keymatexportlen; i++)
                    BIO_printf(bio, "\x25\x30\x32\x58", exportedkeymat[i]);
                BIO_printf(bio, "\xa");
            }
            OPENSSL_free(exportedkeymat);
        }
    }
    BIO_printf(bio, "\x2d\x2d\x2d\xa");
    if (peer != NULL)
        X509_free(peer);
    /* flush, or debugging output gets mixed with http response */
    (void)BIO_flush(bio);
}

#ifndef OPENSSL_NO_TLSEXT

static int ocsp_resp_cb(SSL *s, void *arg)
{
    const unsigned char *p;
    int len;
    OCSP_RESPONSE *rsp;
    len = SSL_get_tlsext_status_ocsp_resp(s, &p);
    BIO_puts(arg, "\x4f\x43\x53\x50\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\x3a\x20");
    if (!p) {
        BIO_puts(arg, "\x6e\x6f\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\x20\x73\x65\x6e\x74\xa");
        return 1;
    }
    rsp = d2i_OCSP_RESPONSE(NULL, &p, len);
    if (!rsp) {
        BIO_puts(arg, "\x72\x65\x73\x70\x6f\x6e\x73\x65\x20\x70\x61\x72\x73\x65\x20\x65\x72\x72\x6f\x72\xa");
        BIO_dump_indent(arg, (char *)p, len, 4);
        return 0;
    }
    BIO_puts(arg, "\xa\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\xa");
    OCSP_RESPONSE_print(arg, rsp, 0);
    BIO_puts(arg, "\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\x3d\xa");
    OCSP_RESPONSE_free(rsp);
    return 1;
}

#endif

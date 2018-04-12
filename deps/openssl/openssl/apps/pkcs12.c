/* pkcs12.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 1999-2006 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "\x4f\x70\x65\x6e\x53\x53\x4c\x20\x54\x6f\x6f\x6c\x6b\x69\x74" and "\x4f\x70\x65\x6e\x53\x53\x4c\x20\x50\x72\x6f\x6a\x65\x63\x74" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "\x4f\x70\x65\x6e\x53\x53\x4c"
 *    nor may "\x4f\x70\x65\x6e\x53\x53\x4c" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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

#include <openssl/opensslconf.h>
#if !defined(OPENSSL_NO_DES) && !defined(OPENSSL_NO_SHA1)

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include "apps.h"
# include <openssl/crypto.h>
# include <openssl/err.h>
# include <openssl/pem.h>
# include <openssl/pkcs12.h>

# define PROG pkcs12_main

const EVP_CIPHER *enc;

# define NOKEYS          0x1
# define NOCERTS         0x2
# define INFO            0x4
# define CLCERTS         0x8
# define CACERTS         0x10

static int get_cert_chain(X509 *cert, X509_STORE *store,
                          STACK_OF(X509) **chain);
int dump_certs_keys_p12(BIO *out, PKCS12 *p12, char *pass, int passlen,
                        int options, char *pempass);
int dump_certs_pkeys_bags(BIO *out, STACK_OF(PKCS12_SAFEBAG) *bags,
                          char *pass, int passlen, int options,
                          char *pempass);
int dump_certs_pkeys_bag(BIO *out, PKCS12_SAFEBAG *bags, char *pass,
                         int passlen, int options, char *pempass);
int print_attribs(BIO *out, STACK_OF(X509_ATTRIBUTE) *attrlst,
                  const char *name);
void hex_prin(BIO *out, unsigned char *buf, int len);
int alg_print(BIO *x, X509_ALGOR *alg);
int cert_load(BIO *in, STACK_OF(X509) *sk);
static int set_pbe(BIO *err, int *ppbe, const char *str);

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    ENGINE *e = NULL;
    char *infile = NULL, *outfile = NULL, *keyname = NULL;
    char *certfile = NULL;
    BIO *in = NULL, *out = NULL;
    char **args;
    char *name = NULL;
    char *csp_name = NULL;
    int add_lmk = 0;
    PKCS12 *p12 = NULL;
    char pass[50], macpass[50];
    int export_cert = 0;
    int options = 0;
    int chain = 0;
    int badarg = 0;
    int iter = PKCS12_DEFAULT_ITER;
    int maciter = PKCS12_DEFAULT_ITER;
    int twopass = 0;
    int keytype = 0;
    int cert_pbe;
    int key_pbe = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
    int ret = 1;
    int macver = 1;
    int noprompt = 0;
    STACK_OF(OPENSSL_STRING) *canames = NULL;
    char *cpass = NULL, *mpass = NULL;
    char *passargin = NULL, *passargout = NULL, *passarg = NULL;
    char *passin = NULL, *passout = NULL;
    char *inrand = NULL;
    char *macalg = NULL;
    char *CApath = NULL, *CAfile = NULL;
    char *engine = NULL;

    apps_startup();

    enc = EVP_des_ede3_cbc();
    if (bio_err == NULL)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!load_config(bio_err, NULL))
        goto end;

# ifdef OPENSSL_FIPS
    if (FIPS_mode())
        cert_pbe = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
    else
# endif
        cert_pbe = NID_pbe_WithSHA1And40BitRC2_CBC;

    args = argv + 1;

    while (*args) {
        if (*args[0] == '\x2d') {
            if (!strcmp(*args, "\x2d\x6e\x6f\x6b\x65\x79\x73"))
                options |= NOKEYS;
            else if (!strcmp(*args, "\x2d\x6b\x65\x79\x65\x78"))
                keytype = KEY_EX;
            else if (!strcmp(*args, "\x2d\x6b\x65\x79\x73\x69\x67"))
                keytype = KEY_SIG;
            else if (!strcmp(*args, "\x2d\x6e\x6f\x63\x65\x72\x74\x73"))
                options |= NOCERTS;
            else if (!strcmp(*args, "\x2d\x63\x6c\x63\x65\x72\x74\x73"))
                options |= CLCERTS;
            else if (!strcmp(*args, "\x2d\x63\x61\x63\x65\x72\x74\x73"))
                options |= CACERTS;
            else if (!strcmp(*args, "\x2d\x6e\x6f\x6f\x75\x74"))
                options |= (NOKEYS | NOCERTS);
            else if (!strcmp(*args, "\x2d\x69\x6e\x66\x6f"))
                options |= INFO;
            else if (!strcmp(*args, "\x2d\x63\x68\x61\x69\x6e"))
                chain = 1;
            else if (!strcmp(*args, "\x2d\x74\x77\x6f\x70\x61\x73\x73"))
                twopass = 1;
            else if (!strcmp(*args, "\x2d\x6e\x6f\x6d\x61\x63\x76\x65\x72"))
                macver = 0;
            else if (!strcmp(*args, "\x2d\x64\x65\x73\x63\x65\x72\x74"))
                cert_pbe = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
            else if (!strcmp(*args, "\x2d\x65\x78\x70\x6f\x72\x74"))
                export_cert = 1;
            else if (!strcmp(*args, "\x2d\x64\x65\x73"))
                enc = EVP_des_cbc();
            else if (!strcmp(*args, "\x2d\x64\x65\x73\x33"))
                enc = EVP_des_ede3_cbc();
# ifndef OPENSSL_NO_IDEA
            else if (!strcmp(*args, "\x2d\x69\x64\x65\x61"))
                enc = EVP_idea_cbc();
# endif
# ifndef OPENSSL_NO_SEED
            else if (!strcmp(*args, "\x2d\x73\x65\x65\x64"))
                enc = EVP_seed_cbc();
# endif
# ifndef OPENSSL_NO_AES
            else if (!strcmp(*args, "\x2d\x61\x65\x73\x31\x32\x38"))
                enc = EVP_aes_128_cbc();
            else if (!strcmp(*args, "\x2d\x61\x65\x73\x31\x39\x32"))
                enc = EVP_aes_192_cbc();
            else if (!strcmp(*args, "\x2d\x61\x65\x73\x32\x35\x36"))
                enc = EVP_aes_256_cbc();
# endif
# ifndef OPENSSL_NO_CAMELLIA
            else if (!strcmp(*args, "\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x31\x32\x38"))
                enc = EVP_camellia_128_cbc();
            else if (!strcmp(*args, "\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x31\x39\x32"))
                enc = EVP_camellia_192_cbc();
            else if (!strcmp(*args, "\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x32\x35\x36"))
                enc = EVP_camellia_256_cbc();
# endif
            else if (!strcmp(*args, "\x2d\x6e\x6f\x69\x74\x65\x72"))
                iter = 1;
            else if (!strcmp(*args, "\x2d\x6d\x61\x63\x69\x74\x65\x72"))
                maciter = PKCS12_DEFAULT_ITER;
            else if (!strcmp(*args, "\x2d\x6e\x6f\x6d\x61\x63\x69\x74\x65\x72"))
                maciter = 1;
            else if (!strcmp(*args, "\x2d\x6e\x6f\x6d\x61\x63"))
                maciter = -1;
            else if (!strcmp(*args, "\x2d\x6d\x61\x63\x61\x6c\x67"))
                if (args[1]) {
                    args++;
                    macalg = *args;
                } else
                    badarg = 1;
            else if (!strcmp(*args, "\x2d\x6e\x6f\x64\x65\x73"))
                enc = NULL;
            else if (!strcmp(*args, "\x2d\x63\x65\x72\x74\x70\x62\x65")) {
                if (!set_pbe(bio_err, &cert_pbe, *++args))
                    badarg = 1;
            } else if (!strcmp(*args, "\x2d\x6b\x65\x79\x70\x62\x65")) {
                if (!set_pbe(bio_err, &key_pbe, *++args))
                    badarg = 1;
            } else if (!strcmp(*args, "\x2d\x72\x61\x6e\x64")) {
                if (args[1]) {
                    args++;
                    inrand = *args;
                } else
                    badarg = 1;
            } else if (!strcmp(*args, "\x2d\x69\x6e\x6b\x65\x79")) {
                if (args[1]) {
                    args++;
                    keyname = *args;
                } else
                    badarg = 1;
            } else if (!strcmp(*args, "\x2d\x63\x65\x72\x74\x66\x69\x6c\x65")) {
                if (args[1]) {
                    args++;
                    certfile = *args;
                } else
                    badarg = 1;
            } else if (!strcmp(*args, "\x2d\x6e\x61\x6d\x65")) {
                if (args[1]) {
                    args++;
                    name = *args;
                } else
                    badarg = 1;
            } else if (!strcmp(*args, "\x2d\x4c\x4d\x4b"))
                add_lmk = 1;
            else if (!strcmp(*args, "\x2d\x43\x53\x50")) {
                if (args[1]) {
                    args++;
                    csp_name = *args;
                } else
                    badarg = 1;
            } else if (!strcmp(*args, "\x2d\x63\x61\x6e\x61\x6d\x65")) {
                if (args[1]) {
                    args++;
                    if (!canames)
                        canames = sk_OPENSSL_STRING_new_null();
                    sk_OPENSSL_STRING_push(canames, *args);
                } else
                    badarg = 1;
            } else if (!strcmp(*args, "\x2d\x69\x6e")) {
                if (args[1]) {
                    args++;
                    infile = *args;
                } else
                    badarg = 1;
            } else if (!strcmp(*args, "\x2d\x6f\x75\x74")) {
                if (args[1]) {
                    args++;
                    outfile = *args;
                } else
                    badarg = 1;
            } else if (!strcmp(*args, "\x2d\x70\x61\x73\x73\x69\x6e")) {
                if (args[1]) {
                    args++;
                    passargin = *args;
                } else
                    badarg = 1;
            } else if (!strcmp(*args, "\x2d\x70\x61\x73\x73\x6f\x75\x74")) {
                if (args[1]) {
                    args++;
                    passargout = *args;
                } else
                    badarg = 1;
            } else if (!strcmp(*args, "\x2d\x70\x61\x73\x73\x77\x6f\x72\x64")) {
                if (args[1]) {
                    args++;
                    passarg = *args;
                    noprompt = 1;
                } else
                    badarg = 1;
            } else if (!strcmp(*args, "\x2d\x43\x41\x70\x61\x74\x68")) {
                if (args[1]) {
                    args++;
                    CApath = *args;
                } else
                    badarg = 1;
            } else if (!strcmp(*args, "\x2d\x43\x41\x66\x69\x6c\x65")) {
                if (args[1]) {
                    args++;
                    CAfile = *args;
                } else
                    badarg = 1;
# ifndef OPENSSL_NO_ENGINE
            } else if (!strcmp(*args, "\x2d\x65\x6e\x67\x69\x6e\x65")) {
                if (args[1]) {
                    args++;
                    engine = *args;
                } else
                    badarg = 1;
# endif
            } else
                badarg = 1;

        } else
            badarg = 1;
        args++;
    }

    if (badarg) {
        BIO_printf(bio_err, "\x55\x73\x61\x67\x65\x3a\x20\x70\x6b\x63\x73\x31\x32\x20\x5b\x6f\x70\x74\x69\x6f\x6e\x73\x5d\xa");
        BIO_printf(bio_err, "\x77\x68\x65\x72\x65\x20\x6f\x70\x74\x69\x6f\x6e\x73\x20\x61\x72\x65\xa");
        BIO_printf(bio_err, "\x2d\x65\x78\x70\x6f\x72\x74\x20\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x50\x4b\x43\x53\x31\x32\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err, "\x2d\x63\x68\x61\x69\x6e\x20\x20\x20\x20\x20\x20\x20\x20\x61\x64\x64\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x63\x68\x61\x69\x6e\xa");
        BIO_printf(bio_err, "\x2d\x69\x6e\x6b\x65\x79\x20\x66\x69\x6c\x65\x20\x20\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x69\x66\x20\x6e\x6f\x74\x20\x69\x6e\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err, "\x2d\x63\x65\x72\x74\x66\x69\x6c\x65\x20\x66\x20\x20\x20\x61\x64\x64\x20\x61\x6c\x6c\x20\x63\x65\x72\x74\x73\x20\x69\x6e\x20\x66\xa");
        BIO_printf(bio_err, "\x2d\x43\x41\x70\x61\x74\x68\x20\x61\x72\x67\x20\x20\x20\x2d\x20\x50\x45\x4d\x20\x66\x6f\x72\x6d\x61\x74\x20\x64\x69\x72\x65\x63\x74\x6f\x72\x79\x20\x6f\x66\x20\x43\x41\x27\x73\xa");
        BIO_printf(bio_err, "\x2d\x43\x41\x66\x69\x6c\x65\x20\x61\x72\x67\x20\x20\x20\x2d\x20\x50\x45\x4d\x20\x66\x6f\x72\x6d\x61\x74\x20\x66\x69\x6c\x65\x20\x6f\x66\x20\x43\x41\x27\x73\xa");
        BIO_printf(bio_err, "\x2d\x6e\x61\x6d\x65\x20\x22\x6e\x61\x6d\x65\x22\x20\x20\x75\x73\x65\x20\x6e\x61\x6d\x65\x20\x61\x73\x20\x66\x72\x69\x65\x6e\x64\x6c\x79\x20\x6e\x61\x6d\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x63\x61\x6e\x61\x6d\x65\x20\x22\x6e\x6d\x22\x20\x20\x75\x73\x65\x20\x6e\x6d\x20\x61\x73\x20\x43\x41\x20\x66\x72\x69\x65\x6e\x64\x6c\x79\x20\x6e\x61\x6d\x65\x20\x28\x63\x61\x6e\x20\x62\x65\x20\x75\x73\x65\x64\x20\x6d\x6f\x72\x65\x20\x74\x68\x61\x6e\x20\x6f\x6e\x63\x65\x29\x2e\xa");
        BIO_printf(bio_err, "\x2d\x69\x6e\x20\x20\x69\x6e\x66\x69\x6c\x65\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\x6e\x61\x6d\x65\xa");
        BIO_printf(bio_err, "\x2d\x6f\x75\x74\x20\x6f\x75\x74\x66\x69\x6c\x65\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\x6e\x61\x6d\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x6f\x75\x74\x20\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x6f\x75\x74\x70\x75\x74\x20\x61\x6e\x79\x74\x68\x69\x6e\x67\x2c\x20\x6a\x75\x73\x74\x20\x76\x65\x72\x69\x66\x79\x2e\xa");
        BIO_printf(bio_err, "\x2d\x6e\x6f\x6d\x61\x63\x76\x65\x72\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x76\x65\x72\x69\x66\x79\x20\x4d\x41\x43\x2e\xa");
        BIO_printf(bio_err, "\x2d\x6e\x6f\x63\x65\x72\x74\x73\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x6f\x75\x74\x70\x75\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x2e\xa");
        BIO_printf(bio_err,
                   "\x2d\x63\x6c\x63\x65\x72\x74\x73\x20\x20\x20\x20\x20\x20\x6f\x6e\x6c\x79\x20\x6f\x75\x74\x70\x75\x74\x20\x63\x6c\x69\x65\x6e\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x2e\xa");
        BIO_printf(bio_err, "\x2d\x63\x61\x63\x65\x72\x74\x73\x20\x20\x20\x20\x20\x20\x6f\x6e\x6c\x79\x20\x6f\x75\x74\x70\x75\x74\x20\x43\x41\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x2e\xa");
        BIO_printf(bio_err, "\x2d\x6e\x6f\x6b\x65\x79\x73\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x6f\x75\x74\x70\x75\x74\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x73\x2e\xa");
        BIO_printf(bio_err,
                   "\x2d\x69\x6e\x66\x6f\x20\x20\x20\x20\x20\x20\x20\x20\x20\x67\x69\x76\x65\x20\x69\x6e\x66\x6f\x20\x61\x62\x6f\x75\x74\x20\x50\x4b\x43\x53\x23\x31\x32\x20\x73\x74\x72\x75\x63\x74\x75\x72\x65\x2e\xa");
        BIO_printf(bio_err, "\x2d\x64\x65\x73\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x73\x20\x77\x69\x74\x68\x20\x44\x45\x53\xa");
        BIO_printf(bio_err,
                   "\x2d\x64\x65\x73\x33\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x73\x20\x77\x69\x74\x68\x20\x74\x72\x69\x70\x6c\x65\x20\x44\x45\x53\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x29\xa");
# ifndef OPENSSL_NO_IDEA
        BIO_printf(bio_err, "\x2d\x69\x64\x65\x61\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x73\x20\x77\x69\x74\x68\x20\x69\x64\x65\x61\xa");
# endif
# ifndef OPENSSL_NO_SEED
        BIO_printf(bio_err, "\x2d\x73\x65\x65\x64\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x73\x20\x77\x69\x74\x68\x20\x73\x65\x65\x64\xa");
# endif
# ifndef OPENSSL_NO_AES
        BIO_printf(bio_err, "\x2d\x61\x65\x73\x31\x32\x38\x2c\x20\x2d\x61\x65\x73\x31\x39\x32\x2c\x20\x2d\x61\x65\x73\x32\x35\x36\xa");
        BIO_printf(bio_err,
                   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x50\x45\x4d\x20\x6f\x75\x74\x70\x75\x74\x20\x77\x69\x74\x68\x20\x63\x62\x63\x20\x61\x65\x73\xa");
# endif
# ifndef OPENSSL_NO_CAMELLIA
        BIO_printf(bio_err, "\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x31\x32\x38\x2c\x20\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x31\x39\x32\x2c\x20\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x32\x35\x36\xa");
        BIO_printf(bio_err,
                   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x50\x45\x4d\x20\x6f\x75\x74\x70\x75\x74\x20\x77\x69\x74\x68\x20\x63\x62\x63\x20\x63\x61\x6d\x65\x6c\x6c\x69\x61\xa");
# endif
        BIO_printf(bio_err, "\x2d\x6e\x6f\x64\x65\x73\x20\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x73\xa");
        BIO_printf(bio_err, "\x2d\x6e\x6f\x69\x74\x65\x72\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x75\x73\x65\x20\x65\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e\x20\x69\x74\x65\x72\x61\x74\x69\x6f\x6e\xa");
        BIO_printf(bio_err, "\x2d\x6e\x6f\x6d\x61\x63\x69\x74\x65\x72\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x75\x73\x65\x20\x4d\x41\x43\x20\x69\x74\x65\x72\x61\x74\x69\x6f\x6e\xa");
        BIO_printf(bio_err, "\x2d\x6d\x61\x63\x69\x74\x65\x72\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x4d\x41\x43\x20\x69\x74\x65\x72\x61\x74\x69\x6f\x6e\xa");
        BIO_printf(bio_err, "\x2d\x6e\x6f\x6d\x61\x63\x20\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x20\x4d\x41\x43\xa");
        BIO_printf(bio_err,
                   "\x2d\x74\x77\x6f\x70\x61\x73\x73\x20\x20\x20\x20\x20\x20\x73\x65\x70\x61\x72\x61\x74\x65\x20\x4d\x41\x43\x2c\x20\x65\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x73\xa");
        BIO_printf(bio_err,
                   "\x2d\x64\x65\x73\x63\x65\x72\x74\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x50\x4b\x43\x53\x23\x31\x32\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x77\x69\x74\x68\x20\x74\x72\x69\x70\x6c\x65\x20\x44\x45\x53\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x20\x52\x43\x32\x2d\x34\x30\x29\xa");
        BIO_printf(bio_err,
                   "\x2d\x63\x65\x72\x74\x70\x62\x65\x20\x61\x6c\x67\x20\x20\x73\x70\x65\x63\x69\x66\x79\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x50\x42\x45\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x20\x52\x43\x32\x2d\x34\x30\x29\xa");
        BIO_printf(bio_err,
                   "\x2d\x6b\x65\x79\x70\x62\x65\x20\x61\x6c\x67\x20\x20\x20\x73\x70\x65\x63\x69\x66\x79\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x50\x42\x45\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x20\x33\x44\x45\x53\x29\xa");
        BIO_printf(bio_err,
                   "\x2d\x6d\x61\x63\x61\x6c\x67\x20\x61\x6c\x67\x20\x20\x20\x64\x69\x67\x65\x73\x74\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x20\x75\x73\x65\x64\x20\x69\x6e\x20\x4d\x41\x43\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x20\x53\x48\x41\x31\x29\xa");
        BIO_printf(bio_err, "\x2d\x6b\x65\x79\x65\x78\x20\x20\x20\x20\x20\x20\x20\x20\x73\x65\x74\x20\x4d\x53\x20\x6b\x65\x79\x20\x65\x78\x63\x68\x61\x6e\x67\x65\x20\x74\x79\x70\x65\xa");
        BIO_printf(bio_err, "\x2d\x6b\x65\x79\x73\x69\x67\x20\x20\x20\x20\x20\x20\x20\x73\x65\x74\x20\x4d\x53\x20\x6b\x65\x79\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x74\x79\x70\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x70\x61\x73\x73\x77\x6f\x72\x64\x20\x70\x20\x20\x20\x73\x65\x74\x20\x69\x6d\x70\x6f\x72\x74\x2f\x65\x78\x70\x6f\x72\x74\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x20\x73\x6f\x75\x72\x63\x65\xa");
        BIO_printf(bio_err, "\x2d\x70\x61\x73\x73\x69\x6e\x20\x70\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x70\x61\x73\x73\x20\x70\x68\x72\x61\x73\x65\x20\x73\x6f\x75\x72\x63\x65\xa");
        BIO_printf(bio_err, "\x2d\x70\x61\x73\x73\x6f\x75\x74\x20\x70\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x70\x61\x73\x73\x20\x70\x68\x72\x61\x73\x65\x20\x73\x6f\x75\x72\x63\x65\xa");
# ifndef OPENSSL_NO_ENGINE
        BIO_printf(bio_err,
                   "\x2d\x65\x6e\x67\x69\x6e\x65\x20\x65\x20\x20\x20\x20\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x65\x2c\x20\x70\x6f\x73\x73\x69\x62\x6c\x79\x20\x61\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20\x64\x65\x76\x69\x63\x65\x2e\xa");
# endif
        BIO_printf(bio_err, "\x2d\x72\x61\x6e\x64\x20\x66\x69\x6c\x65\x25\x63\x66\x69\x6c\x65\x25\x63\x2e\x2e\x2e\xa", LIST_SEPARATOR_CHAR,
                   LIST_SEPARATOR_CHAR);
        BIO_printf(bio_err,
                   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6c\x6f\x61\x64\x20\x74\x68\x65\x20\x66\x69\x6c\x65\x20\x28\x6f\x72\x20\x74\x68\x65\x20\x66\x69\x6c\x65\x73\x20\x69\x6e\x20\x74\x68\x65\x20\x64\x69\x72\x65\x63\x74\x6f\x72\x79\x29\x20\x69\x6e\x74\x6f\xa");
        BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x74\x68\x65\x20\x72\x61\x6e\x64\x6f\x6d\x20\x6e\x75\x6d\x62\x65\x72\x20\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\xa");
        BIO_printf(bio_err, "\x2d\x43\x53\x50\x20\x6e\x61\x6d\x65\x20\x20\x20\x20\x20\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x43\x53\x50\x20\x6e\x61\x6d\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x4c\x4d\x4b\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x41\x64\x64\x20\x6c\x6f\x63\x61\x6c\x20\x6d\x61\x63\x68\x69\x6e\x65\x20\x6b\x65\x79\x73\x65\x74\x20\x61\x74\x74\x72\x69\x62\x75\x74\x65\x20\x74\x6f\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\xa");
        goto end;
    }
    e = setup_engine(bio_err, engine, 0);

    if (passarg) {
        if (export_cert)
            passargout = passarg;
        else
            passargin = passarg;
    }

    if (!app_passwd(bio_err, passargin, passargout, &passin, &passout)) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x73\xa");
        goto end;
    }

    if (!cpass) {
        if (export_cert)
            cpass = passout;
        else
            cpass = passin;
    }

    if (cpass) {
        mpass = cpass;
        noprompt = 1;
    } else {
        cpass = pass;
        mpass = macpass;
    }

    if (export_cert || inrand) {
        app_RAND_load_file(NULL, bio_err, (inrand != NULL));
        if (inrand != NULL)
            BIO_printf(bio_err, "\x25\x6c\x64\x20\x73\x65\x6d\x69\x2d\x72\x61\x6e\x64\x6f\x6d\x20\x62\x79\x74\x65\x73\x20\x6c\x6f\x61\x64\x65\x64\xa",
                       app_RAND_load_files(inrand));
    }
    ERR_load_crypto_strings();

# ifdef CRYPTO_MDEBUG
    CRYPTO_push_info("\x72\x65\x61\x64\x20\x66\x69\x6c\x65\x73");
# endif

    if (!infile)
        in = BIO_new_fp(stdin, BIO_NOCLOSE);
    else
        in = BIO_new_file(infile, "\x72\x62");
    if (!in) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x6f\x70\x65\x6e\x69\x6e\x67\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x25\x73\xa",
                   infile ? infile : "\x3c\x73\x74\x64\x69\x6e\x3e");
        perror(infile);
        goto end;
    }
# ifdef CRYPTO_MDEBUG
    CRYPTO_pop_info();
    CRYPTO_push_info("\x77\x72\x69\x74\x65\x20\x66\x69\x6c\x65\x73");
# endif

    if (!outfile) {
        out = BIO_new_fp(stdout, BIO_NOCLOSE);
# ifdef OPENSSL_SYS_VMS
        {
            BIO *tmpbio = BIO_new(BIO_f_linebuffer());
            out = BIO_push(tmpbio, out);
        }
# endif
    } else
        out = BIO_new_file(outfile, "\x77\x62");
    if (!out) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x6f\x70\x65\x6e\x69\x6e\x67\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x25\x73\xa",
                   outfile ? outfile : "\x3c\x73\x74\x64\x6f\x75\x74\x3e");
        perror(outfile);
        goto end;
    }
    if (twopass) {
# ifdef CRYPTO_MDEBUG
        CRYPTO_push_info("\x72\x65\x61\x64\x20\x4d\x41\x43\x20\x70\x61\x73\x73\x77\x6f\x72\x64");
# endif
        if (EVP_read_pw_string
            (macpass, sizeof(macpass), "\x45\x6e\x74\x65\x72\x20\x4d\x41\x43\x20\x50\x61\x73\x73\x77\x6f\x72\x64\x3a", export_cert)) {
            BIO_printf(bio_err, "\x43\x61\x6e\x27\x74\x20\x72\x65\x61\x64\x20\x50\x61\x73\x73\x77\x6f\x72\x64\xa");
            goto end;
        }
# ifdef CRYPTO_MDEBUG
        CRYPTO_pop_info();
# endif
    }

    if (export_cert) {
        EVP_PKEY *key = NULL;
        X509 *ucert = NULL, *x = NULL;
        STACK_OF(X509) *certs = NULL;
        const EVP_MD *macmd = NULL;
        unsigned char *catmp = NULL;
        int i;

        if ((options & (NOCERTS | NOKEYS)) == (NOCERTS | NOKEYS)) {
            BIO_printf(bio_err, "\x4e\x6f\x74\x68\x69\x6e\x67\x20\x74\x6f\x20\x64\x6f\x21\xa");
            goto export_end;
        }

        if (options & NOCERTS)
            chain = 0;

# ifdef CRYPTO_MDEBUG
        CRYPTO_push_info("\x70\x72\x6f\x63\x65\x73\x73\x20\x2d\x65\x78\x70\x6f\x72\x74\x5f\x63\x65\x72\x74");
        CRYPTO_push_info("\x72\x65\x61\x64\x69\x6e\x67\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79");
# endif
        if (!(options & NOKEYS)) {
            key = load_key(bio_err, keyname ? keyname : infile,
                           FORMAT_PEM, 1, passin, e, "\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79");
            if (!key)
                goto export_end;
        }
# ifdef CRYPTO_MDEBUG
        CRYPTO_pop_info();
        CRYPTO_push_info("\x72\x65\x61\x64\x69\x6e\x67\x20\x63\x65\x72\x74\x73\x20\x66\x72\x6f\x6d\x20\x69\x6e\x70\x75\x74");
# endif

        /* Load in all certs in input file */
        if (!(options & NOCERTS)) {
            certs = load_certs(bio_err, infile, FORMAT_PEM, NULL, e,
                               "\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73");
            if (!certs)
                goto export_end;

            if (key) {
                /* Look for matching private key */
                for (i = 0; i < sk_X509_num(certs); i++) {
                    x = sk_X509_value(certs, i);
                    if (X509_check_private_key(x, key)) {
                        ucert = x;
                        /* Zero keyid and alias */
                        X509_keyid_set1(ucert, NULL, 0);
                        X509_alias_set1(ucert, NULL, 0);
                        /* Remove from list */
                        (void)sk_X509_delete(certs, i);
                        break;
                    }
                }
                if (!ucert) {
                    BIO_printf(bio_err,
                               "\x4e\x6f\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x6d\x61\x74\x63\x68\x65\x73\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\xa");
                    goto export_end;
                }
            }

        }
# ifdef CRYPTO_MDEBUG
        CRYPTO_pop_info();
        CRYPTO_push_info("\x72\x65\x61\x64\x69\x6e\x67\x20\x63\x65\x72\x74\x73\x20\x66\x72\x6f\x6d\x20\x69\x6e\x70\x75\x74\x20\x32");
# endif

        /* Add any more certificates asked for */
        if (certfile) {
            STACK_OF(X509) *morecerts = NULL;
            if (!(morecerts = load_certs(bio_err, certfile, FORMAT_PEM,
                                         NULL, e,
                                         "\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x66\x72\x6f\x6d\x20\x63\x65\x72\x74\x66\x69\x6c\x65")))
                goto export_end;
            while (sk_X509_num(morecerts) > 0)
                sk_X509_push(certs, sk_X509_shift(morecerts));
            sk_X509_free(morecerts);
        }
# ifdef CRYPTO_MDEBUG
        CRYPTO_pop_info();
        CRYPTO_push_info("\x72\x65\x61\x64\x69\x6e\x67\x20\x63\x65\x72\x74\x73\x20\x66\x72\x6f\x6d\x20\x63\x65\x72\x74\x66\x69\x6c\x65");
# endif

# ifdef CRYPTO_MDEBUG
        CRYPTO_pop_info();
        CRYPTO_push_info("\x62\x75\x69\x6c\x64\x69\x6e\x67\x20\x63\x68\x61\x69\x6e");
# endif

        /* If chaining get chain from user cert */
        if (chain) {
            int vret;
            STACK_OF(X509) *chain2;
            X509_STORE *store = X509_STORE_new();
            if (!store) {
                BIO_printf(bio_err, "\x4d\x65\x6d\x6f\x72\x79\x20\x61\x6c\x6c\x6f\x63\x61\x74\x69\x6f\x6e\x20\x65\x72\x72\x6f\x72\xa");
                goto export_end;
            }
            if (!X509_STORE_load_locations(store, CAfile, CApath))
                X509_STORE_set_default_paths(store);

            vret = get_cert_chain(ucert, store, &chain2);
            X509_STORE_free(store);

            if (vret == X509_V_OK) {
                /* Exclude verified certificate */
                for (i = 1; i < sk_X509_num(chain2); i++)
                    sk_X509_push(certs, sk_X509_value(chain2, i));
                /* Free first certificate */
                X509_free(sk_X509_value(chain2, 0));
                sk_X509_free(chain2);
            } else {
                if (vret != X509_V_ERR_UNSPECIFIED)
                    BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x25\x73\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x63\x68\x61\x69\x6e\x2e\xa",
                               X509_verify_cert_error_string(vret));
                else
                    ERR_print_errors(bio_err);
                goto export_end;
            }
        }

        /* Add any CA names */

        for (i = 0; i < sk_OPENSSL_STRING_num(canames); i++) {
            catmp = (unsigned char *)sk_OPENSSL_STRING_value(canames, i);
            X509_alias_set1(sk_X509_value(certs, i), catmp, -1);
        }

        if (csp_name && key)
            EVP_PKEY_add1_attr_by_NID(key, NID_ms_csp_name,
                                      MBSTRING_ASC, (unsigned char *)csp_name,
                                      -1);

        if (add_lmk && key)
            EVP_PKEY_add1_attr_by_NID(key, NID_LocalKeySet, 0, NULL, -1);

# ifdef CRYPTO_MDEBUG
        CRYPTO_pop_info();
        CRYPTO_push_info("\x72\x65\x61\x64\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64");
# endif

        if (!noprompt &&
            EVP_read_pw_string(pass, sizeof(pass), "\x45\x6e\x74\x65\x72\x20\x45\x78\x70\x6f\x72\x74\x20\x50\x61\x73\x73\x77\x6f\x72\x64\x3a",
                               1)) {
            BIO_printf(bio_err, "\x43\x61\x6e\x27\x74\x20\x72\x65\x61\x64\x20\x50\x61\x73\x73\x77\x6f\x72\x64\xa");
            goto export_end;
        }
        if (!twopass)
            BUF_strlcpy(macpass, pass, sizeof(macpass));

# ifdef CRYPTO_MDEBUG
        CRYPTO_pop_info();
        CRYPTO_push_info("\x63\x72\x65\x61\x74\x69\x6e\x67\x20\x50\x4b\x43\x53\x23\x31\x32\x20\x73\x74\x72\x75\x63\x74\x75\x72\x65");
# endif

        p12 = PKCS12_create(cpass, name, key, ucert, certs,
                            key_pbe, cert_pbe, iter, -1, keytype);

        if (!p12) {
            ERR_print_errors(bio_err);
            goto export_end;
        }

        if (macalg) {
            macmd = EVP_get_digestbyname(macalg);
            if (!macmd) {
                BIO_printf(bio_err, "\x55\x6e\x6b\x6e\x6f\x77\x6e\x20\x64\x69\x67\x65\x73\x74\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x20\x25\x73\xa", macalg);
            }
        }

        if (maciter != -1)
            PKCS12_set_mac(p12, mpass, -1, NULL, 0, maciter, macmd);

# ifdef CRYPTO_MDEBUG
        CRYPTO_pop_info();
        CRYPTO_push_info("\x77\x72\x69\x74\x69\x6e\x67\x20\x70\x6b\x63\x73\x31\x32");
# endif

        i2d_PKCS12_bio(out, p12);

        ret = 0;

 export_end:
# ifdef CRYPTO_MDEBUG
        CRYPTO_pop_info();
        CRYPTO_pop_info();
        CRYPTO_push_info("\x70\x72\x6f\x63\x65\x73\x73\x20\x2d\x65\x78\x70\x6f\x72\x74\x5f\x63\x65\x72\x74\x3a\x20\x66\x72\x65\x65\x69\x6e\x67");
# endif

        if (key)
            EVP_PKEY_free(key);
        if (certs)
            sk_X509_pop_free(certs, X509_free);
        if (ucert)
            X509_free(ucert);

# ifdef CRYPTO_MDEBUG
        CRYPTO_pop_info();
# endif
        goto end;

    }

    if (!(p12 = d2i_PKCS12_bio(in, NULL))) {
        ERR_print_errors(bio_err);
        goto end;
    }
# ifdef CRYPTO_MDEBUG
    CRYPTO_push_info("\x72\x65\x61\x64\x20\x69\x6d\x70\x6f\x72\x74\x20\x70\x61\x73\x73\x77\x6f\x72\x64");
# endif
    if (!noprompt
        && EVP_read_pw_string(pass, sizeof(pass), "\x45\x6e\x74\x65\x72\x20\x49\x6d\x70\x6f\x72\x74\x20\x50\x61\x73\x73\x77\x6f\x72\x64\x3a",
                              0)) {
        BIO_printf(bio_err, "\x43\x61\x6e\x27\x74\x20\x72\x65\x61\x64\x20\x50\x61\x73\x73\x77\x6f\x72\x64\xa");
        goto end;
    }
# ifdef CRYPTO_MDEBUG
    CRYPTO_pop_info();
# endif

    if (!twopass)
        BUF_strlcpy(macpass, pass, sizeof(macpass));

    if ((options & INFO) && p12->mac)
        BIO_printf(bio_err, "\x4d\x41\x43\x20\x49\x74\x65\x72\x61\x74\x69\x6f\x6e\x20\x25\x6c\x64\xa",
                   p12->mac->iter ? ASN1_INTEGER_get(p12->mac->iter) : 1);
    if (macver) {
# ifdef CRYPTO_MDEBUG
        CRYPTO_push_info("\x76\x65\x72\x69\x66\x79\x20\x4d\x41\x43");
# endif
        /* If we enter empty password try no password first */
        if (!mpass[0] && PKCS12_verify_mac(p12, NULL, 0)) {
            /* If mac and crypto pass the same set it to NULL too */
            if (!twopass)
                cpass = NULL;
        } else if (!PKCS12_verify_mac(p12, mpass, -1)) {
            BIO_printf(bio_err, "\x4d\x61\x63\x20\x76\x65\x72\x69\x66\x79\x20\x65\x72\x72\x6f\x72\x3a\x20\x69\x6e\x76\x61\x6c\x69\x64\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x3f\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
        BIO_printf(bio_err, "\x4d\x41\x43\x20\x76\x65\x72\x69\x66\x69\x65\x64\x20\x4f\x4b\xa");
# ifdef CRYPTO_MDEBUG
        CRYPTO_pop_info();
# endif
    }
# ifdef CRYPTO_MDEBUG
    CRYPTO_push_info("\x6f\x75\x74\x70\x75\x74\x20\x6b\x65\x79\x73\x20\x61\x6e\x64\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73");
# endif
    if (!dump_certs_keys_p12(out, p12, cpass, -1, options, passout)) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x6f\x75\x74\x70\x75\x74\x74\x69\x6e\x67\x20\x6b\x65\x79\x73\x20\x61\x6e\x64\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\xa");
        ERR_print_errors(bio_err);
        goto end;
    }
# ifdef CRYPTO_MDEBUG
    CRYPTO_pop_info();
# endif
    ret = 0;
 end:
    if (p12)
        PKCS12_free(p12);
    if (export_cert || inrand)
        app_RAND_write_file(NULL, bio_err);
# ifdef CRYPTO_MDEBUG
    CRYPTO_remove_all_info();
# endif
    release_engine(e);
    BIO_free(in);
    BIO_free_all(out);
    if (canames)
        sk_OPENSSL_STRING_free(canames);
    if (passin)
        OPENSSL_free(passin);
    if (passout)
        OPENSSL_free(passout);
    apps_shutdown();
    OPENSSL_EXIT(ret);
}

int dump_certs_keys_p12(BIO *out, PKCS12 *p12, char *pass,
                        int passlen, int options, char *pempass)
{
    STACK_OF(PKCS7) *asafes = NULL;
    STACK_OF(PKCS12_SAFEBAG) *bags;
    int i, bagnid;
    int ret = 0;
    PKCS7 *p7;

    if (!(asafes = PKCS12_unpack_authsafes(p12)))
        return 0;
    for (i = 0; i < sk_PKCS7_num(asafes); i++) {
        p7 = sk_PKCS7_value(asafes, i);
        bagnid = OBJ_obj2nid(p7->type);
        if (bagnid == NID_pkcs7_data) {
            bags = PKCS12_unpack_p7data(p7);
            if (options & INFO)
                BIO_printf(bio_err, "\x50\x4b\x43\x53\x37\x20\x44\x61\x74\x61\xa");
        } else if (bagnid == NID_pkcs7_encrypted) {
            if (options & INFO) {
                BIO_printf(bio_err, "\x50\x4b\x43\x53\x37\x20\x45\x6e\x63\x72\x79\x70\x74\x65\x64\x20\x64\x61\x74\x61\x3a\x20");
                alg_print(bio_err, p7->d.encrypted->enc_data->algorithm);
            }
            bags = PKCS12_unpack_p7encdata(p7, pass, passlen);
        } else
            continue;
        if (!bags)
            goto err;
        if (!dump_certs_pkeys_bags(out, bags, pass, passlen,
                                   options, pempass)) {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            goto err;
        }
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        bags = NULL;
    }
    ret = 1;

 err:

    if (asafes)
        sk_PKCS7_pop_free(asafes, PKCS7_free);
    return ret;
}

int dump_certs_pkeys_bags(BIO *out, STACK_OF(PKCS12_SAFEBAG) *bags,
                          char *pass, int passlen, int options, char *pempass)
{
    int i;
    for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
        if (!dump_certs_pkeys_bag(out,
                                  sk_PKCS12_SAFEBAG_value(bags, i),
                                  pass, passlen, options, pempass))
            return 0;
    }
    return 1;
}

int dump_certs_pkeys_bag(BIO *out, PKCS12_SAFEBAG *bag, char *pass,
                         int passlen, int options, char *pempass)
{
    EVP_PKEY *pkey;
    PKCS8_PRIV_KEY_INFO *p8;
    X509 *x509;
    int ret = 0;

    switch (M_PKCS12_bag_type(bag)) {
    case NID_keyBag:
        if (options & INFO)
            BIO_printf(bio_err, "\x4b\x65\x79\x20\x62\x61\x67\xa");
        if (options & NOKEYS)
            return 1;
        print_attribs(out, bag->attrib, "\x42\x61\x67\x20\x41\x74\x74\x72\x69\x62\x75\x74\x65\x73");
        p8 = bag->value.keybag;
        if (!(pkey = EVP_PKCS82PKEY(p8)))
            return 0;
        print_attribs(out, p8->attributes, "\x4b\x65\x79\x20\x41\x74\x74\x72\x69\x62\x75\x74\x65\x73");
        ret = PEM_write_bio_PrivateKey(out, pkey, enc, NULL, 0, NULL, pempass);
        EVP_PKEY_free(pkey);
        break;

    case NID_pkcs8ShroudedKeyBag:
        if (options & INFO) {
            BIO_printf(bio_err, "\x53\x68\x72\x6f\x75\x64\x65\x64\x20\x4b\x65\x79\x62\x61\x67\x3a\x20");
            alg_print(bio_err, bag->value.shkeybag->algor);
        }
        if (options & NOKEYS)
            return 1;
        print_attribs(out, bag->attrib, "\x42\x61\x67\x20\x41\x74\x74\x72\x69\x62\x75\x74\x65\x73");
        if (!(p8 = PKCS12_decrypt_skey(bag, pass, passlen)))
            return 0;
        if (!(pkey = EVP_PKCS82PKEY(p8))) {
            PKCS8_PRIV_KEY_INFO_free(p8);
            return 0;
        }
        print_attribs(out, p8->attributes, "\x4b\x65\x79\x20\x41\x74\x74\x72\x69\x62\x75\x74\x65\x73");
        PKCS8_PRIV_KEY_INFO_free(p8);
        ret = PEM_write_bio_PrivateKey(out, pkey, enc, NULL, 0, NULL, pempass);
        EVP_PKEY_free(pkey);
        break;

    case NID_certBag:
        if (options & INFO)
            BIO_printf(bio_err, "\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x62\x61\x67\xa");
        if (options & NOCERTS)
            return 1;
        if (PKCS12_get_attr(bag, NID_localKeyID)) {
            if (options & CACERTS)
                return 1;
        } else if (options & CLCERTS)
            return 1;
        print_attribs(out, bag->attrib, "\x42\x61\x67\x20\x41\x74\x74\x72\x69\x62\x75\x74\x65\x73");
        if (M_PKCS12_cert_bag_type(bag) != NID_x509Certificate)
            return 1;
        if (!(x509 = PKCS12_certbag2x509(bag)))
            return 0;
        dump_cert_text(out, x509);
        ret = PEM_write_bio_X509(out, x509);
        X509_free(x509);
        break;

    case NID_safeContentsBag:
        if (options & INFO)
            BIO_printf(bio_err, "\x53\x61\x66\x65\x20\x43\x6f\x6e\x74\x65\x6e\x74\x73\x20\x62\x61\x67\xa");
        print_attribs(out, bag->attrib, "\x42\x61\x67\x20\x41\x74\x74\x72\x69\x62\x75\x74\x65\x73");
        return dump_certs_pkeys_bags(out, bag->value.safes, pass,
                                     passlen, options, pempass);

    default:
        BIO_printf(bio_err, "\x57\x61\x72\x6e\x69\x6e\x67\x20\x75\x6e\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x20\x62\x61\x67\x20\x74\x79\x70\x65\x3a\x20");
        i2a_ASN1_OBJECT(bio_err, bag->type);
        BIO_printf(bio_err, "\xa");
        return 1;
        break;
    }
    return ret;
}

/* Given a single certificate return a verified chain or NULL if error */

static int get_cert_chain(X509 *cert, X509_STORE *store,
                          STACK_OF(X509) **chain)
{
    X509_STORE_CTX store_ctx;
    STACK_OF(X509) *chn = NULL;
    int i = 0;

    if (!X509_STORE_CTX_init(&store_ctx, store, cert, NULL)) {
        *chain = NULL;
        return X509_V_ERR_UNSPECIFIED;
    }

    if (X509_verify_cert(&store_ctx) > 0)
        chn = X509_STORE_CTX_get1_chain(&store_ctx);
    else if ((i = X509_STORE_CTX_get_error(&store_ctx)) == 0)
        i = X509_V_ERR_UNSPECIFIED;

    X509_STORE_CTX_cleanup(&store_ctx);
    *chain = chn;
    return i;
}

int alg_print(BIO *x, X509_ALGOR *alg)
{
    int pbenid, aparamtype;
    ASN1_OBJECT *aoid;
    void *aparam;
    PBEPARAM *pbe = NULL;

    X509_ALGOR_get0(&aoid, &aparamtype, &aparam, alg);

    pbenid = OBJ_obj2nid(aoid);

    BIO_printf(x, "\x25\x73", OBJ_nid2ln(pbenid));

    /*
     * If PBE algorithm is PBES2 decode algorithm parameters
     * for additional details.
     */
    if (pbenid == NID_pbes2) {
        PBE2PARAM *pbe2 = NULL;
        int encnid;
        if (aparamtype == V_ASN1_SEQUENCE)
            pbe2 = ASN1_item_unpack(aparam, ASN1_ITEM_rptr(PBE2PARAM));
        if (pbe2 == NULL) {
            BIO_puts(x, "\x3c\x75\x6e\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x3e");
            goto done;
        }
        X509_ALGOR_get0(&aoid, &aparamtype, &aparam, pbe2->keyfunc);
        pbenid = OBJ_obj2nid(aoid);
        X509_ALGOR_get0(&aoid, NULL, NULL, pbe2->encryption);
        encnid = OBJ_obj2nid(aoid);
        BIO_printf(x, "\x2c\x20\x25\x73\x2c\x20\x25\x73", OBJ_nid2ln(pbenid),
                   OBJ_nid2sn(encnid));
        /* If KDF is PBKDF2 decode parameters */
        if (pbenid == NID_id_pbkdf2) {
            PBKDF2PARAM *kdf = NULL;
            int prfnid;
            if (aparamtype == V_ASN1_SEQUENCE)
                kdf = ASN1_item_unpack(aparam, ASN1_ITEM_rptr(PBKDF2PARAM));
            if (kdf == NULL) {
                BIO_puts(x, "\x3c\x75\x6e\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x3e");
                goto done;
            }

            if (kdf->prf == NULL) {
                prfnid = NID_hmacWithSHA1;
            } else {
                X509_ALGOR_get0(&aoid, NULL, NULL, kdf->prf);
                prfnid = OBJ_obj2nid(aoid);
            }
            BIO_printf(x, "\x2c\x20\x49\x74\x65\x72\x61\x74\x69\x6f\x6e\x20\x25\x6c\x64\x2c\x20\x50\x52\x46\x20\x25\x73",
                       ASN1_INTEGER_get(kdf->iter), OBJ_nid2sn(prfnid));
            PBKDF2PARAM_free(kdf);
        }
        PBE2PARAM_free(pbe2);
    } else {
        if (aparamtype == V_ASN1_SEQUENCE)
            pbe = ASN1_item_unpack(aparam, ASN1_ITEM_rptr(PBEPARAM));
        if (pbe == NULL) {
            BIO_puts(x, "\x3c\x75\x6e\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x3e");
            goto done;
        }
        BIO_printf(x, "\x2c\x20\x49\x74\x65\x72\x61\x74\x69\x6f\x6e\x20\x25\x6c\x64", ASN1_INTEGER_get(pbe->iter));
        PBEPARAM_free(pbe);
    }
 done:
    BIO_puts(x, "\xa");
    return 1;
}

/* Load all certificates from a given file */

int cert_load(BIO *in, STACK_OF(X509) *sk)
{
    int ret;
    X509 *cert;
    ret = 0;
# ifdef CRYPTO_MDEBUG
    CRYPTO_push_info("\x63\x65\x72\x74\x5f\x6c\x6f\x61\x64\x28\x29\x3a\x20\x72\x65\x61\x64\x69\x6e\x67\x20\x6f\x6e\x65\x20\x63\x65\x72\x74");
# endif
    while ((cert = PEM_read_bio_X509(in, NULL, NULL, NULL))) {
# ifdef CRYPTO_MDEBUG
        CRYPTO_pop_info();
# endif
        ret = 1;
        sk_X509_push(sk, cert);
# ifdef CRYPTO_MDEBUG
        CRYPTO_push_info("\x63\x65\x72\x74\x5f\x6c\x6f\x61\x64\x28\x29\x3a\x20\x72\x65\x61\x64\x69\x6e\x67\x20\x6f\x6e\x65\x20\x63\x65\x72\x74");
# endif
    }
# ifdef CRYPTO_MDEBUG
    CRYPTO_pop_info();
# endif
    if (ret)
        ERR_clear_error();
    return ret;
}

/* Generalised attribute print: handle PKCS#8 and bag attributes */

int print_attribs(BIO *out, STACK_OF(X509_ATTRIBUTE) *attrlst,
                  const char *name)
{
    X509_ATTRIBUTE *attr;
    ASN1_TYPE *av;
    char *value;
    int i, attr_nid;
    if (!attrlst) {
        BIO_printf(out, "\x25\x73\x3a\x20\x3c\x4e\x6f\x20\x41\x74\x74\x72\x69\x62\x75\x74\x65\x73\x3e\xa", name);
        return 1;
    }
    if (!sk_X509_ATTRIBUTE_num(attrlst)) {
        BIO_printf(out, "\x25\x73\x3a\x20\x3c\x45\x6d\x70\x74\x79\x20\x41\x74\x74\x72\x69\x62\x75\x74\x65\x73\x3e\xa", name);
        return 1;
    }
    BIO_printf(out, "\x25\x73\xa", name);
    for (i = 0; i < sk_X509_ATTRIBUTE_num(attrlst); i++) {
        attr = sk_X509_ATTRIBUTE_value(attrlst, i);
        attr_nid = OBJ_obj2nid(attr->object);
        BIO_printf(out, "\x20\x20\x20\x20");
        if (attr_nid == NID_undef) {
            i2a_ASN1_OBJECT(out, attr->object);
            BIO_printf(out, "\x3a\x20");
        } else
            BIO_printf(out, "\x25\x73\x3a\x20", OBJ_nid2ln(attr_nid));

        if (sk_ASN1_TYPE_num(attr->value.set)) {
            av = sk_ASN1_TYPE_value(attr->value.set, 0);
            switch (av->type) {
            case V_ASN1_BMPSTRING:
                value = OPENSSL_uni2asc(av->value.bmpstring->data,
                                        av->value.bmpstring->length);
                BIO_printf(out, "\x25\x73\xa", value);
                OPENSSL_free(value);
                break;

            case V_ASN1_OCTET_STRING:
                hex_prin(out, av->value.octet_string->data,
                         av->value.octet_string->length);
                BIO_printf(out, "\xa");
                break;

            case V_ASN1_BIT_STRING:
                hex_prin(out, av->value.bit_string->data,
                         av->value.bit_string->length);
                BIO_printf(out, "\xa");
                break;

            default:
                BIO_printf(out, "\x3c\x55\x6e\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x20\x74\x61\x67\x20\x25\x64\x3e\xa", av->type);
                break;
            }
        } else
            BIO_printf(out, "\x3c\x4e\x6f\x20\x56\x61\x6c\x75\x65\x73\x3e\xa");
    }
    return 1;
}

void hex_prin(BIO *out, unsigned char *buf, int len)
{
    int i;
    for (i = 0; i < len; i++)
        BIO_printf(out, "\x25\x30\x32\x58\x20", buf[i]);
}

static int set_pbe(BIO *err, int *ppbe, const char *str)
{
    if (!str)
        return 0;
    if (!strcmp(str, "\x4e\x4f\x4e\x45")) {
        *ppbe = -1;
        return 1;
    }
    *ppbe = OBJ_txt2nid(str);
    if (*ppbe == NID_undef) {
        BIO_printf(bio_err, "\x55\x6e\x6b\x6e\x6f\x77\x6e\x20\x50\x42\x45\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x20\x25\x73\xa", str);
        return 0;
    }
    return 1;
}

#else
static void *dummy = &dummy;
#endif

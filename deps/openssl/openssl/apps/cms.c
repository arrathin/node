/* apps/cms.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2008-2018 The OpenSSL Project.  All rights reserved.
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
 */

/* CMS utility function */

#include <stdio.h>
#include <string.h>
#include "apps.h"

#ifndef OPENSSL_NO_CMS

# include <openssl/crypto.h>
# include <openssl/pem.h>
# include <openssl/err.h>
# include <openssl/x509_vfy.h>
# include <openssl/x509v3.h>
# include <openssl/cms.h>

# undef PROG
# define PROG cms_main
static int save_certs(char *signerfile, STACK_OF(X509) *signers);
static int cms_cb(int ok, X509_STORE_CTX *ctx);
static void receipt_request_print(BIO *out, CMS_ContentInfo *cms);
static CMS_ReceiptRequest *make_receipt_request(STACK_OF(OPENSSL_STRING)
                                                *rr_to, int rr_allorfirst, STACK_OF(OPENSSL_STRING)
                                                *rr_from);
static int cms_set_pkey_param(EVP_PKEY_CTX *pctx,
                              STACK_OF(OPENSSL_STRING) *param);

# define SMIME_OP        0x10
# define SMIME_IP        0x20
# define SMIME_SIGNERS   0x40
# define SMIME_ENCRYPT           (1 | SMIME_OP)
# define SMIME_DECRYPT           (2 | SMIME_IP)
# define SMIME_SIGN              (3 | SMIME_OP | SMIME_SIGNERS)
# define SMIME_VERIFY            (4 | SMIME_IP)
# define SMIME_CMSOUT            (5 | SMIME_IP | SMIME_OP)
# define SMIME_RESIGN            (6 | SMIME_IP | SMIME_OP | SMIME_SIGNERS)
# define SMIME_DATAOUT           (7 | SMIME_IP)
# define SMIME_DATA_CREATE       (8 | SMIME_OP)
# define SMIME_DIGEST_VERIFY     (9 | SMIME_IP)
# define SMIME_DIGEST_CREATE     (10 | SMIME_OP)
# define SMIME_UNCOMPRESS        (11 | SMIME_IP)
# define SMIME_COMPRESS          (12 | SMIME_OP)
# define SMIME_ENCRYPTED_DECRYPT (13 | SMIME_IP)
# define SMIME_ENCRYPTED_ENCRYPT (14 | SMIME_OP)
# define SMIME_SIGN_RECEIPT      (15 | SMIME_IP | SMIME_OP)
# define SMIME_VERIFY_RECEIPT    (16 | SMIME_IP)

int verify_err = 0;

typedef struct cms_key_param_st cms_key_param;

struct cms_key_param_st {
    int idx;
    STACK_OF(OPENSSL_STRING) *param;
    cms_key_param *next;
};

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    ENGINE *e = NULL;
    int operation = 0;
    int ret = 0;
    char **args;
    const char *inmode = "\x72", *outmode = "\x77";
    char *infile = NULL, *outfile = NULL, *rctfile = NULL;
    char *signerfile = NULL, *recipfile = NULL;
    STACK_OF(OPENSSL_STRING) *sksigners = NULL, *skkeys = NULL;
    char *certfile = NULL, *keyfile = NULL, *contfile = NULL;
    char *certsoutfile = NULL;
    const EVP_CIPHER *cipher = NULL, *wrap_cipher = NULL;
    CMS_ContentInfo *cms = NULL, *rcms = NULL;
    X509_STORE *store = NULL;
    X509 *cert = NULL, *recip = NULL, *signer = NULL;
    EVP_PKEY *key = NULL;
    STACK_OF(X509) *encerts = NULL, *other = NULL;
    BIO *in = NULL, *out = NULL, *indata = NULL, *rctin = NULL;
    int badarg = 0;
    int flags = CMS_DETACHED, noout = 0, print = 0;
    int verify_retcode = 0;
    int rr_print = 0, rr_allorfirst = -1;
    STACK_OF(OPENSSL_STRING) *rr_to = NULL, *rr_from = NULL;
    CMS_ReceiptRequest *rr = NULL;
    char *to = NULL, *from = NULL, *subject = NULL;
    char *CAfile = NULL, *CApath = NULL;
    char *passargin = NULL, *passin = NULL;
    char *inrand = NULL;
    int need_rand = 0;
    const EVP_MD *sign_md = NULL;
    int informat = FORMAT_SMIME, outformat = FORMAT_SMIME;
    int rctformat = FORMAT_SMIME, keyform = FORMAT_PEM;
    char *engine = NULL;
    unsigned char *secret_key = NULL, *secret_keyid = NULL;
    unsigned char *pwri_pass = NULL, *pwri_tmp = NULL;
    size_t secret_keylen = 0, secret_keyidlen = 0;

    cms_key_param *key_first = NULL, *key_param = NULL;

    ASN1_OBJECT *econtent_type = NULL;

    X509_VERIFY_PARAM *vpm = NULL;

    args = argv + 1;
    ret = 1;

    apps_startup();

    if (bio_err == NULL) {
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);
    }

    if (!load_config(bio_err, NULL))
        goto end;

    while (!badarg && *args && *args[0] == '\x2d') {
        if (!strcmp(*args, "\x2d\x65\x6e\x63\x72\x79\x70\x74"))
            operation = SMIME_ENCRYPT;
        else if (!strcmp(*args, "\x2d\x64\x65\x63\x72\x79\x70\x74"))
            operation = SMIME_DECRYPT;
        else if (!strcmp(*args, "\x2d\x73\x69\x67\x6e"))
            operation = SMIME_SIGN;
        else if (!strcmp(*args, "\x2d\x73\x69\x67\x6e\x5f\x72\x65\x63\x65\x69\x70\x74"))
            operation = SMIME_SIGN_RECEIPT;
        else if (!strcmp(*args, "\x2d\x72\x65\x73\x69\x67\x6e"))
            operation = SMIME_RESIGN;
        else if (!strcmp(*args, "\x2d\x76\x65\x72\x69\x66\x79"))
            operation = SMIME_VERIFY;
        else if (!strcmp(*args, "\x2d\x76\x65\x72\x69\x66\x79\x5f\x72\x65\x74\x63\x6f\x64\x65"))
            verify_retcode = 1;
        else if (!strcmp(*args, "\x2d\x76\x65\x72\x69\x66\x79\x5f\x72\x65\x63\x65\x69\x70\x74")) {
            operation = SMIME_VERIFY_RECEIPT;
            if (!args[1])
                goto argerr;
            args++;
            rctfile = *args;
        } else if (!strcmp(*args, "\x2d\x63\x6d\x73\x6f\x75\x74"))
            operation = SMIME_CMSOUT;
        else if (!strcmp(*args, "\x2d\x64\x61\x74\x61\x5f\x6f\x75\x74"))
            operation = SMIME_DATAOUT;
        else if (!strcmp(*args, "\x2d\x64\x61\x74\x61\x5f\x63\x72\x65\x61\x74\x65"))
            operation = SMIME_DATA_CREATE;
        else if (!strcmp(*args, "\x2d\x64\x69\x67\x65\x73\x74\x5f\x76\x65\x72\x69\x66\x79"))
            operation = SMIME_DIGEST_VERIFY;
        else if (!strcmp(*args, "\x2d\x64\x69\x67\x65\x73\x74\x5f\x63\x72\x65\x61\x74\x65"))
            operation = SMIME_DIGEST_CREATE;
        else if (!strcmp(*args, "\x2d\x63\x6f\x6d\x70\x72\x65\x73\x73"))
            operation = SMIME_COMPRESS;
        else if (!strcmp(*args, "\x2d\x75\x6e\x63\x6f\x6d\x70\x72\x65\x73\x73"))
            operation = SMIME_UNCOMPRESS;
        else if (!strcmp(*args, "\x2d\x45\x6e\x63\x72\x79\x70\x74\x65\x64\x44\x61\x74\x61\x5f\x64\x65\x63\x72\x79\x70\x74"))
            operation = SMIME_ENCRYPTED_DECRYPT;
        else if (!strcmp(*args, "\x2d\x45\x6e\x63\x72\x79\x70\x74\x65\x64\x44\x61\x74\x61\x5f\x65\x6e\x63\x72\x79\x70\x74"))
            operation = SMIME_ENCRYPTED_ENCRYPT;
# ifndef OPENSSL_NO_DES
        else if (!strcmp(*args, "\x2d\x64\x65\x73\x33"))
            cipher = EVP_des_ede3_cbc();
        else if (!strcmp(*args, "\x2d\x64\x65\x73"))
            cipher = EVP_des_cbc();
        else if (!strcmp(*args, "\x2d\x64\x65\x73\x33\x2d\x77\x72\x61\x70"))
            wrap_cipher = EVP_des_ede3_wrap();
# endif
# ifndef OPENSSL_NO_SEED
        else if (!strcmp(*args, "\x2d\x73\x65\x65\x64"))
            cipher = EVP_seed_cbc();
# endif
# ifndef OPENSSL_NO_RC2
        else if (!strcmp(*args, "\x2d\x72\x63\x32\x2d\x34\x30"))
            cipher = EVP_rc2_40_cbc();
        else if (!strcmp(*args, "\x2d\x72\x63\x32\x2d\x31\x32\x38"))
            cipher = EVP_rc2_cbc();
        else if (!strcmp(*args, "\x2d\x72\x63\x32\x2d\x36\x34"))
            cipher = EVP_rc2_64_cbc();
# endif
# ifndef OPENSSL_NO_AES
        else if (!strcmp(*args, "\x2d\x61\x65\x73\x31\x32\x38"))
            cipher = EVP_aes_128_cbc();
        else if (!strcmp(*args, "\x2d\x61\x65\x73\x31\x39\x32"))
            cipher = EVP_aes_192_cbc();
        else if (!strcmp(*args, "\x2d\x61\x65\x73\x32\x35\x36"))
            cipher = EVP_aes_256_cbc();
        else if (!strcmp(*args, "\x2d\x61\x65\x73\x31\x32\x38\x2d\x77\x72\x61\x70"))
            wrap_cipher = EVP_aes_128_wrap();
        else if (!strcmp(*args, "\x2d\x61\x65\x73\x31\x39\x32\x2d\x77\x72\x61\x70"))
            wrap_cipher = EVP_aes_192_wrap();
        else if (!strcmp(*args, "\x2d\x61\x65\x73\x32\x35\x36\x2d\x77\x72\x61\x70"))
            wrap_cipher = EVP_aes_256_wrap();
# endif
# ifndef OPENSSL_NO_CAMELLIA
        else if (!strcmp(*args, "\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x31\x32\x38"))
            cipher = EVP_camellia_128_cbc();
        else if (!strcmp(*args, "\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x31\x39\x32"))
            cipher = EVP_camellia_192_cbc();
        else if (!strcmp(*args, "\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x32\x35\x36"))
            cipher = EVP_camellia_256_cbc();
# endif
        else if (!strcmp(*args, "\x2d\x64\x65\x62\x75\x67\x5f\x64\x65\x63\x72\x79\x70\x74"))
            flags |= CMS_DEBUG_DECRYPT;
        else if (!strcmp(*args, "\x2d\x74\x65\x78\x74"))
            flags |= CMS_TEXT;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x69\x6e\x74\x65\x72\x6e"))
            flags |= CMS_NOINTERN;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x76\x65\x72\x69\x66\x79")
                 || !strcmp(*args, "\x2d\x6e\x6f\x5f\x73\x69\x67\x6e\x65\x72\x5f\x63\x65\x72\x74\x5f\x76\x65\x72\x69\x66\x79"))
            flags |= CMS_NO_SIGNER_CERT_VERIFY;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x63\x65\x72\x74\x73"))
            flags |= CMS_NOCERTS;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x61\x74\x74\x72"))
            flags |= CMS_NOATTR;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x64\x65\x74\x61\x63\x68"))
            flags &= ~CMS_DETACHED;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x73\x6d\x69\x6d\x65\x63\x61\x70"))
            flags |= CMS_NOSMIMECAP;
        else if (!strcmp(*args, "\x2d\x62\x69\x6e\x61\x72\x79"))
            flags |= CMS_BINARY;
        else if (!strcmp(*args, "\x2d\x6b\x65\x79\x69\x64"))
            flags |= CMS_USE_KEYID;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x73\x69\x67\x73"))
            flags |= CMS_NOSIGS;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x5f\x63\x6f\x6e\x74\x65\x6e\x74\x5f\x76\x65\x72\x69\x66\x79"))
            flags |= CMS_NO_CONTENT_VERIFY;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x5f\x61\x74\x74\x72\x5f\x76\x65\x72\x69\x66\x79"))
            flags |= CMS_NO_ATTR_VERIFY;
        else if (!strcmp(*args, "\x2d\x73\x74\x72\x65\x61\x6d"))
            flags |= CMS_STREAM;
        else if (!strcmp(*args, "\x2d\x69\x6e\x64\x65\x66"))
            flags |= CMS_STREAM;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x69\x6e\x64\x65\x66"))
            flags &= ~CMS_STREAM;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x6f\x6c\x64\x6d\x69\x6d\x65"))
            flags |= CMS_NOOLDMIMETYPE;
        else if (!strcmp(*args, "\x2d\x63\x72\x6c\x66\x65\x6f\x6c"))
            flags |= CMS_CRLFEOL;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x6f\x75\x74"))
            noout = 1;
        else if (!strcmp(*args, "\x2d\x72\x65\x63\x65\x69\x70\x74\x5f\x72\x65\x71\x75\x65\x73\x74\x5f\x70\x72\x69\x6e\x74"))
            rr_print = 1;
        else if (!strcmp(*args, "\x2d\x72\x65\x63\x65\x69\x70\x74\x5f\x72\x65\x71\x75\x65\x73\x74\x5f\x61\x6c\x6c"))
            rr_allorfirst = 0;
        else if (!strcmp(*args, "\x2d\x72\x65\x63\x65\x69\x70\x74\x5f\x72\x65\x71\x75\x65\x73\x74\x5f\x66\x69\x72\x73\x74"))
            rr_allorfirst = 1;
        else if (!strcmp(*args, "\x2d\x72\x65\x63\x65\x69\x70\x74\x5f\x72\x65\x71\x75\x65\x73\x74\x5f\x66\x72\x6f\x6d")) {
            if (!args[1])
                goto argerr;
            args++;
            if (!rr_from)
                rr_from = sk_OPENSSL_STRING_new_null();
            sk_OPENSSL_STRING_push(rr_from, *args);
        } else if (!strcmp(*args, "\x2d\x72\x65\x63\x65\x69\x70\x74\x5f\x72\x65\x71\x75\x65\x73\x74\x5f\x74\x6f")) {
            if (!args[1])
                goto argerr;
            args++;
            if (!rr_to)
                rr_to = sk_OPENSSL_STRING_new_null();
            sk_OPENSSL_STRING_push(rr_to, *args);
        } else if (!strcmp(*args, "\x2d\x70\x72\x69\x6e\x74")) {
            noout = 1;
            print = 1;
        } else if (!strcmp(*args, "\x2d\x73\x65\x63\x72\x65\x74\x6b\x65\x79")) {
            long ltmp;
            if (!args[1])
                goto argerr;
            args++;
            secret_key = string_to_hex(*args, &ltmp);
            if (!secret_key) {
                BIO_printf(bio_err, "\x49\x6e\x76\x61\x6c\x69\x64\x20\x6b\x65\x79\x20\x25\x73\xa", *args);
                goto argerr;
            }
            secret_keylen = (size_t)ltmp;
        } else if (!strcmp(*args, "\x2d\x73\x65\x63\x72\x65\x74\x6b\x65\x79\x69\x64")) {
            long ltmp;
            if (!args[1])
                goto argerr;
            args++;
            secret_keyid = string_to_hex(*args, &ltmp);
            if (!secret_keyid) {
                BIO_printf(bio_err, "\x49\x6e\x76\x61\x6c\x69\x64\x20\x69\x64\x20\x25\x73\xa", *args);
                goto argerr;
            }
            secret_keyidlen = (size_t)ltmp;
        } else if (!strcmp(*args, "\x2d\x70\x77\x72\x69\x5f\x70\x61\x73\x73\x77\x6f\x72\x64")) {
            if (!args[1])
                goto argerr;
            args++;
            pwri_pass = (unsigned char *)*args;
        } else if (!strcmp(*args, "\x2d\x65\x63\x6f\x6e\x74\x65\x6e\x74\x5f\x74\x79\x70\x65")) {
            if (!args[1])
                goto argerr;
            args++;
            econtent_type = OBJ_txt2obj(*args, 0);
            if (!econtent_type) {
                BIO_printf(bio_err, "\x49\x6e\x76\x61\x6c\x69\x64\x20\x4f\x49\x44\x20\x25\x73\xa", *args);
                goto argerr;
            }
        } else if (!strcmp(*args, "\x2d\x72\x61\x6e\x64")) {
            if (!args[1])
                goto argerr;
            args++;
            inrand = *args;
            need_rand = 1;
        }
# ifndef OPENSSL_NO_ENGINE
        else if (!strcmp(*args, "\x2d\x65\x6e\x67\x69\x6e\x65")) {
            if (!args[1])
                goto argerr;
            engine = *++args;
        }
# endif
        else if (!strcmp(*args, "\x2d\x70\x61\x73\x73\x69\x6e")) {
            if (!args[1])
                goto argerr;
            passargin = *++args;
        } else if (!strcmp(*args, "\x2d\x74\x6f")) {
            if (!args[1])
                goto argerr;
            to = *++args;
        } else if (!strcmp(*args, "\x2d\x66\x72\x6f\x6d")) {
            if (!args[1])
                goto argerr;
            from = *++args;
        } else if (!strcmp(*args, "\x2d\x73\x75\x62\x6a\x65\x63\x74")) {
            if (!args[1])
                goto argerr;
            subject = *++args;
        } else if (!strcmp(*args, "\x2d\x73\x69\x67\x6e\x65\x72")) {
            if (!args[1])
                goto argerr;
            /* If previous -signer argument add signer to list */

            if (signerfile) {
                if (!sksigners)
                    sksigners = sk_OPENSSL_STRING_new_null();
                sk_OPENSSL_STRING_push(sksigners, signerfile);
                if (!keyfile)
                    keyfile = signerfile;
                if (!skkeys)
                    skkeys = sk_OPENSSL_STRING_new_null();
                sk_OPENSSL_STRING_push(skkeys, keyfile);
                keyfile = NULL;
            }
            signerfile = *++args;
        } else if (!strcmp(*args, "\x2d\x72\x65\x63\x69\x70")) {
            if (!args[1])
                goto argerr;
            if (operation == SMIME_ENCRYPT) {
                if (!encerts)
                    encerts = sk_X509_new_null();
                cert = load_cert(bio_err, *++args, FORMAT_PEM,
                                 NULL, e, "\x72\x65\x63\x69\x70\x69\x65\x6e\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x66\x69\x6c\x65");
                if (!cert)
                    goto end;
                sk_X509_push(encerts, cert);
                cert = NULL;
            } else
                recipfile = *++args;
        } else if (!strcmp(*args, "\x2d\x63\x65\x72\x74\x73\x6f\x75\x74")) {
            if (!args[1])
                goto argerr;
            certsoutfile = *++args;
        } else if (!strcmp(*args, "\x2d\x6d\x64")) {
            if (!args[1])
                goto argerr;
            sign_md = EVP_get_digestbyname(*++args);
            if (sign_md == NULL) {
                BIO_printf(bio_err, "\x55\x6e\x6b\x6e\x6f\x77\x6e\x20\x64\x69\x67\x65\x73\x74\x20\x25\x73\xa", *args);
                goto argerr;
            }
        } else if (!strcmp(*args, "\x2d\x69\x6e\x6b\x65\x79")) {
            if (!args[1])
                goto argerr;
            /* If previous -inkey arument add signer to list */
            if (keyfile) {
                if (!signerfile) {
                    BIO_puts(bio_err, "\x49\x6c\x6c\x65\x67\x61\x6c\x20\x2d\x69\x6e\x6b\x65\x79\x20\x77\x69\x74\x68\x6f\x75\x74\x20\x2d\x73\x69\x67\x6e\x65\x72\xa");
                    goto argerr;
                }
                if (!sksigners)
                    sksigners = sk_OPENSSL_STRING_new_null();
                sk_OPENSSL_STRING_push(sksigners, signerfile);
                signerfile = NULL;
                if (!skkeys)
                    skkeys = sk_OPENSSL_STRING_new_null();
                sk_OPENSSL_STRING_push(skkeys, keyfile);
            }
            keyfile = *++args;
        } else if (!strcmp(*args, "\x2d\x6b\x65\x79\x66\x6f\x72\x6d")) {
            if (!args[1])
                goto argerr;
            keyform = str2fmt(*++args);
        } else if (!strcmp(*args, "\x2d\x6b\x65\x79\x6f\x70\x74")) {
            int keyidx = -1;
            if (!args[1])
                goto argerr;
            if (operation == SMIME_ENCRYPT) {
                if (encerts)
                    keyidx += sk_X509_num(encerts);
            } else {
                if (keyfile || signerfile)
                    keyidx++;
                if (skkeys)
                    keyidx += sk_OPENSSL_STRING_num(skkeys);
            }
            if (keyidx < 0) {
                BIO_printf(bio_err, "\x4e\x6f\x20\x6b\x65\x79\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
                goto argerr;
            }
            if (key_param == NULL || key_param->idx != keyidx) {
                cms_key_param *nparam;
                nparam = OPENSSL_malloc(sizeof(cms_key_param));
                if (!nparam) {
                    BIO_printf(bio_err, "\x4f\x75\x74\x20\x6f\x66\x20\x6d\x65\x6d\x6f\x72\x79\xa");
                    goto argerr;
                }
                nparam->idx = keyidx;
                nparam->param = sk_OPENSSL_STRING_new_null();
                nparam->next = NULL;
                if (key_first == NULL)
                    key_first = nparam;
                else
                    key_param->next = nparam;
                key_param = nparam;
            }
            sk_OPENSSL_STRING_push(key_param->param, *++args);
        } else if (!strcmp(*args, "\x2d\x72\x63\x74\x66\x6f\x72\x6d")) {
            if (!args[1])
                goto argerr;
            rctformat = str2fmt(*++args);
        } else if (!strcmp(*args, "\x2d\x63\x65\x72\x74\x66\x69\x6c\x65")) {
            if (!args[1])
                goto argerr;
            certfile = *++args;
        } else if (!strcmp(*args, "\x2d\x43\x41\x66\x69\x6c\x65")) {
            if (!args[1])
                goto argerr;
            CAfile = *++args;
        } else if (!strcmp(*args, "\x2d\x43\x41\x70\x61\x74\x68")) {
            if (!args[1])
                goto argerr;
            CApath = *++args;
        } else if (!strcmp(*args, "\x2d\x69\x6e")) {
            if (!args[1])
                goto argerr;
            infile = *++args;
        } else if (!strcmp(*args, "\x2d\x69\x6e\x66\x6f\x72\x6d")) {
            if (!args[1])
                goto argerr;
            informat = str2fmt(*++args);
        } else if (!strcmp(*args, "\x2d\x6f\x75\x74\x66\x6f\x72\x6d")) {
            if (!args[1])
                goto argerr;
            outformat = str2fmt(*++args);
        } else if (!strcmp(*args, "\x2d\x6f\x75\x74")) {
            if (!args[1])
                goto argerr;
            outfile = *++args;
        } else if (!strcmp(*args, "\x2d\x63\x6f\x6e\x74\x65\x6e\x74")) {
            if (!args[1])
                goto argerr;
            contfile = *++args;
        } else if (args_verify(&args, NULL, &badarg, bio_err, &vpm))
            continue;
        else if ((cipher = EVP_get_cipherbyname(*args + 1)) == NULL)
            badarg = 1;
        args++;
    }

    if (((rr_allorfirst != -1) || rr_from) && !rr_to) {
        BIO_puts(bio_err, "\x4e\x6f\x20\x53\x69\x67\x6e\x65\x64\x20\x52\x65\x63\x65\x69\x70\x74\x73\x20\x52\x65\x63\x69\x70\x69\x65\x6e\x74\x73\xa");
        goto argerr;
    }

    if (!(operation & SMIME_SIGNERS) && (rr_to || rr_from)) {
        BIO_puts(bio_err, "\x53\x69\x67\x6e\x65\x64\x20\x72\x65\x63\x65\x69\x70\x74\x73\x20\x6f\x6e\x6c\x79\x20\x61\x6c\x6c\x6f\x77\x65\x64\x20\x77\x69\x74\x68\x20\x2d\x73\x69\x67\x6e\xa");
        goto argerr;
    }
    if (!(operation & SMIME_SIGNERS) && (skkeys || sksigners)) {
        BIO_puts(bio_err, "\x4d\x75\x6c\x74\x69\x70\x6c\x65\x20\x73\x69\x67\x6e\x65\x72\x73\x20\x6f\x72\x20\x6b\x65\x79\x73\x20\x6e\x6f\x74\x20\x61\x6c\x6c\x6f\x77\x65\x64\xa");
        goto argerr;
    }

    if (operation & SMIME_SIGNERS) {
        if (keyfile && !signerfile) {
            BIO_puts(bio_err, "\x49\x6c\x6c\x65\x67\x61\x6c\x20\x2d\x69\x6e\x6b\x65\x79\x20\x77\x69\x74\x68\x6f\x75\x74\x20\x2d\x73\x69\x67\x6e\x65\x72\xa");
            goto argerr;
        }
        /* Check to see if any final signer needs to be appended */
        if (signerfile) {
            if (!sksigners)
                sksigners = sk_OPENSSL_STRING_new_null();
            sk_OPENSSL_STRING_push(sksigners, signerfile);
            if (!skkeys)
                skkeys = sk_OPENSSL_STRING_new_null();
            if (!keyfile)
                keyfile = signerfile;
            sk_OPENSSL_STRING_push(skkeys, keyfile);
        }
        if (!sksigners) {
            BIO_printf(bio_err, "\x4e\x6f\x20\x73\x69\x67\x6e\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
            badarg = 1;
        }
        signerfile = NULL;
        keyfile = NULL;
        need_rand = 1;
    }

    else if (operation == SMIME_DECRYPT) {
        if (!recipfile && !keyfile && !secret_key && !pwri_pass) {
            BIO_printf(bio_err,
                       "\x4e\x6f\x20\x72\x65\x63\x69\x70\x69\x65\x6e\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x6f\x72\x20\x6b\x65\x79\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
            badarg = 1;
        }
    } else if (operation == SMIME_ENCRYPT) {
        if (!*args && !secret_key && !pwri_pass && !encerts) {
            BIO_printf(bio_err, "\x4e\x6f\x20\x72\x65\x63\x69\x70\x69\x65\x6e\x74\x28\x73\x29\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x28\x73\x29\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
            badarg = 1;
        }
        need_rand = 1;
    } else if (!operation)
        badarg = 1;

    if (badarg) {
 argerr:
        BIO_printf(bio_err, "\x55\x73\x61\x67\x65\x20\x63\x6d\x73\x20\x5b\x6f\x70\x74\x69\x6f\x6e\x73\x5d\x20\x63\x65\x72\x74\x2e\x70\x65\x6d\x20\x2e\x2e\x2e\xa");
        BIO_printf(bio_err, "\x77\x68\x65\x72\x65\x20\x6f\x70\x74\x69\x6f\x6e\x73\x20\x61\x72\x65\xa");
        BIO_printf(bio_err, "\x2d\x65\x6e\x63\x72\x79\x70\x74\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x6d\x65\x73\x73\x61\x67\x65\xa");
        BIO_printf(bio_err, "\x2d\x64\x65\x63\x72\x79\x70\x74\x20\x20\x20\x20\x20\x20\x20\x64\x65\x63\x72\x79\x70\x74\x20\x65\x6e\x63\x72\x79\x70\x74\x65\x64\x20\x6d\x65\x73\x73\x61\x67\x65\xa");
        BIO_printf(bio_err, "\x2d\x73\x69\x67\x6e\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x73\x69\x67\x6e\x20\x6d\x65\x73\x73\x61\x67\x65\xa");
        BIO_printf(bio_err, "\x2d\x76\x65\x72\x69\x66\x79\x20\x20\x20\x20\x20\x20\x20\x20\x76\x65\x72\x69\x66\x79\x20\x73\x69\x67\x6e\x65\x64\x20\x6d\x65\x73\x73\x61\x67\x65\xa");
        BIO_printf(bio_err, "\x2d\x63\x6d\x73\x6f\x75\x74\x20\x20\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x43\x4d\x53\x20\x73\x74\x72\x75\x63\x74\x75\x72\x65\xa");
# ifndef OPENSSL_NO_DES
        BIO_printf(bio_err, "\x2d\x64\x65\x73\x33\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x77\x69\x74\x68\x20\x74\x72\x69\x70\x6c\x65\x20\x44\x45\x53\xa");
        BIO_printf(bio_err, "\x2d\x64\x65\x73\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x77\x69\x74\x68\x20\x44\x45\x53\xa");
# endif
# ifndef OPENSSL_NO_SEED
        BIO_printf(bio_err, "\x2d\x73\x65\x65\x64\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x77\x69\x74\x68\x20\x53\x45\x45\x44\xa");
# endif
# ifndef OPENSSL_NO_RC2
        BIO_printf(bio_err, "\x2d\x72\x63\x32\x2d\x34\x30\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x77\x69\x74\x68\x20\x52\x43\x32\x2d\x34\x30\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x29\xa");
        BIO_printf(bio_err, "\x2d\x72\x63\x32\x2d\x36\x34\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x77\x69\x74\x68\x20\x52\x43\x32\x2d\x36\x34\xa");
        BIO_printf(bio_err, "\x2d\x72\x63\x32\x2d\x31\x32\x38\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x77\x69\x74\x68\x20\x52\x43\x32\x2d\x31\x32\x38\xa");
# endif
# ifndef OPENSSL_NO_AES
        BIO_printf(bio_err, "\x2d\x61\x65\x73\x31\x32\x38\x2c\x20\x2d\x61\x65\x73\x31\x39\x32\x2c\x20\x2d\x61\x65\x73\x32\x35\x36\xa");
        BIO_printf(bio_err,
                   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x50\x45\x4d\x20\x6f\x75\x74\x70\x75\x74\x20\x77\x69\x74\x68\x20\x63\x62\x63\x20\x61\x65\x73\xa");
# endif
# ifndef OPENSSL_NO_CAMELLIA
        BIO_printf(bio_err, "\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x31\x32\x38\x2c\x20\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x31\x39\x32\x2c\x20\x2d\x63\x61\x6d\x65\x6c\x6c\x69\x61\x32\x35\x36\xa");
        BIO_printf(bio_err,
                   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x65\x6e\x63\x72\x79\x70\x74\x20\x50\x45\x4d\x20\x6f\x75\x74\x70\x75\x74\x20\x77\x69\x74\x68\x20\x63\x62\x63\x20\x63\x61\x6d\x65\x6c\x6c\x69\x61\xa");
# endif
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x69\x6e\x74\x65\x72\x6e\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x73\x65\x61\x72\x63\x68\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x69\x6e\x20\x6d\x65\x73\x73\x61\x67\x65\x20\x66\x6f\x72\x20\x73\x69\x67\x6e\x65\x72\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x73\x69\x67\x73\x20\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x76\x65\x72\x69\x66\x79\x20\x6d\x65\x73\x73\x61\x67\x65\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x76\x65\x72\x69\x66\x79\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x76\x65\x72\x69\x66\x79\x20\x73\x69\x67\x6e\x65\x72\x73\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x63\x65\x72\x74\x73\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x69\x6e\x63\x6c\x75\x64\x65\x20\x73\x69\x67\x6e\x65\x72\x73\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x77\x68\x65\x6e\x20\x73\x69\x67\x6e\x69\x6e\x67\xa");
        BIO_printf(bio_err, "\x2d\x6e\x6f\x64\x65\x74\x61\x63\x68\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x6f\x70\x61\x71\x75\x65\x20\x73\x69\x67\x6e\x69\x6e\x67\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x61\x74\x74\x72\x20\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x69\x6e\x63\x6c\x75\x64\x65\x20\x61\x6e\x79\x20\x73\x69\x67\x6e\x65\x64\x20\x61\x74\x74\x72\x69\x62\x75\x74\x65\x73\xa");
        BIO_printf(bio_err,
                   "\x2d\x62\x69\x6e\x61\x72\x79\x20\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x74\x72\x61\x6e\x73\x6c\x61\x74\x65\x20\x6d\x65\x73\x73\x61\x67\x65\x20\x74\x6f\x20\x74\x65\x78\x74\xa");
        BIO_printf(bio_err, "\x2d\x63\x65\x72\x74\x66\x69\x6c\x65\x20\x66\x69\x6c\x65\x20\x6f\x74\x68\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err, "\x2d\x63\x65\x72\x74\x73\x6f\x75\x74\x20\x66\x69\x6c\x65\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err, "\x2d\x73\x69\x67\x6e\x65\x72\x20\x66\x69\x6c\x65\x20\x20\x20\x73\x69\x67\x6e\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x72\x65\x63\x69\x70\x20\x20\x66\x69\x6c\x65\x20\x20\x20\x72\x65\x63\x69\x70\x69\x65\x6e\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x66\x69\x6c\x65\x20\x66\x6f\x72\x20\x64\x65\x63\x72\x79\x70\x74\x69\x6f\x6e\xa");
        BIO_printf(bio_err, "\x2d\x6b\x65\x79\x69\x64\x20\x20\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x73\x75\x62\x6a\x65\x63\x74\x20\x6b\x65\x79\x20\x69\x64\x65\x6e\x74\x69\x66\x69\x65\x72\xa");
        BIO_printf(bio_err, "\x2d\x69\x6e\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x69\x6e\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x53\x4d\x49\x4d\x45\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x29\x2c\x20\x50\x45\x4d\x20\x6f\x72\x20\x44\x45\x52\xa");
        BIO_printf(bio_err,
                   "\x2d\x69\x6e\x6b\x65\x79\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x28\x69\x66\x20\x6e\x6f\x74\x20\x73\x69\x67\x6e\x65\x72\x20\x6f\x72\x20\x72\x65\x63\x69\x70\x69\x65\x6e\x74\x29\xa");
        BIO_printf(bio_err,
                   "\x2d\x6b\x65\x79\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x66\x6f\x72\x6d\x61\x74\x20\x28\x50\x45\x4d\x20\x6f\x72\x20\x45\x4e\x47\x49\x4e\x45\x29\xa");
        BIO_printf(bio_err, "\x2d\x6b\x65\x79\x6f\x70\x74\x20\x6e\x6d\x3a\x76\x20\x20\x20\x73\x65\x74\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\xa");
        BIO_printf(bio_err, "\x2d\x6f\x75\x74\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x6f\x75\x74\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x53\x4d\x49\x4d\x45\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x29\x2c\x20\x50\x45\x4d\x20\x6f\x72\x20\x44\x45\x52\xa");
        BIO_printf(bio_err,
                   "\x2d\x63\x6f\x6e\x74\x65\x6e\x74\x20\x66\x69\x6c\x65\x20\x20\x73\x75\x70\x70\x6c\x79\x20\x6f\x72\x20\x6f\x76\x65\x72\x72\x69\x64\x65\x20\x63\x6f\x6e\x74\x65\x6e\x74\x20\x66\x6f\x72\x20\x64\x65\x74\x61\x63\x68\x65\x64\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65\xa");
        BIO_printf(bio_err, "\x2d\x74\x6f\x20\x61\x64\x64\x72\x20\x20\x20\x20\x20\x20\x20\x74\x6f\x20\x61\x64\x64\x72\x65\x73\x73\xa");
        BIO_printf(bio_err, "\x2d\x66\x72\x6f\x6d\x20\x61\x64\x20\x20\x20\x20\x20\x20\x20\x66\x72\x6f\x6d\x20\x61\x64\x64\x72\x65\x73\x73\xa");
        BIO_printf(bio_err, "\x2d\x73\x75\x62\x6a\x65\x63\x74\x20\x73\x20\x20\x20\x20\x20\x73\x75\x62\x6a\x65\x63\x74\xa");
        BIO_printf(bio_err,
                   "\x2d\x74\x65\x78\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x63\x6c\x75\x64\x65\x20\x6f\x72\x20\x64\x65\x6c\x65\x74\x65\x20\x74\x65\x78\x74\x20\x4d\x49\x4d\x45\x20\x68\x65\x61\x64\x65\x72\x73\xa");
        BIO_printf(bio_err,
                   "\x2d\x43\x41\x70\x61\x74\x68\x20\x64\x69\x72\x20\x20\x20\x20\x74\x72\x75\x73\x74\x65\x64\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x64\x69\x72\x65\x63\x74\x6f\x72\x79\xa");
        BIO_printf(bio_err, "\x2d\x43\x41\x66\x69\x6c\x65\x20\x66\x69\x6c\x65\x20\x20\x20\x74\x72\x75\x73\x74\x65\x64\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x5f\x61\x6c\x74\x5f\x63\x68\x61\x69\x6e\x73\x20\x6f\x6e\x6c\x79\x20\x65\x76\x65\x72\x20\x75\x73\x65\x20\x74\x68\x65\x20\x66\x69\x72\x73\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x63\x68\x61\x69\x6e\x20\x66\x6f\x75\x6e\x64\xa");
        BIO_printf(bio_err,
                   "\x2d\x63\x72\x6c\x5f\x63\x68\x65\x63\x6b\x20\x20\x20\x20\x20\x63\x68\x65\x63\x6b\x20\x72\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x20\x73\x74\x61\x74\x75\x73\x20\x6f\x66\x20\x73\x69\x67\x6e\x65\x72\x27\x73\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x75\x73\x69\x6e\x67\x20\x43\x52\x4c\x73\xa");
        BIO_printf(bio_err,
                   "\x2d\x63\x72\x6c\x5f\x63\x68\x65\x63\x6b\x5f\x61\x6c\x6c\x20\x63\x68\x65\x63\x6b\x20\x72\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x20\x73\x74\x61\x74\x75\x73\x20\x6f\x66\x20\x73\x69\x67\x6e\x65\x72\x27\x73\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x63\x68\x61\x69\x6e\x20\x75\x73\x69\x6e\x67\x20\x43\x52\x4c\x73\xa");
# ifndef OPENSSL_NO_ENGINE
        BIO_printf(bio_err,
                   "\x2d\x65\x6e\x67\x69\x6e\x65\x20\x65\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x65\x2c\x20\x70\x6f\x73\x73\x69\x62\x6c\x79\x20\x61\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20\x64\x65\x76\x69\x63\x65\x2e\xa");
# endif
        BIO_printf(bio_err, "\x2d\x70\x61\x73\x73\x69\x6e\x20\x61\x72\x67\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x70\x61\x73\x73\x20\x70\x68\x72\x61\x73\x65\x20\x73\x6f\x75\x72\x63\x65\xa");
        BIO_printf(bio_err, "\x2d\x72\x61\x6e\x64\x20\x66\x69\x6c\x65\x25\x63\x66\x69\x6c\x65\x25\x63\x2e\x2e\x2e\xa", LIST_SEPARATOR_CHAR,
                   LIST_SEPARATOR_CHAR);
        BIO_printf(bio_err,
                   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6c\x6f\x61\x64\x20\x74\x68\x65\x20\x66\x69\x6c\x65\x20\x28\x6f\x72\x20\x74\x68\x65\x20\x66\x69\x6c\x65\x73\x20\x69\x6e\x20\x74\x68\x65\x20\x64\x69\x72\x65\x63\x74\x6f\x72\x79\x29\x20\x69\x6e\x74\x6f\xa");
        BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x74\x68\x65\x20\x72\x61\x6e\x64\x6f\x6d\x20\x6e\x75\x6d\x62\x65\x72\x20\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\xa");
        BIO_printf(bio_err,
                   "\x63\x65\x72\x74\x2e\x70\x65\x6d\x20\x20\x20\x20\x20\x20\x20\x72\x65\x63\x69\x70\x69\x65\x6e\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x28\x73\x29\x20\x66\x6f\x72\x20\x65\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e\xa");
        goto end;
    }
    e = setup_engine(bio_err, engine, 0);

    if (!app_passwd(bio_err, passargin, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\xa");
        goto end;
    }

    if (need_rand) {
        app_RAND_load_file(NULL, bio_err, (inrand != NULL));
        if (inrand != NULL)
            BIO_printf(bio_err, "\x25\x6c\x64\x20\x73\x65\x6d\x69\x2d\x72\x61\x6e\x64\x6f\x6d\x20\x62\x79\x74\x65\x73\x20\x6c\x6f\x61\x64\x65\x64\xa",
                       app_RAND_load_files(inrand));
    }

    ret = 2;

    if (!(operation & SMIME_SIGNERS))
        flags &= ~CMS_DETACHED;

    if (operation & SMIME_OP) {
        if (outformat == FORMAT_ASN1)
            outmode = "\x77\x62";
    } else {
        if (flags & CMS_BINARY)
            outmode = "\x77\x62";
    }

    if (operation & SMIME_IP) {
        if (informat == FORMAT_ASN1)
            inmode = "\x72\x62";
    } else {
        if (flags & CMS_BINARY)
            inmode = "\x72\x62";
    }

    if (operation == SMIME_ENCRYPT) {
        if (!cipher) {
# ifndef OPENSSL_NO_DES
            cipher = EVP_des_ede3_cbc();
# else
            BIO_printf(bio_err, "\x4e\x6f\x20\x63\x69\x70\x68\x65\x72\x20\x73\x65\x6c\x65\x63\x74\x65\x64\xa");
            goto end;
# endif
        }

        if (secret_key && !secret_keyid) {
            BIO_printf(bio_err, "\x4e\x6f\x20\x73\x65\x63\x72\x65\x74\x20\x6b\x65\x79\x20\x69\x64\xa");
            goto end;
        }

        if (*args && !encerts)
            encerts = sk_X509_new_null();
        while (*args) {
            if (!(cert = load_cert(bio_err, *args, FORMAT_PEM,
                                   NULL, e, "\x72\x65\x63\x69\x70\x69\x65\x6e\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x66\x69\x6c\x65")))
                goto end;
            sk_X509_push(encerts, cert);
            cert = NULL;
            args++;
        }
    }

    if (certfile) {
        if (!(other = load_certs(bio_err, certfile, FORMAT_PEM, NULL,
                                 e, "\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x66\x69\x6c\x65"))) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (recipfile && (operation == SMIME_DECRYPT)) {
        if (!(recip = load_cert(bio_err, recipfile, FORMAT_PEM, NULL,
                                e, "\x72\x65\x63\x69\x70\x69\x65\x6e\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x66\x69\x6c\x65"))) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (operation == SMIME_SIGN_RECEIPT) {
        if (!(signer = load_cert(bio_err, signerfile, FORMAT_PEM, NULL,
                                 e, "\x72\x65\x63\x65\x69\x70\x74\x20\x73\x69\x67\x6e\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x66\x69\x6c\x65"))) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (operation == SMIME_DECRYPT) {
        if (!keyfile)
            keyfile = recipfile;
    } else if ((operation == SMIME_SIGN) || (operation == SMIME_SIGN_RECEIPT)) {
        if (!keyfile)
            keyfile = signerfile;
    } else
        keyfile = NULL;

    if (keyfile) {
        key = load_key(bio_err, keyfile, keyform, 0, passin, e,
                       "\x73\x69\x67\x6e\x69\x6e\x67\x20\x6b\x65\x79\x20\x66\x69\x6c\x65");
        if (!key)
            goto end;
    }

    if (infile) {
        if (!(in = BIO_new_file(infile, inmode))) {
            BIO_printf(bio_err, "\x43\x61\x6e\x27\x74\x20\x6f\x70\x65\x6e\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x25\x73\xa", infile);
            goto end;
        }
    } else
        in = BIO_new_fp(stdin, BIO_NOCLOSE);

    if (operation & SMIME_IP) {
        if (informat == FORMAT_SMIME)
            cms = SMIME_read_CMS(in, &indata);
        else if (informat == FORMAT_PEM)
            cms = PEM_read_bio_CMS(in, NULL, NULL, NULL);
        else if (informat == FORMAT_ASN1)
            cms = d2i_CMS_bio(in, NULL);
        else {
            BIO_printf(bio_err, "\x42\x61\x64\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x66\x6f\x72\x20\x43\x4d\x53\x20\x66\x69\x6c\x65\xa");
            goto end;
        }

        if (!cms) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x72\x65\x61\x64\x69\x6e\x67\x20\x53\x2f\x4d\x49\x4d\x45\x20\x6d\x65\x73\x73\x61\x67\x65\xa");
            goto end;
        }
        if (contfile) {
            BIO_free(indata);
            if (!(indata = BIO_new_file(contfile, "\x72\x62"))) {
                BIO_printf(bio_err, "\x43\x61\x6e\x27\x74\x20\x72\x65\x61\x64\x20\x63\x6f\x6e\x74\x65\x6e\x74\x20\x66\x69\x6c\x65\x20\x25\x73\xa", contfile);
                goto end;
            }
        }
        if (certsoutfile) {
            STACK_OF(X509) *allcerts;
            allcerts = CMS_get1_certs(cms);
            if (!save_certs(certsoutfile, allcerts)) {
                BIO_printf(bio_err,
                           "\x45\x72\x72\x6f\x72\x20\x77\x72\x69\x74\x69\x6e\x67\x20\x63\x65\x72\x74\x73\x20\x74\x6f\x20\x25\x73\xa", certsoutfile);
                ret = 5;
                goto end;
            }
            sk_X509_pop_free(allcerts, X509_free);
        }
    }

    if (rctfile) {
        char *rctmode = (rctformat == FORMAT_ASN1) ? "\x72\x62" : "\x72";
        if (!(rctin = BIO_new_file(rctfile, rctmode))) {
            BIO_printf(bio_err, "\x43\x61\x6e\x27\x74\x20\x6f\x70\x65\x6e\x20\x72\x65\x63\x65\x69\x70\x74\x20\x66\x69\x6c\x65\x20\x25\x73\xa", rctfile);
            goto end;
        }

        if (rctformat == FORMAT_SMIME)
            rcms = SMIME_read_CMS(rctin, NULL);
        else if (rctformat == FORMAT_PEM)
            rcms = PEM_read_bio_CMS(rctin, NULL, NULL, NULL);
        else if (rctformat == FORMAT_ASN1)
            rcms = d2i_CMS_bio(rctin, NULL);
        else {
            BIO_printf(bio_err, "\x42\x61\x64\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x66\x6f\x72\x20\x72\x65\x63\x65\x69\x70\x74\xa");
            goto end;
        }

        if (!rcms) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x72\x65\x61\x64\x69\x6e\x67\x20\x72\x65\x63\x65\x69\x70\x74\xa");
            goto end;
        }
    }

    if (outfile) {
        if (!(out = BIO_new_file(outfile, outmode))) {
            BIO_printf(bio_err, "\x43\x61\x6e\x27\x74\x20\x6f\x70\x65\x6e\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x25\x73\xa", outfile);
            goto end;
        }
    } else {
        out = BIO_new_fp(stdout, BIO_NOCLOSE);
# ifdef OPENSSL_SYS_VMS
        {
            BIO *tmpbio = BIO_new(BIO_f_linebuffer());
            out = BIO_push(tmpbio, out);
        }
# endif
    }

    if ((operation == SMIME_VERIFY) || (operation == SMIME_VERIFY_RECEIPT)) {
        if (!(store = setup_verify(bio_err, CAfile, CApath)))
            goto end;
        X509_STORE_set_verify_cb(store, cms_cb);
        if (vpm)
            X509_STORE_set1_param(store, vpm);
    }

    ret = 3;

    if (operation == SMIME_DATA_CREATE) {
        cms = CMS_data_create(in, flags);
    } else if (operation == SMIME_DIGEST_CREATE) {
        cms = CMS_digest_create(in, sign_md, flags);
    } else if (operation == SMIME_COMPRESS) {
        cms = CMS_compress(in, -1, flags);
    } else if (operation == SMIME_ENCRYPT) {
        int i;
        flags |= CMS_PARTIAL;
        cms = CMS_encrypt(NULL, in, cipher, flags);
        if (!cms)
            goto end;
        for (i = 0; i < sk_X509_num(encerts); i++) {
            CMS_RecipientInfo *ri;
            cms_key_param *kparam;
            int tflags = flags;
            X509 *x = sk_X509_value(encerts, i);
            for (kparam = key_first; kparam; kparam = kparam->next) {
                if (kparam->idx == i) {
                    tflags |= CMS_KEY_PARAM;
                    break;
                }
            }
            ri = CMS_add1_recipient_cert(cms, x, tflags);
            if (!ri)
                goto end;
            if (kparam) {
                EVP_PKEY_CTX *pctx;
                pctx = CMS_RecipientInfo_get0_pkey_ctx(ri);
                if (!cms_set_pkey_param(pctx, kparam->param))
                    goto end;
            }
            if (CMS_RecipientInfo_type(ri) == CMS_RECIPINFO_AGREE
                && wrap_cipher) {
                EVP_CIPHER_CTX *wctx;
                wctx = CMS_RecipientInfo_kari_get0_ctx(ri);
                EVP_EncryptInit_ex(wctx, wrap_cipher, NULL, NULL, NULL);
            }
        }

        if (secret_key) {
            if (!CMS_add0_recipient_key(cms, NID_undef,
                                        secret_key, secret_keylen,
                                        secret_keyid, secret_keyidlen,
                                        NULL, NULL, NULL))
                goto end;
            /* NULL these because call absorbs them */
            secret_key = NULL;
            secret_keyid = NULL;
        }
        if (pwri_pass) {
            pwri_tmp = (unsigned char *)BUF_strdup((char *)pwri_pass);
            if (!pwri_tmp)
                goto end;
            if (!CMS_add0_recipient_password(cms,
                                             -1, NID_undef, NID_undef,
                                             pwri_tmp, -1, NULL))
                goto end;
            pwri_tmp = NULL;
        }
        if (!(flags & CMS_STREAM)) {
            if (!CMS_final(cms, in, NULL, flags))
                goto end;
        }
    } else if (operation == SMIME_ENCRYPTED_ENCRYPT) {
        cms = CMS_EncryptedData_encrypt(in, cipher,
                                        secret_key, secret_keylen, flags);

    } else if (operation == SMIME_SIGN_RECEIPT) {
        CMS_ContentInfo *srcms = NULL;
        STACK_OF(CMS_SignerInfo) *sis;
        CMS_SignerInfo *si;
        sis = CMS_get0_SignerInfos(cms);
        if (!sis)
            goto end;
        si = sk_CMS_SignerInfo_value(sis, 0);
        srcms = CMS_sign_receipt(si, signer, key, other, flags);
        if (!srcms)
            goto end;
        CMS_ContentInfo_free(cms);
        cms = srcms;
    } else if (operation & SMIME_SIGNERS) {
        int i;
        /*
         * If detached data content we enable streaming if S/MIME output
         * format.
         */
        if (operation == SMIME_SIGN) {

            if (flags & CMS_DETACHED) {
                if (outformat == FORMAT_SMIME)
                    flags |= CMS_STREAM;
            }
            flags |= CMS_PARTIAL;
            cms = CMS_sign(NULL, NULL, other, in, flags);
            if (!cms)
                goto end;
            if (econtent_type)
                CMS_set1_eContentType(cms, econtent_type);

            if (rr_to) {
                rr = make_receipt_request(rr_to, rr_allorfirst, rr_from);
                if (!rr) {
                    BIO_puts(bio_err,
                             "\x53\x69\x67\x6e\x65\x64\x20\x52\x65\x63\x65\x69\x70\x74\x20\x52\x65\x71\x75\x65\x73\x74\x20\x43\x72\x65\x61\x74\x69\x6f\x6e\x20\x45\x72\x72\x6f\x72\xa");
                    goto end;
                }
            }
        } else
            flags |= CMS_REUSE_DIGEST;
        for (i = 0; i < sk_OPENSSL_STRING_num(sksigners); i++) {
            CMS_SignerInfo *si;
            cms_key_param *kparam;
            int tflags = flags;
            signerfile = sk_OPENSSL_STRING_value(sksigners, i);
            keyfile = sk_OPENSSL_STRING_value(skkeys, i);

            signer = load_cert(bio_err, signerfile, FORMAT_PEM, NULL,
                               e, "\x73\x69\x67\x6e\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65");
            if (!signer) {
                ret = 2;
                goto end;
            }
            key = load_key(bio_err, keyfile, keyform, 0, passin, e,
                           "\x73\x69\x67\x6e\x69\x6e\x67\x20\x6b\x65\x79\x20\x66\x69\x6c\x65");
            if (!key) {
                ret = 2;
                goto end;
            }
            for (kparam = key_first; kparam; kparam = kparam->next) {
                if (kparam->idx == i) {
                    tflags |= CMS_KEY_PARAM;
                    break;
                }
            }
            si = CMS_add1_signer(cms, signer, key, sign_md, tflags);
            if (!si)
                goto end;
            if (kparam) {
                EVP_PKEY_CTX *pctx;
                pctx = CMS_SignerInfo_get0_pkey_ctx(si);
                if (!cms_set_pkey_param(pctx, kparam->param))
                    goto end;
            }
            if (rr && !CMS_add1_ReceiptRequest(si, rr))
                goto end;
            X509_free(signer);
            signer = NULL;
            EVP_PKEY_free(key);
            key = NULL;
        }
        /* If not streaming or resigning finalize structure */
        if ((operation == SMIME_SIGN) && !(flags & CMS_STREAM)) {
            if (!CMS_final(cms, in, NULL, flags))
                goto end;
        }
    }

    if (!cms) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x63\x72\x65\x61\x74\x69\x6e\x67\x20\x43\x4d\x53\x20\x73\x74\x72\x75\x63\x74\x75\x72\x65\xa");
        goto end;
    }

    ret = 4;
    if (operation == SMIME_DECRYPT) {
        if (flags & CMS_DEBUG_DECRYPT)
            CMS_decrypt(cms, NULL, NULL, NULL, NULL, flags);

        if (secret_key) {
            if (!CMS_decrypt_set1_key(cms,
                                      secret_key, secret_keylen,
                                      secret_keyid, secret_keyidlen)) {
                BIO_puts(bio_err, "\x45\x72\x72\x6f\x72\x20\x64\x65\x63\x72\x79\x70\x74\x69\x6e\x67\x20\x43\x4d\x53\x20\x75\x73\x69\x6e\x67\x20\x73\x65\x63\x72\x65\x74\x20\x6b\x65\x79\xa");
                goto end;
            }
        }

        if (key) {
            if (!CMS_decrypt_set1_pkey(cms, key, recip)) {
                BIO_puts(bio_err, "\x45\x72\x72\x6f\x72\x20\x64\x65\x63\x72\x79\x70\x74\x69\x6e\x67\x20\x43\x4d\x53\x20\x75\x73\x69\x6e\x67\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\xa");
                goto end;
            }
        }

        if (pwri_pass) {
            if (!CMS_decrypt_set1_password(cms, pwri_pass, -1)) {
                BIO_puts(bio_err, "\x45\x72\x72\x6f\x72\x20\x64\x65\x63\x72\x79\x70\x74\x69\x6e\x67\x20\x43\x4d\x53\x20\x75\x73\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\xa");
                goto end;
            }
        }

        if (!CMS_decrypt(cms, NULL, NULL, indata, out, flags)) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x64\x65\x63\x72\x79\x70\x74\x69\x6e\x67\x20\x43\x4d\x53\x20\x73\x74\x72\x75\x63\x74\x75\x72\x65\xa");
            goto end;
        }
    } else if (operation == SMIME_DATAOUT) {
        if (!CMS_data(cms, out, flags))
            goto end;
    } else if (operation == SMIME_UNCOMPRESS) {
        if (!CMS_uncompress(cms, indata, out, flags))
            goto end;
    } else if (operation == SMIME_DIGEST_VERIFY) {
        if (CMS_digest_verify(cms, indata, out, flags) > 0)
            BIO_printf(bio_err, "\x56\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x20\x73\x75\x63\x63\x65\x73\x73\x66\x75\x6c\xa");
        else {
            BIO_printf(bio_err, "\x56\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x20\x66\x61\x69\x6c\x75\x72\x65\xa");
            goto end;
        }
    } else if (operation == SMIME_ENCRYPTED_DECRYPT) {
        if (!CMS_EncryptedData_decrypt(cms, secret_key, secret_keylen,
                                       indata, out, flags))
            goto end;
    } else if (operation == SMIME_VERIFY) {
        if (CMS_verify(cms, other, store, indata, out, flags) > 0)
            BIO_printf(bio_err, "\x56\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x20\x73\x75\x63\x63\x65\x73\x73\x66\x75\x6c\xa");
        else {
            BIO_printf(bio_err, "\x56\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x20\x66\x61\x69\x6c\x75\x72\x65\xa");
            if (verify_retcode)
                ret = verify_err + 32;
            goto end;
        }
        if (signerfile) {
            STACK_OF(X509) *signers;
            signers = CMS_get0_signers(cms);
            if (!save_certs(signerfile, signers)) {
                BIO_printf(bio_err,
                           "\x45\x72\x72\x6f\x72\x20\x77\x72\x69\x74\x69\x6e\x67\x20\x73\x69\x67\x6e\x65\x72\x73\x20\x74\x6f\x20\x25\x73\xa", signerfile);
                ret = 5;
                goto end;
            }
            sk_X509_free(signers);
        }
        if (rr_print)
            receipt_request_print(bio_err, cms);

    } else if (operation == SMIME_VERIFY_RECEIPT) {
        if (CMS_verify_receipt(rcms, cms, other, store, flags) > 0)
            BIO_printf(bio_err, "\x56\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x20\x73\x75\x63\x63\x65\x73\x73\x66\x75\x6c\xa");
        else {
            BIO_printf(bio_err, "\x56\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x20\x66\x61\x69\x6c\x75\x72\x65\xa");
            goto end;
        }
    } else {
        if (noout) {
            if (print)
                CMS_ContentInfo_print_ctx(out, cms, 0, NULL);
        } else if (outformat == FORMAT_SMIME) {
            if (to)
                BIO_printf(out, "\x54\x6f\x3a\x20\x25\x73\xa", to);
            if (from)
                BIO_printf(out, "\x46\x72\x6f\x6d\x3a\x20\x25\x73\xa", from);
            if (subject)
                BIO_printf(out, "\x53\x75\x62\x6a\x65\x63\x74\x3a\x20\x25\x73\xa", subject);
            if (operation == SMIME_RESIGN)
                ret = SMIME_write_CMS(out, cms, indata, flags);
            else
                ret = SMIME_write_CMS(out, cms, in, flags);
        } else if (outformat == FORMAT_PEM)
            ret = PEM_write_bio_CMS_stream(out, cms, in, flags);
        else if (outformat == FORMAT_ASN1)
            ret = i2d_CMS_bio_stream(out, cms, in, flags);
        else {
            BIO_printf(bio_err, "\x42\x61\x64\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x66\x6f\x72\x20\x43\x4d\x53\x20\x66\x69\x6c\x65\xa");
            goto end;
        }
        if (ret <= 0) {
            ret = 6;
            goto end;
        }
    }
    ret = 0;
 end:
    if (ret)
        ERR_print_errors(bio_err);
    if (need_rand)
        app_RAND_write_file(NULL, bio_err);
    sk_X509_pop_free(encerts, X509_free);
    sk_X509_pop_free(other, X509_free);
    if (vpm)
        X509_VERIFY_PARAM_free(vpm);
    if (sksigners)
        sk_OPENSSL_STRING_free(sksigners);
    if (skkeys)
        sk_OPENSSL_STRING_free(skkeys);
    if (secret_key)
        OPENSSL_free(secret_key);
    if (secret_keyid)
        OPENSSL_free(secret_keyid);
    if (pwri_tmp)
        OPENSSL_free(pwri_tmp);
    if (econtent_type)
        ASN1_OBJECT_free(econtent_type);
    if (rr)
        CMS_ReceiptRequest_free(rr);
    if (rr_to)
        sk_OPENSSL_STRING_free(rr_to);
    if (rr_from)
        sk_OPENSSL_STRING_free(rr_from);
    for (key_param = key_first; key_param;) {
        cms_key_param *tparam;
        sk_OPENSSL_STRING_free(key_param->param);
        tparam = key_param->next;
        OPENSSL_free(key_param);
        key_param = tparam;
    }
    X509_STORE_free(store);
    X509_free(cert);
    X509_free(recip);
    X509_free(signer);
    EVP_PKEY_free(key);
    CMS_ContentInfo_free(cms);
    CMS_ContentInfo_free(rcms);
    release_engine(e);
    BIO_free(rctin);
    BIO_free(in);
    BIO_free(indata);
    BIO_free_all(out);
    if (passin)
        OPENSSL_free(passin);
    return (ret);
}

static int save_certs(char *signerfile, STACK_OF(X509) *signers)
{
    int i;
    BIO *tmp;
    if (!signerfile)
        return 1;
    tmp = BIO_new_file(signerfile, "\x77");
    if (!tmp)
        return 0;
    for (i = 0; i < sk_X509_num(signers); i++)
        PEM_write_bio_X509(tmp, sk_X509_value(signers, i));
    BIO_free(tmp);
    return 1;
}

/* Minimal callback just to output policy info (if any) */

static int cms_cb(int ok, X509_STORE_CTX *ctx)
{
    int error;

    error = X509_STORE_CTX_get_error(ctx);

    verify_err = error;

    if ((error != X509_V_ERR_NO_EXPLICIT_POLICY)
        && ((error != X509_V_OK) || (ok != 2)))
        return ok;

    policies_print(NULL, ctx);

    return ok;

}

static void gnames_stack_print(BIO *out, STACK_OF(GENERAL_NAMES) *gns)
{
    STACK_OF(GENERAL_NAME) *gens;
    GENERAL_NAME *gen;
    int i, j;
    for (i = 0; i < sk_GENERAL_NAMES_num(gns); i++) {
        gens = sk_GENERAL_NAMES_value(gns, i);
        for (j = 0; j < sk_GENERAL_NAME_num(gens); j++) {
            gen = sk_GENERAL_NAME_value(gens, j);
            BIO_puts(out, "\x20\x20\x20\x20");
            GENERAL_NAME_print(out, gen);
            BIO_puts(out, "\xa");
        }
    }
    return;
}

static void receipt_request_print(BIO *out, CMS_ContentInfo *cms)
{
    STACK_OF(CMS_SignerInfo) *sis;
    CMS_SignerInfo *si;
    CMS_ReceiptRequest *rr;
    int allorfirst;
    STACK_OF(GENERAL_NAMES) *rto, *rlist;
    ASN1_STRING *scid;
    int i, rv;
    sis = CMS_get0_SignerInfos(cms);
    for (i = 0; i < sk_CMS_SignerInfo_num(sis); i++) {
        si = sk_CMS_SignerInfo_value(sis, i);
        rv = CMS_get1_ReceiptRequest(si, &rr);
        BIO_printf(bio_err, "\x53\x69\x67\x6e\x65\x72\x20\x25\x64\x3a\xa", i + 1);
        if (rv == 0)
            BIO_puts(bio_err, "\x20\x20\x4e\x6f\x20\x52\x65\x63\x65\x69\x70\x74\x20\x52\x65\x71\x75\x65\x73\x74\xa");
        else if (rv < 0) {
            BIO_puts(bio_err, "\x20\x20\x52\x65\x63\x65\x69\x70\x74\x20\x52\x65\x71\x75\x65\x73\x74\x20\x50\x61\x72\x73\x65\x20\x45\x72\x72\x6f\x72\xa");
            ERR_print_errors(bio_err);
        } else {
            char *id;
            int idlen;
            CMS_ReceiptRequest_get0_values(rr, &scid, &allorfirst,
                                           &rlist, &rto);
            BIO_puts(out, "\x20\x20\x53\x69\x67\x6e\x65\x64\x20\x43\x6f\x6e\x74\x65\x6e\x74\x20\x49\x44\x3a\xa");
            idlen = ASN1_STRING_length(scid);
            id = (char *)ASN1_STRING_data(scid);
            BIO_dump_indent(out, id, idlen, 4);
            BIO_puts(out, "\x20\x20\x52\x65\x63\x65\x69\x70\x74\x73\x20\x46\x72\x6f\x6d");
            if (rlist) {
                BIO_puts(out, "\x20\x4c\x69\x73\x74\x3a\xa");
                gnames_stack_print(out, rlist);
            } else if (allorfirst == 1)
                BIO_puts(out, "\x3a\x20\x46\x69\x72\x73\x74\x20\x54\x69\x65\x72\xa");
            else if (allorfirst == 0)
                BIO_puts(out, "\x3a\x20\x41\x6c\x6c\xa");
            else
                BIO_printf(out, "\x20\x55\x6e\x6b\x6e\x6f\x77\x6e\x20\x28\x25\x64\x29\xa", allorfirst);
            BIO_puts(out, "\x20\x20\x52\x65\x63\x65\x69\x70\x74\x73\x20\x54\x6f\x3a\xa");
            gnames_stack_print(out, rto);
        }
        if (rr)
            CMS_ReceiptRequest_free(rr);
    }
}

static STACK_OF(GENERAL_NAMES) *make_names_stack(STACK_OF(OPENSSL_STRING) *ns)
{
    int i;
    STACK_OF(GENERAL_NAMES) *ret;
    GENERAL_NAMES *gens = NULL;
    GENERAL_NAME *gen = NULL;
    ret = sk_GENERAL_NAMES_new_null();
    if (!ret)
        goto err;
    for (i = 0; i < sk_OPENSSL_STRING_num(ns); i++) {
        char *str = sk_OPENSSL_STRING_value(ns, i);
        gen = a2i_GENERAL_NAME(NULL, NULL, NULL, GEN_EMAIL, str, 0);
        if (!gen)
            goto err;
        gens = GENERAL_NAMES_new();
        if (!gens)
            goto err;
        if (!sk_GENERAL_NAME_push(gens, gen))
            goto err;
        gen = NULL;
        if (!sk_GENERAL_NAMES_push(ret, gens))
            goto err;
        gens = NULL;
    }

    return ret;

 err:
    if (ret)
        sk_GENERAL_NAMES_pop_free(ret, GENERAL_NAMES_free);
    if (gens)
        GENERAL_NAMES_free(gens);
    if (gen)
        GENERAL_NAME_free(gen);
    return NULL;
}

static CMS_ReceiptRequest *make_receipt_request(STACK_OF(OPENSSL_STRING)
                                                *rr_to, int rr_allorfirst, STACK_OF(OPENSSL_STRING)
                                                *rr_from)
{
    STACK_OF(GENERAL_NAMES) *rct_to, *rct_from;
    CMS_ReceiptRequest *rr;
    rct_to = make_names_stack(rr_to);
    if (!rct_to)
        goto err;
    if (rr_from) {
        rct_from = make_names_stack(rr_from);
        if (!rct_from)
            goto err;
    } else
        rct_from = NULL;
    rr = CMS_ReceiptRequest_create0(NULL, -1, rr_allorfirst, rct_from,
                                    rct_to);
    return rr;
 err:
    return NULL;
}

static int cms_set_pkey_param(EVP_PKEY_CTX *pctx,
                              STACK_OF(OPENSSL_STRING) *param)
{
    char *keyopt;
    int i;
    if (sk_OPENSSL_STRING_num(param) <= 0)
        return 1;
    for (i = 0; i < sk_OPENSSL_STRING_num(param); i++) {
        keyopt = sk_OPENSSL_STRING_value(param, i);
        if (pkey_ctrl_string(pctx, keyopt) <= 0) {
            BIO_printf(bio_err, "\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x20\x65\x72\x72\x6f\x72\x20\x22\x25\x73\x22\xa", keyopt);
            ERR_print_errors(bio_err);
            return 0;
        }
    }
    return 1;
}

#endif

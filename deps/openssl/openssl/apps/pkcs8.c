/* pkcs8.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999-2004.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
#include <stdio.h>
#include <string.h>
#include "apps.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>

#define PROG pkcs8_main

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    ENGINE *e = NULL;
    char **args, *infile = NULL, *outfile = NULL;
    char *passargin = NULL, *passargout = NULL;
    BIO *in = NULL, *out = NULL;
    int topk8 = 0;
    int pbe_nid = -1;
    const EVP_CIPHER *cipher = NULL;
    int iter = PKCS12_DEFAULT_ITER;
    int informat, outformat;
    int p8_broken = PKCS8_OK;
    int nocrypt = 0;
    X509_SIG *p8 = NULL;
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;
    EVP_PKEY *pkey = NULL;
    char pass[50], *passin = NULL, *passout = NULL, *p8pass = NULL;
    int badarg = 0;
    int ret = 1;
    char *engine = NULL;

    if (bio_err == NULL)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!load_config(bio_err, NULL))
        goto end;

    informat = FORMAT_PEM;
    outformat = FORMAT_PEM;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    args = argv + 1;
    while (!badarg && *args && *args[0] == '\x2d') {
        if (!strcmp(*args, "\x2d\x76\x32")) {
            if (args[1]) {
                args++;
                cipher = EVP_get_cipherbyname(*args);
                if (!cipher) {
                    BIO_printf(bio_err, "\x55\x6e\x6b\x6e\x6f\x77\x6e\x20\x63\x69\x70\x68\x65\x72\x20\x25\x73\xa", *args);
                    badarg = 1;
                }
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x76\x31")) {
            if (args[1]) {
                args++;
                pbe_nid = OBJ_txt2nid(*args);
                if (pbe_nid == NID_undef) {
                    BIO_printf(bio_err, "\x55\x6e\x6b\x6e\x6f\x77\x6e\x20\x50\x42\x45\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x20\x25\x73\xa", *args);
                    badarg = 1;
                }
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x76\x32\x70\x72\x66")) {
            if (args[1]) {
                args++;
                pbe_nid = OBJ_txt2nid(*args);
                if (!EVP_PBE_find(EVP_PBE_TYPE_PRF, pbe_nid, NULL, NULL, 0)) {
                    BIO_printf(bio_err, "\x55\x6e\x6b\x6e\x6f\x77\x6e\x20\x50\x52\x46\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x20\x25\x73\xa", *args);
                    badarg = 1;
                }
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x69\x6e\x66\x6f\x72\x6d")) {
            if (args[1]) {
                args++;
                informat = str2fmt(*args);
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x6f\x75\x74\x66\x6f\x72\x6d")) {
            if (args[1]) {
                args++;
                outformat = str2fmt(*args);
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x74\x6f\x70\x6b\x38"))
            topk8 = 1;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x69\x74\x65\x72"))
            iter = 1;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x63\x72\x79\x70\x74"))
            nocrypt = 1;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x6f\x63\x74"))
            p8_broken = PKCS8_NO_OCTET;
        else if (!strcmp(*args, "\x2d\x6e\x73\x64\x62"))
            p8_broken = PKCS8_NS_DB;
        else if (!strcmp(*args, "\x2d\x65\x6d\x62\x65\x64"))
            p8_broken = PKCS8_EMBEDDED_PARAM;
        else if (!strcmp(*args, "\x2d\x70\x61\x73\x73\x69\x6e")) {
            if (!args[1])
                goto bad;
            passargin = *(++args);
        } else if (!strcmp(*args, "\x2d\x70\x61\x73\x73\x6f\x75\x74")) {
            if (!args[1])
                goto bad;
            passargout = *(++args);
        }
#ifndef OPENSSL_NO_ENGINE
        else if (strcmp(*args, "\x2d\x65\x6e\x67\x69\x6e\x65") == 0) {
            if (!args[1])
                goto bad;
            engine = *(++args);
        }
#endif
        else if (!strcmp(*args, "\x2d\x69\x6e")) {
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
        } else
            badarg = 1;
        args++;
    }

    if (badarg) {
 bad:
        BIO_printf(bio_err, "\x55\x73\x61\x67\x65\x20\x70\x6b\x63\x73\x38\x20\x5b\x6f\x70\x74\x69\x6f\x6e\x73\x5d\xa");
        BIO_printf(bio_err, "\x77\x68\x65\x72\x65\x20\x6f\x70\x74\x69\x6f\x6e\x73\x20\x61\x72\x65\xa");
        BIO_printf(bio_err, "\x2d\x69\x6e\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err, "\x2d\x69\x6e\x66\x6f\x72\x6d\x20\x58\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x28\x44\x45\x52\x20\x6f\x72\x20\x50\x45\x4d\x29\xa");
        BIO_printf(bio_err,
                   "\x2d\x70\x61\x73\x73\x69\x6e\x20\x61\x72\x67\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x70\x61\x73\x73\x20\x70\x68\x72\x61\x73\x65\x20\x73\x6f\x75\x72\x63\x65\xa");
        BIO_printf(bio_err, "\x2d\x6f\x75\x74\x66\x6f\x72\x6d\x20\x58\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x28\x44\x45\x52\x20\x6f\x72\x20\x50\x45\x4d\x29\xa");
        BIO_printf(bio_err, "\x2d\x6f\x75\x74\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x70\x61\x73\x73\x6f\x75\x74\x20\x61\x72\x67\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x70\x61\x73\x73\x20\x70\x68\x72\x61\x73\x65\x20\x73\x6f\x75\x72\x63\x65\xa");
        BIO_printf(bio_err, "\x2d\x74\x6f\x70\x6b\x38\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x50\x4b\x43\x53\x38\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x6f\x63\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x28\x6e\x6f\x6e\x73\x74\x61\x6e\x64\x61\x72\x64\x29\x20\x6e\x6f\x20\x6f\x63\x74\x65\x74\x20\x66\x6f\x72\x6d\x61\x74\xa");
        BIO_printf(bio_err,
                   "\x2d\x65\x6d\x62\x65\x64\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x28\x6e\x6f\x6e\x73\x74\x61\x6e\x64\x61\x72\x64\x29\x20\x65\x6d\x62\x65\x64\x64\x65\x64\x20\x44\x53\x41\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x20\x66\x6f\x72\x6d\x61\x74\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x73\x64\x62\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x28\x6e\x6f\x6e\x73\x74\x61\x6e\x64\x61\x72\x64\x29\x20\x44\x53\x41\x20\x4e\x65\x74\x73\x63\x61\x70\x65\x20\x44\x42\x20\x66\x6f\x72\x6d\x61\x74\xa");
        BIO_printf(bio_err, "\x2d\x6e\x6f\x69\x74\x65\x72\x20\x20\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x31\x20\x61\x73\x20\x69\x74\x65\x72\x61\x74\x69\x6f\x6e\x20\x63\x6f\x75\x6e\x74\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x63\x72\x79\x70\x74\x20\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x6f\x72\x20\x65\x78\x70\x65\x63\x74\x20\x75\x6e\x65\x6e\x63\x72\x79\x70\x74\x65\x64\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\xa");
        BIO_printf(bio_err,
                   "\x2d\x76\x32\x20\x61\x6c\x67\x20\x20\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x50\x4b\x43\x53\x23\x35\x20\x76\x32\x2e\x30\x20\x61\x6e\x64\x20\x63\x69\x70\x68\x65\x72\x20\x22\x61\x6c\x67\x22\xa");
        BIO_printf(bio_err,
                   "\x2d\x76\x31\x20\x6f\x62\x6a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x50\x4b\x43\x53\x23\x35\x20\x76\x31\x2e\x35\x20\x61\x6e\x64\x20\x63\x69\x70\x68\x65\x72\x20\x22\x61\x6c\x67\x22\xa");
#ifndef OPENSSL_NO_ENGINE
        BIO_printf(bio_err,
                   "\x20\x2d\x65\x6e\x67\x69\x6e\x65\x20\x65\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x65\x2c\x20\x70\x6f\x73\x73\x69\x62\x6c\x79\x20\x61\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20\x64\x65\x76\x69\x63\x65\x2e\xa");
#endif
        goto end;
    }
    e = setup_engine(bio_err, engine, 0);

    if (!app_passwd(bio_err, passargin, passargout, &passin, &passout)) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x73\xa");
        goto end;
    }

    if ((pbe_nid == -1) && !cipher)
        pbe_nid = NID_pbeWithMD5AndDES_CBC;

    if (infile) {
        if (!(in = BIO_new_file(infile, "\x72\x62"))) {
            BIO_printf(bio_err, "\x43\x61\x6e\x27\x74\x20\x6f\x70\x65\x6e\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x25\x73\xa", infile);
            goto end;
        }
    } else
        in = BIO_new_fp(stdin, BIO_NOCLOSE);

    if (outfile) {
        if (!(out = BIO_new_file(outfile, "\x77\x62"))) {
            BIO_printf(bio_err, "\x43\x61\x6e\x27\x74\x20\x6f\x70\x65\x6e\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x25\x73\xa", outfile);
            goto end;
        }
    } else {
        out = BIO_new_fp(stdout, BIO_NOCLOSE);
#ifdef OPENSSL_SYS_VMS
        {
            BIO *tmpbio = BIO_new(BIO_f_linebuffer());
            out = BIO_push(tmpbio, out);
        }
#endif
    }
    if (topk8) {
        pkey = load_key(bio_err, infile, informat, 1, passin, e, "\x6b\x65\x79");
        if (!pkey)
            goto end;
        if (!(p8inf = EVP_PKEY2PKCS8_broken(pkey, p8_broken))) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x63\x6f\x6e\x76\x65\x72\x74\x69\x6e\x67\x20\x6b\x65\x79\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
        if (nocrypt) {
            if (outformat == FORMAT_PEM)
                PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8inf);
            else if (outformat == FORMAT_ASN1)
                i2d_PKCS8_PRIV_KEY_INFO_bio(out, p8inf);
            else {
                BIO_printf(bio_err, "\x42\x61\x64\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20\x6b\x65\x79\xa");
                goto end;
            }
        } else {
            if (passout)
                p8pass = passout;
            else {
                p8pass = pass;
                if (EVP_read_pw_string
                    (pass, sizeof(pass), "\x45\x6e\x74\x65\x72\x20\x45\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e\x20\x50\x61\x73\x73\x77\x6f\x72\x64\x3a", 1))
                    goto end;
            }
            app_RAND_load_file(NULL, bio_err, 0);
            if (!(p8 = PKCS8_encrypt(pbe_nid, cipher,
                                     p8pass, strlen(p8pass),
                                     NULL, 0, iter, p8inf))) {
                BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x65\x6e\x63\x72\x79\x70\x74\x69\x6e\x67\x20\x6b\x65\x79\xa");
                ERR_print_errors(bio_err);
                goto end;
            }
            app_RAND_write_file(NULL, bio_err);
            if (outformat == FORMAT_PEM)
                PEM_write_bio_PKCS8(out, p8);
            else if (outformat == FORMAT_ASN1)
                i2d_PKCS8_bio(out, p8);
            else {
                BIO_printf(bio_err, "\x42\x61\x64\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20\x6b\x65\x79\xa");
                goto end;
            }
        }

        ret = 0;
        goto end;
    }

    if (nocrypt) {
        if (informat == FORMAT_PEM)
            p8inf = PEM_read_bio_PKCS8_PRIV_KEY_INFO(in, NULL, NULL, NULL);
        else if (informat == FORMAT_ASN1)
            p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(in, NULL);
        else {
            BIO_printf(bio_err, "\x42\x61\x64\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20\x6b\x65\x79\xa");
            goto end;
        }
    } else {
        if (informat == FORMAT_PEM)
            p8 = PEM_read_bio_PKCS8(in, NULL, NULL, NULL);
        else if (informat == FORMAT_ASN1)
            p8 = d2i_PKCS8_bio(in, NULL);
        else {
            BIO_printf(bio_err, "\x42\x61\x64\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20\x6b\x65\x79\xa");
            goto end;
        }

        if (!p8) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x72\x65\x61\x64\x69\x6e\x67\x20\x6b\x65\x79\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
        if (passin)
            p8pass = passin;
        else {
            p8pass = pass;
            EVP_read_pw_string(pass, sizeof(pass), "\x45\x6e\x74\x65\x72\x20\x50\x61\x73\x73\x77\x6f\x72\x64\x3a", 0);
        }
        p8inf = PKCS8_decrypt(p8, p8pass, strlen(p8pass));
    }

    if (!p8inf) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x64\x65\x63\x72\x79\x70\x74\x69\x6e\x67\x20\x6b\x65\x79\xa");
        ERR_print_errors(bio_err);
        goto end;
    }

    if (!(pkey = EVP_PKCS82PKEY(p8inf))) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x63\x6f\x6e\x76\x65\x72\x74\x69\x6e\x67\x20\x6b\x65\x79\xa");
        ERR_print_errors(bio_err);
        goto end;
    }

    if (p8inf->broken) {
        BIO_printf(bio_err, "\x57\x61\x72\x6e\x69\x6e\x67\x3a\x20\x62\x72\x6f\x6b\x65\x6e\x20\x6b\x65\x79\x20\x65\x6e\x63\x6f\x64\x69\x6e\x67\x3a\x20");
        switch (p8inf->broken) {
        case PKCS8_NO_OCTET:
            BIO_printf(bio_err, "\x4e\x6f\x20\x4f\x63\x74\x65\x74\x20\x53\x74\x72\x69\x6e\x67\x20\x69\x6e\x20\x50\x72\x69\x76\x61\x74\x65\x4b\x65\x79\xa");
            break;

        case PKCS8_EMBEDDED_PARAM:
            BIO_printf(bio_err, "\x44\x53\x41\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x20\x69\x6e\x63\x6c\x75\x64\x65\x64\x20\x69\x6e\x20\x50\x72\x69\x76\x61\x74\x65\x4b\x65\x79\xa");
            break;

        case PKCS8_NS_DB:
            BIO_printf(bio_err, "\x44\x53\x41\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\x20\x69\x6e\x63\x6c\x75\x64\x65\x20\x69\x6e\x20\x50\x72\x69\x76\x61\x74\x65\x4b\x65\x79\xa");
            break;

        case PKCS8_NEG_PRIVKEY:
            BIO_printf(bio_err, "\x44\x53\x41\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x76\x61\x6c\x75\x65\x20\x69\x73\x20\x6e\x65\x67\x61\x74\x69\x76\x65\xa");
            break;

        default:
            BIO_printf(bio_err, "\x55\x6e\x6b\x6e\x6f\x77\x6e\x20\x62\x72\x6f\x6b\x65\x6e\x20\x74\x79\x70\x65\xa");
            break;
        }
    }

    if (outformat == FORMAT_PEM)
        PEM_write_bio_PrivateKey(out, pkey, NULL, NULL, 0, NULL, passout);
    else if (outformat == FORMAT_ASN1)
        i2d_PrivateKey_bio(out, pkey);
    else {
        BIO_printf(bio_err, "\x42\x61\x64\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20\x6b\x65\x79\xa");
        goto end;
    }
    ret = 0;

 end:
    X509_SIG_free(p8);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    EVP_PKEY_free(pkey);
    release_engine(e);
    BIO_free_all(out);
    BIO_free(in);
    if (passin)
        OPENSSL_free(passin);
    if (passout)
        OPENSSL_free(passout);

    return ret;
}

/* apps/spkac.c */

/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 1999. Based on an original idea by Massimiliano Pala (madwolf@openca.org).
 */
/* ====================================================================
 * Copyright (c) 1999-2017 The OpenSSL Project.  All rights reserved.
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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/lhash.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#undef PROG
#define PROG    spkac_main

/*-
 * -in arg      - input file - default stdin
 * -out arg     - output file - default stdout
 */

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    ENGINE *e = NULL;
    int i, badops = 0, ret = 1;
    BIO *in = NULL, *out = NULL;
    int verify = 0, noout = 0, pubkey = 0;
    char *infile = NULL, *outfile = NULL, *prog;
    char *passargin = NULL, *passin = NULL;
    const char *spkac = "\x53\x50\x4b\x41\x43", *spksect = "\x64\x65\x66\x61\x75\x6c\x74";
    char *spkstr = NULL;
    char *challenge = NULL, *keyfile = NULL;
    CONF *conf = NULL;
    NETSCAPE_SPKI *spki = NULL;
    EVP_PKEY *pkey = NULL;
    char *engine = NULL;

    apps_startup();

    if (!bio_err)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!load_config(bio_err, NULL))
        goto end;

    prog = argv[0];
    argc--;
    argv++;
    while (argc >= 1) {
        if (strcmp(*argv, "\x2d\x69\x6e") == 0) {
            if (--argc < 1)
                goto bad;
            infile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6f\x75\x74") == 0) {
            if (--argc < 1)
                goto bad;
            outfile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x70\x61\x73\x73\x69\x6e") == 0) {
            if (--argc < 1)
                goto bad;
            passargin = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6b\x65\x79") == 0) {
            if (--argc < 1)
                goto bad;
            keyfile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x63\x68\x61\x6c\x6c\x65\x6e\x67\x65") == 0) {
            if (--argc < 1)
                goto bad;
            challenge = *(++argv);
        } else if (strcmp(*argv, "\x2d\x73\x70\x6b\x61\x63") == 0) {
            if (--argc < 1)
                goto bad;
            spkac = *(++argv);
        } else if (strcmp(*argv, "\x2d\x73\x70\x6b\x73\x65\x63\x74") == 0) {
            if (--argc < 1)
                goto bad;
            spksect = *(++argv);
        }
#ifndef OPENSSL_NO_ENGINE
        else if (strcmp(*argv, "\x2d\x65\x6e\x67\x69\x6e\x65") == 0) {
            if (--argc < 1)
                goto bad;
            engine = *(++argv);
        }
#endif
        else if (strcmp(*argv, "\x2d\x6e\x6f\x6f\x75\x74") == 0)
            noout = 1;
        else if (strcmp(*argv, "\x2d\x70\x75\x62\x6b\x65\x79") == 0)
            pubkey = 1;
        else if (strcmp(*argv, "\x2d\x76\x65\x72\x69\x66\x79") == 0)
            verify = 1;
        else
            badops = 1;
        argc--;
        argv++;
    }

    if (badops) {
 bad:
        BIO_printf(bio_err, "\x25\x73\x20\x5b\x6f\x70\x74\x69\x6f\x6e\x73\x5d\xa", prog);
        BIO_printf(bio_err, "\x77\x68\x65\x72\x65\x20\x6f\x70\x74\x69\x6f\x6e\x73\x20\x61\x72\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x69\x6e\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x6f\x75\x74\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err,
                   "\x20\x2d\x6b\x65\x79\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x63\x72\x65\x61\x74\x65\x20\x53\x50\x4b\x41\x43\x20\x75\x73\x69\x6e\x67\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\xa");
        BIO_printf(bio_err,
                   "\x20\x2d\x70\x61\x73\x73\x69\x6e\x20\x61\x72\x67\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x70\x61\x73\x73\x20\x70\x68\x72\x61\x73\x65\x20\x73\x6f\x75\x72\x63\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x63\x68\x61\x6c\x6c\x65\x6e\x67\x65\x20\x61\x72\x67\x20\x63\x68\x61\x6c\x6c\x65\x6e\x67\x65\x20\x73\x74\x72\x69\x6e\x67\xa");
        BIO_printf(bio_err, "\x20\x2d\x73\x70\x6b\x61\x63\x20\x61\x72\x67\x20\x20\x20\x20\x20\x61\x6c\x74\x65\x72\x6e\x61\x74\x69\x76\x65\x20\x53\x50\x4b\x41\x43\x20\x6e\x61\x6d\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x6e\x6f\x6f\x75\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x70\x72\x69\x6e\x74\x20\x53\x50\x4b\x41\x43\xa");
        BIO_printf(bio_err, "\x20\x2d\x70\x75\x62\x6b\x65\x79\x20\x20\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\xa");
        BIO_printf(bio_err, "\x20\x2d\x76\x65\x72\x69\x66\x79\x20\x20\x20\x20\x20\x20\x20\x20\x76\x65\x72\x69\x66\x79\x20\x53\x50\x4b\x41\x43\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65\xa");
#ifndef OPENSSL_NO_ENGINE
        BIO_printf(bio_err,
                   "\x20\x2d\x65\x6e\x67\x69\x6e\x65\x20\x65\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x65\x2c\x20\x70\x6f\x73\x73\x69\x62\x6c\x79\x20\x61\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20\x64\x65\x76\x69\x63\x65\x2e\xa");
#endif
        goto end;
    }

    ERR_load_crypto_strings();
    if (!app_passwd(bio_err, passargin, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\xa");
        goto end;
    }
    e = setup_engine(bio_err, engine, 0);

    if (keyfile != NULL) {
        pkey = load_key(bio_err,
                        strcmp(keyfile, "\x2d") ? keyfile : NULL,
                        FORMAT_PEM, 1, passin, e, "\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79");
        if (pkey == NULL)
            goto end;
        spki = NETSCAPE_SPKI_new();
        if (spki == NULL)
            goto end;
        if (challenge != NULL)
            ASN1_STRING_set(spki->spkac->challenge,
                            challenge, (int)strlen(challenge));
        NETSCAPE_SPKI_set_pubkey(spki, pkey);
        NETSCAPE_SPKI_sign(spki, pkey, EVP_md5());
        spkstr = NETSCAPE_SPKI_b64_encode(spki);
        if (spkstr == NULL)
            goto end;

        if (outfile)
            out = BIO_new_file(outfile, "\x77");
        else {
            out = BIO_new_fp(stdout, BIO_NOCLOSE);
#ifdef OPENSSL_SYS_VMS
            {
                BIO *tmpbio = BIO_new(BIO_f_linebuffer());
                out = BIO_push(tmpbio, out);
            }
#endif
        }

        if (!out) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x6f\x70\x65\x6e\x69\x6e\x67\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
        BIO_printf(out, "\x53\x50\x4b\x41\x43\x3d\x25\x73\xa", spkstr);
        OPENSSL_free(spkstr);
        ret = 0;
        goto end;
    }

    if (infile)
        in = BIO_new_file(infile, "\x72");
    else
        in = BIO_new_fp(stdin, BIO_NOCLOSE);

    if (!in) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x6f\x70\x65\x6e\x69\x6e\x67\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        ERR_print_errors(bio_err);
        goto end;
    }

    conf = NCONF_new(NULL);
    i = NCONF_load_bio(conf, in, NULL);

    if (!i) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x70\x61\x72\x73\x69\x6e\x67\x20\x63\x6f\x6e\x66\x69\x67\x20\x66\x69\x6c\x65\xa");
        ERR_print_errors(bio_err);
        goto end;
    }

    spkstr = NCONF_get_string(conf, spksect, spkac);

    if (!spkstr) {
        BIO_printf(bio_err, "\x43\x61\x6e\x27\x74\x20\x66\x69\x6e\x64\x20\x53\x50\x4b\x41\x43\x20\x63\x61\x6c\x6c\x65\x64\x20\x22\x25\x73\x22\xa", spkac);
        ERR_print_errors(bio_err);
        goto end;
    }

    spki = NETSCAPE_SPKI_b64_decode(spkstr, -1);

    if (spki == NULL) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x6c\x6f\x61\x64\x69\x6e\x67\x20\x53\x50\x4b\x41\x43\xa");
        ERR_print_errors(bio_err);
        goto end;
    }

    if (outfile)
        out = BIO_new_file(outfile, "\x77");
    else {
        out = BIO_new_fp(stdout, BIO_NOCLOSE);
#ifdef OPENSSL_SYS_VMS
        {
            BIO *tmpbio = BIO_new(BIO_f_linebuffer());
            out = BIO_push(tmpbio, out);
        }
#endif
    }

    if (!out) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x6f\x70\x65\x6e\x69\x6e\x67\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        ERR_print_errors(bio_err);
        goto end;
    }

    if (!noout)
        NETSCAPE_SPKI_print(out, spki);
    pkey = NETSCAPE_SPKI_get_pubkey(spki);
    if (verify) {
        i = NETSCAPE_SPKI_verify(spki, pkey);
        if (i > 0) {
            BIO_printf(bio_err, "\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x4f\x4b\xa");
        } else {
            BIO_printf(bio_err, "\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x46\x61\x69\x6c\x75\x72\x65\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
    }
    if (pubkey)
        PEM_write_bio_PUBKEY(out, pkey);

    ret = 0;

 end:
    NCONF_free(conf);
    NETSCAPE_SPKI_free(spki);
    BIO_free(in);
    BIO_free_all(out);
    EVP_PKEY_free(pkey);
    release_engine(e);
    if (passin)
        OPENSSL_free(passin);
    apps_shutdown();
    OPENSSL_EXIT(ret);
}

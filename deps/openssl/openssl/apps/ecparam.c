/* apps/ecparam.c */
/*
 * Written by Nils Larsch for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 1998-2018 The OpenSSL Project.  All rights reserved.
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
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("\x43\x6f\x6e\x74\x72\x69\x62\x75\x74\x69\x6f\x6e") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * The elliptic curve binary polynomial software is originally written by
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems Laboratories.
 *
 */

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_EC
# include <assert.h>
# include <stdio.h>
# include <stdlib.h>
# include <time.h>
# include <string.h>
# include "apps.h"
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/bn.h>
# include <openssl/ec.h>
# include <openssl/x509.h>
# include <openssl/pem.h>

# undef PROG
# define PROG    ecparam_main

/*-
 * -inform arg      - input format - default PEM (DER or PEM)
 * -outform arg     - output format - default PEM
 * -in  arg         - input file  - default stdin
 * -out arg         - output file - default stdout
 * -noout           - do not print the ec parameter
 * -text            - print the ec parameters in text form
 * -check           - validate the ec parameters
 * -C               - print a 'C' function creating the parameters
 * -name arg        - use the ec parameters with 'short name' name
 * -list_curves     - prints a list of all currently available curve 'short names'
 * -conv_form arg   - specifies the point conversion form
 *                  - possible values: compressed
 *                                     uncompressed (default)
 *                                     hybrid
 * -param_enc arg   - specifies the way the ec parameters are encoded
 *                    in the asn1 der encoding
 *                    possible values: named_curve (default)
 *                                     explicit
 * -no_seed         - if 'explicit' parameters are chosen do not use the seed
 * -genkey          - generate ec key
 * -rand file       - files to use for random number input
 * -engine e        - use engine e, possibly a hardware device
 */

static int ecparam_print_var(BIO *, BIGNUM *, const char *, int,
                             unsigned char *);

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    EC_GROUP *group = NULL;
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
    int new_form = 0;
    int asn1_flag = OPENSSL_EC_NAMED_CURVE;
    int new_asn1_flag = 0;
    char *curve_name = NULL, *inrand = NULL;
    int list_curves = 0, no_seed = 0, check = 0,
        badops = 0, text = 0, i, need_rand = 0, genkey = 0;
    char *infile = NULL, *outfile = NULL, *prog;
    BIO *in = NULL, *out = NULL;
    int informat, outformat, noout = 0, C = 0, ret = 1;
    char *engine = NULL;
    ENGINE *e = NULL;

    BIGNUM *ec_p = NULL, *ec_a = NULL, *ec_b = NULL,
        *ec_gen = NULL, *ec_order = NULL, *ec_cofactor = NULL;
    unsigned char *buffer = NULL;

    apps_startup();

    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (!load_config(bio_err, NULL))
        goto end;

    informat = FORMAT_PEM;
    outformat = FORMAT_PEM;

    prog = argv[0];
    argc--;
    argv++;
    while (argc >= 1) {
        if (strcmp(*argv, "\x2d\x69\x6e\x66\x6f\x72\x6d") == 0) {
            if (--argc < 1)
                goto bad;
            informat = str2fmt(*(++argv));
        } else if (strcmp(*argv, "\x2d\x6f\x75\x74\x66\x6f\x72\x6d") == 0) {
            if (--argc < 1)
                goto bad;
            outformat = str2fmt(*(++argv));
        } else if (strcmp(*argv, "\x2d\x69\x6e") == 0) {
            if (--argc < 1)
                goto bad;
            infile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6f\x75\x74") == 0) {
            if (--argc < 1)
                goto bad;
            outfile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x74\x65\x78\x74") == 0)
            text = 1;
        else if (strcmp(*argv, "\x2d\x43") == 0)
            C = 1;
        else if (strcmp(*argv, "\x2d\x63\x68\x65\x63\x6b") == 0)
            check = 1;
        else if (strcmp(*argv, "\x2d\x6e\x61\x6d\x65") == 0) {
            if (--argc < 1)
                goto bad;
            curve_name = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6c\x69\x73\x74\x5f\x63\x75\x72\x76\x65\x73") == 0)
            list_curves = 1;
        else if (strcmp(*argv, "\x2d\x63\x6f\x6e\x76\x5f\x66\x6f\x72\x6d") == 0) {
            if (--argc < 1)
                goto bad;
            ++argv;
            new_form = 1;
            if (strcmp(*argv, "\x63\x6f\x6d\x70\x72\x65\x73\x73\x65\x64") == 0)
                form = POINT_CONVERSION_COMPRESSED;
            else if (strcmp(*argv, "\x75\x6e\x63\x6f\x6d\x70\x72\x65\x73\x73\x65\x64") == 0)
                form = POINT_CONVERSION_UNCOMPRESSED;
            else if (strcmp(*argv, "\x68\x79\x62\x72\x69\x64") == 0)
                form = POINT_CONVERSION_HYBRID;
            else
                goto bad;
        } else if (strcmp(*argv, "\x2d\x70\x61\x72\x61\x6d\x5f\x65\x6e\x63") == 0) {
            if (--argc < 1)
                goto bad;
            ++argv;
            new_asn1_flag = 1;
            if (strcmp(*argv, "\x6e\x61\x6d\x65\x64\x5f\x63\x75\x72\x76\x65") == 0)
                asn1_flag = OPENSSL_EC_NAMED_CURVE;
            else if (strcmp(*argv, "\x65\x78\x70\x6c\x69\x63\x69\x74") == 0)
                asn1_flag = 0;
            else
                goto bad;
        } else if (strcmp(*argv, "\x2d\x6e\x6f\x5f\x73\x65\x65\x64") == 0)
            no_seed = 1;
        else if (strcmp(*argv, "\x2d\x6e\x6f\x6f\x75\x74") == 0)
            noout = 1;
        else if (strcmp(*argv, "\x2d\x67\x65\x6e\x6b\x65\x79") == 0) {
            genkey = 1;
            need_rand = 1;
        } else if (strcmp(*argv, "\x2d\x72\x61\x6e\x64") == 0) {
            if (--argc < 1)
                goto bad;
            inrand = *(++argv);
            need_rand = 1;
        } else if (strcmp(*argv, "\x2d\x65\x6e\x67\x69\x6e\x65") == 0) {
            if (--argc < 1)
                goto bad;
            engine = *(++argv);
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
        BIO_printf(bio_err, "\x25\x73\x20\x5b\x6f\x70\x74\x69\x6f\x6e\x73\x5d\x20\x3c\x69\x6e\x66\x69\x6c\x65\x20\x3e\x6f\x75\x74\x66\x69\x6c\x65\xa", prog);
        BIO_printf(bio_err, "\x77\x68\x65\x72\x65\x20\x6f\x70\x74\x69\x6f\x6e\x73\x20\x61\x72\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x69\x6e\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20"
                   "\x64\x65\x66\x61\x75\x6c\x74\x20\x50\x45\x4d\x20\x28\x44\x45\x52\x20\x6f\x72\x20\x50\x45\x4d\x29\xa");
        BIO_printf(bio_err, "\x20\x2d\x6f\x75\x74\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20"
                   "\x64\x65\x66\x61\x75\x6c\x74\x20\x50\x45\x4d\xa");
        BIO_printf(bio_err, "\x20\x2d\x69\x6e\x20\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x20\x2d\x20"
                   "\x64\x65\x66\x61\x75\x6c\x74\x20\x73\x74\x64\x69\x6e\xa");
        BIO_printf(bio_err, "\x20\x2d\x6f\x75\x74\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x2d\x20"
                   "\x64\x65\x66\x61\x75\x6c\x74\x20\x73\x74\x64\x6f\x75\x74\xa");
        BIO_printf(bio_err, "\x20\x2d\x6e\x6f\x6f\x75\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x20\x6e\x6f\x74\x20\x70\x72\x69\x6e\x74\x20\x74\x68\x65\x20"
                   "\x65\x63\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\xa");
        BIO_printf(bio_err, "\x20\x2d\x74\x65\x78\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x70\x72\x69\x6e\x74\x20\x74\x68\x65\x20\x65\x63\x20"
                   "\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x20\x69\x6e\x20\x74\x65\x78\x74\x20\x66\x6f\x72\x6d\xa");
        BIO_printf(bio_err, "\x20\x2d\x63\x68\x65\x63\x6b\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x76\x61\x6c\x69\x64\x61\x74\x65\x20\x74\x68\x65\x20\x65\x63\x20"
                   "\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\xa");
        BIO_printf(bio_err, "\x20\x2d\x43\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x70\x72\x69\x6e\x74\x20\x61\x20\x27\x43\x27\x20"
                   "\x66\x75\x6e\x63\x74\x69\x6f\x6e\x20\x63\x72\x65\x61\x74\x69\x6e\x67\x20\x74\x68\x65\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\xa");
        BIO_printf(bio_err, "\x20\x2d\x6e\x61\x6d\x65\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x74\x68\x65\x20"
                   "\x65\x63\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x20\x77\x69\x74\x68\x20\x27\x73\x68\x6f\x72\x74\x20\x6e\x61\x6d\x65\x27\x20\x6e\x61\x6d\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x6c\x69\x73\x74\x5f\x63\x75\x72\x76\x65\x73\x20\x20\x20\x20\x20\x20\x70\x72\x69\x6e\x74\x73\x20\x61\x20\x6c\x69\x73\x74\x20\x6f\x66\x20"
                   "\x61\x6c\x6c\x20\x63\x75\x72\x72\x65\x6e\x74\x6c\x79\x20\x61\x76\x61\x69\x6c\x61\x62\x6c\x65\x20\x63\x75\x72\x76\x65\x20\x27\x73\x68\x6f\x72\x74\x20\x6e\x61\x6d\x65\x73\x27\xa");
        BIO_printf(bio_err, "\x20\x2d\x63\x6f\x6e\x76\x5f\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x20\x73\x70\x65\x63\x69\x66\x69\x65\x73\x20\x74\x68\x65\x20"
                   "\x70\x6f\x69\x6e\x74\x20\x63\x6f\x6e\x76\x65\x72\x73\x69\x6f\x6e\x20\x66\x6f\x72\x6d\x20\xa");
        BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x70\x6f\x73\x73\x69\x62\x6c\x65\x20\x76\x61\x6c\x75\x65\x73\x3a"
                   "\x20\x63\x6f\x6d\x70\x72\x65\x73\x73\x65\x64\xa");
        BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20"
                   "\x20\x75\x6e\x63\x6f\x6d\x70\x72\x65\x73\x73\x65\x64\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x29\xa");
        BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20"
                   "\x20\x68\x79\x62\x72\x69\x64\xa");
        BIO_printf(bio_err, "\x20\x2d\x70\x61\x72\x61\x6d\x5f\x65\x6e\x63\x20\x61\x72\x67\x20\x20\x20\x20\x73\x70\x65\x63\x69\x66\x69\x65\x73\x20\x74\x68\x65\x20\x77\x61\x79"
                   "\x20\x74\x68\x65\x20\x65\x63\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x20\x61\x72\x65\x20\x65\x6e\x63\x6f\x64\x65\x64\xa");
        BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x20\x74\x68\x65\x20\x61\x73\x6e\x31\x20\x64\x65\x72\x20"
                   "\x65\x6e\x63\x6f\x64\x69\x6e\x67\xa");
        BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x70\x6f\x73\x73\x69\x62\x6c\x65\x20\x76\x61\x6c\x75\x65\x73\x3a"
                   "\x20\x6e\x61\x6d\x65\x64\x5f\x63\x75\x72\x76\x65\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x29\xa");
        BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20"
                   "\x20\x65\x78\x70\x6c\x69\x63\x69\x74\xa");
        BIO_printf(bio_err, "\x20\x2d\x6e\x6f\x5f\x73\x65\x65\x64\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x69\x66\x20\x27\x65\x78\x70\x6c\x69\x63\x69\x74\x27"
                   "\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x20\x61\x72\x65\x20\x63\x68\x6f\x73\x65\x6e\x20\x64\x6f\x20\x6e\x6f\x74" "\x20\x75\x73\x65\x20\x74\x68\x65\x20\x73\x65\x65\x64\xa");
        BIO_printf(bio_err, "\x20\x2d\x67\x65\x6e\x6b\x65\x79\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x20\x65\x63" "\x20\x6b\x65\x79\xa");
        BIO_printf(bio_err, "\x20\x2d\x72\x61\x6e\x64\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x66\x69\x6c\x65\x73\x20\x74\x6f\x20\x75\x73\x65\x20\x66\x6f\x72"
                   "\x20\x72\x61\x6e\x64\x6f\x6d\x20\x6e\x75\x6d\x62\x65\x72\x20\x69\x6e\x70\x75\x74\xa");
        BIO_printf(bio_err, "\x20\x2d\x65\x6e\x67\x69\x6e\x65\x20\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x65\x2c\x20"
                   "\x70\x6f\x73\x73\x69\x62\x6c\x79\x20\x61\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20\x64\x65\x76\x69\x63\x65\xa");
        goto end;
    }

    ERR_load_crypto_strings();

    in = BIO_new(BIO_s_file());
    out = BIO_new(BIO_s_file());
    if ((in == NULL) || (out == NULL)) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (infile == NULL)
        BIO_set_fp(in, stdin, BIO_NOCLOSE);
    else {
        if (BIO_read_filename(in, infile) <= 0) {
            perror(infile);
            goto end;
        }
    }
    if (outfile == NULL) {
        BIO_set_fp(out, stdout, BIO_NOCLOSE);
# ifdef OPENSSL_SYS_VMS
        {
            BIO *tmpbio = BIO_new(BIO_f_linebuffer());
            out = BIO_push(tmpbio, out);
        }
# endif
    } else {
        if (BIO_write_filename(out, outfile) <= 0) {
            perror(outfile);
            goto end;
        }
    }

    e = setup_engine(bio_err, engine, 0);

    if (list_curves) {
        EC_builtin_curve *curves = NULL;
        size_t crv_len = 0;
        size_t n = 0;

        crv_len = EC_get_builtin_curves(NULL, 0);

        curves = OPENSSL_malloc((int)(sizeof(EC_builtin_curve) * crv_len));

        if (curves == NULL)
            goto end;

        if (!EC_get_builtin_curves(curves, crv_len)) {
            OPENSSL_free(curves);
            goto end;
        }

        for (n = 0; n < crv_len; n++) {
            const char *comment;
            const char *sname;
            comment = curves[n].comment;
            sname = OBJ_nid2sn(curves[n].nid);
            if (comment == NULL)
                comment = "\x43\x55\x52\x56\x45\x20\x44\x45\x53\x43\x52\x49\x50\x54\x49\x4f\x4e\x20\x4e\x4f\x54\x20\x41\x56\x41\x49\x4c\x41\x42\x4c\x45";
            if (sname == NULL)
                sname = "";

            BIO_printf(out, "\x20\x20\x25\x2d\x31\x30\x73\x3a\x20", sname);
            BIO_printf(out, "\x25\x73\xa", comment);
        }

        OPENSSL_free(curves);
        ret = 0;
        goto end;
    }

    if (curve_name != NULL) {
        int nid;

        /*
         * workaround for the SECG curve names secp192r1 and secp256r1 (which
         * are the same as the curves prime192v1 and prime256v1 defined in
         * X9.62)
         */
        if (!strcmp(curve_name, "\x73\x65\x63\x70\x31\x39\x32\x72\x31")) {
            BIO_printf(bio_err, "\x75\x73\x69\x6e\x67\x20\x63\x75\x72\x76\x65\x20\x6e\x61\x6d\x65\x20\x70\x72\x69\x6d\x65\x31\x39\x32\x76\x31\x20"
                       "\x69\x6e\x73\x74\x65\x61\x64\x20\x6f\x66\x20\x73\x65\x63\x70\x31\x39\x32\x72\x31\xa");
            nid = NID_X9_62_prime192v1;
        } else if (!strcmp(curve_name, "\x73\x65\x63\x70\x32\x35\x36\x72\x31")) {
            BIO_printf(bio_err, "\x75\x73\x69\x6e\x67\x20\x63\x75\x72\x76\x65\x20\x6e\x61\x6d\x65\x20\x70\x72\x69\x6d\x65\x32\x35\x36\x76\x31\x20"
                       "\x69\x6e\x73\x74\x65\x61\x64\x20\x6f\x66\x20\x73\x65\x63\x70\x32\x35\x36\x72\x31\xa");
            nid = NID_X9_62_prime256v1;
        } else
            nid = OBJ_sn2nid(curve_name);

        if (nid == 0)
            nid = EC_curve_nist2nid(curve_name);

        if (nid == 0) {
            BIO_printf(bio_err, "\x75\x6e\x6b\x6e\x6f\x77\x6e\x20\x63\x75\x72\x76\x65\x20\x6e\x61\x6d\x65\x20\x28\x25\x73\x29\xa", curve_name);
            goto end;
        }

        group = EC_GROUP_new_by_curve_name(nid);
        if (group == NULL) {
            BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x63\x72\x65\x61\x74\x65\x20\x63\x75\x72\x76\x65\x20\x28\x25\x73\x29\xa", curve_name);
            goto end;
        }
        EC_GROUP_set_asn1_flag(group, asn1_flag);
        EC_GROUP_set_point_conversion_form(group, form);
    } else if (informat == FORMAT_ASN1) {
        group = d2i_ECPKParameters_bio(in, NULL);
    } else if (informat == FORMAT_PEM) {
        group = PEM_read_bio_ECPKParameters(in, NULL, NULL, NULL);
    } else {
        BIO_printf(bio_err, "\x62\x61\x64\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
        goto end;
    }

    if (group == NULL) {
        BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6c\x6f\x61\x64\x20\x65\x6c\x6c\x69\x70\x74\x69\x63\x20\x63\x75\x72\x76\x65\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\xa");
        ERR_print_errors(bio_err);
        goto end;
    }

    if (new_form)
        EC_GROUP_set_point_conversion_form(group, form);

    if (new_asn1_flag)
        EC_GROUP_set_asn1_flag(group, asn1_flag);

    if (no_seed) {
        EC_GROUP_set_seed(group, NULL, 0);
    }

    if (text) {
        if (!ECPKParameters_print(out, group, 0))
            goto end;
    }

    if (check) {
        BIO_printf(bio_err, "\x63\x68\x65\x63\x6b\x69\x6e\x67\x20\x65\x6c\x6c\x69\x70\x74\x69\x63\x20\x63\x75\x72\x76\x65\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x3a\x20");
        if (!EC_GROUP_check(group, NULL)) {
            BIO_printf(bio_err, "\x66\x61\x69\x6c\x65\x64\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
        BIO_printf(bio_err, "\x6f\x6b\xa");

    }

    if (C) {
        size_t buf_len = 0, tmp_len = 0;
        const EC_POINT *point;
        int is_prime, len = 0;
        const EC_METHOD *meth = EC_GROUP_method_of(group);

        if ((ec_p = BN_new()) == NULL || (ec_a = BN_new()) == NULL ||
            (ec_b = BN_new()) == NULL || (ec_gen = BN_new()) == NULL ||
            (ec_order = BN_new()) == NULL ||
            (ec_cofactor = BN_new()) == NULL) {
            perror("\x4f\x50\x45\x4e\x53\x53\x4c\x5f\x6d\x61\x6c\x6c\x6f\x63");
            goto end;
        }

        is_prime = (EC_METHOD_get_field_type(meth) == NID_X9_62_prime_field);

        if (is_prime) {
            if (!EC_GROUP_get_curve_GFp(group, ec_p, ec_a, ec_b, NULL))
                goto end;
        } else {
            /* TODO */
            goto end;
        }

        if ((point = EC_GROUP_get0_generator(group)) == NULL)
            goto end;
        if (!EC_POINT_point2bn(group, point,
                               EC_GROUP_get_point_conversion_form(group),
                               ec_gen, NULL))
            goto end;
        if (!EC_GROUP_get_order(group, ec_order, NULL))
            goto end;
        if (!EC_GROUP_get_cofactor(group, ec_cofactor, NULL))
            goto end;

        if (!ec_p || !ec_a || !ec_b || !ec_gen || !ec_order || !ec_cofactor)
            goto end;

        len = BN_num_bits(ec_order);

        if ((tmp_len = (size_t)BN_num_bytes(ec_p)) > buf_len)
            buf_len = tmp_len;
        if ((tmp_len = (size_t)BN_num_bytes(ec_a)) > buf_len)
            buf_len = tmp_len;
        if ((tmp_len = (size_t)BN_num_bytes(ec_b)) > buf_len)
            buf_len = tmp_len;
        if ((tmp_len = (size_t)BN_num_bytes(ec_gen)) > buf_len)
            buf_len = tmp_len;
        if ((tmp_len = (size_t)BN_num_bytes(ec_order)) > buf_len)
            buf_len = tmp_len;
        if ((tmp_len = (size_t)BN_num_bytes(ec_cofactor)) > buf_len)
            buf_len = tmp_len;

        buffer = (unsigned char *)OPENSSL_malloc(buf_len);

        if (buffer == NULL) {
            perror("\x4f\x50\x45\x4e\x53\x53\x4c\x5f\x6d\x61\x6c\x6c\x6f\x63");
            goto end;
        }

        ecparam_print_var(out, ec_p, "\x65\x63\x5f\x70", len, buffer);
        ecparam_print_var(out, ec_a, "\x65\x63\x5f\x61", len, buffer);
        ecparam_print_var(out, ec_b, "\x65\x63\x5f\x62", len, buffer);
        ecparam_print_var(out, ec_gen, "\x65\x63\x5f\x67\x65\x6e", len, buffer);
        ecparam_print_var(out, ec_order, "\x65\x63\x5f\x6f\x72\x64\x65\x72", len, buffer);
        ecparam_print_var(out, ec_cofactor, "\x65\x63\x5f\x63\x6f\x66\x61\x63\x74\x6f\x72", len, buffer);

        BIO_printf(out, "\xa\xa");

        BIO_printf(out, "\x45\x43\x5f\x47\x52\x4f\x55\x50\x20\x2a\x67\x65\x74\x5f\x65\x63\x5f\x67\x72\x6f\x75\x70\x5f\x25\x64\x28\x76\x6f\x69\x64\x29\xa\x9\x7b\xa", len);
        BIO_printf(out, "\x9\x69\x6e\x74\x20\x6f\x6b\x3d\x30\x3b\xa");
        BIO_printf(out, "\x9E\x43\x5f\x47\x52\x4f\x55\x50\x20\x2a\x67\x72\x6f\x75\x70\x20\x3d\x20\x4e\x55\x4c\x4c\x3b\xa");
        BIO_printf(out, "\x9E\x43\x5f\x50\x4f\x49\x4e\x54\x20\x2a\x70\x6f\x69\x6e\x74\x20\x3d\x20\x4e\x55\x4c\x4c\x3b\xa");
        BIO_printf(out, "\x9B\x49\x47\x4e\x55\x4d\x20\x20\x20\x2a\x74\x6d\x70\x5f\x31\x20\x3d\x20\x4e\x55\x4c\x4c\x2c\x20\x2a\x74\x6d\x70\x5f\x32\x20\x3d\x20\x4e\x55\x4c\x4c\x2c\x20"
                   "\x2a\x74\x6d\x70\x5f\x33\x20\x3d\x20\x4e\x55\x4c\x4c\x3b\xa\xa");
        BIO_printf(out, "\x9\x69\x66\x20\x28\x28\x74\x6d\x70\x5f\x31\x20\x3d\x20\x42\x4e\x5f\x62\x69\x6e\x32\x62\x6e\x28\x65\x63\x5f\x70\x5f\x25\x64\x2c\x20"
                   "\x73\x69\x7a\x65\x6f\x66\x28\x65\x63\x5f\x70\x5f\x25\x64\x29\x2c\x20\x4e\x55\x4c\x4c\x29\x29\x20\x3d\x3d\x20\x4e\x55\x4c\x4c\x29\xa\x9\x9"
                   "\x67\x6f\x74\x6f\x20\x65\x72\x72\x3b\xa", len, len);
        BIO_printf(out, "\x9\x69\x66\x20\x28\x28\x74\x6d\x70\x5f\x32\x20\x3d\x20\x42\x4e\x5f\x62\x69\x6e\x32\x62\x6e\x28\x65\x63\x5f\x61\x5f\x25\x64\x2c\x20"
                   "\x73\x69\x7a\x65\x6f\x66\x28\x65\x63\x5f\x61\x5f\x25\x64\x29\x2c\x20\x4e\x55\x4c\x4c\x29\x29\x20\x3d\x3d\x20\x4e\x55\x4c\x4c\x29\xa\x9\x9"
                   "\x67\x6f\x74\x6f\x20\x65\x72\x72\x3b\xa", len, len);
        BIO_printf(out, "\x9\x69\x66\x20\x28\x28\x74\x6d\x70\x5f\x33\x20\x3d\x20\x42\x4e\x5f\x62\x69\x6e\x32\x62\x6e\x28\x65\x63\x5f\x62\x5f\x25\x64\x2c\x20"
                   "\x73\x69\x7a\x65\x6f\x66\x28\x65\x63\x5f\x62\x5f\x25\x64\x29\x2c\x20\x4e\x55\x4c\x4c\x29\x29\x20\x3d\x3d\x20\x4e\x55\x4c\x4c\x29\xa\x9\x9"
                   "\x67\x6f\x74\x6f\x20\x65\x72\x72\x3b\xa", len, len);
        if (is_prime) {
            BIO_printf(out, "\x9\x69\x66\x20\x28\x28\x67\x72\x6f\x75\x70\x20\x3d\x20\x45\x43\x5f\x47\x52\x4f\x55\x50\x5f\x6e\x65\x77\x5f\x63\x75\x72\x76\x65\x5f"
                       "\x47\x46\x70\x28\x74\x6d\x70\x5f\x31\x2c\x20\x74\x6d\x70\x5f\x32\x2c\x20\x74\x6d\x70\x5f\x33\x2c\x20\x4e\x55\x4c\x4c\x29\x29\x20\x3d\x3d\x20\x4e\x55\x4c\x4c\x29"
                       "\xa\x9\x9\x67\x6f\x74\x6f\x20\x65\x72\x72\x3b\xa\xa");
        } else {
            /* TODO */
            goto end;
        }
        BIO_printf(out, "\x9\x2f\x2a\x20\x62\x75\x69\x6c\x64\x20\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\x20\x2a\x2f\xa");
        BIO_printf(out, "\x9\x69\x66\x20\x28\x28\x74\x6d\x70\x5f\x31\x20\x3d\x20\x42\x4e\x5f\x62\x69\x6e\x32\x62\x6e\x28\x65\x63\x5f\x67\x65\x6e\x5f\x25\x64\x2c\x20"
                   "\x73\x69\x7a\x65\x6f\x66\x28\x65\x63\x5f\x67\x65\x6e\x5f\x25\x64\x29\x2c\x20\x74\x6d\x70\x5f\x31\x29\x29\x20\x3d\x3d\x20\x4e\x55\x4c\x4c\x29"
                   "\xa\x9\x9\x67\x6f\x74\x6f\x20\x65\x72\x72\x3b\xa", len, len);
        BIO_printf(out, "\x9\x70\x6f\x69\x6e\x74\x20\x3d\x20\x45\x43\x5f\x50\x4f\x49\x4e\x54\x5f\x62\x6e\x32\x70\x6f\x69\x6e\x74\x28\x67\x72\x6f\x75\x70\x2c\x20\x74\x6d\x70\x5f\x31\x2c\x20"
                   "\x4e\x55\x4c\x4c\x2c\x20\x4e\x55\x4c\x4c\x29\x3b\xa");
        BIO_printf(out, "\x9\x69\x66\x20\x28\x70\x6f\x69\x6e\x74\x20\x3d\x3d\x20\x4e\x55\x4c\x4c\x29\xa\x9\x9\x67\x6f\x74\x6f\x20\x65\x72\x72\x3b\xa");
        BIO_printf(out, "\x9\x69\x66\x20\x28\x28\x74\x6d\x70\x5f\x32\x20\x3d\x20\x42\x4e\x5f\x62\x69\x6e\x32\x62\x6e\x28\x65\x63\x5f\x6f\x72\x64\x65\x72\x5f\x25\x64\x2c\x20"
                   "\x73\x69\x7a\x65\x6f\x66\x28\x65\x63\x5f\x6f\x72\x64\x65\x72\x5f\x25\x64\x29\x2c\x20\x74\x6d\x70\x5f\x32\x29\x29\x20\x3d\x3d\x20\x4e\x55\x4c\x4c\x29"
                   "\xa\x9\x9\x67\x6f\x74\x6f\x20\x65\x72\x72\x3b\xa", len, len);
        BIO_printf(out, "\x9\x69\x66\x20\x28\x28\x74\x6d\x70\x5f\x33\x20\x3d\x20\x42\x4e\x5f\x62\x69\x6e\x32\x62\x6e\x28\x65\x63\x5f\x63\x6f\x66\x61\x63\x74\x6f\x72\x5f\x25\x64\x2c\x20"
                   "\x73\x69\x7a\x65\x6f\x66\x28\x65\x63\x5f\x63\x6f\x66\x61\x63\x74\x6f\x72\x5f\x25\x64\x29\x2c\x20\x74\x6d\x70\x5f\x33\x29\x29\x20\x3d\x3d\x20\x4e\x55\x4c\x4c\x29"
                   "\xa\x9\x9\x67\x6f\x74\x6f\x20\x65\x72\x72\x3b\xa", len, len);
        BIO_printf(out, "\x9\x69\x66\x20\x28\x21\x45\x43\x5f\x47\x52\x4f\x55\x50\x5f\x73\x65\x74\x5f\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\x28\x67\x72\x6f\x75\x70\x2c\x20\x70\x6f\x69\x6e\x74\x2c"
                   "\x20\x74\x6d\x70\x5f\x32\x2c\x20\x74\x6d\x70\x5f\x33\x29\x29\xa\x9\x9\x67\x6f\x74\x6f\x20\x65\x72\x72\x3b\xa");
        BIO_printf(out, "\xa\x9\x6f\x6b\x3d\x31\x3b\xa");
        BIO_printf(out, "\x65\x72\x72\x3a\xa");
        BIO_printf(out, "\x9\x69\x66\x20\x28\x74\x6d\x70\x5f\x31\x29\xa\x9\x9B\x4e\x5f\x66\x72\x65\x65\x28\x74\x6d\x70\x5f\x31\x29\x3b\xa");
        BIO_printf(out, "\x9\x69\x66\x20\x28\x74\x6d\x70\x5f\x32\x29\xa\x9\x9B\x4e\x5f\x66\x72\x65\x65\x28\x74\x6d\x70\x5f\x32\x29\x3b\xa");
        BIO_printf(out, "\x9\x69\x66\x20\x28\x74\x6d\x70\x5f\x33\x29\xa\x9\x9B\x4e\x5f\x66\x72\x65\x65\x28\x74\x6d\x70\x5f\x33\x29\x3b\xa");
        BIO_printf(out, "\x9\x69\x66\x20\x28\x70\x6f\x69\x6e\x74\x29\xa\x9\x9E\x43\x5f\x50\x4f\x49\x4e\x54\x5f\x66\x72\x65\x65\x28\x70\x6f\x69\x6e\x74\x29\x3b\xa");
        BIO_printf(out, "\x9\x69\x66\x20\x28\x21\x6f\x6b\x29\xa");
        BIO_printf(out, "\x9\x9\x7b\xa");
        BIO_printf(out, "\x9\x9E\x43\x5f\x47\x52\x4f\x55\x50\x5f\x66\x72\x65\x65\x28\x67\x72\x6f\x75\x70\x29\x3b\xa");
        BIO_printf(out, "\x9\x9\x67\x72\x6f\x75\x70\x20\x3d\x20\x4e\x55\x4c\x4c\x3b\xa");
        BIO_printf(out, "\x9\x9\x7d\xa");
        BIO_printf(out, "\x9\x72\x65\x74\x75\x72\x6e\x28\x67\x72\x6f\x75\x70\x29\x3b\xa\x9\x7d\xa");
    }

    if (outformat == FORMAT_ASN1 && genkey)
        noout = 1;

    if (!noout) {
        if (outformat == FORMAT_ASN1)
            i = i2d_ECPKParameters_bio(out, group);
        else if (outformat == FORMAT_PEM)
            i = PEM_write_bio_ECPKParameters(out, group);
        else {
            BIO_printf(bio_err, "\x62\x61\x64\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72"
                       "\x20\x6f\x75\x74\x66\x69\x6c\x65\xa");
            goto end;
        }
        if (!i) {
            BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x77\x72\x69\x74\x65\x20\x65\x6c\x6c\x69\x70\x74\x69\x63\x20"
                       "\x63\x75\x72\x76\x65\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (need_rand) {
        app_RAND_load_file(NULL, bio_err, (inrand != NULL));
        if (inrand != NULL)
            BIO_printf(bio_err, "\x25\x6c\x64\x20\x73\x65\x6d\x69\x2d\x72\x61\x6e\x64\x6f\x6d\x20\x62\x79\x74\x65\x73\x20\x6c\x6f\x61\x64\x65\x64\xa",
                       app_RAND_load_files(inrand));
    }

    if (genkey) {
        EC_KEY *eckey = EC_KEY_new();

        if (eckey == NULL)
            goto end;

        assert(need_rand);

        if (EC_KEY_set_group(eckey, group) == 0)
            goto end;

        if (new_form)
            EC_KEY_set_conv_form(eckey, form);

        if (!EC_KEY_generate_key(eckey)) {
            EC_KEY_free(eckey);
            goto end;
        }
        if (outformat == FORMAT_ASN1)
            i = i2d_ECPrivateKey_bio(out, eckey);
        else if (outformat == FORMAT_PEM)
            i = PEM_write_bio_ECPrivateKey(out, eckey, NULL,
                                           NULL, 0, NULL, NULL);
        else {
            BIO_printf(bio_err, "\x62\x61\x64\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20"
                       "\x66\x6f\x72\x20\x6f\x75\x74\x66\x69\x6c\x65\xa");
            EC_KEY_free(eckey);
            goto end;
        }
        EC_KEY_free(eckey);
    }

    if (need_rand)
        app_RAND_write_file(NULL, bio_err);

    ret = 0;
 end:
    if (ec_p)
        BN_free(ec_p);
    if (ec_a)
        BN_free(ec_a);
    if (ec_b)
        BN_free(ec_b);
    if (ec_gen)
        BN_free(ec_gen);
    if (ec_order)
        BN_free(ec_order);
    if (ec_cofactor)
        BN_free(ec_cofactor);
    if (buffer)
        OPENSSL_free(buffer);
    if (group != NULL)
        EC_GROUP_free(group);
    release_engine(e);
    if (in != NULL)
        BIO_free(in);
    if (out != NULL)
        BIO_free_all(out);
    apps_shutdown();
    OPENSSL_EXIT(ret);
}

static int ecparam_print_var(BIO *out, BIGNUM *in, const char *var,
                             int len, unsigned char *buffer)
{
    BIO_printf(out, "\x73\x74\x61\x74\x69\x63\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x63\x68\x61\x72\x20\x25\x73\x5f\x25\x64\x5b\x5d\x20\x3d\x20\x7b", var, len);
    if (BN_is_zero(in))
        BIO_printf(out, "\xa\x90\x78\x30\x30");
    else {
        int i, l;

        l = BN_bn2bin(in, buffer);
        for (i = 0; i < l - 1; i++) {
            if ((i % 12) == 0)
                BIO_printf(out, "\xa\x9");
            BIO_printf(out, "\x30\x78\x25\x30\x32\x58\x2c", buffer[i]);
        }
        if ((i % 12) == 0)
            BIO_printf(out, "\xa\x9");
        BIO_printf(out, "\x30\x78\x25\x30\x32\x58", buffer[i]);
    }
    BIO_printf(out, "\xa\x9\x7d\x3b\xa\xa");
    return 1;
}
#else                           /* !OPENSSL_NO_EC */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif

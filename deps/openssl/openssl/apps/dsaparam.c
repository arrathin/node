/* apps/dsaparam.c */
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

#include <openssl/opensslconf.h> /* for OPENSSL_NO_DSA */
/*
 * Until the key-gen callbacks are modified to use newer prototypes, we allow
 * deprecated functions for openssl-internal code
 */
#ifdef OPENSSL_NO_DEPRECATED
# undef OPENSSL_NO_DEPRECATED
#endif

#ifndef OPENSSL_NO_DSA
# include <assert.h>
# include <stdio.h>
# include <stdlib.h>
# include <time.h>
# include <string.h>
# include "apps.h"
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/bn.h>
# include <openssl/dsa.h>
# include <openssl/x509.h>
# include <openssl/pem.h>

# undef PROG
# define PROG    dsaparam_main

/*-
 * -inform arg  - input format - default PEM (DER or PEM)
 * -outform arg - output format - default PEM
 * -in arg      - input file - default stdin
 * -out arg     - output file - default stdout
 * -noout
 * -text
 * -C
 * -noout
 * -genkey
 *  #ifdef GENCB_TEST
 * -timebomb n  - interrupt keygen after <n> seconds
 *  #endif
 */

# ifdef GENCB_TEST

static int stop_keygen_flag = 0;

static void timebomb_sigalarm(int foo)
{
    stop_keygen_flag = 1;
}

# endif

static int MS_CALLBACK dsa_cb(int p, int n, BN_GENCB *cb);

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    DSA *dsa = NULL;
    int i, badops = 0, text = 0;
    BIO *in = NULL, *out = NULL;
    int informat, outformat, noout = 0, C = 0, ret = 1;
    char *infile, *outfile, *prog, *inrand = NULL;
    int numbits = -1, num, genkey = 0;
    int need_rand = 0;
    char *engine = NULL;
    ENGINE *e = NULL;
# ifdef GENCB_TEST
    int timebomb = 0;
# endif

    apps_startup();

    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (!load_config(bio_err, NULL))
        goto end;

    infile = NULL;
    outfile = NULL;
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
        }
# ifndef OPENSSL_NO_ENGINE
        else if (strcmp(*argv, "\x2d\x65\x6e\x67\x69\x6e\x65") == 0) {
            if (--argc < 1)
                goto bad;
            engine = *(++argv);
        }
# endif
# ifdef GENCB_TEST
        else if (strcmp(*argv, "\x2d\x74\x69\x6d\x65\x62\x6f\x6d\x62") == 0) {
            if (--argc < 1)
                goto bad;
            timebomb = atoi(*(++argv));
        }
# endif
        else if (strcmp(*argv, "\x2d\x74\x65\x78\x74") == 0)
            text = 1;
        else if (strcmp(*argv, "\x2d\x43") == 0)
            C = 1;
        else if (strcmp(*argv, "\x2d\x67\x65\x6e\x6b\x65\x79") == 0) {
            genkey = 1;
            need_rand = 1;
        } else if (strcmp(*argv, "\x2d\x72\x61\x6e\x64") == 0) {
            if (--argc < 1)
                goto bad;
            inrand = *(++argv);
            need_rand = 1;
        } else if (strcmp(*argv, "\x2d\x6e\x6f\x6f\x75\x74") == 0)
            noout = 1;
        else if (sscanf(*argv, "\x25\x64", &num) == 1) {
            /* generate a key */
            numbits = num;
            need_rand = 1;
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
        BIO_printf(bio_err, "\x25\x73\x20\x5b\x6f\x70\x74\x69\x6f\x6e\x73\x5d\x20\x5b\x62\x69\x74\x73\x5d\x20\x3c\x69\x6e\x66\x69\x6c\x65\x20\x3e\x6f\x75\x74\x66\x69\x6c\x65\xa", prog);
        BIO_printf(bio_err, "\x77\x68\x65\x72\x65\x20\x6f\x70\x74\x69\x6f\x6e\x73\x20\x61\x72\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x69\x6e\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20\x44\x45\x52\x20\x6f\x72\x20\x50\x45\x4d\xa");
        BIO_printf(bio_err, "\x20\x2d\x6f\x75\x74\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20\x44\x45\x52\x20\x6f\x72\x20\x50\x45\x4d\xa");
        BIO_printf(bio_err, "\x20\x2d\x69\x6e\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x6f\x75\x74\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x74\x65\x78\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x70\x72\x69\x6e\x74\x20\x61\x73\x20\x74\x65\x78\x74\xa");
        BIO_printf(bio_err, "\x20\x2d\x43\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x4f\x75\x74\x70\x75\x74\x20\x43\x20\x63\x6f\x64\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x6e\x6f\x6f\x75\x74\x20\x20\x20\x20\x20\x20\x20\x20\x6e\x6f\x20\x6f\x75\x74\x70\x75\x74\xa");
        BIO_printf(bio_err, "\x20\x2d\x67\x65\x6e\x6b\x65\x79\x20\x20\x20\x20\x20\x20\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x20\x61\x20\x44\x53\x41\x20\x6b\x65\x79\xa");
        BIO_printf(bio_err,
                   "\x20\x2d\x72\x61\x6e\x64\x20\x20\x20\x20\x20\x20\x20\x20\x20\x66\x69\x6c\x65\x73\x20\x74\x6f\x20\x75\x73\x65\x20\x66\x6f\x72\x20\x72\x61\x6e\x64\x6f\x6d\x20\x6e\x75\x6d\x62\x65\x72\x20\x69\x6e\x70\x75\x74\xa");
# ifndef OPENSSL_NO_ENGINE
        BIO_printf(bio_err,
                   "\x20\x2d\x65\x6e\x67\x69\x6e\x65\x20\x65\x20\x20\x20\x20\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x65\x2c\x20\x70\x6f\x73\x73\x69\x62\x6c\x79\x20\x61\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20\x64\x65\x76\x69\x63\x65\x2e\xa");
# endif
# ifdef GENCB_TEST
        BIO_printf(bio_err,
                   "\x20\x2d\x74\x69\x6d\x65\x62\x6f\x6d\x62\x20\x6e\x20\x20\x20\x69\x6e\x74\x65\x72\x72\x75\x70\x74\x20\x6b\x65\x79\x67\x65\x6e\x20\x61\x66\x74\x65\x72\x20\x3c\x6e\x3e\x20\x73\x65\x63\x6f\x6e\x64\x73\xa");
# endif
        BIO_printf(bio_err,
                   "\x20\x6e\x75\x6d\x62\x65\x72\x20\x20\x20\x20\x20\x20\x20\x20\x6e\x75\x6d\x62\x65\x72\x20\x6f\x66\x20\x62\x69\x74\x73\x20\x74\x6f\x20\x75\x73\x65\x20\x66\x6f\x72\x20\x67\x65\x6e\x65\x72\x61\x74\x69\x6e\x67\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\xa");
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

    if (need_rand) {
        app_RAND_load_file(NULL, bio_err, (inrand != NULL));
        if (inrand != NULL)
            BIO_printf(bio_err, "\x25\x6c\x64\x20\x73\x65\x6d\x69\x2d\x72\x61\x6e\x64\x6f\x6d\x20\x62\x79\x74\x65\x73\x20\x6c\x6f\x61\x64\x65\x64\xa",
                       app_RAND_load_files(inrand));
    }

    if (numbits > 0) {
        BN_GENCB cb;
        BN_GENCB_set(&cb, dsa_cb, bio_err);
        assert(need_rand);
        dsa = DSA_new();
        if (!dsa) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x61\x6c\x6c\x6f\x63\x61\x74\x69\x6e\x67\x20\x44\x53\x41\x20\x6f\x62\x6a\x65\x63\x74\xa");
            goto end;
        }
        BIO_printf(bio_err, "\x47\x65\x6e\x65\x72\x61\x74\x69\x6e\x67\x20\x44\x53\x41\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x2c\x20\x25\x64\x20\x62\x69\x74\x20\x6c\x6f\x6e\x67\x20\x70\x72\x69\x6d\x65\xa",
                   num);
        BIO_printf(bio_err, "\x54\x68\x69\x73\x20\x63\x6f\x75\x6c\x64\x20\x74\x61\x6b\x65\x20\x73\x6f\x6d\x65\x20\x74\x69\x6d\x65\xa");
# ifdef GENCB_TEST
        if (timebomb > 0) {
            struct sigaction act;
            act.sa_handler = timebomb_sigalarm;
            act.sa_flags = 0;
            BIO_printf(bio_err,
                       "\x28\x74\x68\x6f\x75\x67\x68\x20\x49\x27\x6c\x6c\x20\x73\x74\x6f\x70\x20\x69\x74\x20\x69\x66\x20\x6e\x6f\x74\x20\x64\x6f\x6e\x65\x20\x77\x69\x74\x68\x69\x6e\x20\x25\x64\x20\x73\x65\x63\x73\x29\xa",
                       timebomb);
            if (sigaction(SIGALRM, &act, NULL) != 0) {
                BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x2c\x20\x63\x6f\x75\x6c\x64\x6e\x27\x74\x20\x73\x65\x74\x20\x53\x49\x47\x41\x4c\x52\x4d\x20\x68\x61\x6e\x64\x6c\x65\x72\xa");
                goto end;
            }
            alarm(timebomb);
        }
# endif
        if (!DSA_generate_parameters_ex(dsa, num, NULL, 0, NULL, NULL, &cb)) {
# ifdef GENCB_TEST
            if (stop_keygen_flag) {
                BIO_printf(bio_err, "\x44\x53\x41\x20\x6b\x65\x79\x20\x67\x65\x6e\x65\x72\x61\x74\x69\x6f\x6e\x20\x74\x69\x6d\x65\x2d\x73\x74\x6f\x70\x70\x65\x64\xa");
                /* This is an asked-for behaviour! */
                ret = 0;
                goto end;
            }
# endif
            ERR_print_errors(bio_err);
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x2c\x20\x44\x53\x41\x20\x6b\x65\x79\x20\x67\x65\x6e\x65\x72\x61\x74\x69\x6f\x6e\x20\x66\x61\x69\x6c\x65\x64\xa");
            goto end;
        }
    } else if (informat == FORMAT_ASN1)
        dsa = d2i_DSAparams_bio(in, NULL);
    else if (informat == FORMAT_PEM)
        dsa = PEM_read_bio_DSAparams(in, NULL, NULL, NULL);
    else {
        BIO_printf(bio_err, "\x62\x61\x64\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
        goto end;
    }
    if (dsa == NULL) {
        BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6c\x6f\x61\x64\x20\x44\x53\x41\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\xa");
        ERR_print_errors(bio_err);
        goto end;
    }

    if (text) {
        DSAparams_print(out, dsa);
    }

    if (C) {
        unsigned char *data;
        int l, len, bits_p;

        len = BN_num_bytes(dsa->p);
        bits_p = BN_num_bits(dsa->p);
        data = (unsigned char *)OPENSSL_malloc(len + 20);
        if (data == NULL) {
            perror("\x4f\x50\x45\x4e\x53\x53\x4c\x5f\x6d\x61\x6c\x6c\x6f\x63");
            goto end;
        }
        l = BN_bn2bin(dsa->p, data);
        printf("\x73\x74\x61\x74\x69\x63\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x63\x68\x61\x72\x20\x64\x73\x61\x25\x64\x5f\x70\x5b\x5d\x3d\x7b", bits_p);
        for (i = 0; i < l; i++) {
            if ((i % 12) == 0)
                printf("\xa\x9");
            printf("\x30\x78\x25\x30\x32\x58\x2c", data[i]);
        }
        printf("\xa\x9\x7d\x3b\xa");

        l = BN_bn2bin(dsa->q, data);
        printf("\x73\x74\x61\x74\x69\x63\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x63\x68\x61\x72\x20\x64\x73\x61\x25\x64\x5f\x71\x5b\x5d\x3d\x7b", bits_p);
        for (i = 0; i < l; i++) {
            if ((i % 12) == 0)
                printf("\xa\x9");
            printf("\x30\x78\x25\x30\x32\x58\x2c", data[i]);
        }
        printf("\xa\x9\x7d\x3b\xa");

        l = BN_bn2bin(dsa->g, data);
        printf("\x73\x74\x61\x74\x69\x63\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x63\x68\x61\x72\x20\x64\x73\x61\x25\x64\x5f\x67\x5b\x5d\x3d\x7b", bits_p);
        for (i = 0; i < l; i++) {
            if ((i % 12) == 0)
                printf("\xa\x9");
            printf("\x30\x78\x25\x30\x32\x58\x2c", data[i]);
        }
        printf("\xa\x9\x7d\x3b\xa\xa");

        printf("\x44\x53\x41\x20\x2a\x67\x65\x74\x5f\x64\x73\x61\x25\x64\x28\x29\xa\x9\x7b\xa", bits_p);
        printf("\x9D\x53\x41\x20\x2a\x64\x73\x61\x3b\xa\xa");
        printf("\x9\x69\x66\x20\x28\x28\x64\x73\x61\x3d\x44\x53\x41\x5f\x6e\x65\x77\x28\x29\x29\x20\x3d\x3d\x20\x4e\x55\x4c\x4c\x29\x20\x72\x65\x74\x75\x72\x6e\x28\x4e\x55\x4c\x4c\x29\x3b\xa");
        printf("\x9d\x73\x61\x2d\x3e\x70\x3d\x42\x4e\x5f\x62\x69\x6e\x32\x62\x6e\x28\x64\x73\x61\x25\x64\x5f\x70\x2c\x73\x69\x7a\x65\x6f\x66\x28\x64\x73\x61\x25\x64\x5f\x70\x29\x2c\x4e\x55\x4c\x4c\x29\x3b\xa",
               bits_p, bits_p);
        printf("\x9d\x73\x61\x2d\x3e\x71\x3d\x42\x4e\x5f\x62\x69\x6e\x32\x62\x6e\x28\x64\x73\x61\x25\x64\x5f\x71\x2c\x73\x69\x7a\x65\x6f\x66\x28\x64\x73\x61\x25\x64\x5f\x71\x29\x2c\x4e\x55\x4c\x4c\x29\x3b\xa",
               bits_p, bits_p);
        printf("\x9d\x73\x61\x2d\x3e\x67\x3d\x42\x4e\x5f\x62\x69\x6e\x32\x62\x6e\x28\x64\x73\x61\x25\x64\x5f\x67\x2c\x73\x69\x7a\x65\x6f\x66\x28\x64\x73\x61\x25\x64\x5f\x67\x29\x2c\x4e\x55\x4c\x4c\x29\x3b\xa",
               bits_p, bits_p);
        printf
            ("\x9\x69\x66\x20\x28\x28\x64\x73\x61\x2d\x3e\x70\x20\x3d\x3d\x20\x4e\x55\x4c\x4c\x29\x20\x7c\x7c\x20\x28\x64\x73\x61\x2d\x3e\x71\x20\x3d\x3d\x20\x4e\x55\x4c\x4c\x29\x20\x7c\x7c\x20\x28\x64\x73\x61\x2d\x3e\x67\x20\x3d\x3d\x20\x4e\x55\x4c\x4c\x29\x29\xa");
        printf("\x9\x9\x7b\x20\x44\x53\x41\x5f\x66\x72\x65\x65\x28\x64\x73\x61\x29\x3b\x20\x72\x65\x74\x75\x72\x6e\x28\x4e\x55\x4c\x4c\x29\x3b\x20\x7d\xa");
        printf("\x9\x72\x65\x74\x75\x72\x6e\x28\x64\x73\x61\x29\x3b\xa\x9\x7d\xa");
    }

    if (outformat == FORMAT_ASN1 && genkey)
        noout = 1;

    if (!noout) {
        if (outformat == FORMAT_ASN1)
            i = i2d_DSAparams_bio(out, dsa);
        else if (outformat == FORMAT_PEM)
            i = PEM_write_bio_DSAparams(out, dsa);
        else {
            BIO_printf(bio_err, "\x62\x61\x64\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20\x6f\x75\x74\x66\x69\x6c\x65\xa");
            goto end;
        }
        if (!i) {
            BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x77\x72\x69\x74\x65\x20\x44\x53\x41\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
    }
    if (genkey) {
        DSA *dsakey;

        assert(need_rand);
        if ((dsakey = DSAparams_dup(dsa)) == NULL)
            goto end;
        if (!DSA_generate_key(dsakey)) {
            ERR_print_errors(bio_err);
            DSA_free(dsakey);
            goto end;
        }
        if (outformat == FORMAT_ASN1)
            i = i2d_DSAPrivateKey_bio(out, dsakey);
        else if (outformat == FORMAT_PEM)
            i = PEM_write_bio_DSAPrivateKey(out, dsakey, NULL, NULL, 0, NULL,
                                            NULL);
        else {
            BIO_printf(bio_err, "\x62\x61\x64\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20\x6f\x75\x74\x66\x69\x6c\x65\xa");
            DSA_free(dsakey);
            goto end;
        }
        DSA_free(dsakey);
    }
    if (need_rand)
        app_RAND_write_file(NULL, bio_err);
    ret = 0;
 end:
    if (in != NULL)
        BIO_free(in);
    if (out != NULL)
        BIO_free_all(out);
    if (dsa != NULL)
        DSA_free(dsa);
    release_engine(e);
    apps_shutdown();
    OPENSSL_EXIT(ret);
}

static int MS_CALLBACK dsa_cb(int p, int n, BN_GENCB *cb)
{
    char c = '\x2a';

    if (p == 0)
        c = '\x2e';
    if (p == 1)
        c = '\x2b';
    if (p == 2)
        c = '\x2a';
    if (p == 3)
        c = '\xa';
    BIO_write(cb->arg, &c, 1);
    (void)BIO_flush(cb->arg);
# ifdef LINT
    p = n;
# endif
# ifdef GENCB_TEST
    if (stop_keygen_flag)
        return 0;
# endif
    return 1;
}
#else                           /* !OPENSSL_NO_DSA */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif

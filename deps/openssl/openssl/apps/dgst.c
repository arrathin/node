/* apps/dgst.c */
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>

#undef BUFSIZE
#define BUFSIZE 1024*8

#undef PROG
#define PROG    dgst_main

int do_fp(BIO *out, unsigned char *buf, BIO *bp, int sep, int binout,
          EVP_PKEY *key, unsigned char *sigin, int siglen,
          const char *sig_name, const char *md_name,
          const char *file, BIO *bmd);

static void list_md_fn(const EVP_MD *m,
                       const char *from, const char *to, void *arg)
{
    const char *mname;
    /* Skip aliases */
    if (!m)
        return;
    mname = OBJ_nid2ln(EVP_MD_type(m));
    /* Skip shortnames */
    if (strcmp(from, mname))
        return;
    /* Skip clones */
    if (EVP_MD_flags(m) & EVP_MD_FLAG_PKEY_DIGEST)
        return;
    if (strchr(mname, '\x20'))
        mname = EVP_MD_name(m);
    BIO_printf(arg, "\x2d\x25\x2d\x31\x34\x73\x20\x74\x6f\x20\x75\x73\x65\x20\x74\x68\x65\x20\x25\x73\x20\x6d\x65\x73\x73\x61\x67\x65\x20\x64\x69\x67\x65\x73\x74\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\xa",
               mname, mname);
}

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    ENGINE *e = NULL, *impl = NULL;
    unsigned char *buf = NULL;
    int i, err = 1;
    const EVP_MD *md = NULL, *m;
    BIO *in = NULL, *inp;
    BIO *bmd = NULL;
    BIO *out = NULL;
#define PROG_NAME_SIZE  39
    char pname[PROG_NAME_SIZE + 1];
    int separator = 0;
    int debug = 0;
    int keyform = FORMAT_PEM;
    const char *outfile = NULL, *keyfile = NULL;
    const char *sigfile = NULL, *randfile = NULL;
    int out_bin = -1, want_pub = 0, do_verify = 0;
    EVP_PKEY *sigkey = NULL;
    unsigned char *sigbuf = NULL;
    int siglen = 0;
    char *passargin = NULL, *passin = NULL;
#ifndef OPENSSL_NO_ENGINE
    char *engine = NULL;
    int engine_impl = 0;
#endif
    char *hmac_key = NULL;
    char *mac_name = NULL;
    int non_fips_allow = 0;
    STACK_OF(OPENSSL_STRING) *sigopts = NULL, *macopts = NULL;

    apps_startup();

    if ((buf = (unsigned char *)OPENSSL_malloc(BUFSIZE)) == NULL) {
        BIO_printf(bio_err, "\x6f\x75\x74\x20\x6f\x66\x20\x6d\x65\x6d\x6f\x72\x79\xa");
        goto end;
    }
    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (!load_config(bio_err, NULL))
        goto end;

    /* first check the program name */
    program_name(argv[0], pname, sizeof(pname));

    md = EVP_get_digestbyname(pname);

    argc--;
    argv++;
    while (argc > 0) {
        if ((*argv)[0] != '\x2d')
            break;
        if (strcmp(*argv, "\x2d\x63") == 0)
            separator = 1;
        else if (strcmp(*argv, "\x2d\x72") == 0)
            separator = 2;
        else if (strcmp(*argv, "\x2d\x72\x61\x6e\x64") == 0) {
            if (--argc < 1)
                break;
            randfile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6f\x75\x74") == 0) {
            if (--argc < 1)
                break;
            outfile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x73\x69\x67\x6e") == 0) {
            if (--argc < 1)
                break;
            keyfile = *(++argv);
        } else if (!strcmp(*argv, "\x2d\x70\x61\x73\x73\x69\x6e")) {
            if (--argc < 1)
                break;
            passargin = *++argv;
        } else if (strcmp(*argv, "\x2d\x76\x65\x72\x69\x66\x79") == 0) {
            if (--argc < 1)
                break;
            keyfile = *(++argv);
            want_pub = 1;
            do_verify = 1;
        } else if (strcmp(*argv, "\x2d\x70\x72\x76\x65\x72\x69\x66\x79") == 0) {
            if (--argc < 1)
                break;
            keyfile = *(++argv);
            do_verify = 1;
        } else if (strcmp(*argv, "\x2d\x73\x69\x67\x6e\x61\x74\x75\x72\x65") == 0) {
            if (--argc < 1)
                break;
            sigfile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6b\x65\x79\x66\x6f\x72\x6d") == 0) {
            if (--argc < 1)
                break;
            keyform = str2fmt(*(++argv));
        }
#ifndef OPENSSL_NO_ENGINE
        else if (strcmp(*argv, "\x2d\x65\x6e\x67\x69\x6e\x65") == 0) {
            if (--argc < 1)
                break;
            engine = *(++argv);
            e = setup_engine(bio_err, engine, 0);
        } else if (strcmp(*argv, "\x2d\x65\x6e\x67\x69\x6e\x65\x5f\x69\x6d\x70\x6c") == 0)
            engine_impl = 1;
#endif
        else if (strcmp(*argv, "\x2d\x68\x65\x78") == 0)
            out_bin = 0;
        else if (strcmp(*argv, "\x2d\x62\x69\x6e\x61\x72\x79") == 0)
            out_bin = 1;
        else if (strcmp(*argv, "\x2d\x64") == 0)
            debug = 1;
        else if (!strcmp(*argv, "\x2d\x66\x69\x70\x73\x2d\x66\x69\x6e\x67\x65\x72\x70\x72\x69\x6e\x74"))
            hmac_key = "\x65\x74\x61\x6f\x6e\x72\x69\x73\x68\x64\x6c\x63\x75\x70\x66\x6d";
        else if (strcmp(*argv, "\x2d\x6e\x6f\x6e\x2d\x66\x69\x70\x73\x2d\x61\x6c\x6c\x6f\x77") == 0)
            non_fips_allow = 1;
        else if (!strcmp(*argv, "\x2d\x68\x6d\x61\x63")) {
            if (--argc < 1)
                break;
            hmac_key = *++argv;
        } else if (!strcmp(*argv, "\x2d\x6d\x61\x63")) {
            if (--argc < 1)
                break;
            mac_name = *++argv;
        } else if (strcmp(*argv, "\x2d\x73\x69\x67\x6f\x70\x74") == 0) {
            if (--argc < 1)
                break;
            if (!sigopts)
                sigopts = sk_OPENSSL_STRING_new_null();
            if (!sigopts || !sk_OPENSSL_STRING_push(sigopts, *(++argv)))
                break;
        } else if (strcmp(*argv, "\x2d\x6d\x61\x63\x6f\x70\x74") == 0) {
            if (--argc < 1)
                break;
            if (!macopts)
                macopts = sk_OPENSSL_STRING_new_null();
            if (!macopts || !sk_OPENSSL_STRING_push(macopts, *(++argv)))
                break;
        } else if ((m = EVP_get_digestbyname(&((*argv)[1]))) != NULL)
            md = m;
        else
            break;
        argc--;
        argv++;
    }

    if (keyfile != NULL && argc > 1) {
        BIO_printf(bio_err, "\x43\x61\x6e\x20\x6f\x6e\x6c\x79\x20\x73\x69\x67\x6e\x20\x6f\x72\x20\x76\x65\x72\x69\x66\x79\x20\x6f\x6e\x65\x20\x66\x69\x6c\x65\xa");
        goto end;
    }

    if (do_verify && !sigfile) {
        BIO_printf(bio_err,
                   "\x4e\x6f\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x74\x6f\x20\x76\x65\x72\x69\x66\x79\x3a\x20\x75\x73\x65\x20\x74\x68\x65\x20\x2d\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x6f\x70\x74\x69\x6f\x6e\xa");
        goto end;
    }

    if ((argc > 0) && (argv[0][0] == '\x2d')) { /* bad option */
        BIO_printf(bio_err, "\x75\x6e\x6b\x6e\x6f\x77\x6e\x20\x6f\x70\x74\x69\x6f\x6e\x20\x27\x25\x73\x27\xa", *argv);
        BIO_printf(bio_err, "\x6f\x70\x74\x69\x6f\x6e\x73\x20\x61\x72\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x63\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x74\x6f\x20\x6f\x75\x74\x70\x75\x74\x20\x74\x68\x65\x20\x64\x69\x67\x65\x73\x74\x20\x77\x69\x74\x68\x20\x73\x65\x70\x61\x72\x61\x74\x69\x6e\x67\x20\x63\x6f\x6c\x6f\x6e\x73\xa");
        BIO_printf(bio_err,
                   "\x2d\x72\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x74\x6f\x20\x6f\x75\x74\x70\x75\x74\x20\x74\x68\x65\x20\x64\x69\x67\x65\x73\x74\x20\x69\x6e\x20\x63\x6f\x72\x65\x75\x74\x69\x6c\x73\x20\x66\x6f\x72\x6d\x61\x74\xa");
        BIO_printf(bio_err, "\x2d\x64\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x74\x6f\x20\x6f\x75\x74\x70\x75\x74\x20\x64\x65\x62\x75\x67\x20\x69\x6e\x66\x6f\xa");
        BIO_printf(bio_err, "\x2d\x68\x65\x78\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x61\x73\x20\x68\x65\x78\x20\x64\x75\x6d\x70\xa");
        BIO_printf(bio_err, "\x2d\x62\x69\x6e\x61\x72\x79\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x69\x6e\x20\x62\x69\x6e\x61\x72\x79\x20\x66\x6f\x72\x6d\xa");
        BIO_printf(bio_err, "\x2d\x68\x6d\x61\x63\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x73\x65\x74\x20\x74\x68\x65\x20\x48\x4d\x41\x43\x20\x6b\x65\x79\x20\x74\x6f\x20\x61\x72\x67\xa");
        BIO_printf(bio_err, "\x2d\x6e\x6f\x6e\x2d\x66\x69\x70\x73\x2d\x61\x6c\x6c\x6f\x77\x20\x61\x6c\x6c\x6f\x77\x20\x75\x73\x65\x20\x6f\x66\x20\x6e\x6f\x6e\x20\x46\x49\x50\x53\x20\x64\x69\x67\x65\x73\x74\xa");
        BIO_printf(bio_err,
                   "\x2d\x73\x69\x67\x6e\x20\x20\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x73\x69\x67\x6e\x20\x64\x69\x67\x65\x73\x74\x20\x75\x73\x69\x6e\x67\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x69\x6e\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x76\x65\x72\x69\x66\x79\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x76\x65\x72\x69\x66\x79\x20\x61\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x75\x73\x69\x6e\x67\x20\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\x20\x69\x6e\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x70\x72\x76\x65\x72\x69\x66\x79\x20\x66\x69\x6c\x65\x20\x20\x76\x65\x72\x69\x66\x79\x20\x61\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x75\x73\x69\x6e\x67\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x69\x6e\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x6b\x65\x79\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x20\x6b\x65\x79\x20\x66\x69\x6c\x65\x20\x66\x6f\x72\x6d\x61\x74\x20\x28\x50\x45\x4d\x20\x6f\x72\x20\x45\x4e\x47\x49\x4e\x45\x29\xa");
        BIO_printf(bio_err,
                   "\x2d\x6f\x75\x74\x20\x66\x69\x6c\x65\x6e\x61\x6d\x65\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x74\x6f\x20\x66\x69\x6c\x65\x6e\x61\x6d\x65\x20\x72\x61\x74\x68\x65\x72\x20\x74\x68\x61\x6e\x20\x73\x74\x64\x6f\x75\x74\xa");
        BIO_printf(bio_err, "\x2d\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x66\x69\x6c\x65\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x74\x6f\x20\x76\x65\x72\x69\x66\x79\xa");
        BIO_printf(bio_err, "\x2d\x73\x69\x67\x6f\x70\x74\x20\x6e\x6d\x3a\x76\x20\x20\x20\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\xa");
        BIO_printf(bio_err, "\x2d\x68\x6d\x61\x63\x20\x6b\x65\x79\x20\x20\x20\x20\x20\x20\x20\x63\x72\x65\x61\x74\x65\x20\x68\x61\x73\x68\x65\x64\x20\x4d\x41\x43\x20\x77\x69\x74\x68\x20\x6b\x65\x79\xa");
        BIO_printf(bio_err,
                   "\x2d\x6d\x61\x63\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x20\x20\x63\x72\x65\x61\x74\x65\x20\x4d\x41\x43\x20\x28\x6e\x6f\x74\x20\x6e\x65\x63\x63\x65\x73\x73\x61\x72\x69\x6c\x79\x20\x48\x4d\x41\x43\x29\xa");
        BIO_printf(bio_err,
                   "\x2d\x6d\x61\x63\x6f\x70\x74\x20\x6e\x6d\x3a\x76\x20\x20\x20\x20\x4d\x41\x43\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\x20\x6f\x72\x20\x6b\x65\x79\xa");
#ifndef OPENSSL_NO_ENGINE
        BIO_printf(bio_err,
                   "\x2d\x65\x6e\x67\x69\x6e\x65\x20\x65\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x65\x2c\x20\x70\x6f\x73\x73\x69\x62\x6c\x79\x20\x61\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20\x64\x65\x76\x69\x63\x65\x2e\xa");
#endif

        EVP_MD_do_all_sorted(list_md_fn, bio_err);
        goto end;
    }
#ifndef OPENSSL_NO_ENGINE
    if (engine_impl)
        impl = e;
#endif

    in = BIO_new(BIO_s_file());
    bmd = BIO_new(BIO_f_md());
    if ((in == NULL) || (bmd == NULL)) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (debug) {
        BIO_set_callback(in, BIO_debug_callback);
        /* needed for windows 3.1 */
        BIO_set_callback_arg(in, (char *)bio_err);
    }

    if (!app_passwd(bio_err, passargin, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\xa");
        goto end;
    }

    if (out_bin == -1) {
        if (keyfile)
            out_bin = 1;
        else
            out_bin = 0;
    }

    if (randfile)
        app_RAND_load_file(randfile, bio_err, 0);

    if (outfile) {
        if (out_bin)
            out = BIO_new_file(outfile, "\x77\x62");
        else
            out = BIO_new_file(outfile, "\x77");
    } else {
        out = BIO_new_fp(stdout, BIO_NOCLOSE);
#ifdef OPENSSL_SYS_VMS
        {
            BIO *tmpbio = BIO_new(BIO_f_linebuffer());
            out = BIO_push(tmpbio, out);
        }
#endif
    }

    if (!out) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x6f\x70\x65\x6e\x69\x6e\x67\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x25\x73\xa",
                   outfile ? outfile : "\x28\x73\x74\x64\x6f\x75\x74\x29");
        ERR_print_errors(bio_err);
        goto end;
    }
    if ((! !mac_name + ! !keyfile + ! !hmac_key) > 1) {
        BIO_printf(bio_err, "\x4d\x41\x43\x20\x61\x6e\x64\x20\x53\x69\x67\x6e\x69\x6e\x67\x20\x6b\x65\x79\x20\x63\x61\x6e\x6e\x6f\x74\x20\x62\x6f\x74\x68\x20\x62\x65\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
        goto end;
    }

    if (keyfile) {
        if (want_pub)
            sigkey = load_pubkey(bio_err, keyfile, keyform, 0, NULL,
                                 e, "\x6b\x65\x79\x20\x66\x69\x6c\x65");
        else
            sigkey = load_key(bio_err, keyfile, keyform, 0, passin,
                              e, "\x6b\x65\x79\x20\x66\x69\x6c\x65");
        if (!sigkey) {
            /*
             * load_[pub]key() has already printed an appropriate message
             */
            goto end;
        }
    }

    if (mac_name) {
        EVP_PKEY_CTX *mac_ctx = NULL;
        int r = 0;
        if (!init_gen_str(bio_err, &mac_ctx, mac_name, impl, 0))
            goto mac_end;
        if (macopts) {
            char *macopt;
            for (i = 0; i < sk_OPENSSL_STRING_num(macopts); i++) {
                macopt = sk_OPENSSL_STRING_value(macopts, i);
                if (pkey_ctrl_string(mac_ctx, macopt) <= 0) {
                    BIO_printf(bio_err,
                               "\x4d\x41\x43\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x20\x65\x72\x72\x6f\x72\x20\x22\x25\x73\x22\xa", macopt);
                    ERR_print_errors(bio_err);
                    goto mac_end;
                }
            }
        }
        if (EVP_PKEY_keygen(mac_ctx, &sigkey) <= 0) {
            BIO_puts(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x6e\x65\x72\x61\x74\x69\x6e\x67\x20\x6b\x65\x79\xa");
            ERR_print_errors(bio_err);
            goto mac_end;
        }
        r = 1;
 mac_end:
        if (mac_ctx)
            EVP_PKEY_CTX_free(mac_ctx);
        if (r == 0)
            goto end;
    }

    if (non_fips_allow) {
        EVP_MD_CTX *md_ctx;
        BIO_get_md_ctx(bmd, &md_ctx);
        EVP_MD_CTX_set_flags(md_ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
    }

    if (hmac_key) {
        sigkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, impl,
                                      (unsigned char *)hmac_key, -1);
        if (!sigkey)
            goto end;
    }

    if (sigkey) {
        EVP_MD_CTX *mctx = NULL;
        EVP_PKEY_CTX *pctx = NULL;
        int r;
        if (!BIO_get_md_ctx(bmd, &mctx)) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x63\x6f\x6e\x74\x65\x78\x74\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
        if (do_verify)
            r = EVP_DigestVerifyInit(mctx, &pctx, md, impl, sigkey);
        else
            r = EVP_DigestSignInit(mctx, &pctx, md, impl, sigkey);
        if (!r) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x73\x65\x74\x74\x69\x6e\x67\x20\x63\x6f\x6e\x74\x65\x78\x74\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
        if (sigopts) {
            char *sigopt;
            for (i = 0; i < sk_OPENSSL_STRING_num(sigopts); i++) {
                sigopt = sk_OPENSSL_STRING_value(sigopts, i);
                if (pkey_ctrl_string(pctx, sigopt) <= 0) {
                    BIO_printf(bio_err, "\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x20\x65\x72\x72\x6f\x72\x20\x22\x25\x73\x22\xa", sigopt);
                    ERR_print_errors(bio_err);
                    goto end;
                }
            }
        }
    }
    /* we use md as a filter, reading from 'in' */
    else {
        EVP_MD_CTX *mctx = NULL;
        if (!BIO_get_md_ctx(bmd, &mctx)) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x63\x6f\x6e\x74\x65\x78\x74\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
        if (md == NULL)
            md = EVP_md5();
        if (!EVP_DigestInit_ex(mctx, md, impl)) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x73\x65\x74\x74\x69\x6e\x67\x20\x64\x69\x67\x65\x73\x74\x20\x25\x73\xa", pname);
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if (sigfile && sigkey) {
        BIO *sigbio;
        sigbio = BIO_new_file(sigfile, "\x72\x62");
        siglen = EVP_PKEY_size(sigkey);
        sigbuf = OPENSSL_malloc(siglen);
        if (!sigbio) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x6f\x70\x65\x6e\x69\x6e\x67\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x66\x69\x6c\x65\x20\x25\x73\xa", sigfile);
            ERR_print_errors(bio_err);
            goto end;
        }
        if (!sigbuf) {
            BIO_printf(bio_err, "\x4f\x75\x74\x20\x6f\x66\x20\x6d\x65\x6d\x6f\x72\x79\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
        siglen = BIO_read(sigbio, sigbuf, siglen);
        BIO_free(sigbio);
        if (siglen <= 0) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x72\x65\x61\x64\x69\x6e\x67\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x66\x69\x6c\x65\x20\x25\x73\xa", sigfile);
            ERR_print_errors(bio_err);
            goto end;
        }
    }
    inp = BIO_push(bmd, in);

    if (md == NULL) {
        EVP_MD_CTX *tctx;
        BIO_get_md_ctx(bmd, &tctx);
        md = EVP_MD_CTX_md(tctx);
    }

    if (argc == 0) {
        BIO_set_fp(in, stdin, BIO_NOCLOSE);
        err = do_fp(out, buf, inp, separator, out_bin, sigkey, sigbuf,
                    siglen, NULL, NULL, "\x73\x74\x64\x69\x6e", bmd);
    } else {
        const char *md_name = NULL, *sig_name = NULL;
        if (!out_bin) {
            if (sigkey) {
                const EVP_PKEY_ASN1_METHOD *ameth;
                ameth = EVP_PKEY_get0_asn1(sigkey);
                if (ameth)
                    EVP_PKEY_asn1_get0_info(NULL, NULL,
                                            NULL, NULL, &sig_name, ameth);
            }
            if (md)
                md_name = EVP_MD_name(md);
        }
        err = 0;
        for (i = 0; i < argc; i++) {
            int r;
            if (BIO_read_filename(in, argv[i]) <= 0) {
                perror(argv[i]);
                err++;
                continue;
            } else
                r = do_fp(out, buf, inp, separator, out_bin, sigkey, sigbuf,
                          siglen, sig_name, md_name, argv[i], bmd);
            if (r)
                err = r;
            (void)BIO_reset(bmd);
        }
    }
 end:
    if (buf != NULL) {
        OPENSSL_cleanse(buf, BUFSIZE);
        OPENSSL_free(buf);
    }
    if (in != NULL)
        BIO_free(in);
    if (passin)
        OPENSSL_free(passin);
    BIO_free_all(out);
    EVP_PKEY_free(sigkey);
    if (sigopts)
        sk_OPENSSL_STRING_free(sigopts);
    if (macopts)
        sk_OPENSSL_STRING_free(macopts);
    if (sigbuf)
        OPENSSL_free(sigbuf);
    if (bmd != NULL)
        BIO_free(bmd);
    release_engine(e);
    apps_shutdown();
    OPENSSL_EXIT(err);
}

int do_fp(BIO *out, unsigned char *buf, BIO *bp, int sep, int binout,
          EVP_PKEY *key, unsigned char *sigin, int siglen,
          const char *sig_name, const char *md_name,
          const char *file, BIO *bmd)
{
    size_t len;
    int i;

    for (;;) {
        i = BIO_read(bp, (char *)buf, BUFSIZE);
        if (i < 0) {
            BIO_printf(bio_err, "\x52\x65\x61\x64\x20\x45\x72\x72\x6f\x72\x20\x69\x6e\x20\x25\x73\xa", file);
            ERR_print_errors(bio_err);
            return 1;
        }
        if (i == 0)
            break;
    }
    if (sigin) {
        EVP_MD_CTX *ctx;
        BIO_get_md_ctx(bp, &ctx);
        i = EVP_DigestVerifyFinal(ctx, sigin, (unsigned int)siglen);
        if (i > 0)
            BIO_printf(out, "\x56\x65\x72\x69\x66\x69\x65\x64\x20\x4f\x4b\xa");
        else if (i == 0) {
            BIO_printf(out, "\x56\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x20\x46\x61\x69\x6c\x75\x72\x65\xa");
            return 1;
        } else {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x56\x65\x72\x69\x66\x79\x69\x6e\x67\x20\x44\x61\x74\x61\xa");
            ERR_print_errors(bio_err);
            return 1;
        }
        return 0;
    }
    if (key) {
        EVP_MD_CTX *ctx;
        BIO_get_md_ctx(bp, &ctx);
        len = BUFSIZE;
        if (!EVP_DigestSignFinal(ctx, buf, &len)) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x53\x69\x67\x6e\x69\x6e\x67\x20\x44\x61\x74\x61\xa");
            ERR_print_errors(bio_err);
            return 1;
        }
    } else {
        len = BIO_gets(bp, (char *)buf, BUFSIZE);
        if ((int)len < 0) {
            ERR_print_errors(bio_err);
            return 1;
        }
    }

    if (binout)
        BIO_write(out, buf, len);
    else if (sep == 2) {
        for (i = 0; i < (int)len; i++)
            BIO_printf(out, "\x25\x30\x32\x78", buf[i]);
        BIO_printf(out, "\x20\x2a\x25\x73\xa", file);
    } else {
        if (sig_name) {
            BIO_puts(out, sig_name);
            if (md_name)
                BIO_printf(out, "\x2d\x25\x73", md_name);
            BIO_printf(out, "\x28\x25\x73\x29\x3d\x20", file);
        } else if (md_name)
            BIO_printf(out, "\x25\x73\x28\x25\x73\x29\x3d\x20", md_name, file);
        else
            BIO_printf(out, "\x28\x25\x73\x29\x3d\x20", file);
        for (i = 0; i < (int)len; i++) {
            if (sep && (i != 0))
                BIO_printf(out, "\x3a");
            BIO_printf(out, "\x25\x30\x32\x78", buf[i]);
        }
        BIO_printf(out, "\xa");
    }
    return 0;
}

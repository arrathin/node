/* apps/enc.c */
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
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#ifndef OPENSSL_NO_COMP
# include <openssl/comp.h>
#endif
#include <ctype.h>

int set_hex(char *in, unsigned char *out, int size);
#undef SIZE
#undef BSIZE
#undef PROG

#define SIZE    (512)
#define BSIZE   (8*1024)
#define PROG    enc_main

struct doall_enc_ciphers {
    BIO *bio;
    int n;
};

static void show_ciphers(const OBJ_NAME *name, void *arg)
{
    struct doall_enc_ciphers *dec = (struct doall_enc_ciphers *)arg;
    const EVP_CIPHER *cipher;

    if (!islower((unsigned char)*name->name))
        return;

    /* Filter out ciphers that we cannot use */
    cipher = EVP_get_cipherbyname(name->name);
    if (cipher == NULL ||
            (EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) != 0 ||
            EVP_CIPHER_mode(cipher) == EVP_CIPH_XTS_MODE)
        return;

    BIO_printf(dec->bio, "\x2d\x25\x2d\x32\x35\x73", name->name);
    if (++dec->n == 3) {
        BIO_printf(dec->bio, "\xa");
        dec->n = 0;
    } else
        BIO_printf(dec->bio, "\x20");
}

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    static const char magic[] = "\x53\x61\x6c\x74\x65\x64\x5f\x5f";
    char mbuf[sizeof(magic) - 1];
    char *strbuf = NULL;
    unsigned char *buff = NULL, *bufsize = NULL;
    int bsize = BSIZE, verbose = 0;
    int ret = 1, inl;
    int nopad = 0;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    unsigned char salt[PKCS5_SALT_LEN];
    char *str = NULL, *passarg = NULL, *pass = NULL;
    char *hkey = NULL, *hiv = NULL, *hsalt = NULL;
    char *md = NULL;
    int enc = 1, printkey = 0, i, base64 = 0;
#ifdef ZLIB
    int do_zlib = 0;
    BIO *bzl = NULL;
#endif
    int debug = 0, olb64 = 0, nosalt = 0;
    const EVP_CIPHER *cipher = NULL, *c;
    EVP_CIPHER_CTX *ctx = NULL;
    char *inf = NULL, *outf = NULL;
    BIO *in = NULL, *out = NULL, *b64 = NULL, *benc = NULL, *rbio =
        NULL, *wbio = NULL;
#define PROG_NAME_SIZE  39
    char pname[PROG_NAME_SIZE + 1];
    char *engine = NULL;
    ENGINE *e = NULL;
    const EVP_MD *dgst = NULL;
    int non_fips_allow = 0;
    struct doall_enc_ciphers dec;

    apps_startup();

    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (!load_config(bio_err, NULL))
        goto end;

    /* first check the program name */
    program_name(argv[0], pname, sizeof(pname));
    if (strcmp(pname, "\x62\x61\x73\x65\x36\x34") == 0)
        base64 = 1;
#ifdef ZLIB
    if (strcmp(pname, "\x7a\x6c\x69\x62") == 0)
        do_zlib = 1;
#endif

    cipher = EVP_get_cipherbyname(pname);
#ifdef ZLIB
    if (!do_zlib && !base64 && (cipher == NULL)
        && (strcmp(pname, "\x65\x6e\x63") != 0))
#else
    if (!base64 && (cipher == NULL) && (strcmp(pname, "\x65\x6e\x63") != 0))
#endif
    {
        BIO_printf(bio_err, "\x25\x73\x20\x69\x73\x20\x61\x6e\x20\x75\x6e\x6b\x6e\x6f\x77\x6e\x20\x63\x69\x70\x68\x65\x72\xa", pname);
        goto bad;
    }

    argc--;
    argv++;
    while (argc >= 1) {
        if (strcmp(*argv, "\x2d\x65") == 0)
            enc = 1;
        else if (strcmp(*argv, "\x2d\x69\x6e") == 0) {
            if (--argc < 1)
                goto bad;
            inf = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6f\x75\x74") == 0) {
            if (--argc < 1)
                goto bad;
            outf = *(++argv);
        } else if (strcmp(*argv, "\x2d\x70\x61\x73\x73") == 0) {
            if (--argc < 1)
                goto bad;
            passarg = *(++argv);
        }
#ifndef OPENSSL_NO_ENGINE
        else if (strcmp(*argv, "\x2d\x65\x6e\x67\x69\x6e\x65") == 0) {
            if (--argc < 1)
                goto bad;
            engine = *(++argv);
        }
#endif
        else if (strcmp(*argv, "\x2d\x64") == 0)
            enc = 0;
        else if (strcmp(*argv, "\x2d\x70") == 0)
            printkey = 1;
        else if (strcmp(*argv, "\x2d\x76") == 0)
            verbose = 1;
        else if (strcmp(*argv, "\x2d\x6e\x6f\x70\x61\x64") == 0)
            nopad = 1;
        else if (strcmp(*argv, "\x2d\x73\x61\x6c\x74") == 0)
            nosalt = 0;
        else if (strcmp(*argv, "\x2d\x6e\x6f\x73\x61\x6c\x74") == 0)
            nosalt = 1;
        else if (strcmp(*argv, "\x2d\x64\x65\x62\x75\x67") == 0)
            debug = 1;
        else if (strcmp(*argv, "\x2d\x50") == 0)
            printkey = 2;
        else if (strcmp(*argv, "\x2d\x41") == 0)
            olb64 = 1;
        else if (strcmp(*argv, "\x2d\x61") == 0)
            base64 = 1;
        else if (strcmp(*argv, "\x2d\x62\x61\x73\x65\x36\x34") == 0)
            base64 = 1;
#ifdef ZLIB
        else if (strcmp(*argv, "\x2d\x7a") == 0)
            do_zlib = 1;
#endif
        else if (strcmp(*argv, "\x2d\x62\x75\x66\x73\x69\x7a\x65") == 0) {
            if (--argc < 1)
                goto bad;
            bufsize = (unsigned char *)*(++argv);
        } else if (strcmp(*argv, "\x2d\x6b") == 0) {
            if (--argc < 1)
                goto bad;
            str = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6b\x66\x69\x6c\x65") == 0) {
            static char buf[128];
            FILE *infile;
            char *file;

            if (--argc < 1)
                goto bad;
            file = *(++argv);
            infile = fopen(file, "\x72");
            if (infile == NULL) {
                BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x72\x65\x61\x64\x20\x6b\x65\x79\x20\x66\x72\x6f\x6d\x20\x27\x25\x73\x27\xa", file);
                goto bad;
            }
            buf[0] = '\0';
            if (!fgets(buf, sizeof(buf), infile)) {
                BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x72\x65\x61\x64\x20\x6b\x65\x79\x20\x66\x72\x6f\x6d\x20\x27\x25\x73\x27\xa", file);
                goto bad;
            }
            fclose(infile);
            i = strlen(buf);
            if ((i > 0) && ((buf[i - 1] == '\xa') || (buf[i - 1] == '\xd')))
                buf[--i] = '\x0';
            if ((i > 0) && ((buf[i - 1] == '\xa') || (buf[i - 1] == '\xd')))
                buf[--i] = '\x0';
            if (i < 1) {
                BIO_printf(bio_err, "\x7a\x65\x72\x6f\x20\x6c\x65\x6e\x67\x74\x68\x20\x70\x61\x73\x73\x77\x6f\x72\x64\xa");
                goto bad;
            }
            str = buf;
        } else if (strcmp(*argv, "\x2d\x4b") == 0) {
            if (--argc < 1)
                goto bad;
            hkey = *(++argv);
        } else if (strcmp(*argv, "\x2d\x53") == 0) {
            if (--argc < 1)
                goto bad;
            hsalt = *(++argv);
        } else if (strcmp(*argv, "\x2d\x69\x76") == 0) {
            if (--argc < 1)
                goto bad;
            hiv = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6d\x64") == 0) {
            if (--argc < 1)
                goto bad;
            md = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6e\x6f\x6e\x2d\x66\x69\x70\x73\x2d\x61\x6c\x6c\x6f\x77") == 0)
            non_fips_allow = 1;
        else if ((argv[0][0] == '\x2d') &&
                 ((c = EVP_get_cipherbyname(&(argv[0][1]))) != NULL)) {
            cipher = c;
        } else if (strcmp(*argv, "\x2d\x6e\x6f\x6e\x65") == 0)
            cipher = NULL;
        else {
            BIO_printf(bio_err, "\x75\x6e\x6b\x6e\x6f\x77\x6e\x20\x6f\x70\x74\x69\x6f\x6e\x20\x27\x25\x73\x27\xa", *argv);
 bad:
            BIO_printf(bio_err, "\x6f\x70\x74\x69\x6f\x6e\x73\x20\x61\x72\x65\xa");
            BIO_printf(bio_err, "\x25\x2d\x31\x34\x73\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\xa", "\x2d\x69\x6e\x20\x3c\x66\x69\x6c\x65\x3e");
            BIO_printf(bio_err, "\x25\x2d\x31\x34\x73\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\xa", "\x2d\x6f\x75\x74\x20\x3c\x66\x69\x6c\x65\x3e");
            BIO_printf(bio_err, "\x25\x2d\x31\x34\x73\x20\x70\x61\x73\x73\x20\x70\x68\x72\x61\x73\x65\x20\x73\x6f\x75\x72\x63\x65\xa", "\x2d\x70\x61\x73\x73\x20\x3c\x61\x72\x67\x3e");
            BIO_printf(bio_err, "\x25\x2d\x31\x34\x73\x20\x65\x6e\x63\x72\x79\x70\x74\xa", "\x2d\x65");
            BIO_printf(bio_err, "\x25\x2d\x31\x34\x73\x20\x64\x65\x63\x72\x79\x70\x74\xa", "\x2d\x64");
            BIO_printf(bio_err,
                       "\x25\x2d\x31\x34\x73\x20\x62\x61\x73\x65\x36\x34\x20\x65\x6e\x63\x6f\x64\x65\x2f\x64\x65\x63\x6f\x64\x65\x2c\x20\x64\x65\x70\x65\x6e\x64\x69\x6e\x67\x20\x6f\x6e\x20\x65\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e\x20\x66\x6c\x61\x67\xa",
                       "\x2d\x61\x2f\x2d\x62\x61\x73\x65\x36\x34");
            BIO_printf(bio_err, "\x25\x2d\x31\x34\x73\x20\x70\x61\x73\x73\x70\x68\x72\x61\x73\x65\x20\x69\x73\x20\x74\x68\x65\x20\x6e\x65\x78\x74\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\xa",
                       "\x2d\x6b");
            BIO_printf(bio_err,
                       "\x25\x2d\x31\x34\x73\x20\x70\x61\x73\x73\x70\x68\x72\x61\x73\x65\x20\x69\x73\x20\x74\x68\x65\x20\x66\x69\x72\x73\x74\x20\x6c\x69\x6e\x65\x20\x6f\x66\x20\x74\x68\x65\x20\x66\x69\x6c\x65\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\xa",
                       "\x2d\x6b\x66\x69\x6c\x65");
            BIO_printf(bio_err,
                       "\x25\x2d\x31\x34\x73\x20\x74\x68\x65\x20\x6e\x65\x78\x74\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\x20\x69\x73\x20\x74\x68\x65\x20\x6d\x64\x20\x74\x6f\x20\x75\x73\x65\x20\x74\x6f\x20\x63\x72\x65\x61\x74\x65\x20\x61\x20\x6b\x65\x79\xa",
                       "\x2d\x6d\x64");
            BIO_printf(bio_err,
                       "\x25\x2d\x31\x34\x73\x20\x20\x20\x66\x72\x6f\x6d\x20\x61\x20\x70\x61\x73\x73\x70\x68\x72\x61\x73\x65\x2e\x20\x20\x4f\x6e\x65\x20\x6f\x66\x20\x6d\x64\x32\x2c\x20\x6d\x64\x35\x2c\x20\x73\x68\x61\x20\x6f\x72\x20\x73\x68\x61\x31\xa",
                       "");
            BIO_printf(bio_err, "\x25\x2d\x31\x34\x73\x20\x73\x61\x6c\x74\x20\x69\x6e\x20\x68\x65\x78\x20\x69\x73\x20\x74\x68\x65\x20\x6e\x65\x78\x74\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\xa",
                       "\x2d\x53");
            BIO_printf(bio_err, "\x25\x2d\x31\x34\x73\x20\x6b\x65\x79\x2f\x69\x76\x20\x69\x6e\x20\x68\x65\x78\x20\x69\x73\x20\x74\x68\x65\x20\x6e\x65\x78\x74\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\xa",
                       "\x2d\x4b\x2f\x2d\x69\x76");
            BIO_printf(bio_err, "\x25\x2d\x31\x34\x73\x20\x70\x72\x69\x6e\x74\x20\x74\x68\x65\x20\x69\x76\x2f\x6b\x65\x79\x20\x28\x74\x68\x65\x6e\x20\x65\x78\x69\x74\x20\x69\x66\x20\x2d\x50\x29\xa",
                       "\x2d\x5b\x70\x50\x5d");
            BIO_printf(bio_err, "\x25\x2d\x31\x34\x73\x20\x62\x75\x66\x66\x65\x72\x20\x73\x69\x7a\x65\xa", "\x2d\x62\x75\x66\x73\x69\x7a\x65\x20\x3c\x6e\x3e");
            BIO_printf(bio_err, "\x25\x2d\x31\x34\x73\x20\x64\x69\x73\x61\x62\x6c\x65\x20\x73\x74\x61\x6e\x64\x61\x72\x64\x20\x62\x6c\x6f\x63\x6b\x20\x70\x61\x64\x64\x69\x6e\x67\xa",
                       "\x2d\x6e\x6f\x70\x61\x64");
#ifndef OPENSSL_NO_ENGINE
            BIO_printf(bio_err,
                       "\x25\x2d\x31\x34\x73\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x65\x2c\x20\x70\x6f\x73\x73\x69\x62\x6c\x79\x20\x61\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20\x64\x65\x76\x69\x63\x65\x2e\xa",
                       "\x2d\x65\x6e\x67\x69\x6e\x65\x20\x65");
#endif

            BIO_printf(bio_err, "\x43\x69\x70\x68\x65\x72\x20\x54\x79\x70\x65\x73\xa");
            dec.n = 0;
            dec.bio = bio_err;
            OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH,
                                   show_ciphers, &dec);
            BIO_printf(bio_err, "\xa");

            goto end;
        }
        argc--;
        argv++;
    }

    e = setup_engine(bio_err, engine, 0);

    if (cipher && EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) {
        BIO_printf(bio_err,
                   "\x41\x45\x41\x44\x20\x63\x69\x70\x68\x65\x72\x73\x20\x6e\x6f\x74\x20\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x20\x62\x79\x20\x74\x68\x65\x20\x65\x6e\x63\x20\x75\x74\x69\x6c\x69\x74\x79\xa");
        goto end;
    }

    if (cipher && (EVP_CIPHER_mode(cipher) == EVP_CIPH_XTS_MODE)) {
        BIO_printf(bio_err,
                   "\x43\x69\x70\x68\x65\x72\x73\x20\x69\x6e\x20\x58\x54\x53\x20\x6d\x6f\x64\x65\x20\x61\x72\x65\x20\x6e\x6f\x74\x20\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x20\x62\x79\x20\x74\x68\x65\x20\x65\x6e\x63\x20\x75\x74\x69\x6c\x69\x74\x79\xa");
        goto end;
    }

    if (md && (dgst = EVP_get_digestbyname(md)) == NULL) {
        BIO_printf(bio_err, "\x25\x73\x20\x69\x73\x20\x61\x6e\x20\x75\x6e\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x20\x6d\x65\x73\x73\x61\x67\x65\x20\x64\x69\x67\x65\x73\x74\x20\x74\x79\x70\x65\xa", md);
        goto end;
    }

    if (dgst == NULL) {
        dgst = EVP_md5();
    }

    if (bufsize != NULL) {
        unsigned long n;

        for (n = 0; *bufsize; bufsize++) {
            i = *bufsize;
            if ((i <= '\x39') && (i >= '\x30'))
                n = n * 10 + i - '\x30';
            else if (i == '\x6b') {
                n *= 1024;
                bufsize++;
                break;
            }
        }
        if (*bufsize != '\x0') {
            BIO_printf(bio_err, "\x69\x6e\x76\x61\x6c\x69\x64\x20\x27\x62\x75\x66\x73\x69\x7a\x65\x27\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x2e\xa");
            goto end;
        }

        /* It must be large enough for a base64 encoded line */
        if (base64 && n < 80)
            n = 80;

        bsize = (int)n;
        if (verbose)
            BIO_printf(bio_err, "\x62\x75\x66\x73\x69\x7a\x65\x3d\x25\x64\xa", bsize);
    }

    strbuf = OPENSSL_malloc(SIZE);
    buff = (unsigned char *)OPENSSL_malloc(EVP_ENCODE_LENGTH(bsize));
    if ((buff == NULL) || (strbuf == NULL)) {
        BIO_printf(bio_err, "\x4f\x50\x45\x4e\x53\x53\x4c\x5f\x6d\x61\x6c\x6c\x6f\x63\x20\x66\x61\x69\x6c\x75\x72\x65\x20\x25\x6c\x64\xa",
                   (long)EVP_ENCODE_LENGTH(bsize));
        goto end;
    }

    in = BIO_new(BIO_s_file());
    out = BIO_new(BIO_s_file());
    if ((in == NULL) || (out == NULL)) {
        ERR_print_errors(bio_err);
        goto end;
    }
    if (debug) {
        BIO_set_callback(in, BIO_debug_callback);
        BIO_set_callback(out, BIO_debug_callback);
        BIO_set_callback_arg(in, (char *)bio_err);
        BIO_set_callback_arg(out, (char *)bio_err);
    }

    if (inf == NULL) {
#ifndef OPENSSL_NO_SETVBUF_IONBF
        if (bufsize != NULL)
            setvbuf(stdin, (char *)NULL, _IONBF, 0);
#endif                          /* ndef OPENSSL_NO_SETVBUF_IONBF */
        BIO_set_fp(in, stdin, BIO_NOCLOSE);
    } else {
        if (BIO_read_filename(in, inf) <= 0) {
            perror(inf);
            goto end;
        }
    }

    if (!str && passarg) {
        if (!app_passwd(bio_err, passarg, NULL, &pass, NULL)) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\xa");
            goto end;
        }
        str = pass;
    }

    if ((str == NULL) && (cipher != NULL) && (hkey == NULL)) {
        for (;;) {
            char buf[200];

            BIO_snprintf(buf, sizeof(buf), "\x65\x6e\x74\x65\x72\x20\x25\x73\x20\x25\x73\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x3a",
                         OBJ_nid2ln(EVP_CIPHER_nid(cipher)),
                         (enc) ? "\x65\x6e\x63\x72\x79\x70\x74\x69\x6f\x6e" : "\x64\x65\x63\x72\x79\x70\x74\x69\x6f\x6e");
            strbuf[0] = '\x0';
            i = EVP_read_pw_string((char *)strbuf, SIZE, buf, enc);
            if (i == 0) {
                if (strbuf[0] == '\x0') {
                    ret = 1;
                    goto end;
                }
                str = strbuf;
                break;
            }
            if (i < 0) {
                BIO_printf(bio_err, "\x62\x61\x64\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x20\x72\x65\x61\x64\xa");
                goto end;
            }
        }
    }

    if (outf == NULL) {
        BIO_set_fp(out, stdout, BIO_NOCLOSE);
#ifndef OPENSSL_NO_SETVBUF_IONBF
        if (bufsize != NULL)
            setvbuf(stdout, (char *)NULL, _IONBF, 0);
#endif                          /* ndef OPENSSL_NO_SETVBUF_IONBF */
#ifdef OPENSSL_SYS_VMS
        {
            BIO *tmpbio = BIO_new(BIO_f_linebuffer());
            out = BIO_push(tmpbio, out);
        }
#endif
    } else {
        if (BIO_write_filename(out, outf) <= 0) {
            perror(outf);
            goto end;
        }
    }

    rbio = in;
    wbio = out;

#ifdef ZLIB

    if (do_zlib) {
        if ((bzl = BIO_new(BIO_f_zlib())) == NULL)
            goto end;
        if (enc)
            wbio = BIO_push(bzl, wbio);
        else
            rbio = BIO_push(bzl, rbio);
    }
#endif

    if (base64) {
        if ((b64 = BIO_new(BIO_f_base64())) == NULL)
            goto end;
        if (debug) {
            BIO_set_callback(b64, BIO_debug_callback);
            BIO_set_callback_arg(b64, (char *)bio_err);
        }
        if (olb64)
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        if (enc)
            wbio = BIO_push(b64, wbio);
        else
            rbio = BIO_push(b64, rbio);
    }

    if (cipher != NULL) {
        /*
         * Note that str is NULL if a key was passed on the command line, so
         * we get no salt in that case. Is this a bug?
         */
        if (str != NULL) {
            /*
             * Salt handling: if encrypting generate a salt and write to
             * output BIO. If decrypting read salt from input BIO.
             */
            unsigned char *sptr;
            if (nosalt)
                sptr = NULL;
            else {
                if (enc) {
                    if (hsalt) {
                        if (!set_hex(hsalt, salt, sizeof(salt))) {
                            BIO_printf(bio_err, "\x69\x6e\x76\x61\x6c\x69\x64\x20\x68\x65\x78\x20\x73\x61\x6c\x74\x20\x76\x61\x6c\x75\x65\xa");
                            goto end;
                        }
                    } else if (RAND_bytes(salt, sizeof(salt)) <= 0)
                        goto end;
                    /*
                     * If -P option then don't bother writing
                     */
                    if ((printkey != 2)
                        && (BIO_write(wbio, magic,
                                      sizeof(magic) - 1) != sizeof(magic) - 1
                            || BIO_write(wbio,
                                         (char *)salt,
                                         sizeof(salt)) != sizeof(salt))) {
                        BIO_printf(bio_err, "\x65\x72\x72\x6f\x72\x20\x77\x72\x69\x74\x69\x6e\x67\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
                        goto end;
                    }
                } else if (BIO_read(rbio, mbuf, sizeof(mbuf)) != sizeof(mbuf)
                           || BIO_read(rbio,
                                       (unsigned char *)salt,
                                       sizeof(salt)) != sizeof(salt)) {
                    BIO_printf(bio_err, "\x65\x72\x72\x6f\x72\x20\x72\x65\x61\x64\x69\x6e\x67\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
                    goto end;
                } else if (memcmp(mbuf, magic, sizeof(magic) - 1)) {
                    BIO_printf(bio_err, "\x62\x61\x64\x20\x6d\x61\x67\x69\x63\x20\x6e\x75\x6d\x62\x65\x72\xa");
                    goto end;
                }

                sptr = salt;
            }

            EVP_BytesToKey(cipher, dgst, sptr,
                           (unsigned char *)str, strlen(str), 1, key, iv);
            /*
             * zero the complete buffer or the string passed from the command
             * line bug picked up by Larry J. Hughes Jr. <hughes@indiana.edu>
             */
            if (str == strbuf)
                OPENSSL_cleanse(str, SIZE);
            else
                OPENSSL_cleanse(str, strlen(str));
        }
        if (hiv != NULL) {
            int siz = EVP_CIPHER_iv_length(cipher);
            if (siz == 0) {
                BIO_printf(bio_err, "\x77\x61\x72\x6e\x69\x6e\x67\x3a\x20\x69\x76\x20\x6e\x6f\x74\x20\x75\x73\x65\x20\x62\x79\x20\x74\x68\x69\x73\x20\x63\x69\x70\x68\x65\x72\xa");
            } else if (!set_hex(hiv, iv, sizeof(iv))) {
                BIO_printf(bio_err, "\x69\x6e\x76\x61\x6c\x69\x64\x20\x68\x65\x78\x20\x69\x76\x20\x76\x61\x6c\x75\x65\xa");
                goto end;
            }
        }
        if ((hiv == NULL) && (str == NULL)
            && EVP_CIPHER_iv_length(cipher) != 0) {
            /*
             * No IV was explicitly set and no IV was generated during
             * EVP_BytesToKey. Hence the IV is undefined, making correct
             * decryption impossible.
             */
            BIO_printf(bio_err, "\x69\x76\x20\x75\x6e\x64\x65\x66\x69\x6e\x65\x64\xa");
            goto end;
        }
        if ((hkey != NULL) && !set_hex(hkey, key, EVP_CIPHER_key_length(cipher))) {
            BIO_printf(bio_err, "\x69\x6e\x76\x61\x6c\x69\x64\x20\x68\x65\x78\x20\x6b\x65\x79\x20\x76\x61\x6c\x75\x65\xa");
            goto end;
        }

        if ((benc = BIO_new(BIO_f_cipher())) == NULL)
            goto end;

        /*
         * Since we may be changing parameters work on the encryption context
         * rather than calling BIO_set_cipher().
         */

        BIO_get_cipher_ctx(benc, &ctx);

        if (non_fips_allow)
            EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_FLAG_NON_FIPS_ALLOW);

        if (!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, enc)) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x73\x65\x74\x74\x69\x6e\x67\x20\x63\x69\x70\x68\x65\x72\x20\x25\x73\xa",
                       EVP_CIPHER_name(cipher));
            ERR_print_errors(bio_err);
            goto end;
        }

        if (nopad)
            EVP_CIPHER_CTX_set_padding(ctx, 0);

        if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, enc)) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x73\x65\x74\x74\x69\x6e\x67\x20\x63\x69\x70\x68\x65\x72\x20\x25\x73\xa",
                       EVP_CIPHER_name(cipher));
            ERR_print_errors(bio_err);
            goto end;
        }

        if (debug) {
            BIO_set_callback(benc, BIO_debug_callback);
            BIO_set_callback_arg(benc, (char *)bio_err);
        }

        if (printkey) {
            if (!nosalt) {
                printf("\x73\x61\x6c\x74\x3d");
                for (i = 0; i < (int)sizeof(salt); i++)
                    printf("\x25\x30\x32\x58", salt[i]);
                printf("\xa");
            }
            if (cipher->key_len > 0) {
                printf("\x6b\x65\x79\x3d");
                for (i = 0; i < cipher->key_len; i++)
                    printf("\x25\x30\x32\x58", key[i]);
                printf("\xa");
            }
            if (cipher->iv_len > 0) {
                printf("\x69\x76\x20\x3d");
                for (i = 0; i < cipher->iv_len; i++)
                    printf("\x25\x30\x32\x58", iv[i]);
                printf("\xa");
            }
            if (printkey == 2) {
                ret = 0;
                goto end;
            }
        }
    }

    /* Only encrypt/decrypt as we write the file */
    if (benc != NULL)
        wbio = BIO_push(benc, wbio);

    for (;;) {
        inl = BIO_read(rbio, (char *)buff, bsize);
        if (inl <= 0)
            break;
        if (BIO_write(wbio, (char *)buff, inl) != inl) {
            BIO_printf(bio_err, "\x65\x72\x72\x6f\x72\x20\x77\x72\x69\x74\x69\x6e\x67\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
            goto end;
        }
    }
    if (!BIO_flush(wbio)) {
        BIO_printf(bio_err, "\x62\x61\x64\x20\x64\x65\x63\x72\x79\x70\x74\xa");
        goto end;
    }

    ret = 0;
    if (verbose) {
        BIO_printf(bio_err, "\x62\x79\x74\x65\x73\x20\x72\x65\x61\x64\x20\x20\x20\x3a\x25\x38\x6c\x64\xa", BIO_number_read(in));
        BIO_printf(bio_err, "\x62\x79\x74\x65\x73\x20\x77\x72\x69\x74\x74\x65\x6e\x3a\x25\x38\x6c\x64\xa", BIO_number_written(out));
    }
 end:
    ERR_print_errors(bio_err);
    if (strbuf != NULL)
        OPENSSL_free(strbuf);
    if (buff != NULL)
        OPENSSL_free(buff);
    if (in != NULL)
        BIO_free(in);
    if (out != NULL)
        BIO_free_all(out);
    if (benc != NULL)
        BIO_free(benc);
    if (b64 != NULL)
        BIO_free(b64);
#ifdef ZLIB
    if (bzl != NULL)
        BIO_free(bzl);
#endif
    release_engine(e);
    if (pass)
        OPENSSL_free(pass);
    apps_shutdown();
    OPENSSL_EXIT(ret);
}

int set_hex(char *in, unsigned char *out, int size)
{
    int i, n;
    unsigned char j;

    n = strlen(in);
    if (n > (size * 2)) {
        BIO_printf(bio_err, "\x68\x65\x78\x20\x73\x74\x72\x69\x6e\x67\x20\x69\x73\x20\x74\x6f\x6f\x20\x6c\x6f\x6e\x67\xa");
        return (0);
    }
    memset(out, 0, size);
    for (i = 0; i < n; i++) {
        j = (unsigned char)*in;
        *(in++) = '\x0';
        if (j == 0)
            break;
        if ((j >= '\x30') && (j <= '\x39'))
            j -= '\x30';
        else if ((j >= '\x41') && (j <= '\x46'))
            j = j - '\x41' + 10;
        else if ((j >= '\x61') && (j <= '\x66'))
            j = j - '\x61' + 10;
        else {
            BIO_printf(bio_err, "\x6e\x6f\x6e\x2d\x68\x65\x78\x20\x64\x69\x67\x69\x74\xa");
            return (0);
        }
        if (i & 1)
            out[i / 2] |= j;
        else
            out[i / 2] = (j << 4);
    }
    return (1);
}

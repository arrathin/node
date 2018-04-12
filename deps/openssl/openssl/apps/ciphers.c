/* apps/ciphers.c */
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
#ifdef OPENSSL_NO_STDIO
# define APPS_WIN16
#endif
#include "apps.h"
#include <openssl/err.h>
#include <openssl/ssl.h>

#undef PROG
#define PROG    ciphers_main

static const char *ciphers_usage[] = {
    "\x75\x73\x61\x67\x65\x3a\x20\x63\x69\x70\x68\x65\x72\x73\x20\x61\x72\x67\x73\xa",
    "\x20\x2d\x76\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x76\x65\x72\x62\x6f\x73\x65\x20\x6d\x6f\x64\x65\x2c\x20\x61\x20\x74\x65\x78\x74\x75\x61\x6c\x20\x6c\x69\x73\x74\x69\x6e\x67\x20\x6f\x66\x20\x74\x68\x65\x20\x53\x53\x4c\x2f\x54\x4c\x53\x20\x63\x69\x70\x68\x65\x72\x73\x20\x69\x6e\x20\x4f\x70\x65\x6e\x53\x53\x4c\xa",
    "\x20\x2d\x56\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x65\x76\x65\x6e\x20\x6d\x6f\x72\x65\x20\x76\x65\x72\x62\x6f\x73\x65\xa",
    "\x20\x2d\x73\x73\x6c\x32\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x53\x53\x4c\x32\x20\x6d\x6f\x64\x65\xa",
    "\x20\x2d\x73\x73\x6c\x33\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x53\x53\x4c\x33\x20\x6d\x6f\x64\x65\xa",
    "\x20\x2d\x74\x6c\x73\x31\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x54\x4c\x53\x31\x20\x6d\x6f\x64\x65\xa",
    NULL
};

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    int ret = 1, i;
    int verbose = 0, Verbose = 0;
#ifndef OPENSSL_NO_SSL_TRACE
    int stdname = 0;
#endif
    const char **pp;
    const char *p;
    int badops = 0;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char *ciphers = NULL;
    const SSL_METHOD *meth = NULL;
    STACK_OF(SSL_CIPHER) *sk;
    char buf[512];
    BIO *STDout = NULL;

    meth = SSLv23_server_method();

    apps_startup();

    if (bio_err == NULL)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    STDout = BIO_new_fp(stdout, BIO_NOCLOSE);
#ifdef OPENSSL_SYS_VMS
    {
        BIO *tmpbio = BIO_new(BIO_f_linebuffer());
        STDout = BIO_push(tmpbio, STDout);
    }
#endif
    if (!load_config(bio_err, NULL))
        goto end;

    argc--;
    argv++;
    while (argc >= 1) {
        if (strcmp(*argv, "\x2d\x76") == 0)
            verbose = 1;
        else if (strcmp(*argv, "\x2d\x56") == 0)
            verbose = Verbose = 1;
#ifndef OPENSSL_NO_SSL_TRACE
        else if (strcmp(*argv, "\x2d\x73\x74\x64\x6e\x61\x6d\x65") == 0)
            stdname = verbose = 1;
#endif
#ifndef OPENSSL_NO_SSL2
        else if (strcmp(*argv, "\x2d\x73\x73\x6c\x32") == 0)
            meth = SSLv2_client_method();
#endif
#ifndef OPENSSL_NO_SSL3
        else if (strcmp(*argv, "\x2d\x73\x73\x6c\x33") == 0)
            meth = SSLv3_client_method();
#endif
#ifndef OPENSSL_NO_TLS1
        else if (strcmp(*argv, "\x2d\x74\x6c\x73\x31") == 0)
            meth = TLSv1_client_method();
#endif
        else if ((strncmp(*argv, "\x2d\x68", 2) == 0) || (strcmp(*argv, "\x2d\x3f") == 0)) {
            badops = 1;
            break;
        } else {
            ciphers = *argv;
        }
        argc--;
        argv++;
    }

    if (badops) {
        for (pp = ciphers_usage; (*pp != NULL); pp++)
            BIO_printf(bio_err, "\x25\x73", *pp);
        goto end;
    }

    OpenSSL_add_ssl_algorithms();

    ctx = SSL_CTX_new(meth);
    if (ctx == NULL)
        goto err;
    if (ciphers != NULL) {
        if (!SSL_CTX_set_cipher_list(ctx, ciphers)) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x69\x6e\x20\x63\x69\x70\x68\x65\x72\x20\x6c\x69\x73\x74\xa");
            goto err;
        }
    }
    ssl = SSL_new(ctx);
    if (ssl == NULL)
        goto err;

    if (!verbose) {
        for (i = 0;; i++) {
            p = SSL_get_cipher_list(ssl, i);
            if (p == NULL)
                break;
            if (i != 0)
                BIO_printf(STDout, "\x3a");
            BIO_printf(STDout, "\x25\x73", p);
        }
        BIO_printf(STDout, "\xa");
    } else {                    /* verbose */

        sk = SSL_get_ciphers(ssl);

        for (i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
            SSL_CIPHER *c;

            c = sk_SSL_CIPHER_value(sk, i);

            if (Verbose) {
                unsigned long id = SSL_CIPHER_get_id(c);
                int id0 = (int)(id >> 24);
                int id1 = (int)((id >> 16) & 0xffL);
                int id2 = (int)((id >> 8) & 0xffL);
                int id3 = (int)(id & 0xffL);

                if ((id & 0xff000000L) == 0x02000000L) {
                    /* SSL2 cipher */
                    BIO_printf(STDout, "\x20\x20\x20\x20\x20\x30\x78\x25\x30\x32\x58\x2c\x30\x78\x25\x30\x32\x58\x2c\x30\x78\x25\x30\x32\x58\x20\x2d\x20", id1,
                               id2, id3);
                } else if ((id & 0xff000000L) == 0x03000000L) {
                    /* SSL3 cipher */
                    BIO_printf(STDout, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x30\x78\x25\x30\x32\x58\x2c\x30\x78\x25\x30\x32\x58\x20\x2d\x20", id2,
                               id3);
                } else {
                    /* whatever */
                    BIO_printf(STDout, "\x30\x78\x25\x30\x32\x58\x2c\x30\x78\x25\x30\x32\x58\x2c\x30\x78\x25\x30\x32\x58\x2c\x30\x78\x25\x30\x32\x58\x20\x2d\x20", id0,
                               id1, id2, id3);
                }
            }
#ifndef OPENSSL_NO_SSL_TRACE
            if (stdname) {
                const char *nm = SSL_CIPHER_standard_name(c);
                if (nm == NULL)
                    nm = "\x55\x4e\x4b\x4e\x4f\x57\x4e";
                BIO_printf(STDout, "\x25\x73\x20\x2d\x20", nm);
            }
#endif
            BIO_puts(STDout, SSL_CIPHER_description(c, buf, sizeof(buf)));
        }
    }

    ret = 0;
    if (0) {
 err:
        SSL_load_error_strings();
        ERR_print_errors(bio_err);
    }
 end:
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    if (ssl != NULL)
        SSL_free(ssl);
    if (STDout != NULL)
        BIO_free_all(STDout);
    apps_shutdown();
    OPENSSL_EXIT(ret);
}

/* apps/rand.c */
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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

#include "apps.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#undef PROG
#define PROG rand_main

/*-
 * -out file         - write to file
 * -rand file:file   - PRNG seed files
 * -base64           - base64 encode output
 * -hex              - hex encode output
 * num               - write 'num' bytes
 */

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    int i, r, ret = 1;
    int badopt;
    char *outfile = NULL;
    char *inrand = NULL;
    int base64 = 0;
    int hex = 0;
    BIO *out = NULL;
    int num = -1;
    ENGINE *e = NULL;
    char *engine = NULL;

    apps_startup();

    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (!load_config(bio_err, NULL))
        goto err;

    badopt = 0;
    i = 0;
    while (!badopt && argv[++i] != NULL) {
        if (strcmp(argv[i], "\x2d\x6f\x75\x74") == 0) {
            if ((argv[i + 1] != NULL) && (outfile == NULL))
                outfile = argv[++i];
            else
                badopt = 1;
        }
#ifndef OPENSSL_NO_ENGINE
        else if (strcmp(argv[i], "\x2d\x65\x6e\x67\x69\x6e\x65") == 0) {
            if ((argv[i + 1] != NULL) && (engine == NULL))
                engine = argv[++i];
            else
                badopt = 1;
        }
#endif
        else if (strcmp(argv[i], "\x2d\x72\x61\x6e\x64") == 0) {
            if ((argv[i + 1] != NULL) && (inrand == NULL))
                inrand = argv[++i];
            else
                badopt = 1;
        } else if (strcmp(argv[i], "\x2d\x62\x61\x73\x65\x36\x34") == 0) {
            if (!base64)
                base64 = 1;
            else
                badopt = 1;
        } else if (strcmp(argv[i], "\x2d\x68\x65\x78") == 0) {
            if (!hex)
                hex = 1;
            else
                badopt = 1;
        } else if (isdigit((unsigned char)argv[i][0])) {
            if (num < 0) {
                r = sscanf(argv[i], "\x25\x64", &num);
                if (r == 0 || num < 0)
                    badopt = 1;
            } else
                badopt = 1;
        } else
            badopt = 1;
    }

    if (hex && base64)
        badopt = 1;

    if (num < 0)
        badopt = 1;

    if (badopt) {
        BIO_printf(bio_err, "\x55\x73\x61\x67\x65\x3a\x20\x72\x61\x6e\x64\x20\x5b\x6f\x70\x74\x69\x6f\x6e\x73\x5d\x20\x6e\x75\x6d\xa");
        BIO_printf(bio_err, "\x77\x68\x65\x72\x65\x20\x6f\x70\x74\x69\x6f\x6e\x73\x20\x61\x72\x65\xa");
        BIO_printf(bio_err, "\x2d\x6f\x75\x74\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x77\x72\x69\x74\x65\x20\x74\x6f\x20\x66\x69\x6c\x65\xa");
#ifndef OPENSSL_NO_ENGINE
        BIO_printf(bio_err,
                   "\x2d\x65\x6e\x67\x69\x6e\x65\x20\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x65\x2c\x20\x70\x6f\x73\x73\x69\x62\x6c\x79\x20\x61\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20\x64\x65\x76\x69\x63\x65\x2e\xa");
#endif
        BIO_printf(bio_err, "\x2d\x72\x61\x6e\x64\x20\x66\x69\x6c\x65\x25\x63\x66\x69\x6c\x65\x25\x63\x2e\x2e\x2e\x20\x2d\x20\x73\x65\x65\x64\x20\x50\x52\x4e\x47\x20\x66\x72\x6f\x6d\x20\x66\x69\x6c\x65\x73\xa",
                   LIST_SEPARATOR_CHAR, LIST_SEPARATOR_CHAR);
        BIO_printf(bio_err, "\x2d\x62\x61\x73\x65\x36\x34\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x62\x61\x73\x65\x36\x34\x20\x65\x6e\x63\x6f\x64\x65\x20\x6f\x75\x74\x70\x75\x74\xa");
        BIO_printf(bio_err, "\x2d\x68\x65\x78\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x68\x65\x78\x20\x65\x6e\x63\x6f\x64\x65\x20\x6f\x75\x74\x70\x75\x74\xa");
        goto err;
    }
    e = setup_engine(bio_err, engine, 0);

    app_RAND_load_file(NULL, bio_err, (inrand != NULL));
    if (inrand != NULL)
        BIO_printf(bio_err, "\x25\x6c\x64\x20\x73\x65\x6d\x69\x2d\x72\x61\x6e\x64\x6f\x6d\x20\x62\x79\x74\x65\x73\x20\x6c\x6f\x61\x64\x65\x64\xa",
                   app_RAND_load_files(inrand));

    out = BIO_new(BIO_s_file());
    if (out == NULL)
        goto err;
    if (outfile != NULL)
        r = BIO_write_filename(out, outfile);
    else {
        r = BIO_set_fp(out, stdout, BIO_NOCLOSE | BIO_FP_TEXT);
#ifdef OPENSSL_SYS_VMS
        {
            BIO *tmpbio = BIO_new(BIO_f_linebuffer());
            out = BIO_push(tmpbio, out);
        }
#endif
    }
    if (r <= 0)
        goto err;

    if (base64) {
        BIO *b64 = BIO_new(BIO_f_base64());
        if (b64 == NULL)
            goto err;
        out = BIO_push(b64, out);
    }

    while (num > 0) {
        unsigned char buf[4096];
        int chunk;

        chunk = num;
        if (chunk > (int)sizeof(buf))
            chunk = sizeof(buf);
        r = RAND_bytes(buf, chunk);
        if (r <= 0)
            goto err;
        if (!hex)
            BIO_write(out, buf, chunk);
        else {
            for (i = 0; i < chunk; i++)
                BIO_printf(out, "\x25\x30\x32\x78", buf[i]);
        }
        num -= chunk;
    }
    if (hex)
        BIO_puts(out, "\xa");
    (void)BIO_flush(out);

    app_RAND_write_file(NULL, bio_err);
    ret = 0;

 err:
    ERR_print_errors(bio_err);
    release_engine(e);
    if (out)
        BIO_free_all(out);
    apps_shutdown();
    OPENSSL_EXIT(ret);
}

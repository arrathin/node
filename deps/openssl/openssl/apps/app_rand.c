/* apps/app_rand.c */
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
/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
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

#define NON_MAIN
#include "apps.h"
#undef NON_MAIN
#include <openssl/bio.h>
#include <openssl/rand.h>

static int seeded = 0;
static int egdsocket = 0;

int app_RAND_load_file(const char *file, BIO *bio_e, int dont_warn)
{
    int consider_randfile = (file == NULL);
    char buffer[200];

#ifdef OPENSSL_SYS_WINDOWS
    /*
     * allocate 2 to dont_warn not to use RAND_screen() via
     * -no_rand_screen option in s_client
     */
    if (dont_warn != 2) {
      BIO_printf(bio_e, "\x4c\x6f\x61\x64\x69\x6e\x67\x20\x27\x73\x63\x72\x65\x65\x6e\x27\x20\x69\x6e\x74\x6f\x20\x72\x61\x6e\x64\x6f\x6d\x20\x73\x74\x61\x74\x65\x20\x2d");
      BIO_flush(bio_e);
      RAND_screen();
      BIO_printf(bio_e, "\x20\x64\x6f\x6e\x65\xa");
    }
#endif

    if (file == NULL)
        file = RAND_file_name(buffer, sizeof(buffer));
    else if (RAND_egd(file) > 0) {
        /*
         * we try if the given filename is an EGD socket. if it is, we don't
         * write anything back to the file.
         */
        egdsocket = 1;
        return 1;
    }
    if (file == NULL || !RAND_load_file(file, -1)) {
        if (RAND_status() == 0) {
            if (!dont_warn) {
                BIO_printf(bio_e, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6c\x6f\x61\x64\x20\x27\x72\x61\x6e\x64\x6f\x6d\x20\x73\x74\x61\x74\x65\x27\xa");
                BIO_printf(bio_e,
                           "\x54\x68\x69\x73\x20\x6d\x65\x61\x6e\x73\x20\x74\x68\x61\x74\x20\x74\x68\x65\x20\x72\x61\x6e\x64\x6f\x6d\x20\x6e\x75\x6d\x62\x65\x72\x20\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\x20\x68\x61\x73\x20\x6e\x6f\x74\x20\x62\x65\x65\x6e\x20\x73\x65\x65\x64\x65\x64\xa");
                BIO_printf(bio_e, "\x77\x69\x74\x68\x20\x6d\x75\x63\x68\x20\x72\x61\x6e\x64\x6f\x6d\x20\x64\x61\x74\x61\x2e\xa");
                if (consider_randfile) { /* explanation does not apply when a
                                          * file is explicitly named */
                    BIO_printf(bio_e,
                               "\x43\x6f\x6e\x73\x69\x64\x65\x72\x20\x73\x65\x74\x74\x69\x6e\x67\x20\x74\x68\x65\x20\x52\x41\x4e\x44\x46\x49\x4c\x45\x20\x65\x6e\x76\x69\x72\x6f\x6e\x6d\x65\x6e\x74\x20\x76\x61\x72\x69\x61\x62\x6c\x65\x20\x74\x6f\x20\x70\x6f\x69\x6e\x74\x20\x61\x74\x20\x61\x20\x66\x69\x6c\x65\x20\x74\x68\x61\x74\xa");
                    BIO_printf(bio_e,
                               "\x27\x72\x61\x6e\x64\x6f\x6d\x27\x20\x64\x61\x74\x61\x20\x63\x61\x6e\x20\x62\x65\x20\x6b\x65\x70\x74\x20\x69\x6e\x20\x28\x74\x68\x65\x20\x66\x69\x6c\x65\x20\x77\x69\x6c\x6c\x20\x62\x65\x20\x6f\x76\x65\x72\x77\x72\x69\x74\x74\x65\x6e\x29\x2e\xa");
                }
            }
            return 0;
        }
    }
    seeded = 1;
    return 1;
}

long app_RAND_load_files(char *name)
{
    char *p, *n;
    int last;
    long tot = 0;
    int egd;

    for (;;) {
        last = 0;
        for (p = name; ((*p != '\x0') && (*p != LIST_SEPARATOR_CHAR)); p++) ;
        if (*p == '\x0')
            last = 1;
        *p = '\x0';
        n = name;
        name = p + 1;
        if (*n == '\x0')
            break;

        egd = RAND_egd(n);
        if (egd > 0)
            tot += egd;
        else
            tot += RAND_load_file(n, -1);
        if (last)
            break;
    }
    if (tot > 512)
        app_RAND_allow_write_file();
    return (tot);
}

int app_RAND_write_file(const char *file, BIO *bio_e)
{
    char buffer[200];

    if (egdsocket || !seeded)
        /*
         * If we did not manage to read the seed file, we should not write a
         * low-entropy seed file back -- it would suppress a crucial warning
         * the next time we want to use it.
         */
        return 0;

    if (file == NULL)
        file = RAND_file_name(buffer, sizeof(buffer));
    if (file == NULL || !RAND_write_file(file)) {
        BIO_printf(bio_e, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x77\x72\x69\x74\x65\x20\x27\x72\x61\x6e\x64\x6f\x6d\x20\x73\x74\x61\x74\x65\x27\xa");
        return 0;
    }
    return 1;
}

void app_RAND_allow_write_file(void)
{
    seeded = 1;
}

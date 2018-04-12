/* crypto/bio/bio_cb.c */
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
#include "cryptlib.h"
#include <openssl/bio.h>
#include <openssl/err.h>

long MS_CALLBACK BIO_debug_callback(BIO *bio, int cmd, const char *argp,
                                    int argi, long argl, long ret)
{
    BIO *b;
    MS_STATIC char buf[256];
    char *p;
    long r = 1;
    int len;
    size_t p_maxlen;

    if (BIO_CB_RETURN & cmd)
        r = ret;

    len = BIO_snprintf(buf,sizeof(buf),"\x42\x49\x4f\x5b\x25\x70\x5d\x3a\x20",(void *)bio);

    /* Ignore errors and continue printing the other information. */
    if (len < 0)
        len = 0;
    p = buf + len;
    p_maxlen = sizeof(buf) - len;

    switch (cmd) {
    case BIO_CB_FREE:
        BIO_snprintf(p, p_maxlen, "\x46\x72\x65\x65\x20\x2d\x20\x25\x73\xa", bio->method->name);
        break;
    case BIO_CB_READ:
        if (bio->method->type & BIO_TYPE_DESCRIPTOR)
            BIO_snprintf(p, p_maxlen, "\x72\x65\x61\x64\x28\x25\x64\x2c\x25\x6c\x75\x29\x20\x2d\x20\x25\x73\x20\x66\x64\x3d\x25\x64\xa",
                         bio->num, (unsigned long)argi,
                         bio->method->name, bio->num);
        else
            BIO_snprintf(p, p_maxlen, "\x72\x65\x61\x64\x28\x25\x64\x2c\x25\x6c\x75\x29\x20\x2d\x20\x25\x73\xa",
                         bio->num, (unsigned long)argi, bio->method->name);
        break;
    case BIO_CB_WRITE:
        if (bio->method->type & BIO_TYPE_DESCRIPTOR)
            BIO_snprintf(p, p_maxlen, "\x77\x72\x69\x74\x65\x28\x25\x64\x2c\x25\x6c\x75\x29\x20\x2d\x20\x25\x73\x20\x66\x64\x3d\x25\x64\xa",
                         bio->num, (unsigned long)argi,
                         bio->method->name, bio->num);
        else
            BIO_snprintf(p, p_maxlen, "\x77\x72\x69\x74\x65\x28\x25\x64\x2c\x25\x6c\x75\x29\x20\x2d\x20\x25\x73\xa",
                         bio->num, (unsigned long)argi, bio->method->name);
        break;
    case BIO_CB_PUTS:
        BIO_snprintf(p, p_maxlen, "\x70\x75\x74\x73\x28\x29\x20\x2d\x20\x25\x73\xa", bio->method->name);
        break;
    case BIO_CB_GETS:
        BIO_snprintf(p, p_maxlen, "\x67\x65\x74\x73\x28\x25\x6c\x75\x29\x20\x2d\x20\x25\x73\xa", (unsigned long)argi,
                     bio->method->name);
        break;
    case BIO_CB_CTRL:
        BIO_snprintf(p, p_maxlen, "\x63\x74\x72\x6c\x28\x25\x6c\x75\x29\x20\x2d\x20\x25\x73\xa", (unsigned long)argi,
                     bio->method->name);
        break;
    case BIO_CB_RETURN | BIO_CB_READ:
        BIO_snprintf(p, p_maxlen, "\x72\x65\x61\x64\x20\x72\x65\x74\x75\x72\x6e\x20\x25\x6c\x64\xa", ret);
        break;
    case BIO_CB_RETURN | BIO_CB_WRITE:
        BIO_snprintf(p, p_maxlen, "\x77\x72\x69\x74\x65\x20\x72\x65\x74\x75\x72\x6e\x20\x25\x6c\x64\xa", ret);
        break;
    case BIO_CB_RETURN | BIO_CB_GETS:
        BIO_snprintf(p, p_maxlen, "\x67\x65\x74\x73\x20\x72\x65\x74\x75\x72\x6e\x20\x25\x6c\x64\xa", ret);
        break;
    case BIO_CB_RETURN | BIO_CB_PUTS:
        BIO_snprintf(p, p_maxlen, "\x70\x75\x74\x73\x20\x72\x65\x74\x75\x72\x6e\x20\x25\x6c\x64\xa", ret);
        break;
    case BIO_CB_RETURN | BIO_CB_CTRL:
        BIO_snprintf(p, p_maxlen, "\x63\x74\x72\x6c\x20\x72\x65\x74\x75\x72\x6e\x20\x25\x6c\x64\xa", ret);
        break;
    default:
        BIO_snprintf(p, p_maxlen, "\x62\x69\x6f\x20\x63\x61\x6c\x6c\x62\x61\x63\x6b\x20\x2d\x20\x75\x6e\x6b\x6e\x6f\x77\x6e\x20\x74\x79\x70\x65\x20\x28\x25\x64\x29\xa", cmd);
        break;
    }

    b = (BIO *)bio->cb_arg;
    if (b != NULL)
        BIO_write(b, buf, strlen(buf));
#if !defined(OPENSSL_NO_STDIO) && !defined(OPENSSL_SYS_WIN16)
    else
        fputs(buf, stderr);
#endif
    return (r);
}

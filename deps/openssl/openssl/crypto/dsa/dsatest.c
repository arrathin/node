/* crypto/dsa/dsatest.c */
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

/*
 * Until the key-gen callbacks are modified to use newer prototypes, we allow
 * deprecated functions for openssl-internal code
 */
#ifdef OPENSSL_NO_DEPRECATED
# undef OPENSSL_NO_DEPRECATED
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "../e_os.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>

#ifdef OPENSSL_NO_DSA
int main(int argc, char *argv[])
{
    printf("\x4e\x6f\x20\x44\x53\x41\x20\x73\x75\x70\x70\x6f\x72\x74\xa");
    return (0);
}
#else
# include <openssl/dsa.h>

# ifdef OPENSSL_SYS_WIN16
#  define MS_CALLBACK     _far _loadds
# else
#  define MS_CALLBACK
# endif

static int MS_CALLBACK dsa_cb(int p, int n, BN_GENCB *arg);

/*
 * seed, out_p, out_q, out_g are taken from the updated Appendix 5 to FIPS
 * PUB 186 and also appear in Appendix 5 to FIPS PIB 186-1
 */
static unsigned char seed[20] = {
    0xd5, 0x01, 0x4e, 0x4b, 0x60, 0xef, 0x2b, 0xa8, 0xb6, 0x21, 0x1b, 0x40,
    0x62, 0xba, 0x32, 0x24, 0xe0, 0x42, 0x7d, 0xd3,
};

static unsigned char out_p[] = {
    0x8d, 0xf2, 0xa4, 0x94, 0x49, 0x22, 0x76, 0xaa,
    0x3d, 0x25, 0x75, 0x9b, 0xb0, 0x68, 0x69, 0xcb,
    0xea, 0xc0, 0xd8, 0x3a, 0xfb, 0x8d, 0x0c, 0xf7,
    0xcb, 0xb8, 0x32, 0x4f, 0x0d, 0x78, 0x82, 0xe5,
    0xd0, 0x76, 0x2f, 0xc5, 0xb7, 0x21, 0x0e, 0xaf,
    0xc2, 0xe9, 0xad, 0xac, 0x32, 0xab, 0x7a, 0xac,
    0x49, 0x69, 0x3d, 0xfb, 0xf8, 0x37, 0x24, 0xc2,
    0xec, 0x07, 0x36, 0xee, 0x31, 0xc8, 0x02, 0x91,
};

static unsigned char out_q[] = {
    0xc7, 0x73, 0x21, 0x8c, 0x73, 0x7e, 0xc8, 0xee,
    0x99, 0x3b, 0x4f, 0x2d, 0xed, 0x30, 0xf4, 0x8e,
    0xda, 0xce, 0x91, 0x5f,
};

static unsigned char out_g[] = {
    0x62, 0x6d, 0x02, 0x78, 0x39, 0xea, 0x0a, 0x13,
    0x41, 0x31, 0x63, 0xa5, 0x5b, 0x4c, 0xb5, 0x00,
    0x29, 0x9d, 0x55, 0x22, 0x95, 0x6c, 0xef, 0xcb,
    0x3b, 0xff, 0x10, 0xf3, 0x99, 0xce, 0x2c, 0x2e,
    0x71, 0xcb, 0x9d, 0xe5, 0xfa, 0x24, 0xba, 0xbf,
    0x58, 0xe5, 0xb7, 0x95, 0x21, 0x92, 0x5c, 0x9c,
    0xc4, 0x2e, 0x9f, 0x6f, 0x46, 0x4b, 0x08, 0x8c,
    0xc5, 0x72, 0xaf, 0x53, 0xe6, 0xd7, 0x88, 0x02,
};

static const unsigned char str1[] = "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30";

static const char rnd_seed[] =
    "\x73\x74\x72\x69\x6e\x67\x20\x74\x6f\x20\x6d\x61\x6b\x65\x20\x74\x68\x65\x20\x72\x61\x6e\x64\x6f\x6d\x20\x6e\x75\x6d\x62\x65\x72\x20\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\x20\x74\x68\x69\x6e\x6b\x20\x69\x74\x20\x68\x61\x73\x20\x65\x6e\x74\x72\x6f\x70\x79";

static BIO *bio_err = NULL;

int main(int argc, char **argv)
{
    BN_GENCB cb;
    DSA *dsa = NULL;
    int counter, ret = 0, i, j;
    unsigned char buf[256];
    unsigned long h;
    unsigned char sig[256];
    unsigned int siglen;

    if (bio_err == NULL)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    CRYPTO_malloc_debug_init();
    CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    ERR_load_crypto_strings();
    RAND_seed(rnd_seed, sizeof(rnd_seed));

    BIO_printf(bio_err, "\x74\x65\x73\x74\x20\x67\x65\x6e\x65\x72\x61\x74\x69\x6f\x6e\x20\x6f\x66\x20\x44\x53\x41\x20\x70\x61\x72\x61\x6d\x65\x74\x65\x72\x73\xa");

    BN_GENCB_set(&cb, dsa_cb, bio_err);
    if (((dsa = DSA_new()) == NULL) || !DSA_generate_parameters_ex(dsa, 512,
                                                                   seed, 20,
                                                                   &counter,
                                                                   &h, &cb))
        goto end;

    BIO_printf(bio_err, "\x73\x65\x65\x64\xa");
    for (i = 0; i < 20; i += 4) {
        BIO_printf(bio_err, "\x25\x30\x32\x58\x25\x30\x32\x58\x25\x30\x32\x58\x25\x30\x32\x58\x20",
                   seed[i], seed[i + 1], seed[i + 2], seed[i + 3]);
    }
    BIO_printf(bio_err, "\xac\x6f\x75\x6e\x74\x65\x72\x3d\x25\x64\x20\x68\x3d\x25\x6c\x64\xa", counter, h);

    DSA_print(bio_err, dsa, 0);
    if (counter != 105) {
        BIO_printf(bio_err, "\x63\x6f\x75\x6e\x74\x65\x72\x20\x73\x68\x6f\x75\x6c\x64\x20\x62\x65\x20\x31\x30\x35\xa");
        goto end;
    }
    if (h != 2) {
        BIO_printf(bio_err, "\x68\x20\x73\x68\x6f\x75\x6c\x64\x20\x62\x65\x20\x32\xa");
        goto end;
    }

    i = BN_bn2bin(dsa->q, buf);
    j = sizeof(out_q);
    if ((i != j) || (memcmp(buf, out_q, i) != 0)) {
        BIO_printf(bio_err, "\x71\x20\x76\x61\x6c\x75\x65\x20\x69\x73\x20\x77\x72\x6f\x6e\x67\xa");
        goto end;
    }

    i = BN_bn2bin(dsa->p, buf);
    j = sizeof(out_p);
    if ((i != j) || (memcmp(buf, out_p, i) != 0)) {
        BIO_printf(bio_err, "\x70\x20\x76\x61\x6c\x75\x65\x20\x69\x73\x20\x77\x72\x6f\x6e\x67\xa");
        goto end;
    }

    i = BN_bn2bin(dsa->g, buf);
    j = sizeof(out_g);
    if ((i != j) || (memcmp(buf, out_g, i) != 0)) {
        BIO_printf(bio_err, "\x67\x20\x76\x61\x6c\x75\x65\x20\x69\x73\x20\x77\x72\x6f\x6e\x67\xa");
        goto end;
    }

    dsa->flags |= DSA_FLAG_NO_EXP_CONSTTIME;
    DSA_generate_key(dsa);
    DSA_sign(0, str1, 20, sig, &siglen, dsa);
    if (DSA_verify(0, str1, 20, sig, siglen, dsa) == 1)
        ret = 1;

    dsa->flags &= ~DSA_FLAG_NO_EXP_CONSTTIME;
    DSA_generate_key(dsa);
    DSA_sign(0, str1, 20, sig, &siglen, dsa);
    if (DSA_verify(0, str1, 20, sig, siglen, dsa) == 1)
        ret = 1;

 end:
    if (!ret)
        ERR_print_errors(bio_err);
    if (dsa != NULL)
        DSA_free(dsa);
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();
    CRYPTO_mem_leaks(bio_err);
    if (bio_err != NULL) {
        BIO_free(bio_err);
        bio_err = NULL;
    }
# ifdef OPENSSL_SYS_NETWARE
    if (!ret)
        printf("\x45\x52\x52\x4f\x52\xa");
# endif
    EXIT(!ret);
    return (0);
}

static int MS_CALLBACK dsa_cb(int p, int n, BN_GENCB *arg)
{
    char c = '\x2a';
    static int ok = 0, num = 0;

    if (p == 0) {
        c = '\x2e';
        num++;
    };
    if (p == 1)
        c = '\x2b';
    if (p == 2) {
        c = '\x2a';
        ok++;
    }
    if (p == 3)
        c = '\xa';
    BIO_write(arg->arg, &c, 1);
    (void)BIO_flush(arg->arg);

    if (!ok && (p == 0) && (num > 1)) {
        BIO_printf((BIO *)arg, "\x65\x72\x72\x6f\x72\x20\x69\x6e\x20\x64\x73\x61\x74\x65\x73\x74\xa");
        return 0;
    }
    return 1;
}
#endif

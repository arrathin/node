/* crypto/bn/exptest.c */
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

#include "../e_os.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define NUM_BITS        (BN_BITS*2)

static const char rnd_seed[] =
    "\x73\x74\x72\x69\x6e\x67\x20\x74\x6f\x20\x6d\x61\x6b\x65\x20\x74\x68\x65\x20\x72\x61\x6e\x64\x6f\x6d\x20\x6e\x75\x6d\x62\x65\x72\x20\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\x20\x74\x68\x69\x6e\x6b\x20\x69\x74\x20\x68\x61\x73\x20\x65\x6e\x74\x72\x6f\x70\x79";

/*
 * Test that r == 0 in test_exp_mod_zero(). Returns one on success,
 * returns zero and prints debug output otherwise.
 */
static int a_is_zero_mod_one(const char *method, const BIGNUM *r,
                             const BIGNUM *a) {
    if (!BN_is_zero(r)) {
        fprintf(stderr, "\x25\x73\x20\x66\x61\x69\x6c\x65\x64\x3a\xa", method);
        fprintf(stderr, "\x61\x20\x2a\x2a\x20\x30\x20\x6d\x6f\x64\x20\x31\x20\x3d\x20\x72\x20\x28\x73\x68\x6f\x75\x6c\x64\x20\x62\x65\x20\x30\x29\xa");
        fprintf(stderr, "\x61\x20\x3d\x20");
        BN_print_fp(stderr, a);
        fprintf(stderr, "\xa\x72\x20\x3d\x20");
        BN_print_fp(stderr, r);
        fprintf(stderr, "\xa");
        return 0;
    }
    return 1;
}

/*
 * test_exp_mod_zero tests that x**0 mod 1 == 0. It returns zero on success.
 */
static int test_exp_mod_zero()
{
    BIGNUM a, p, m;
    BIGNUM r;
    BN_ULONG one_word = 1;
    BN_CTX *ctx = BN_CTX_new();
    int ret = 1, failed = 0;

    BN_init(&m);
    BN_one(&m);

    BN_init(&a);
    BN_one(&a);

    BN_init(&p);
    BN_zero(&p);

    BN_init(&r);

    if (!BN_rand(&a, 1024, 0, 0))
        goto err;

    if (!BN_mod_exp(&r, &a, &p, &m, ctx))
        goto err;

    if (!a_is_zero_mod_one("\x42\x4e\x5f\x6d\x6f\x64\x5f\x65\x78\x70", &r, &a))
        failed = 1;

    if (!BN_mod_exp_recp(&r, &a, &p, &m, ctx))
        goto err;

    if (!a_is_zero_mod_one("\x42\x4e\x5f\x6d\x6f\x64\x5f\x65\x78\x70\x5f\x72\x65\x63\x70", &r, &a))
        failed = 1;

    if (!BN_mod_exp_simple(&r, &a, &p, &m, ctx))
        goto err;

    if (!a_is_zero_mod_one("\x42\x4e\x5f\x6d\x6f\x64\x5f\x65\x78\x70\x5f\x73\x69\x6d\x70\x6c\x65", &r, &a))
        failed = 1;

    if (!BN_mod_exp_mont(&r, &a, &p, &m, ctx, NULL))
        goto err;

    if (!a_is_zero_mod_one("\x42\x4e\x5f\x6d\x6f\x64\x5f\x65\x78\x70\x5f\x6d\x6f\x6e\x74", &r, &a))
        failed = 1;

    if (!BN_mod_exp_mont_consttime(&r, &a, &p, &m, ctx, NULL)) {
        goto err;
    }

    if (!a_is_zero_mod_one("\x42\x4e\x5f\x6d\x6f\x64\x5f\x65\x78\x70\x5f\x6d\x6f\x6e\x74\x5f\x63\x6f\x6e\x73\x74\x74\x69\x6d\x65", &r, &a))
        failed = 1;

    /*
     * A different codepath exists for single word multiplication
     * in non-constant-time only.
     */
    if (!BN_mod_exp_mont_word(&r, one_word, &p, &m, ctx, NULL))
        goto err;

    if (!BN_is_zero(&r)) {
        fprintf(stderr, "\x42\x4e\x5f\x6d\x6f\x64\x5f\x65\x78\x70\x5f\x6d\x6f\x6e\x74\x5f\x77\x6f\x72\x64\x20\x66\x61\x69\x6c\x65\x64\x3a\xa");
        fprintf(stderr, "\x31\x20\x2a\x2a\x20\x30\x20\x6d\x6f\x64\x20\x31\x20\x3d\x20\x72\x20\x28\x73\x68\x6f\x75\x6c\x64\x20\x62\x65\x20\x30\x29\xa");
        fprintf(stderr, "\x72\x20\x3d\x20");
        BN_print_fp(stderr, &r);
        fprintf(stderr, "\xa");
        return 0;
    }

    ret = failed;

 err:
    BN_free(&r);
    BN_free(&a);
    BN_free(&p);
    BN_free(&m);
    BN_CTX_free(ctx);

    return ret;
}

int main(int argc, char *argv[])
{
    BN_CTX *ctx;
    BIO *out = NULL;
    int i, ret;
    unsigned char c;
    BIGNUM *r_mont, *r_mont_const, *r_recp, *r_simple, *a, *b, *m;

    /*
     * Seed or BN_rand may fail, and we don't even check its return
     * value (which we should)
     */
    RAND_seed(rnd_seed, sizeof(rnd_seed));

    ERR_load_BN_strings();

    ctx = BN_CTX_new();
    if (ctx == NULL)
        EXIT(1);
    r_mont = BN_new();
    r_mont_const = BN_new();
    r_recp = BN_new();
    r_simple = BN_new();
    a = BN_new();
    b = BN_new();
    m = BN_new();
    if ((r_mont == NULL) || (r_recp == NULL) || (a == NULL) || (b == NULL))
        goto err;

    out = BIO_new(BIO_s_file());

    if (out == NULL)
        EXIT(1);
    BIO_set_fp(out, stdout, BIO_NOCLOSE);

    for (i = 0; i < 200; i++) {
        RAND_bytes(&c, 1);
        c = (c % BN_BITS) - BN_BITS2;
        BN_rand(a, NUM_BITS + c, 0, 0);

        RAND_bytes(&c, 1);
        c = (c % BN_BITS) - BN_BITS2;
        BN_rand(b, NUM_BITS + c, 0, 0);

        RAND_bytes(&c, 1);
        c = (c % BN_BITS) - BN_BITS2;
        BN_rand(m, NUM_BITS + c, 0, 1);

        BN_mod(a, a, m, ctx);
        BN_mod(b, b, m, ctx);

        ret = BN_mod_exp_mont(r_mont, a, b, m, ctx, NULL);
        if (ret <= 0) {
            printf("\x42\x4e\x5f\x6d\x6f\x64\x5f\x65\x78\x70\x5f\x6d\x6f\x6e\x74\x28\x29\x20\x70\x72\x6f\x62\x6c\x65\x6d\x73\xa");
            ERR_print_errors(out);
            EXIT(1);
        }

        ret = BN_mod_exp_recp(r_recp, a, b, m, ctx);
        if (ret <= 0) {
            printf("\x42\x4e\x5f\x6d\x6f\x64\x5f\x65\x78\x70\x5f\x72\x65\x63\x70\x28\x29\x20\x70\x72\x6f\x62\x6c\x65\x6d\x73\xa");
            ERR_print_errors(out);
            EXIT(1);
        }

        ret = BN_mod_exp_simple(r_simple, a, b, m, ctx);
        if (ret <= 0) {
            printf("\x42\x4e\x5f\x6d\x6f\x64\x5f\x65\x78\x70\x5f\x73\x69\x6d\x70\x6c\x65\x28\x29\x20\x70\x72\x6f\x62\x6c\x65\x6d\x73\xa");
            ERR_print_errors(out);
            EXIT(1);
        }

        ret = BN_mod_exp_mont_consttime(r_mont_const, a, b, m, ctx, NULL);
        if (ret <= 0) {
            printf("\x42\x4e\x5f\x6d\x6f\x64\x5f\x65\x78\x70\x5f\x6d\x6f\x6e\x74\x5f\x63\x6f\x6e\x73\x74\x74\x69\x6d\x65\x28\x29\x20\x70\x72\x6f\x62\x6c\x65\x6d\x73\xa");
            ERR_print_errors(out);
            EXIT(1);
        }

        if (BN_cmp(r_simple, r_mont) == 0
            && BN_cmp(r_simple, r_recp) == 0
            && BN_cmp(r_simple, r_mont_const) == 0) {
            printf("\x2e");
            fflush(stdout);
        } else {
            if (BN_cmp(r_simple, r_mont) != 0)
                printf("\xa\x73\x69\x6d\x70\x6c\x65\x20\x61\x6e\x64\x20\x6d\x6f\x6e\x74\x20\x72\x65\x73\x75\x6c\x74\x73\x20\x64\x69\x66\x66\x65\x72\xa");
            if (BN_cmp(r_simple, r_mont_const) != 0)
                printf("\xa\x73\x69\x6d\x70\x6c\x65\x20\x61\x6e\x64\x20\x6d\x6f\x6e\x74\x20\x63\x6f\x6e\x73\x74\x20\x74\x69\x6d\x65\x20\x72\x65\x73\x75\x6c\x74\x73\x20\x64\x69\x66\x66\x65\x72\xa");
            if (BN_cmp(r_simple, r_recp) != 0)
                printf("\xa\x73\x69\x6d\x70\x6c\x65\x20\x61\x6e\x64\x20\x72\x65\x63\x70\x20\x72\x65\x73\x75\x6c\x74\x73\x20\x64\x69\x66\x66\x65\x72\xa");

            printf("\x61\x20\x28\x25\x33\x64\x29\x20\x3d\x20", BN_num_bits(a));
            BN_print(out, a);
            printf("\xab\x20\x28\x25\x33\x64\x29\x20\x3d\x20", BN_num_bits(b));
            BN_print(out, b);
            printf("\xa\x6d\x20\x28\x25\x33\x64\x29\x20\x3d\x20", BN_num_bits(m));
            BN_print(out, m);
            printf("\xa\x73\x69\x6d\x70\x6c\x65\x20\x20\x20\x3d");
            BN_print(out, r_simple);
            printf("\xa\x72\x65\x63\x70\x20\x20\x20\x20\x20\x3d");
            BN_print(out, r_recp);
            printf("\xa\x6d\x6f\x6e\x74\x20\x20\x20\x20\x20\x3d");
            BN_print(out, r_mont);
            printf("\xa\x6d\x6f\x6e\x74\x5f\x63\x74\x20\x20\x3d");
            BN_print(out, r_mont_const);
            printf("\xa");
            EXIT(1);
        }
    }
    BN_free(r_mont);
    BN_free(r_mont_const);
    BN_free(r_recp);
    BN_free(r_simple);
    BN_free(a);
    BN_free(b);
    BN_free(m);
    BN_CTX_free(ctx);
    ERR_remove_thread_state(NULL);
    CRYPTO_mem_leaks(out);
    BIO_free(out);
    printf("\xa");

    if (test_exp_mod_zero() != 0)
        goto err;

    printf("\x64\x6f\x6e\x65\xa");

    EXIT(0);
 err:
    ERR_load_crypto_strings();
    ERR_print_errors(out);
#ifdef OPENSSL_SYS_NETWARE
    printf("\x45\x52\x52\x4f\x52\xa");
#endif
    EXIT(1);
    return (1);
}

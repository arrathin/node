/* Written by Ben Laurie, 2001 */
/*
 * Copyright (c) 2001-2019 The OpenSSL Project.  All rights reserved.
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
 */

#include <stdio.h>
#include <string.h>

#include "../e_os.h"

#include <openssl/opensslconf.h>
#include <openssl/evp.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif
#include <openssl/err.h>
#include <openssl/conf.h>

static void hexdump(FILE *f, const char *title, const unsigned char *s, int l)
{
    int n = 0;

    fprintf(f, "\x25\x73", title);
    for (; n < l; ++n) {
        if ((n % 16) == 0)
            fprintf(f, "\xa\x25\x30\x34\x78", n);
        fprintf(f, "\x20\x25\x30\x32\x78", s[n]);
    }
    fprintf(f, "\xa");
}

static int convert(unsigned char *s)
{
    unsigned char *d;
    int digits = 0;

    for (d = s; *s; s += 2, ++d) {
        unsigned int n;

        if (!s[1]) {
            fprintf(stderr, "\x4f\x64\x64\x20\x6e\x75\x6d\x62\x65\x72\x20\x6f\x66\x20\x68\x65\x78\x20\x64\x69\x67\x69\x74\x73\x21");
            EXIT(4);
        }
        sscanf((char *)s, "\x25\x32\x78", &n);
        *d = (unsigned char)n;
        digits++;
    }
    return digits;
}

static char *sstrsep(char **string, const char *delim)
{
    char isdelim[256];
    char *token = *string;

    if (**string == 0)
        return NULL;

    memset(isdelim, 0, 256);
    isdelim[0] = 1;

    while (*delim) {
        isdelim[(unsigned char)(*delim)] = 1;
        delim++;
    }

    while (!isdelim[(unsigned char)(**string)]) {
        (*string)++;
    }

    if (**string) {
        **string = 0;
        (*string)++;
    }

    return token;
}

static unsigned char *ustrsep(char **p, const char *sep)
{
    return (unsigned char *)sstrsep(p, sep);
}

static int test1_exit(int ec)
{
    EXIT(ec);
    return (0);                 /* To keep some compilers quiet */
}

static void test1(const EVP_CIPHER *c, const unsigned char *key, int kn,
                  const unsigned char *iv, int in,
                  const unsigned char *plaintext, int pn,
                  const unsigned char *ciphertext, int cn,
                  const unsigned char *aad, int an,
                  const unsigned char *tag, int tn, int encdec)
{
    EVP_CIPHER_CTX ctx;
    unsigned char out[4096];
    int outl, outl2, mode;

    printf("\x54\x65\x73\x74\x69\x6e\x67\x20\x63\x69\x70\x68\x65\x72\x20\x25\x73\x25\x73\xa", EVP_CIPHER_name(c),
           (encdec ==
            1 ? "\x28\x65\x6e\x63\x72\x79\x70\x74\x29" : (encdec ==
                               0 ? "\x28\x64\x65\x63\x72\x79\x70\x74\x29" : "\x28\x65\x6e\x63\x72\x79\x70\x74\x2f\x64\x65\x63\x72\x79\x70\x74\x29")));
    hexdump(stdout, "\x4b\x65\x79", key, kn);
    if (in)
        hexdump(stdout, "\x49\x56", iv, in);
    hexdump(stdout, "\x50\x6c\x61\x69\x6e\x74\x65\x78\x74", plaintext, pn);
    hexdump(stdout, "\x43\x69\x70\x68\x65\x72\x74\x65\x78\x74", ciphertext, cn);
    if (an)
        hexdump(stdout, "\x41\x41\x44", aad, an);
    if (tn)
        hexdump(stdout, "\x54\x61\x67", tag, tn);
    mode = EVP_CIPHER_mode(c);
    if (kn != EVP_CIPHER_key_length(c)) {
        fprintf(stderr, "\x4b\x65\x79\x20\x6c\x65\x6e\x67\x74\x68\x20\x64\x6f\x65\x73\x6e\x27\x74\x20\x6d\x61\x74\x63\x68\x2c\x20\x67\x6f\x74\x20\x25\x64\x20\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x6c\x75\xa", kn,
                (unsigned long)EVP_CIPHER_key_length(c));
        test1_exit(5);
    }
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CIPHER_CTX_set_flags(&ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (encdec != 0) {
        if (mode == EVP_CIPH_GCM_MODE) {
            if (!EVP_EncryptInit_ex(&ctx, c, NULL, NULL, NULL)) {
                fprintf(stderr, "\x45\x6e\x63\x72\x79\x70\x74\x49\x6e\x69\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(10);
            }
            if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, in, NULL)) {
                fprintf(stderr, "\x49\x56\x20\x6c\x65\x6e\x67\x74\x68\x20\x73\x65\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(11);
            }
            if (!EVP_EncryptInit_ex(&ctx, NULL, NULL, key, iv)) {
                fprintf(stderr, "\x4b\x65\x79\x2f\x49\x56\x20\x73\x65\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(12);
            }
            if (an && !EVP_EncryptUpdate(&ctx, NULL, &outl, aad, an)) {
                fprintf(stderr, "\x41\x41\x44\x20\x73\x65\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(13);
            }
        } else if (mode == EVP_CIPH_CCM_MODE) {
            if (!EVP_EncryptInit_ex(&ctx, c, NULL, NULL, NULL)) {
                fprintf(stderr, "\x45\x6e\x63\x72\x79\x70\x74\x49\x6e\x69\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(10);
            }
            if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, in, NULL)) {
                fprintf(stderr, "\x49\x56\x20\x6c\x65\x6e\x67\x74\x68\x20\x73\x65\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(11);
            }
            if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG, tn, NULL)) {
                fprintf(stderr, "\x54\x61\x67\x20\x6c\x65\x6e\x67\x74\x68\x20\x73\x65\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(11);
            }
            if (!EVP_EncryptInit_ex(&ctx, NULL, NULL, key, iv)) {
                fprintf(stderr, "\x4b\x65\x79\x2f\x49\x56\x20\x73\x65\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(12);
            }
            if (!EVP_EncryptUpdate(&ctx, NULL, &outl, NULL, pn)) {
                fprintf(stderr, "\x50\x6c\x61\x69\x6e\x74\x65\x78\x74\x20\x6c\x65\x6e\x67\x74\x68\x20\x73\x65\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(12);
            }
            if (an && !EVP_EncryptUpdate(&ctx, NULL, &outl, aad, an)) {
                fprintf(stderr, "\x41\x41\x44\x20\x73\x65\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(13);
            }
        } else if (mode == EVP_CIPH_WRAP_MODE) {
            if (!EVP_EncryptInit_ex(&ctx, c, NULL, key, in ? iv : NULL)) {
                fprintf(stderr, "\x45\x6e\x63\x72\x79\x70\x74\x49\x6e\x69\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(10);
            }
        } else if (!EVP_EncryptInit_ex(&ctx, c, NULL, key, iv)) {
            fprintf(stderr, "\x45\x6e\x63\x72\x79\x70\x74\x49\x6e\x69\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
            ERR_print_errors_fp(stderr);
            test1_exit(10);
        }
        EVP_CIPHER_CTX_set_padding(&ctx, 0);

        if (!EVP_EncryptUpdate(&ctx, out, &outl, plaintext, pn)) {
            fprintf(stderr, "\x45\x6e\x63\x72\x79\x70\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
            ERR_print_errors_fp(stderr);
            test1_exit(6);
        }
        if (!EVP_EncryptFinal_ex(&ctx, out + outl, &outl2)) {
            fprintf(stderr, "\x45\x6e\x63\x72\x79\x70\x74\x46\x69\x6e\x61\x6c\x20\x66\x61\x69\x6c\x65\x64\xa");
            ERR_print_errors_fp(stderr);
            test1_exit(7);
        }

        if (outl + outl2 != cn) {
            fprintf(stderr, "\x43\x69\x70\x68\x65\x72\x74\x65\x78\x74\x20\x6c\x65\x6e\x67\x74\x68\x20\x6d\x69\x73\x6d\x61\x74\x63\x68\x20\x67\x6f\x74\x20\x25\x64\x20\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x64\xa",
                    outl + outl2, cn);
            test1_exit(8);
        }

        if (memcmp(out, ciphertext, cn)) {
            fprintf(stderr, "\x43\x69\x70\x68\x65\x72\x74\x65\x78\x74\x20\x6d\x69\x73\x6d\x61\x74\x63\x68\xa");
            hexdump(stderr, "\x47\x6f\x74", out, cn);
            hexdump(stderr, "\x45\x78\x70\x65\x63\x74\x65\x64", ciphertext, cn);
            test1_exit(9);
        }
        if (mode == EVP_CIPH_GCM_MODE || mode == EVP_CIPH_CCM_MODE) {
            unsigned char rtag[16];
            /*
             * Note: EVP_CTRL_CCM_GET_TAG has same value as
             * EVP_CTRL_GCM_GET_TAG
             */
            if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_GET_TAG, tn, rtag)) {
                fprintf(stderr, "\x47\x65\x74\x20\x74\x61\x67\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(14);
            }
            if (memcmp(rtag, tag, tn)) {
                fprintf(stderr, "\x54\x61\x67\x20\x6d\x69\x73\x6d\x61\x74\x63\x68\xa");
                hexdump(stderr, "\x47\x6f\x74", rtag, tn);
                hexdump(stderr, "\x45\x78\x70\x65\x63\x74\x65\x64", tag, tn);
                test1_exit(9);
            }
        }
    }

    if (encdec <= 0) {
        if (mode == EVP_CIPH_GCM_MODE) {
            if (!EVP_DecryptInit_ex(&ctx, c, NULL, NULL, NULL)) {
                fprintf(stderr, "\x45\x6e\x63\x72\x79\x70\x74\x49\x6e\x69\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(10);
            }
            if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, in, NULL)) {
                fprintf(stderr, "\x49\x56\x20\x6c\x65\x6e\x67\x74\x68\x20\x73\x65\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(11);
            }
            if (!EVP_DecryptInit_ex(&ctx, NULL, NULL, key, iv)) {
                fprintf(stderr, "\x4b\x65\x79\x2f\x49\x56\x20\x73\x65\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(12);
            }
            if (!EVP_CIPHER_CTX_ctrl
                (&ctx, EVP_CTRL_GCM_SET_TAG, tn, (void *)tag)) {
                fprintf(stderr, "\x53\x65\x74\x20\x74\x61\x67\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(14);
            }
            if (an && !EVP_DecryptUpdate(&ctx, NULL, &outl, aad, an)) {
                fprintf(stderr, "\x41\x41\x44\x20\x73\x65\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(13);
            }
        } else if (mode == EVP_CIPH_CCM_MODE) {
            if (!EVP_DecryptInit_ex(&ctx, c, NULL, NULL, NULL)) {
                fprintf(stderr, "\x44\x65\x63\x72\x79\x70\x74\x49\x6e\x69\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(10);
            }
            if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, in, NULL)) {
                fprintf(stderr, "\x49\x56\x20\x6c\x65\x6e\x67\x74\x68\x20\x73\x65\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(11);
            }
            if (!EVP_CIPHER_CTX_ctrl
                (&ctx, EVP_CTRL_CCM_SET_TAG, tn, (void *)tag)) {
                fprintf(stderr, "\x54\x61\x67\x20\x6c\x65\x6e\x67\x74\x68\x20\x73\x65\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(11);
            }
            if (!EVP_DecryptInit_ex(&ctx, NULL, NULL, key, iv)) {
                fprintf(stderr, "\x4b\x65\x79\x2f\x4e\x6f\x6e\x63\x65\x20\x73\x65\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(12);
            }
            if (!EVP_DecryptUpdate(&ctx, NULL, &outl, NULL, pn)) {
                fprintf(stderr, "\x50\x6c\x61\x69\x6e\x74\x65\x78\x74\x20\x6c\x65\x6e\x67\x74\x68\x20\x73\x65\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(12);
            }
            if (an && !EVP_EncryptUpdate(&ctx, NULL, &outl, aad, an)) {
                fprintf(stderr, "\x41\x41\x44\x20\x73\x65\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(13);
            }
        } else if (mode == EVP_CIPH_WRAP_MODE) {
            if (!EVP_DecryptInit_ex(&ctx, c, NULL, key, in ? iv : NULL)) {
                fprintf(stderr, "\x45\x6e\x63\x72\x79\x70\x74\x49\x6e\x69\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
                ERR_print_errors_fp(stderr);
                test1_exit(10);
            }
        } else if (!EVP_DecryptInit_ex(&ctx, c, NULL, key, iv)) {
            fprintf(stderr, "\x44\x65\x63\x72\x79\x70\x74\x49\x6e\x69\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
            ERR_print_errors_fp(stderr);
            test1_exit(11);
        }
        EVP_CIPHER_CTX_set_padding(&ctx, 0);

        if (!EVP_DecryptUpdate(&ctx, out, &outl, ciphertext, cn)) {
            fprintf(stderr, "\x44\x65\x63\x72\x79\x70\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
            ERR_print_errors_fp(stderr);
            test1_exit(6);
        }
        if (mode != EVP_CIPH_CCM_MODE
            && !EVP_DecryptFinal_ex(&ctx, out + outl, &outl2)) {
            fprintf(stderr, "\x44\x65\x63\x72\x79\x70\x74\x46\x69\x6e\x61\x6c\x20\x66\x61\x69\x6c\x65\x64\xa");
            ERR_print_errors_fp(stderr);
            test1_exit(7);
        }

        if (outl + outl2 != pn) {
            fprintf(stderr, "\x50\x6c\x61\x69\x6e\x74\x65\x78\x74\x20\x6c\x65\x6e\x67\x74\x68\x20\x6d\x69\x73\x6d\x61\x74\x63\x68\x20\x67\x6f\x74\x20\x25\x64\x20\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x64\xa",
                    outl + outl2, pn);
            test1_exit(8);
        }

        if (memcmp(out, plaintext, pn)) {
            fprintf(stderr, "\x50\x6c\x61\x69\x6e\x74\x65\x78\x74\x20\x6d\x69\x73\x6d\x61\x74\x63\x68\xa");
            hexdump(stderr, "\x47\x6f\x74", out, pn);
            hexdump(stderr, "\x45\x78\x70\x65\x63\x74\x65\x64", plaintext, pn);
            test1_exit(9);
        }
    }

    EVP_CIPHER_CTX_cleanup(&ctx);

    printf("\xa");
}

static int test_cipher(const char *cipher, const unsigned char *key, int kn,
                       const unsigned char *iv, int in,
                       const unsigned char *plaintext, int pn,
                       const unsigned char *ciphertext, int cn,
                       const unsigned char *aad, int an,
                       const unsigned char *tag, int tn, int encdec)
{
    const EVP_CIPHER *c;

    c = EVP_get_cipherbyname(cipher);
    if (!c)
        return 0;

    test1(c, key, kn, iv, in, plaintext, pn, ciphertext, cn, aad, an, tag, tn,
          encdec);

    return 1;
}

static int test_digest(const char *digest,
                       const unsigned char *plaintext, int pn,
                       const unsigned char *ciphertext, unsigned int cn)
{
    const EVP_MD *d;
    EVP_MD_CTX ctx;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdn;

    d = EVP_get_digestbyname(digest);
    if (!d)
        return 0;

    printf("\x54\x65\x73\x74\x69\x6e\x67\x20\x64\x69\x67\x65\x73\x74\x20\x25\x73\xa", EVP_MD_name(d));
    hexdump(stdout, "\x50\x6c\x61\x69\x6e\x74\x65\x78\x74", plaintext, pn);
    hexdump(stdout, "\x44\x69\x67\x65\x73\x74", ciphertext, cn);

    EVP_MD_CTX_init(&ctx);
    if (!EVP_DigestInit_ex(&ctx, d, NULL)) {
        fprintf(stderr, "\x44\x69\x67\x65\x73\x74\x49\x6e\x69\x74\x20\x66\x61\x69\x6c\x65\x64\xa");
        ERR_print_errors_fp(stderr);
        EXIT(100);
    }
    if (!EVP_DigestUpdate(&ctx, plaintext, pn)) {
        fprintf(stderr, "\x44\x69\x67\x65\x73\x74\x55\x70\x64\x61\x74\x65\x20\x66\x61\x69\x6c\x65\x64\xa");
        ERR_print_errors_fp(stderr);
        EXIT(101);
    }
    if (!EVP_DigestFinal_ex(&ctx, md, &mdn)) {
        fprintf(stderr, "\x44\x69\x67\x65\x73\x74\x46\x69\x6e\x61\x6c\x20\x66\x61\x69\x6c\x65\x64\xa");
        ERR_print_errors_fp(stderr);
        EXIT(101);
    }
    EVP_MD_CTX_cleanup(&ctx);

    if (mdn != cn) {
        fprintf(stderr, "\x44\x69\x67\x65\x73\x74\x20\x6c\x65\x6e\x67\x74\x68\x20\x6d\x69\x73\x6d\x61\x74\x63\x68\x2c\x20\x67\x6f\x74\x20\x25\x64\x20\x65\x78\x70\x65\x63\x74\x65\x64\x20\x25\x64\xa", mdn,
                cn);
        EXIT(102);
    }

    if (memcmp(md, ciphertext, cn)) {
        fprintf(stderr, "\x44\x69\x67\x65\x73\x74\x20\x6d\x69\x73\x6d\x61\x74\x63\x68\xa");
        hexdump(stderr, "\x47\x6f\x74", md, cn);
        hexdump(stderr, "\x45\x78\x70\x65\x63\x74\x65\x64", ciphertext, cn);
        EXIT(103);
    }

    printf("\xa");

    EVP_MD_CTX_cleanup(&ctx);

    return 1;
}

int main(int argc, char **argv)
{
    const char *szTestFile;
    FILE *f;

    if (argc != 2) {
        fprintf(stderr, "\x25\x73\x20\x3c\x74\x65\x73\x74\x20\x66\x69\x6c\x65\x3e\xa", argv[0]);
        EXIT(1);
    }
    CRYPTO_malloc_debug_init();
    CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    szTestFile = argv[1];

    f = fopen(szTestFile, "\x72");
    if (!f) {
        perror(szTestFile);
        EXIT(2);
    }
    ERR_load_crypto_strings();
    /* Load up the software EVP_CIPHER and EVP_MD definitions */
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
#ifndef OPENSSL_NO_ENGINE
    /* Load all compiled-in ENGINEs */
    ENGINE_load_builtin_engines();
#endif
#if 0
    OPENSSL_config();
#endif
#ifndef OPENSSL_NO_ENGINE
    /*
     * Register all available ENGINE implementations of ciphers and digests.
     * This could perhaps be changed to "ENGINE_register_all_complete()"?
     */
    ENGINE_register_all_ciphers();
    ENGINE_register_all_digests();
    /*
     * If we add command-line options, this statement should be switchable.
     * It'll prevent ENGINEs being ENGINE_init()ialised for cipher/digest use
     * if they weren't already initialised.
     */
    /* ENGINE_set_cipher_flags(ENGINE_CIPHER_FLAG_NOINIT); */
#endif

    for (;;) {
        char line[4096];
        char *p;
        char *cipher;
        unsigned char *iv, *key, *plaintext, *ciphertext, *aad, *tag;
        int encdec;
        int kn, in, pn, cn;
        int an = 0;
        int tn = 0;

        if (!fgets((char *)line, sizeof(line), f))
            break;
        if (line[0] == '\x23' || line[0] == '\xa')
            continue;
        p = line;
        cipher = sstrsep(&p, "\x3a");
        key = ustrsep(&p, "\x3a");
        iv = ustrsep(&p, "\x3a");
        plaintext = ustrsep(&p, "\x3a");
        ciphertext = ustrsep(&p, "\x3a");
        if (p[-1] == '\xa') {
            encdec = -1;
            p[-1] = '\x0';
            tag = aad = NULL;
            an = tn = 0;
        } else {
            aad = ustrsep(&p, "\x3a");
            tag = ustrsep(&p, "\x3a");
            if (tag == NULL) {
                p = (char *)aad;
                tag = aad = NULL;
                an = tn = 0;
            }
            if (p[-1] == '\xa') {
                encdec = -1;
                p[-1] = '\x0';
            } else
                encdec = atoi(sstrsep(&p, "\xa"));
        }

        kn = convert(key);
        in = convert(iv);
        pn = convert(plaintext);
        cn = convert(ciphertext);
        if (aad) {
            an = convert(aad);
            tn = convert(tag);
        }

        if (!test_cipher
            (cipher, key, kn, iv, in, plaintext, pn, ciphertext, cn, aad, an,
             tag, tn, encdec)
            && !test_digest(cipher, plaintext, pn, ciphertext, cn)) {
#ifdef OPENSSL_NO_AES
            if (strstr(cipher, "\x41\x45\x53") == cipher) {
                fprintf(stdout, "\x43\x69\x70\x68\x65\x72\x20\x64\x69\x73\x61\x62\x6c\x65\x64\x2c\x20\x73\x6b\x69\x70\x70\x69\x6e\x67\x20\x25\x73\xa", cipher);
                continue;
            }
#endif
#ifdef OPENSSL_NO_DES
            if (strstr(cipher, "\x44\x45\x53") == cipher) {
                fprintf(stdout, "\x43\x69\x70\x68\x65\x72\x20\x64\x69\x73\x61\x62\x6c\x65\x64\x2c\x20\x73\x6b\x69\x70\x70\x69\x6e\x67\x20\x25\x73\xa", cipher);
                continue;
            }
#endif
#ifdef OPENSSL_NO_RC4
            if (strstr(cipher, "\x52\x43\x34") == cipher) {
                fprintf(stdout, "\x43\x69\x70\x68\x65\x72\x20\x64\x69\x73\x61\x62\x6c\x65\x64\x2c\x20\x73\x6b\x69\x70\x70\x69\x6e\x67\x20\x25\x73\xa", cipher);
                continue;
            }
#endif
#ifdef OPENSSL_NO_CAMELLIA
            if (strstr(cipher, "\x43\x41\x4d\x45\x4c\x4c\x49\x41") == cipher) {
                fprintf(stdout, "\x43\x69\x70\x68\x65\x72\x20\x64\x69\x73\x61\x62\x6c\x65\x64\x2c\x20\x73\x6b\x69\x70\x70\x69\x6e\x67\x20\x25\x73\xa", cipher);
                continue;
            }
#endif
#ifdef OPENSSL_NO_SEED
            if (strstr(cipher, "\x53\x45\x45\x44") == cipher) {
                fprintf(stdout, "\x43\x69\x70\x68\x65\x72\x20\x64\x69\x73\x61\x62\x6c\x65\x64\x2c\x20\x73\x6b\x69\x70\x70\x69\x6e\x67\x20\x25\x73\xa", cipher);
                continue;
            }
#endif
            fprintf(stderr, "\x43\x61\x6e\x27\x74\x20\x66\x69\x6e\x64\x20\x25\x73\xa", cipher);
            EXIT(3);
        }
    }
    fclose(f);

#ifndef OPENSSL_NO_ENGINE
    ENGINE_cleanup();
#endif
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();
    CRYPTO_mem_leaks_fp(stderr);

    return 0;
}

/* v3_scts.c */
/*
 * Written by Rob Stradling (rob@comodo.com) for the OpenSSL project 2014.
 */
/* ====================================================================
 * Copyright (c) 2014 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "\x4f\x70\x65\x6e\x53\x53\x4c\x20\x54\x6f\x6f\x6c\x6b\x69\x74" and "\x4f\x70\x65\x6e\x53\x53\x4c\x20\x50\x72\x6f\x6a\x65\x63\x74" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "\x4f\x70\x65\x6e\x53\x53\x4c"
 *    nor may "\x4f\x70\x65\x6e\x53\x53\x4c" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/x509v3.h>

/* Signature and hash algorithms from RFC 5246 */
#define TLSEXT_hash_sha256                              4

#define TLSEXT_signature_rsa                            1
#define TLSEXT_signature_ecdsa                          3


#define n2s(c,s)        ((s=(((unsigned int)(c[0]))<< 8)| \
                            (((unsigned int)(c[1]))    )),c+=2)

#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
# define SCT_TIMESTAMP unsigned __int64
#elif defined(__arch64__)
# define SCT_TIMESTAMP unsigned long
#else
# define SCT_TIMESTAMP unsigned long long
#endif

#define n2l8(c,l)       (l =((SCT_TIMESTAMP)(*((c)++)))<<56, \
                         l|=((SCT_TIMESTAMP)(*((c)++)))<<48, \
                         l|=((SCT_TIMESTAMP)(*((c)++)))<<40, \
                         l|=((SCT_TIMESTAMP)(*((c)++)))<<32, \
                         l|=((SCT_TIMESTAMP)(*((c)++)))<<24, \
                         l|=((SCT_TIMESTAMP)(*((c)++)))<<16, \
                         l|=((SCT_TIMESTAMP)(*((c)++)))<< 8, \
                         l|=((SCT_TIMESTAMP)(*((c)++))))

typedef struct SCT_st {
    /* The encoded SCT */
    unsigned char *sct;
    unsigned short sctlen;
    /*
     * Components of the SCT.  "logid", "ext" and "sig" point to addresses
     * inside "sct".
     */
    unsigned char version;
    unsigned char *logid;
    unsigned short logidlen;
    SCT_TIMESTAMP timestamp;
    unsigned char *ext;
    unsigned short extlen;
    unsigned char hash_alg;
    unsigned char sig_alg;
    unsigned char *sig;
    unsigned short siglen;
} SCT;

DECLARE_STACK_OF(SCT)

static void SCT_LIST_free(STACK_OF(SCT) *a);
static STACK_OF(SCT) *d2i_SCT_LIST(STACK_OF(SCT) **a,
                                   const unsigned char **pp, long length);
static int i2r_SCT_LIST(X509V3_EXT_METHOD *method, STACK_OF(SCT) *sct_list,
                        BIO *out, int indent);

const X509V3_EXT_METHOD v3_ct_scts[] = {
    {NID_ct_precert_scts, 0, NULL,
     0, (X509V3_EXT_FREE)SCT_LIST_free,
     (X509V3_EXT_D2I)d2i_SCT_LIST, 0,
     0, 0, 0, 0,
     (X509V3_EXT_I2R)i2r_SCT_LIST, 0,
     NULL},

    {NID_ct_cert_scts, 0, NULL,
     0, (X509V3_EXT_FREE)SCT_LIST_free,
     (X509V3_EXT_D2I)d2i_SCT_LIST, 0,
     0, 0, 0, 0,
     (X509V3_EXT_I2R)i2r_SCT_LIST, 0,
     NULL},
};

static void tls12_signature_print(BIO *out, const unsigned char hash_alg,
                                  const unsigned char sig_alg)
{
    int nid = NID_undef;
    /* RFC6962 only permits two signature algorithms */
    if (hash_alg == TLSEXT_hash_sha256) {
        if (sig_alg == TLSEXT_signature_rsa)
            nid = NID_sha256WithRSAEncryption;
        else if (sig_alg == TLSEXT_signature_ecdsa)
            nid = NID_ecdsa_with_SHA256;
    }
    if (nid == NID_undef)
        BIO_printf(out, "\x25\x30\x32\x58\x25\x30\x32\x58", hash_alg, sig_alg);
    else
        BIO_printf(out, "\x25\x73", OBJ_nid2ln(nid));
}

static void timestamp_print(BIO *out, SCT_TIMESTAMP timestamp)
{
    ASN1_GENERALIZEDTIME *gen;
    char genstr[20];
    gen = ASN1_GENERALIZEDTIME_new();
    ASN1_GENERALIZEDTIME_adj(gen, (time_t)0,
                             (int)(timestamp / 86400000),
                             (int)(timestamp % 86400000) / 1000);
    /*
     * Note GeneralizedTime from ASN1_GENERALIZETIME_adj is always 15
     * characters long with a final Z. Update it with fractional seconds.
     */
    BIO_snprintf(genstr, sizeof(genstr), "\x25\x2e\x31\x34\x73\x2e\x25\x30\x33\x64\x5a",
                 ASN1_STRING_data(gen), (unsigned int)(timestamp % 1000));
    ASN1_GENERALIZEDTIME_set_string(gen, genstr);
    ASN1_GENERALIZEDTIME_print(out, gen);
    ASN1_GENERALIZEDTIME_free(gen);
}

static void SCT_free(SCT *sct)
{
    if (sct) {
        if (sct->sct)
            OPENSSL_free(sct->sct);
        OPENSSL_free(sct);
    }
}

static void SCT_LIST_free(STACK_OF(SCT) *a)
{
    sk_SCT_pop_free(a, SCT_free);
}

static STACK_OF(SCT) *d2i_SCT_LIST(STACK_OF(SCT) **a,
                                   const unsigned char **pp, long length)
{
    ASN1_OCTET_STRING *oct = NULL;
    STACK_OF(SCT) *sk = NULL;
    SCT *sct;
    unsigned char *p, *p2;
    unsigned short listlen, sctlen = 0, fieldlen;
    const unsigned char *q = *pp;

    if (d2i_ASN1_OCTET_STRING(&oct, &q, length) == NULL)
        return NULL;
    if (oct->length < 2)
        goto done;
    p = oct->data;
    n2s(p, listlen);
    if (listlen != oct->length - 2)
        goto done;

    if ((sk = sk_SCT_new_null()) == NULL)
        goto done;

    while (listlen > 0) {
        if (listlen < 2)
            goto err;
        n2s(p, sctlen);
        listlen -= 2;

        if ((sctlen < 1) || (sctlen > listlen))
            goto err;
        listlen -= sctlen;

        sct = OPENSSL_malloc(sizeof(SCT));
        if (!sct)
            goto err;
        if (!sk_SCT_push(sk, sct)) {
            OPENSSL_free(sct);
            goto err;
        }

        sct->sct = OPENSSL_malloc(sctlen);
        if (!sct->sct)
            goto err;
        memcpy(sct->sct, p, sctlen);
        sct->sctlen = sctlen;
        p += sctlen;
        p2 = sct->sct;

        sct->version = *p2++;
        if (sct->version == 0) { /* SCT v1 */
            /*-
             * Fixed-length header:
             *              struct {
             * (1 byte)       Version sct_version;
             * (32 bytes)     LogID id;
             * (8 bytes)      uint64 timestamp;
             * (2 bytes + ?)  CtExtensions extensions;
             */
            if (sctlen < 43)
                goto err;
            sctlen -= 43;

            sct->logid = p2;
            sct->logidlen = 32;
            p2 += 32;

            n2l8(p2, sct->timestamp);

            n2s(p2, fieldlen);
            if (sctlen < fieldlen)
                goto err;
            sct->ext = p2;
            sct->extlen = fieldlen;
            p2 += fieldlen;
            sctlen -= fieldlen;

            /*-
             * digitally-signed struct header:
             * (1 byte)       Hash algorithm
             * (1 byte)       Signature algorithm
             * (2 bytes + ?)  Signature
             */
            if (sctlen < 4)
                goto err;
            sctlen -= 4;

            sct->hash_alg = *p2++;
            sct->sig_alg = *p2++;
            n2s(p2, fieldlen);
            if (sctlen != fieldlen)
                goto err;
            sct->sig = p2;
            sct->siglen = fieldlen;
        }
    }

 done:
    ASN1_OCTET_STRING_free(oct);
    *pp = q;
    return sk;

 err:
    SCT_LIST_free(sk);
    sk = NULL;
    goto done;
}

static int i2r_SCT_LIST(X509V3_EXT_METHOD *method, STACK_OF(SCT) *sct_list,
                        BIO *out, int indent)
{
    SCT *sct;
    int i;

    for (i = 0; i < sk_SCT_num(sct_list);) {
        sct = sk_SCT_value(sct_list, i);

        BIO_printf(out, "\x25\x2a\x73\x53\x69\x67\x6e\x65\x64\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x54\x69\x6d\x65\x73\x74\x61\x6d\x70\x3a", indent, "");
        BIO_printf(out, "\xa\x25\x2a\x73\x56\x65\x72\x73\x69\x6f\x6e\x20\x20\x20\x3a\x20", indent + 4, "");

        if (sct->version == 0) { /* SCT v1 */
            BIO_printf(out, "\x76\x31\x28\x30\x29");

            BIO_printf(out, "\xa\x25\x2a\x73\x4c\x6f\x67\x20\x49\x44\x20\x20\x20\x20\x3a\x20", indent + 4, "");
            BIO_hex_string(out, indent + 16, 16, sct->logid, sct->logidlen);

            BIO_printf(out, "\xa\x25\x2a\x73\x54\x69\x6d\x65\x73\x74\x61\x6d\x70\x20\x3a\x20", indent + 4, "");
            timestamp_print(out, sct->timestamp);

            BIO_printf(out, "\xa\x25\x2a\x73\x45\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73\x3a\x20", indent + 4, "");
            if (sct->extlen == 0)
                BIO_printf(out, "\x6e\x6f\x6e\x65");
            else
                BIO_hex_string(out, indent + 16, 16, sct->ext, sct->extlen);

            BIO_printf(out, "\xa\x25\x2a\x73\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x3a\x20", indent + 4, "");
            tls12_signature_print(out, sct->hash_alg, sct->sig_alg);
            BIO_printf(out, "\xa\x25\x2a\x73\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20", indent + 4, "");
            BIO_hex_string(out, indent + 16, 16, sct->sig, sct->siglen);
        } else {                /* Unknown version */

            BIO_printf(out, "\x75\x6e\x6b\x6e\x6f\x77\x6e\xa\x25\x2a\x73", indent + 16, "");
            BIO_hex_string(out, indent + 16, 16, sct->sct, sct->sctlen);
        }

        if (++i < sk_SCT_num(sct_list))
            BIO_printf(out, "\xa");
    }

    return 1;
}

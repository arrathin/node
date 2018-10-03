/* crypto/pem/pem.h */
/* Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
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

#ifndef HEADER_PEM_H
# define HEADER_PEM_H

# include <openssl/e_os2.h>
# ifndef OPENSSL_NO_BIO
#  include <openssl/bio.h>
# endif
# ifndef OPENSSL_NO_STACK
#  include <openssl/stack.h>
# endif
# include <openssl/evp.h>
# include <openssl/x509.h>
# include <openssl/pem2.h>

#ifdef  __cplusplus
extern "C" {
#endif

# define PEM_BUFSIZE             1024

# define PEM_OBJ_UNDEF           0
# define PEM_OBJ_X509            1
# define PEM_OBJ_X509_REQ        2
# define PEM_OBJ_CRL             3
# define PEM_OBJ_SSL_SESSION     4
# define PEM_OBJ_PRIV_KEY        10
# define PEM_OBJ_PRIV_RSA        11
# define PEM_OBJ_PRIV_DSA        12
# define PEM_OBJ_PRIV_DH         13
# define PEM_OBJ_PUB_RSA         14
# define PEM_OBJ_PUB_DSA         15
# define PEM_OBJ_PUB_DH          16
# define PEM_OBJ_DHPARAMS        17
# define PEM_OBJ_DSAPARAMS       18
# define PEM_OBJ_PRIV_RSA_PUBLIC 19
# define PEM_OBJ_PRIV_ECDSA      20
# define PEM_OBJ_PUB_ECDSA       21
# define PEM_OBJ_ECPARAMETERS    22

# define PEM_ERROR               30
# define PEM_DEK_DES_CBC         40
# define PEM_DEK_IDEA_CBC        45
# define PEM_DEK_DES_EDE         50
# define PEM_DEK_DES_ECB         60
# define PEM_DEK_RSA             70
# define PEM_DEK_RSA_MD2         80
# define PEM_DEK_RSA_MD5         90

# define PEM_MD_MD2              NID_md2
# define PEM_MD_MD5              NID_md5
# define PEM_MD_SHA              NID_sha
# define PEM_MD_MD2_RSA          NID_md2WithRSAEncryption
# define PEM_MD_MD5_RSA          NID_md5WithRSAEncryption
# define PEM_MD_SHA_RSA          NID_sha1WithRSAEncryption

# define PEM_STRING_X509_OLD     "\x58\x35\x30\x39\x20\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x45"
# define PEM_STRING_X509         "\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x45"
# define PEM_STRING_X509_PAIR    "\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x45\x20\x50\x41\x49\x52"
# define PEM_STRING_X509_TRUSTED "\x54\x52\x55\x53\x54\x45\x44\x20\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x45"
# define PEM_STRING_X509_REQ_OLD "\x4e\x45\x57\x20\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x45\x20\x52\x45\x51\x55\x45\x53\x54"
# define PEM_STRING_X509_REQ     "\x43\x45\x52\x54\x49\x46\x49\x43\x41\x54\x45\x20\x52\x45\x51\x55\x45\x53\x54"
# define PEM_STRING_X509_CRL     "\x58\x35\x30\x39\x20\x43\x52\x4c"
# define PEM_STRING_EVP_PKEY     "\x41\x4e\x59\x20\x50\x52\x49\x56\x41\x54\x45\x20\x4b\x45\x59"
# define PEM_STRING_PUBLIC       "\x50\x55\x42\x4c\x49\x43\x20\x4b\x45\x59"
# define PEM_STRING_RSA          "\x52\x53\x41\x20\x50\x52\x49\x56\x41\x54\x45\x20\x4b\x45\x59"
# define PEM_STRING_RSA_PUBLIC   "\x52\x53\x41\x20\x50\x55\x42\x4c\x49\x43\x20\x4b\x45\x59"
# define PEM_STRING_DSA          "\x44\x53\x41\x20\x50\x52\x49\x56\x41\x54\x45\x20\x4b\x45\x59"
# define PEM_STRING_DSA_PUBLIC   "\x44\x53\x41\x20\x50\x55\x42\x4c\x49\x43\x20\x4b\x45\x59"
# define PEM_STRING_PKCS7        "\x50\x4b\x43\x53\x37"
# define PEM_STRING_PKCS7_SIGNED "\x50\x4b\x43\x53\x20\x23\x37\x20\x53\x49\x47\x4e\x45\x44\x20\x44\x41\x54\x41"
# define PEM_STRING_PKCS8        "\x45\x4e\x43\x52\x59\x50\x54\x45\x44\x20\x50\x52\x49\x56\x41\x54\x45\x20\x4b\x45\x59"
# define PEM_STRING_PKCS8INF     "\x50\x52\x49\x56\x41\x54\x45\x20\x4b\x45\x59"
# define PEM_STRING_DHPARAMS     "\x44\x48\x20\x50\x41\x52\x41\x4d\x45\x54\x45\x52\x53"
# define PEM_STRING_DHXPARAMS    "\x58\x39\x2e\x34\x32\x20\x44\x48\x20\x50\x41\x52\x41\x4d\x45\x54\x45\x52\x53"
# define PEM_STRING_SSL_SESSION  "\x53\x53\x4c\x20\x53\x45\x53\x53\x49\x4f\x4e\x20\x50\x41\x52\x41\x4d\x45\x54\x45\x52\x53"
# define PEM_STRING_DSAPARAMS    "\x44\x53\x41\x20\x50\x41\x52\x41\x4d\x45\x54\x45\x52\x53"
# define PEM_STRING_ECDSA_PUBLIC "\x45\x43\x44\x53\x41\x20\x50\x55\x42\x4c\x49\x43\x20\x4b\x45\x59"
# define PEM_STRING_ECPARAMETERS "\x45\x43\x20\x50\x41\x52\x41\x4d\x45\x54\x45\x52\x53"
# define PEM_STRING_ECPRIVATEKEY "\x45\x43\x20\x50\x52\x49\x56\x41\x54\x45\x20\x4b\x45\x59"
# define PEM_STRING_PARAMETERS   "\x50\x41\x52\x41\x4d\x45\x54\x45\x52\x53"
# define PEM_STRING_CMS          "\x43\x4d\x53"

  /*
   * Note that this structure is initialised by PEM_SealInit and cleaned up
   * by PEM_SealFinal (at least for now)
   */
typedef struct PEM_Encode_Seal_st {
    EVP_ENCODE_CTX encode;
    EVP_MD_CTX md;
    EVP_CIPHER_CTX cipher;
} PEM_ENCODE_SEAL_CTX;

/* enc_type is one off */
# define PEM_TYPE_ENCRYPTED      10
# define PEM_TYPE_MIC_ONLY       20
# define PEM_TYPE_MIC_CLEAR      30
# define PEM_TYPE_CLEAR          40

typedef struct pem_recip_st {
    char *name;
    X509_NAME *dn;
    int cipher;
    int key_enc;
    /*      char iv[8]; unused and wrong size */
} PEM_USER;

typedef struct pem_ctx_st {
    int type;                   /* what type of object */
    struct {
        int version;
        int mode;
    } proc_type;

    char *domain;

    struct {
        int cipher;
        /*-
        unused, and wrong size
        unsigned char iv[8]; */
    } DEK_info;

    PEM_USER *originator;

    int num_recipient;
    PEM_USER **recipient;
/*-
    XXX(ben): don#t think this is used!
        STACK *x509_chain;      / * certificate chain */
    EVP_MD *md;                 /* signature type */

    int md_enc;                 /* is the md encrypted or not? */
    int md_len;                 /* length of md_data */
    char *md_data;              /* message digest, could be pkey encrypted */

    EVP_CIPHER *dec;            /* date encryption cipher */
    int key_len;                /* key length */
    unsigned char *key;         /* key */
  /*-
    unused, and wrong size
    unsigned char iv[8]; */

    int data_enc;               /* is the data encrypted */
    int data_len;
    unsigned char *data;
} PEM_CTX;

/*
 * These macros make the PEM_read/PEM_write functions easier to maintain and
 * write. Now they are all implemented with either: IMPLEMENT_PEM_rw(...) or
 * IMPLEMENT_PEM_rw_cb(...)
 */

# ifdef OPENSSL_NO_FP_API

#  define IMPLEMENT_PEM_read_fp(name, type, str, asn1) /**/
#  define IMPLEMENT_PEM_write_fp(name, type, str, asn1) /**/
#  define IMPLEMENT_PEM_write_fp_const(name, type, str, asn1) /**/
#  define IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1) /**/
#  define IMPLEMENT_PEM_write_cb_fp_const(name, type, str, asn1) /**/
# else

#  define IMPLEMENT_PEM_read_fp(name, type, str, asn1) \
type *PEM_read_##name(FILE *fp, type **x, pem_password_cb *cb, void *u)\
{ \
return PEM_ASN1_read((d2i_of_void *)d2i_##asn1, str,fp,(void **)x,cb,u); \
}

#  define IMPLEMENT_PEM_write_fp(name, type, str, asn1) \
int PEM_write_##name(FILE *fp, type *x) \
{ \
return PEM_ASN1_write((i2d_of_void *)i2d_##asn1,str,fp,x,NULL,NULL,0,NULL,NULL); \
}

#  define IMPLEMENT_PEM_write_fp_const(name, type, str, asn1) \
int PEM_write_##name(FILE *fp, const type *x) \
{ \
return PEM_ASN1_write((i2d_of_void *)i2d_##asn1,str,fp,(void *)x,NULL,NULL,0,NULL,NULL); \
}

#  define IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1) \
int PEM_write_##name(FILE *fp, type *x, const EVP_CIPHER *enc, \
             unsigned char *kstr, int klen, pem_password_cb *cb, \
                  void *u) \
        { \
        return PEM_ASN1_write((i2d_of_void *)i2d_##asn1,str,fp,x,enc,kstr,klen,cb,u); \
        }

#  define IMPLEMENT_PEM_write_cb_fp_const(name, type, str, asn1) \
int PEM_write_##name(FILE *fp, type *x, const EVP_CIPHER *enc, \
             unsigned char *kstr, int klen, pem_password_cb *cb, \
                  void *u) \
        { \
        return PEM_ASN1_write((i2d_of_void *)i2d_##asn1,str,fp,x,enc,kstr,klen,cb,u); \
        }

# endif

# define IMPLEMENT_PEM_read_bio(name, type, str, asn1) \
type *PEM_read_bio_##name(BIO *bp, type **x, pem_password_cb *cb, void *u)\
{ \
return PEM_ASN1_read_bio((d2i_of_void *)d2i_##asn1, str,bp,(void **)x,cb,u); \
}

# define IMPLEMENT_PEM_write_bio(name, type, str, asn1) \
int PEM_write_bio_##name(BIO *bp, type *x) \
{ \
return PEM_ASN1_write_bio((i2d_of_void *)i2d_##asn1,str,bp,x,NULL,NULL,0,NULL,NULL); \
}

# define IMPLEMENT_PEM_write_bio_const(name, type, str, asn1) \
int PEM_write_bio_##name(BIO *bp, const type *x) \
{ \
return PEM_ASN1_write_bio((i2d_of_void *)i2d_##asn1,str,bp,(void *)x,NULL,NULL,0,NULL,NULL); \
}

# define IMPLEMENT_PEM_write_cb_bio(name, type, str, asn1) \
int PEM_write_bio_##name(BIO *bp, type *x, const EVP_CIPHER *enc, \
             unsigned char *kstr, int klen, pem_password_cb *cb, void *u) \
        { \
        return PEM_ASN1_write_bio((i2d_of_void *)i2d_##asn1,str,bp,x,enc,kstr,klen,cb,u); \
        }

# define IMPLEMENT_PEM_write_cb_bio_const(name, type, str, asn1) \
int PEM_write_bio_##name(BIO *bp, type *x, const EVP_CIPHER *enc, \
             unsigned char *kstr, int klen, pem_password_cb *cb, void *u) \
        { \
        return PEM_ASN1_write_bio((i2d_of_void *)i2d_##asn1,str,bp,(void *)x,enc,kstr,klen,cb,u); \
        }

# define IMPLEMENT_PEM_write(name, type, str, asn1) \
        IMPLEMENT_PEM_write_bio(name, type, str, asn1) \
        IMPLEMENT_PEM_write_fp(name, type, str, asn1)

# define IMPLEMENT_PEM_write_const(name, type, str, asn1) \
        IMPLEMENT_PEM_write_bio_const(name, type, str, asn1) \
        IMPLEMENT_PEM_write_fp_const(name, type, str, asn1)

# define IMPLEMENT_PEM_write_cb(name, type, str, asn1) \
        IMPLEMENT_PEM_write_cb_bio(name, type, str, asn1) \
        IMPLEMENT_PEM_write_cb_fp(name, type, str, asn1)

# define IMPLEMENT_PEM_write_cb_const(name, type, str, asn1) \
        IMPLEMENT_PEM_write_cb_bio_const(name, type, str, asn1) \
        IMPLEMENT_PEM_write_cb_fp_const(name, type, str, asn1)

# define IMPLEMENT_PEM_read(name, type, str, asn1) \
        IMPLEMENT_PEM_read_bio(name, type, str, asn1) \
        IMPLEMENT_PEM_read_fp(name, type, str, asn1)

# define IMPLEMENT_PEM_rw(name, type, str, asn1) \
        IMPLEMENT_PEM_read(name, type, str, asn1) \
        IMPLEMENT_PEM_write(name, type, str, asn1)

# define IMPLEMENT_PEM_rw_const(name, type, str, asn1) \
        IMPLEMENT_PEM_read(name, type, str, asn1) \
        IMPLEMENT_PEM_write_const(name, type, str, asn1)

# define IMPLEMENT_PEM_rw_cb(name, type, str, asn1) \
        IMPLEMENT_PEM_read(name, type, str, asn1) \
        IMPLEMENT_PEM_write_cb(name, type, str, asn1)

/* These are the same except they are for the declarations */

# if defined(OPENSSL_NO_FP_API)

#  define DECLARE_PEM_read_fp(name, type) /**/
#  define DECLARE_PEM_write_fp(name, type) /**/
#  define DECLARE_PEM_write_cb_fp(name, type) /**/
# else

#  define DECLARE_PEM_read_fp(name, type) \
        type *PEM_read_##name(FILE *fp, type **x, pem_password_cb *cb, void *u);

#  define DECLARE_PEM_write_fp(name, type) \
        int PEM_write_##name(FILE *fp, type *x);

#  define DECLARE_PEM_write_fp_const(name, type) \
        int PEM_write_##name(FILE *fp, const type *x);

#  define DECLARE_PEM_write_cb_fp(name, type) \
        int PEM_write_##name(FILE *fp, type *x, const EVP_CIPHER *enc, \
             unsigned char *kstr, int klen, pem_password_cb *cb, void *u);

# endif

# ifndef OPENSSL_NO_BIO
#  define DECLARE_PEM_read_bio(name, type) \
        type *PEM_read_bio_##name(BIO *bp, type **x, pem_password_cb *cb, void *u);

#  define DECLARE_PEM_write_bio(name, type) \
        int PEM_write_bio_##name(BIO *bp, type *x);

#  define DECLARE_PEM_write_bio_const(name, type) \
        int PEM_write_bio_##name(BIO *bp, const type *x);

#  define DECLARE_PEM_write_cb_bio(name, type) \
        int PEM_write_bio_##name(BIO *bp, type *x, const EVP_CIPHER *enc, \
             unsigned char *kstr, int klen, pem_password_cb *cb, void *u);

# else

#  define DECLARE_PEM_read_bio(name, type) /**/
#  define DECLARE_PEM_write_bio(name, type) /**/
#  define DECLARE_PEM_write_bio_const(name, type) /**/
#  define DECLARE_PEM_write_cb_bio(name, type) /**/
# endif
# define DECLARE_PEM_write(name, type) \
        DECLARE_PEM_write_bio(name, type) \
        DECLARE_PEM_write_fp(name, type)
# define DECLARE_PEM_write_const(name, type) \
        DECLARE_PEM_write_bio_const(name, type) \
        DECLARE_PEM_write_fp_const(name, type)
# define DECLARE_PEM_write_cb(name, type) \
        DECLARE_PEM_write_cb_bio(name, type) \
        DECLARE_PEM_write_cb_fp(name, type)
# define DECLARE_PEM_read(name, type) \
        DECLARE_PEM_read_bio(name, type) \
        DECLARE_PEM_read_fp(name, type)
# define DECLARE_PEM_rw(name, type) \
        DECLARE_PEM_read(name, type) \
        DECLARE_PEM_write(name, type)
# define DECLARE_PEM_rw_const(name, type) \
        DECLARE_PEM_read(name, type) \
        DECLARE_PEM_write_const(name, type)
# define DECLARE_PEM_rw_cb(name, type) \
        DECLARE_PEM_read(name, type) \
        DECLARE_PEM_write_cb(name, type)
# if 1
/* "userdata": new with OpenSSL 0.9.4 */
typedef int pem_password_cb (char *buf, int size, int rwflag, void *userdata);
# else
/* OpenSSL 0.9.3, 0.9.3a */
typedef int pem_password_cb (char *buf, int size, int rwflag);
# endif

int PEM_get_EVP_CIPHER_INFO(char *header, EVP_CIPHER_INFO *cipher);
int PEM_do_header(EVP_CIPHER_INFO *cipher, unsigned char *data, long *len,
                  pem_password_cb *callback, void *u);

# ifndef OPENSSL_NO_BIO
int PEM_read_bio(BIO *bp, char **name, char **header,
                 unsigned char **data, long *len);
int PEM_write_bio(BIO *bp, const char *name, const char *hdr,
                  const unsigned char *data, long len);
int PEM_bytes_read_bio(unsigned char **pdata, long *plen, char **pnm,
                       const char *name, BIO *bp, pem_password_cb *cb,
                       void *u);
void *PEM_ASN1_read_bio(d2i_of_void *d2i, const char *name, BIO *bp, void **x,
                        pem_password_cb *cb, void *u);
int PEM_ASN1_write_bio(i2d_of_void *i2d, const char *name, BIO *bp, void *x,
                       const EVP_CIPHER *enc, unsigned char *kstr, int klen,
                       pem_password_cb *cb, void *u);

STACK_OF(X509_INFO) *PEM_X509_INFO_read_bio(BIO *bp, STACK_OF(X509_INFO) *sk,
                                            pem_password_cb *cb, void *u);
int PEM_X509_INFO_write_bio(BIO *bp, X509_INFO *xi, EVP_CIPHER *enc,
                            unsigned char *kstr, int klen,
                            pem_password_cb *cd, void *u);
# endif

int PEM_read(FILE *fp, char **name, char **header,
             unsigned char **data, long *len);
int PEM_write(FILE *fp, const char *name, const char *hdr,
              const unsigned char *data, long len);
void *PEM_ASN1_read(d2i_of_void *d2i, const char *name, FILE *fp, void **x,
                    pem_password_cb *cb, void *u);
int PEM_ASN1_write(i2d_of_void *i2d, const char *name, FILE *fp,
                   void *x, const EVP_CIPHER *enc, unsigned char *kstr,
                   int klen, pem_password_cb *callback, void *u);
STACK_OF(X509_INFO) *PEM_X509_INFO_read(FILE *fp, STACK_OF(X509_INFO) *sk,
                                        pem_password_cb *cb, void *u);

int PEM_SealInit(PEM_ENCODE_SEAL_CTX *ctx, EVP_CIPHER *type,
                 EVP_MD *md_type, unsigned char **ek, int *ekl,
                 unsigned char *iv, EVP_PKEY **pubk, int npubk);
void PEM_SealUpdate(PEM_ENCODE_SEAL_CTX *ctx, unsigned char *out, int *outl,
                    unsigned char *in, int inl);
int PEM_SealFinal(PEM_ENCODE_SEAL_CTX *ctx, unsigned char *sig, int *sigl,
                  unsigned char *out, int *outl, EVP_PKEY *priv);

void PEM_SignInit(EVP_MD_CTX *ctx, EVP_MD *type);
void PEM_SignUpdate(EVP_MD_CTX *ctx, unsigned char *d, unsigned int cnt);
int PEM_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
                  unsigned int *siglen, EVP_PKEY *pkey);

/* The default pem_password_cb that's used internally */
int PEM_def_callback(char *buf, int num, int rwflag, void *userdata);
void PEM_proc_type(char *buf, int type);
void PEM_dek_info(char *buf, const char *type, int len, char *str);

# include <openssl/symhacks.h>

DECLARE_PEM_rw(X509, X509)
DECLARE_PEM_rw(X509_AUX, X509)
DECLARE_PEM_rw(X509_CERT_PAIR, X509_CERT_PAIR)
DECLARE_PEM_rw(X509_REQ, X509_REQ)
DECLARE_PEM_write(X509_REQ_NEW, X509_REQ)
DECLARE_PEM_rw(X509_CRL, X509_CRL)
DECLARE_PEM_rw(PKCS7, PKCS7)
DECLARE_PEM_rw(NETSCAPE_CERT_SEQUENCE, NETSCAPE_CERT_SEQUENCE)
DECLARE_PEM_rw(PKCS8, X509_SIG)
DECLARE_PEM_rw(PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO)
# ifndef OPENSSL_NO_RSA
DECLARE_PEM_rw_cb(RSAPrivateKey, RSA)
DECLARE_PEM_rw_const(RSAPublicKey, RSA)
DECLARE_PEM_rw(RSA_PUBKEY, RSA)
# endif
# ifndef OPENSSL_NO_DSA
DECLARE_PEM_rw_cb(DSAPrivateKey, DSA)
DECLARE_PEM_rw(DSA_PUBKEY, DSA)
DECLARE_PEM_rw_const(DSAparams, DSA)
# endif
# ifndef OPENSSL_NO_EC
DECLARE_PEM_rw_const(ECPKParameters, EC_GROUP)
DECLARE_PEM_rw_cb(ECPrivateKey, EC_KEY)
DECLARE_PEM_rw(EC_PUBKEY, EC_KEY)
# endif
# ifndef OPENSSL_NO_DH
DECLARE_PEM_rw_const(DHparams, DH)
DECLARE_PEM_write_const(DHxparams, DH)
# endif
DECLARE_PEM_rw_cb(PrivateKey, EVP_PKEY)
DECLARE_PEM_rw(PUBKEY, EVP_PKEY)

int PEM_write_bio_PKCS8PrivateKey_nid(BIO *bp, EVP_PKEY *x, int nid,
                                      char *kstr, int klen,
                                      pem_password_cb *cb, void *u);
int PEM_write_bio_PKCS8PrivateKey(BIO *, EVP_PKEY *, const EVP_CIPHER *,
                                  char *, int, pem_password_cb *, void *);
int i2d_PKCS8PrivateKey_bio(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
                            char *kstr, int klen,
                            pem_password_cb *cb, void *u);
int i2d_PKCS8PrivateKey_nid_bio(BIO *bp, EVP_PKEY *x, int nid,
                                char *kstr, int klen,
                                pem_password_cb *cb, void *u);
EVP_PKEY *d2i_PKCS8PrivateKey_bio(BIO *bp, EVP_PKEY **x, pem_password_cb *cb,
                                  void *u);

int i2d_PKCS8PrivateKey_fp(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc,
                           char *kstr, int klen,
                           pem_password_cb *cb, void *u);
int i2d_PKCS8PrivateKey_nid_fp(FILE *fp, EVP_PKEY *x, int nid,
                               char *kstr, int klen,
                               pem_password_cb *cb, void *u);
int PEM_write_PKCS8PrivateKey_nid(FILE *fp, EVP_PKEY *x, int nid,
                                  char *kstr, int klen,
                                  pem_password_cb *cb, void *u);

EVP_PKEY *d2i_PKCS8PrivateKey_fp(FILE *fp, EVP_PKEY **x, pem_password_cb *cb,
                                 void *u);

int PEM_write_PKCS8PrivateKey(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc,
                              char *kstr, int klen, pem_password_cb *cd,
                              void *u);

EVP_PKEY *PEM_read_bio_Parameters(BIO *bp, EVP_PKEY **x);
int PEM_write_bio_Parameters(BIO *bp, EVP_PKEY *x);

EVP_PKEY *b2i_PrivateKey(const unsigned char **in, long length);
EVP_PKEY *b2i_PublicKey(const unsigned char **in, long length);
EVP_PKEY *b2i_PrivateKey_bio(BIO *in);
EVP_PKEY *b2i_PublicKey_bio(BIO *in);
int i2b_PrivateKey_bio(BIO *out, EVP_PKEY *pk);
int i2b_PublicKey_bio(BIO *out, EVP_PKEY *pk);
# ifndef OPENSSL_NO_RC4
EVP_PKEY *b2i_PVK_bio(BIO *in, pem_password_cb *cb, void *u);
int i2b_PVK_bio(BIO *out, EVP_PKEY *pk, int enclevel,
                pem_password_cb *cb, void *u);
# endif

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

void ERR_load_PEM_strings(void);

/* Error codes for the PEM functions. */

/* Function codes. */
# define PEM_F_B2I_DSS                                    127
# define PEM_F_B2I_PVK_BIO                                128
# define PEM_F_B2I_RSA                                    129
# define PEM_F_CHECK_BITLEN_DSA                           130
# define PEM_F_CHECK_BITLEN_RSA                           131
# define PEM_F_D2I_PKCS8PRIVATEKEY_BIO                    120
# define PEM_F_D2I_PKCS8PRIVATEKEY_FP                     121
# define PEM_F_DO_B2I                                     132
# define PEM_F_DO_B2I_BIO                                 133
# define PEM_F_DO_BLOB_HEADER                             134
# define PEM_F_DO_PK8PKEY                                 126
# define PEM_F_DO_PK8PKEY_FP                              125
# define PEM_F_DO_PVK_BODY                                135
# define PEM_F_DO_PVK_HEADER                              136
# define PEM_F_I2B_PVK                                    137
# define PEM_F_I2B_PVK_BIO                                138
# define PEM_F_LOAD_IV                                    101
# define PEM_F_PEM_ASN1_READ                              102
# define PEM_F_PEM_ASN1_READ_BIO                          103
# define PEM_F_PEM_ASN1_WRITE                             104
# define PEM_F_PEM_ASN1_WRITE_BIO                         105
# define PEM_F_PEM_DEF_CALLBACK                           100
# define PEM_F_PEM_DO_HEADER                              106
# define PEM_F_PEM_F_PEM_WRITE_PKCS8PRIVATEKEY            118
# define PEM_F_PEM_GET_EVP_CIPHER_INFO                    107
# define PEM_F_PEM_PK8PKEY                                119
# define PEM_F_PEM_READ                                   108
# define PEM_F_PEM_READ_BIO                               109
# define PEM_F_PEM_READ_BIO_DHPARAMS                      141
# define PEM_F_PEM_READ_BIO_PARAMETERS                    140
# define PEM_F_PEM_READ_BIO_PRIVATEKEY                    123
# define PEM_F_PEM_READ_DHPARAMS                          142
# define PEM_F_PEM_READ_PRIVATEKEY                        124
# define PEM_F_PEM_SEALFINAL                              110
# define PEM_F_PEM_SEALINIT                               111
# define PEM_F_PEM_SIGNFINAL                              112
# define PEM_F_PEM_WRITE                                  113
# define PEM_F_PEM_WRITE_BIO                              114
# define PEM_F_PEM_WRITE_PRIVATEKEY                       139
# define PEM_F_PEM_X509_INFO_READ                         115
# define PEM_F_PEM_X509_INFO_READ_BIO                     116
# define PEM_F_PEM_X509_INFO_WRITE_BIO                    117

/* Reason codes. */
# define PEM_R_BAD_BASE64_DECODE                          100
# define PEM_R_BAD_DECRYPT                                101
# define PEM_R_BAD_END_LINE                               102
# define PEM_R_BAD_IV_CHARS                               103
# define PEM_R_BAD_MAGIC_NUMBER                           116
# define PEM_R_BAD_PASSWORD_READ                          104
# define PEM_R_BAD_VERSION_NUMBER                         117
# define PEM_R_BIO_WRITE_FAILURE                          118
# define PEM_R_CIPHER_IS_NULL                             127
# define PEM_R_ERROR_CONVERTING_PRIVATE_KEY               115
# define PEM_R_EXPECTING_PRIVATE_KEY_BLOB                 119
# define PEM_R_EXPECTING_PUBLIC_KEY_BLOB                  120
# define PEM_R_HEADER_TOO_LONG                            128
# define PEM_R_INCONSISTENT_HEADER                        121
# define PEM_R_KEYBLOB_HEADER_PARSE_ERROR                 122
# define PEM_R_KEYBLOB_TOO_SHORT                          123
# define PEM_R_NOT_DEK_INFO                               105
# define PEM_R_NOT_ENCRYPTED                              106
# define PEM_R_NOT_PROC_TYPE                              107
# define PEM_R_NO_START_LINE                              108
# define PEM_R_PROBLEMS_GETTING_PASSWORD                  109
# define PEM_R_PUBLIC_KEY_NO_RSA                          110
# define PEM_R_PVK_DATA_TOO_SHORT                         124
# define PEM_R_PVK_TOO_SHORT                              125
# define PEM_R_READ_KEY                                   111
# define PEM_R_SHORT_HEADER                               112
# define PEM_R_UNSUPPORTED_CIPHER                         113
# define PEM_R_UNSUPPORTED_ENCRYPTION                     114
# define PEM_R_UNSUPPORTED_KEY_COMPONENTS                 126

# ifdef  __cplusplus
}
# endif
#endif

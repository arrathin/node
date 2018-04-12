/* ocsp.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2000.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
#ifndef OPENSSL_NO_OCSP

# ifdef OPENSSL_SYS_VMS
#  define _XOPEN_SOURCE_EXTENDED/* So fd_set and friends get properly defined
                                 * on OpenVMS */
# endif

# define USE_SOCKETS

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <time.h>
# include "apps.h"              /* needs to be included before the openssl
                                 * headers! */
# include <openssl/e_os2.h>
# include <openssl/crypto.h>
# include <openssl/err.h>
# include <openssl/ssl.h>
# include <openssl/evp.h>
# include <openssl/bn.h>
# include <openssl/x509v3.h>

# if defined(NETWARE_CLIB)
#  ifdef NETWARE_BSDSOCK
#   include <sys/socket.h>
#   include <sys/bsdskt.h>
#  else
#   include <novsock2.h>
#  endif
# elif defined(NETWARE_LIBC)
#  ifdef NETWARE_BSDSOCK
#   include <sys/select.h>
#  else
#   include <novsock2.h>
#  endif
# endif

/* Maximum leeway in validity period: default 5 minutes */
# define MAX_VALIDITY_PERIOD     (5 * 60)

static int add_ocsp_cert(OCSP_REQUEST **req, X509 *cert,
                         const EVP_MD *cert_id_md, X509 *issuer,
                         STACK_OF(OCSP_CERTID) *ids);
static int add_ocsp_serial(OCSP_REQUEST **req, char *serial,
                           const EVP_MD *cert_id_md, X509 *issuer,
                           STACK_OF(OCSP_CERTID) *ids);
static int print_ocsp_summary(BIO *out, OCSP_BASICRESP *bs, OCSP_REQUEST *req,
                              STACK_OF(OPENSSL_STRING) *names,
                              STACK_OF(OCSP_CERTID) *ids, long nsec,
                              long maxage);

static int make_ocsp_response(OCSP_RESPONSE **resp, OCSP_REQUEST *req,
                              CA_DB *db, X509 *ca, X509 *rcert,
                              EVP_PKEY *rkey, const EVP_MD *md,
                              STACK_OF(X509) *rother, unsigned long flags,
                              int nmin, int ndays, int badsig);

static char **lookup_serial(CA_DB *db, ASN1_INTEGER *ser);
static BIO *init_responder(const char *port);
static int do_responder(OCSP_REQUEST **preq, BIO **pcbio, BIO *acbio,
                        const char *port);
static int send_ocsp_response(BIO *cbio, OCSP_RESPONSE *resp);
static OCSP_RESPONSE *query_responder(BIO *err, BIO *cbio, const char *path,
                                      const STACK_OF(CONF_VALUE) *headers,
                                      OCSP_REQUEST *req, int req_timeout);

# undef PROG
# define PROG ocsp_main

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    ENGINE *e = NULL;
    char **args;
    char *host = NULL, *port = NULL, *path = "\x2f";
    char *thost = NULL, *tport = NULL, *tpath = NULL;
    char *reqin = NULL, *respin = NULL;
    char *reqout = NULL, *respout = NULL;
    char *signfile = NULL, *keyfile = NULL;
    char *rsignfile = NULL, *rkeyfile = NULL;
    char *outfile = NULL;
    int add_nonce = 1, noverify = 0, use_ssl = -1;
    STACK_OF(CONF_VALUE) *headers = NULL;
    OCSP_REQUEST *req = NULL;
    OCSP_RESPONSE *resp = NULL;
    OCSP_BASICRESP *bs = NULL;
    X509 *issuer = NULL, *cert = NULL;
    X509 *signer = NULL, *rsigner = NULL;
    EVP_PKEY *key = NULL, *rkey = NULL;
    BIO *acbio = NULL, *cbio = NULL;
    BIO *derbio = NULL;
    BIO *out = NULL;
    int req_timeout = -1;
    int req_text = 0, resp_text = 0;
    long nsec = MAX_VALIDITY_PERIOD, maxage = -1;
    char *CAfile = NULL, *CApath = NULL;
    X509_STORE *store = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    STACK_OF(X509) *sign_other = NULL, *verify_other = NULL, *rother = NULL;
    char *sign_certfile = NULL, *verify_certfile = NULL, *rcertfile = NULL;
    unsigned long sign_flags = 0, verify_flags = 0, rflags = 0;
    int ret = 1;
    int accept_count = -1;
    int badarg = 0;
    int badsig = 0;
    int i;
    int ignore_err = 0;
    STACK_OF(OPENSSL_STRING) *reqnames = NULL;
    STACK_OF(OCSP_CERTID) *ids = NULL;

    X509 *rca_cert = NULL;
    char *ridx_filename = NULL;
    char *rca_filename = NULL;
    CA_DB *rdb = NULL;
    int nmin = 0, ndays = -1;
    const EVP_MD *cert_id_md = NULL, *rsign_md = NULL;

    if (bio_err == NULL)
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!load_config(bio_err, NULL))
        goto end;
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    args = argv + 1;
    reqnames = sk_OPENSSL_STRING_new_null();
    ids = sk_OCSP_CERTID_new_null();
    while (!badarg && *args && *args[0] == '\x2d') {
        if (!strcmp(*args, "\x2d\x6f\x75\x74")) {
            if (args[1]) {
                args++;
                outfile = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x74\x69\x6d\x65\x6f\x75\x74")) {
            if (args[1]) {
                args++;
                req_timeout = atol(*args);
                if (req_timeout < 0) {
                    BIO_printf(bio_err, "\x49\x6c\x6c\x65\x67\x61\x6c\x20\x74\x69\x6d\x65\x6f\x75\x74\x20\x76\x61\x6c\x75\x65\x20\x25\x73\xa", *args);
                    badarg = 1;
                }
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x75\x72\x6c")) {
            if (thost)
                OPENSSL_free(thost);
            if (tport)
                OPENSSL_free(tport);
            if (tpath)
                OPENSSL_free(tpath);
            thost = tport = tpath = NULL;
            if (args[1]) {
                args++;
                if (!OCSP_parse_url(*args, &host, &port, &path, &use_ssl)) {
                    BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x70\x61\x72\x73\x69\x6e\x67\x20\x55\x52\x4c\xa");
                    badarg = 1;
                }
                thost = host;
                tport = port;
                tpath = path;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x68\x6f\x73\x74")) {
            if (args[1]) {
                args++;
                host = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x70\x6f\x72\x74")) {
            if (args[1]) {
                args++;
                port = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x68\x65\x61\x64\x65\x72")) {
            if (args[1] && args[2]) {
                if (!X509V3_add_value(args[1], args[2], &headers))
                    goto end;
                args += 2;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x69\x67\x6e\x6f\x72\x65\x5f\x65\x72\x72"))
            ignore_err = 1;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x76\x65\x72\x69\x66\x79"))
            noverify = 1;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x6e\x63\x65"))
            add_nonce = 2;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x5f\x6e\x6f\x6e\x63\x65"))
            add_nonce = 0;
        else if (!strcmp(*args, "\x2d\x72\x65\x73\x70\x5f\x6e\x6f\x5f\x63\x65\x72\x74\x73"))
            rflags |= OCSP_NOCERTS;
        else if (!strcmp(*args, "\x2d\x72\x65\x73\x70\x5f\x6b\x65\x79\x5f\x69\x64"))
            rflags |= OCSP_RESPID_KEY;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x5f\x63\x65\x72\x74\x73"))
            sign_flags |= OCSP_NOCERTS;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x5f\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x5f\x76\x65\x72\x69\x66\x79"))
            verify_flags |= OCSP_NOSIGS;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x5f\x63\x65\x72\x74\x5f\x76\x65\x72\x69\x66\x79"))
            verify_flags |= OCSP_NOVERIFY;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x5f\x63\x68\x61\x69\x6e"))
            verify_flags |= OCSP_NOCHAIN;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x5f\x63\x65\x72\x74\x5f\x63\x68\x65\x63\x6b\x73"))
            verify_flags |= OCSP_NOCHECKS;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x5f\x65\x78\x70\x6c\x69\x63\x69\x74"))
            verify_flags |= OCSP_NOEXPLICIT;
        else if (!strcmp(*args, "\x2d\x74\x72\x75\x73\x74\x5f\x6f\x74\x68\x65\x72"))
            verify_flags |= OCSP_TRUSTOTHER;
        else if (!strcmp(*args, "\x2d\x6e\x6f\x5f\x69\x6e\x74\x65\x72\x6e"))
            verify_flags |= OCSP_NOINTERN;
        else if (!strcmp(*args, "\x2d\x62\x61\x64\x73\x69\x67"))
            badsig = 1;
        else if (!strcmp(*args, "\x2d\x74\x65\x78\x74")) {
            req_text = 1;
            resp_text = 1;
        } else if (!strcmp(*args, "\x2d\x72\x65\x71\x5f\x74\x65\x78\x74"))
            req_text = 1;
        else if (!strcmp(*args, "\x2d\x72\x65\x73\x70\x5f\x74\x65\x78\x74"))
            resp_text = 1;
        else if (!strcmp(*args, "\x2d\x72\x65\x71\x69\x6e")) {
            if (args[1]) {
                args++;
                reqin = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x72\x65\x73\x70\x69\x6e")) {
            if (args[1]) {
                args++;
                respin = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x73\x69\x67\x6e\x65\x72")) {
            if (args[1]) {
                args++;
                signfile = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x56\x41\x66\x69\x6c\x65")) {
            if (args[1]) {
                args++;
                verify_certfile = *args;
                verify_flags |= OCSP_TRUSTOTHER;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x73\x69\x67\x6e\x5f\x6f\x74\x68\x65\x72")) {
            if (args[1]) {
                args++;
                sign_certfile = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x76\x65\x72\x69\x66\x79\x5f\x6f\x74\x68\x65\x72")) {
            if (args[1]) {
                args++;
                verify_certfile = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x43\x41\x66\x69\x6c\x65")) {
            if (args[1]) {
                args++;
                CAfile = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x43\x41\x70\x61\x74\x68")) {
            if (args[1]) {
                args++;
                CApath = *args;
            } else
                badarg = 1;
        } else if (args_verify(&args, NULL, &badarg, bio_err, &vpm)) {
            if (badarg)
                goto end;
            continue;
        } else if (!strcmp(*args, "\x2d\x76\x61\x6c\x69\x64\x69\x74\x79\x5f\x70\x65\x72\x69\x6f\x64")) {
            if (args[1]) {
                args++;
                nsec = atol(*args);
                if (nsec < 0) {
                    BIO_printf(bio_err,
                               "\x49\x6c\x6c\x65\x67\x61\x6c\x20\x76\x61\x6c\x69\x64\x69\x74\x79\x20\x70\x65\x72\x69\x6f\x64\x20\x25\x73\xa", *args);
                    badarg = 1;
                }
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x73\x74\x61\x74\x75\x73\x5f\x61\x67\x65")) {
            if (args[1]) {
                args++;
                maxage = atol(*args);
                if (maxage < 0) {
                    BIO_printf(bio_err, "\x49\x6c\x6c\x65\x67\x61\x6c\x20\x76\x61\x6c\x69\x64\x69\x74\x79\x20\x61\x67\x65\x20\x25\x73\xa", *args);
                    badarg = 1;
                }
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x73\x69\x67\x6e\x6b\x65\x79")) {
            if (args[1]) {
                args++;
                keyfile = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x72\x65\x71\x6f\x75\x74")) {
            if (args[1]) {
                args++;
                reqout = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x72\x65\x73\x70\x6f\x75\x74")) {
            if (args[1]) {
                args++;
                respout = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x70\x61\x74\x68")) {
            if (args[1]) {
                args++;
                path = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x69\x73\x73\x75\x65\x72")) {
            if (args[1]) {
                args++;
                X509_free(issuer);
                issuer = load_cert(bio_err, *args, FORMAT_PEM,
                                   NULL, e, "\x69\x73\x73\x75\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65");
                if (!issuer)
                    goto end;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x63\x65\x72\x74")) {
            if (args[1]) {
                args++;
                X509_free(cert);
                cert = load_cert(bio_err, *args, FORMAT_PEM,
                                 NULL, e, "\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65");
                if (!cert)
                    goto end;
                if (!cert_id_md)
                    cert_id_md = EVP_sha1();
                if (!add_ocsp_cert(&req, cert, cert_id_md, issuer, ids))
                    goto end;
                if (!sk_OPENSSL_STRING_push(reqnames, *args))
                    goto end;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x73\x65\x72\x69\x61\x6c")) {
            if (args[1]) {
                args++;
                if (!cert_id_md)
                    cert_id_md = EVP_sha1();
                if (!add_ocsp_serial(&req, *args, cert_id_md, issuer, ids))
                    goto end;
                if (!sk_OPENSSL_STRING_push(reqnames, *args))
                    goto end;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x69\x6e\x64\x65\x78")) {
            if (args[1]) {
                args++;
                ridx_filename = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x43\x41")) {
            if (args[1]) {
                args++;
                rca_filename = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x6e\x6d\x69\x6e")) {
            if (args[1]) {
                args++;
                nmin = atol(*args);
                if (nmin < 0) {
                    BIO_printf(bio_err, "\x49\x6c\x6c\x65\x67\x61\x6c\x20\x75\x70\x64\x61\x74\x65\x20\x70\x65\x72\x69\x6f\x64\x20\x25\x73\xa", *args);
                    badarg = 1;
                }
            }
            if (ndays == -1)
                ndays = 0;
            else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x6e\x72\x65\x71\x75\x65\x73\x74")) {
            if (args[1]) {
                args++;
                accept_count = atol(*args);
                if (accept_count < 0) {
                    BIO_printf(bio_err, "\x49\x6c\x6c\x65\x67\x61\x6c\x20\x61\x63\x63\x65\x70\x74\x20\x63\x6f\x75\x6e\x74\x20\x25\x73\xa", *args);
                    badarg = 1;
                }
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x6e\x64\x61\x79\x73")) {
            if (args[1]) {
                args++;
                ndays = atol(*args);
                if (ndays < 0) {
                    BIO_printf(bio_err, "\x49\x6c\x6c\x65\x67\x61\x6c\x20\x75\x70\x64\x61\x74\x65\x20\x70\x65\x72\x69\x6f\x64\x20\x25\x73\xa", *args);
                    badarg = 1;
                }
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x72\x73\x69\x67\x6e\x65\x72")) {
            if (args[1]) {
                args++;
                rsignfile = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x72\x6b\x65\x79")) {
            if (args[1]) {
                args++;
                rkeyfile = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x72\x6f\x74\x68\x65\x72")) {
            if (args[1]) {
                args++;
                rcertfile = *args;
            } else
                badarg = 1;
        } else if (!strcmp(*args, "\x2d\x72\x6d\x64")) {
            if (args[1]) {
                args++;
                rsign_md = EVP_get_digestbyname(*args);
                if (!rsign_md)
                    badarg = 1;
            } else
                badarg = 1;
        } else if ((cert_id_md = EVP_get_digestbyname((*args) + 1)) == NULL) {
            badarg = 1;
        }
        args++;
    }

    /* Have we anything to do? */
    if (!req && !reqin && !respin && !(port && ridx_filename))
        badarg = 1;

    if (badarg) {
        BIO_printf(bio_err, "\x4f\x43\x53\x50\x20\x75\x74\x69\x6c\x69\x74\x79\xa");
        BIO_printf(bio_err, "\x55\x73\x61\x67\x65\x20\x6f\x63\x73\x70\x20\x5b\x6f\x70\x74\x69\x6f\x6e\x73\x5d\xa");
        BIO_printf(bio_err, "\x77\x68\x65\x72\x65\x20\x6f\x70\x74\x69\x6f\x6e\x73\x20\x61\x72\x65\xa");
        BIO_printf(bio_err, "\x2d\x6f\x75\x74\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\x6e\x61\x6d\x65\xa");
        BIO_printf(bio_err, "\x2d\x69\x73\x73\x75\x65\x72\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x69\x73\x73\x75\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\xa");
        BIO_printf(bio_err, "\x2d\x63\x65\x72\x74\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x74\x6f\x20\x63\x68\x65\x63\x6b\xa");
        BIO_printf(bio_err, "\x2d\x73\x65\x72\x69\x61\x6c\x20\x6e\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x73\x65\x72\x69\x61\x6c\x20\x6e\x75\x6d\x62\x65\x72\x20\x74\x6f\x20\x63\x68\x65\x63\x6b\xa");
        BIO_printf(bio_err,
                   "\x2d\x73\x69\x67\x6e\x65\x72\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x74\x6f\x20\x73\x69\x67\x6e\x20\x4f\x43\x53\x50\x20\x72\x65\x71\x75\x65\x73\x74\x20\x77\x69\x74\x68\xa");
        BIO_printf(bio_err,
                   "\x2d\x73\x69\x67\x6e\x6b\x65\x79\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79\x20\x74\x6f\x20\x73\x69\x67\x6e\x20\x4f\x43\x53\x50\x20\x72\x65\x71\x75\x65\x73\x74\x20\x77\x69\x74\x68\xa");
        BIO_printf(bio_err,
                   "\x2d\x73\x69\x67\x6e\x5f\x6f\x74\x68\x65\x72\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x61\x64\x64\x69\x74\x69\x6f\x6e\x61\x6c\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x74\x6f\x20\x69\x6e\x63\x6c\x75\x64\x65\x20\x69\x6e\x20\x73\x69\x67\x6e\x65\x64\x20\x72\x65\x71\x75\x65\x73\x74\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x5f\x63\x65\x72\x74\x73\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x69\x6e\x63\x6c\x75\x64\x65\x20\x61\x6e\x79\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x69\x6e\x20\x73\x69\x67\x6e\x65\x64\x20\x72\x65\x71\x75\x65\x73\x74\xa");
        BIO_printf(bio_err,
                   "\x2d\x72\x65\x71\x5f\x74\x65\x78\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x70\x72\x69\x6e\x74\x20\x74\x65\x78\x74\x20\x66\x6f\x72\x6d\x20\x6f\x66\x20\x72\x65\x71\x75\x65\x73\x74\xa");
        BIO_printf(bio_err,
                   "\x2d\x72\x65\x73\x70\x5f\x74\x65\x78\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x70\x72\x69\x6e\x74\x20\x74\x65\x78\x74\x20\x66\x6f\x72\x6d\x20\x6f\x66\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x74\x65\x78\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x70\x72\x69\x6e\x74\x20\x74\x65\x78\x74\x20\x66\x6f\x72\x6d\x20\x6f\x66\x20\x72\x65\x71\x75\x65\x73\x74\x20\x61\x6e\x64\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x72\x65\x71\x6f\x75\x74\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x77\x72\x69\x74\x65\x20\x44\x45\x52\x20\x65\x6e\x63\x6f\x64\x65\x64\x20\x4f\x43\x53\x50\x20\x72\x65\x71\x75\x65\x73\x74\x20\x74\x6f\x20\x22\x66\x69\x6c\x65\x22\xa");
        BIO_printf(bio_err,
                   "\x2d\x72\x65\x73\x70\x6f\x75\x74\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x77\x72\x69\x74\x65\x20\x44\x45\x52\x20\x65\x6e\x63\x6f\x64\x65\x64\x20\x4f\x43\x53\x50\x20\x72\x65\x70\x6f\x6e\x73\x65\x20\x74\x6f\x20\x22\x66\x69\x6c\x65\x22\xa");
        BIO_printf(bio_err,
                   "\x2d\x72\x65\x71\x69\x6e\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x72\x65\x61\x64\x20\x44\x45\x52\x20\x65\x6e\x63\x6f\x64\x65\x64\x20\x4f\x43\x53\x50\x20\x72\x65\x71\x75\x65\x73\x74\x20\x66\x72\x6f\x6d\x20\x22\x66\x69\x6c\x65\x22\xa");
        BIO_printf(bio_err,
                   "\x2d\x72\x65\x73\x70\x69\x6e\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x72\x65\x61\x64\x20\x44\x45\x52\x20\x65\x6e\x63\x6f\x64\x65\x64\x20\x4f\x43\x53\x50\x20\x72\x65\x70\x6f\x6e\x73\x65\x20\x66\x72\x6f\x6d\x20\x22\x66\x69\x6c\x65\x22\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x6e\x63\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x61\x64\x64\x20\x4f\x43\x53\x50\x20\x6e\x6f\x6e\x63\x65\x20\x74\x6f\x20\x72\x65\x71\x75\x65\x73\x74\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x5f\x6e\x6f\x6e\x63\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x61\x64\x64\x20\x4f\x43\x53\x50\x20\x6e\x6f\x6e\x63\x65\x20\x74\x6f\x20\x72\x65\x71\x75\x65\x73\x74\xa");
        BIO_printf(bio_err, "\x2d\x75\x72\x6c\x20\x55\x52\x4c\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x4f\x43\x53\x50\x20\x72\x65\x73\x70\x6f\x6e\x64\x65\x72\x20\x55\x52\x4c\xa");
        BIO_printf(bio_err,
                   "\x2d\x68\x6f\x73\x74\x20\x68\x6f\x73\x74\x3a\x6e\x20\x20\x20\x20\x20\x20\x20\x20\x20\x73\x65\x6e\x64\x20\x4f\x43\x53\x50\x20\x72\x65\x71\x75\x65\x73\x74\x20\x74\x6f\x20\x68\x6f\x73\x74\x20\x6f\x6e\x20\x70\x6f\x72\x74\x20\x6e\xa");
        BIO_printf(bio_err,
                   "\x2d\x70\x61\x74\x68\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x70\x61\x74\x68\x20\x74\x6f\x20\x75\x73\x65\x20\x69\x6e\x20\x4f\x43\x53\x50\x20\x72\x65\x71\x75\x65\x73\x74\xa");
        BIO_printf(bio_err,
                   "\x2d\x43\x41\x70\x61\x74\x68\x20\x64\x69\x72\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x74\x72\x75\x73\x74\x65\x64\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x64\x69\x72\x65\x63\x74\x6f\x72\x79\xa");
        BIO_printf(bio_err,
                   "\x2d\x43\x41\x66\x69\x6c\x65\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x74\x72\x75\x73\x74\x65\x64\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x5f\x61\x6c\x74\x5f\x63\x68\x61\x69\x6e\x73\x20\x20\x20\x20\x20\x20\x20\x6f\x6e\x6c\x79\x20\x65\x76\x65\x72\x20\x75\x73\x65\x20\x74\x68\x65\x20\x66\x69\x72\x73\x74\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x63\x68\x61\x69\x6e\x20\x66\x6f\x75\x6e\x64\xa");
        BIO_printf(bio_err,
                   "\x2d\x56\x41\x66\x69\x6c\x65\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x76\x61\x6c\x69\x64\x61\x74\x6f\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x76\x61\x6c\x69\x64\x69\x74\x79\x5f\x70\x65\x72\x69\x6f\x64\x20\x6e\x20\x20\x20\x6d\x61\x78\x69\x6d\x75\x6d\x20\x76\x61\x6c\x69\x64\x69\x74\x79\x20\x64\x69\x73\x63\x72\x65\x70\x61\x6e\x63\x79\x20\x69\x6e\x20\x73\x65\x63\x6f\x6e\x64\x73\xa");
        BIO_printf(bio_err,
                   "\x2d\x73\x74\x61\x74\x75\x73\x5f\x61\x67\x65\x20\x6e\x20\x20\x20\x20\x20\x20\x20\x20\x6d\x61\x78\x69\x6d\x75\x6d\x20\x73\x74\x61\x74\x75\x73\x20\x61\x67\x65\x20\x69\x6e\x20\x73\x65\x63\x6f\x6e\x64\x73\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x76\x65\x72\x69\x66\x79\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x76\x65\x72\x69\x66\x79\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\x20\x61\x74\x20\x61\x6c\x6c\xa");
        BIO_printf(bio_err,
                   "\x2d\x76\x65\x72\x69\x66\x79\x5f\x6f\x74\x68\x65\x72\x20\x66\x69\x6c\x65\x20\x20\x20\x61\x64\x64\x69\x74\x69\x6f\x6e\x61\x6c\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x74\x6f\x20\x73\x65\x61\x72\x63\x68\x20\x66\x6f\x72\x20\x73\x69\x67\x6e\x65\x72\xa");
        BIO_printf(bio_err,
                   "\x2d\x74\x72\x75\x73\x74\x5f\x6f\x74\x68\x65\x72\x20\x20\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x76\x65\x72\x69\x66\x79\x20\x61\x64\x64\x69\x74\x69\x6f\x6e\x61\x6c\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x5f\x69\x6e\x74\x65\x72\x6e\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x73\x65\x61\x72\x63\x68\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x63\x6f\x6e\x74\x61\x69\x6e\x65\x64\x20\x69\x6e\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\x20\x66\x6f\x72\x20\x73\x69\x67\x6e\x65\x72\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x5f\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x5f\x76\x65\x72\x69\x66\x79\x20\x64\x6f\x6e\x27\x74\x20\x63\x68\x65\x63\x6b\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x6f\x6e\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x5f\x63\x65\x72\x74\x5f\x76\x65\x72\x69\x66\x79\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x63\x68\x65\x63\x6b\x20\x73\x69\x67\x6e\x69\x6e\x67\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x5f\x63\x68\x61\x69\x6e\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x63\x68\x61\x69\x6e\x20\x76\x65\x72\x69\x66\x79\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6f\x5f\x63\x65\x72\x74\x5f\x63\x68\x65\x63\x6b\x73\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x64\x6f\x20\x61\x64\x64\x69\x74\x69\x6f\x6e\x61\x6c\x20\x63\x68\x65\x63\x6b\x73\x20\x6f\x6e\x20\x73\x69\x67\x6e\x69\x6e\x67\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x70\x6f\x72\x74\x20\x6e\x75\x6d\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x70\x6f\x72\x74\x20\x74\x6f\x20\x72\x75\x6e\x20\x72\x65\x73\x70\x6f\x6e\x64\x65\x72\x20\x6f\x6e\xa");
        BIO_printf(bio_err,
                   "\x2d\x69\x6e\x64\x65\x78\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x73\x74\x61\x74\x75\x73\x20\x69\x6e\x64\x65\x78\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err, "\x2d\x43\x41\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x43\x41\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x72\x73\x69\x67\x6e\x65\x72\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x72\x65\x73\x70\x6f\x6e\x64\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x74\x6f\x20\x73\x69\x67\x6e\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\x73\x20\x77\x69\x74\x68\xa");
        BIO_printf(bio_err,
                   "\x2d\x72\x6b\x65\x79\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x72\x65\x73\x70\x6f\x6e\x64\x65\x72\x20\x6b\x65\x79\x20\x74\x6f\x20\x73\x69\x67\x6e\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\x73\x20\x77\x69\x74\x68\xa");
        BIO_printf(bio_err,
                   "\x2d\x72\x6f\x74\x68\x65\x72\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6f\x74\x68\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x74\x6f\x20\x69\x6e\x63\x6c\x75\x64\x65\x20\x69\x6e\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x72\x65\x73\x70\x5f\x6e\x6f\x5f\x63\x65\x72\x74\x73\x20\x20\x20\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x69\x6e\x63\x6c\x75\x64\x65\x20\x61\x6e\x79\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73\x20\x69\x6e\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x6d\x69\x6e\x20\x6e\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6e\x75\x6d\x62\x65\x72\x20\x6f\x66\x20\x6d\x69\x6e\x75\x74\x65\x73\x20\x62\x65\x66\x6f\x72\x65\x20\x6e\x65\x78\x74\x20\x75\x70\x64\x61\x74\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x64\x61\x79\x73\x20\x6e\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6e\x75\x6d\x62\x65\x72\x20\x6f\x66\x20\x64\x61\x79\x73\x20\x62\x65\x66\x6f\x72\x65\x20\x6e\x65\x78\x74\x20\x75\x70\x64\x61\x74\x65\xa");
        BIO_printf(bio_err,
                   "\x2d\x72\x65\x73\x70\x5f\x6b\x65\x79\x5f\x69\x64\x20\x20\x20\x20\x20\x20\x20\x20\x20\x69\x64\x65\x6e\x74\x69\x66\x79\x20\x72\x65\x70\x6f\x6e\x73\x65\x20\x62\x79\x20\x73\x69\x67\x6e\x69\x6e\x67\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x6b\x65\x79\x20\x49\x44\xa");
        BIO_printf(bio_err,
                   "\x2d\x6e\x72\x65\x71\x75\x65\x73\x74\x20\x6e\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6e\x75\x6d\x62\x65\x72\x20\x6f\x66\x20\x72\x65\x71\x75\x65\x73\x74\x73\x20\x74\x6f\x20\x61\x63\x63\x65\x70\x74\x20\x28\x64\x65\x66\x61\x75\x6c\x74\x20\x75\x6e\x6c\x69\x6d\x69\x74\x65\x64\x29\xa");
        BIO_printf(bio_err,
                   "\x2d\x3c\x64\x67\x73\x74\x20\x61\x6c\x67\x3e\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x75\x73\x65\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x64\x69\x67\x65\x73\x74\x20\x69\x6e\x20\x74\x68\x65\x20\x72\x65\x71\x75\x65\x73\x74\xa");
        BIO_printf(bio_err,
                   "\x2d\x74\x69\x6d\x65\x6f\x75\x74\x20\x6e\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x74\x69\x6d\x65\x6f\x75\x74\x20\x63\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x20\x74\x6f\x20\x4f\x43\x53\x50\x20\x72\x65\x73\x70\x6f\x6e\x64\x65\x72\x20\x61\x66\x74\x65\x72\x20\x6e\x20\x73\x65\x63\x6f\x6e\x64\x73\xa");
        goto end;
    }

    if (outfile)
        out = BIO_new_file(outfile, "\x77");
    else
        out = BIO_new_fp(stdout, BIO_NOCLOSE);

    if (!out) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x6f\x70\x65\x6e\x69\x6e\x67\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        goto end;
    }

    if (!req && (add_nonce != 2))
        add_nonce = 0;

    if (!req && reqin) {
        if (!strcmp(reqin, "\x2d"))
            derbio = BIO_new_fp(stdin, BIO_NOCLOSE);
        else
            derbio = BIO_new_file(reqin, "\x72\x62");
        if (!derbio) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x4f\x70\x65\x6e\x69\x6e\x67\x20\x4f\x43\x53\x50\x20\x72\x65\x71\x75\x65\x73\x74\x20\x66\x69\x6c\x65\xa");
            goto end;
        }
        req = d2i_OCSP_REQUEST_bio(derbio, NULL);
        BIO_free(derbio);
        if (!req) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x72\x65\x61\x64\x69\x6e\x67\x20\x4f\x43\x53\x50\x20\x72\x65\x71\x75\x65\x73\x74\xa");
            goto end;
        }
    }

    if (!req && port) {
        acbio = init_responder(port);
        if (!acbio)
            goto end;
    }

    if (rsignfile && !rdb) {
        if (!rkeyfile)
            rkeyfile = rsignfile;
        rsigner = load_cert(bio_err, rsignfile, FORMAT_PEM,
                            NULL, e, "\x72\x65\x73\x70\x6f\x6e\x64\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65");
        if (!rsigner) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x6c\x6f\x61\x64\x69\x6e\x67\x20\x72\x65\x73\x70\x6f\x6e\x64\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\xa");
            goto end;
        }
        rca_cert = load_cert(bio_err, rca_filename, FORMAT_PEM,
                             NULL, e, "\x43\x41\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65");
        if (rcertfile) {
            rother = load_certs(bio_err, rcertfile, FORMAT_PEM,
                                NULL, e, "\x72\x65\x73\x70\x6f\x6e\x64\x65\x72\x20\x6f\x74\x68\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73");
            if (!rother)
                goto end;
        }
        rkey = load_key(bio_err, rkeyfile, FORMAT_PEM, 0, NULL, NULL,
                        "\x72\x65\x73\x70\x6f\x6e\x64\x65\x72\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79");
        if (!rkey)
            goto end;
    }
    if (acbio)
        BIO_printf(bio_err, "\x57\x61\x69\x74\x69\x6e\x67\x20\x66\x6f\x72\x20\x4f\x43\x53\x50\x20\x63\x6c\x69\x65\x6e\x74\x20\x63\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x73\x2e\x2e\x2e\xa");

 redo_accept:

    if (acbio) {
        if (!do_responder(&req, &cbio, acbio, port))
            goto end;
        if (!req) {
            resp =
                OCSP_response_create(OCSP_RESPONSE_STATUS_MALFORMEDREQUEST,
                                     NULL);
            send_ocsp_response(cbio, resp);
            goto done_resp;
        }
    }

    if (!req && (signfile || reqout || host || add_nonce || ridx_filename)) {
        BIO_printf(bio_err, "\x4e\x65\x65\x64\x20\x61\x6e\x20\x4f\x43\x53\x50\x20\x72\x65\x71\x75\x65\x73\x74\x20\x66\x6f\x72\x20\x74\x68\x69\x73\x20\x6f\x70\x65\x72\x61\x74\x69\x6f\x6e\x21\xa");
        goto end;
    }

    if (req && add_nonce)
        OCSP_request_add1_nonce(req, NULL, -1);

    if (signfile) {
        if (!keyfile)
            keyfile = signfile;
        signer = load_cert(bio_err, signfile, FORMAT_PEM,
                           NULL, e, "\x73\x69\x67\x6e\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65");
        if (!signer) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x6c\x6f\x61\x64\x69\x6e\x67\x20\x73\x69\x67\x6e\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\xa");
            goto end;
        }
        if (sign_certfile) {
            sign_other = load_certs(bio_err, sign_certfile, FORMAT_PEM,
                                    NULL, e, "\x73\x69\x67\x6e\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73");
            if (!sign_other)
                goto end;
        }
        key = load_key(bio_err, keyfile, FORMAT_PEM, 0, NULL, NULL,
                       "\x73\x69\x67\x6e\x65\x72\x20\x70\x72\x69\x76\x61\x74\x65\x20\x6b\x65\x79");
        if (!key)
            goto end;

        if (!OCSP_request_sign
            (req, signer, key, NULL, sign_other, sign_flags)) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x73\x69\x67\x6e\x69\x6e\x67\x20\x4f\x43\x53\x50\x20\x72\x65\x71\x75\x65\x73\x74\xa");
            goto end;
        }
    }

    if (req_text && req)
        OCSP_REQUEST_print(out, req, 0);

    if (reqout) {
        if (!strcmp(reqout, "\x2d"))
            derbio = BIO_new_fp(stdout, BIO_NOCLOSE);
        else
            derbio = BIO_new_file(reqout, "\x77\x62");
        if (!derbio) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x6f\x70\x65\x6e\x69\x6e\x67\x20\x66\x69\x6c\x65\x20\x25\x73\xa", reqout);
            goto end;
        }
        i2d_OCSP_REQUEST_bio(derbio, req);
        BIO_free(derbio);
    }

    if (ridx_filename && (!rkey || !rsigner || !rca_cert)) {
        BIO_printf(bio_err,
                   "\x4e\x65\x65\x64\x20\x61\x20\x72\x65\x73\x70\x6f\x6e\x64\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x2c\x20\x6b\x65\x79\x20\x61\x6e\x64\x20\x43\x41\x20\x66\x6f\x72\x20\x74\x68\x69\x73\x20\x6f\x70\x65\x72\x61\x74\x69\x6f\x6e\x21\xa");
        goto end;
    }

    if (ridx_filename && !rdb) {
        rdb = load_index(ridx_filename, NULL);
        if (!rdb)
            goto end;
        if (!index_index(rdb))
            goto end;
    }

    if (rdb) {
        i = make_ocsp_response(&resp, req, rdb, rca_cert, rsigner, rkey,
                               rsign_md, rother, rflags, nmin, ndays, badsig);
        if (cbio)
            send_ocsp_response(cbio, resp);
    } else if (host) {
# ifndef OPENSSL_NO_SOCK
        resp = process_responder(bio_err, req, host, path,
                                 port, use_ssl, headers, req_timeout);
        if (!resp)
            goto end;
# else
        BIO_printf(bio_err,
                   "\x45\x72\x72\x6f\x72\x20\x63\x72\x65\x61\x74\x69\x6e\x67\x20\x63\x6f\x6e\x6e\x65\x63\x74\x20\x42\x49\x4f\x20\x2d\x20\x73\x6f\x63\x6b\x65\x74\x73\x20\x6e\x6f\x74\x20\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x2e\xa");
        goto end;
# endif
    } else if (respin) {
        if (!strcmp(respin, "\x2d"))
            derbio = BIO_new_fp(stdin, BIO_NOCLOSE);
        else
            derbio = BIO_new_file(respin, "\x72\x62");
        if (!derbio) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x4f\x70\x65\x6e\x69\x6e\x67\x20\x4f\x43\x53\x50\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\x20\x66\x69\x6c\x65\xa");
            goto end;
        }
        resp = d2i_OCSP_RESPONSE_bio(derbio, NULL);
        BIO_free(derbio);
        if (!resp) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x72\x65\x61\x64\x69\x6e\x67\x20\x4f\x43\x53\x50\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\xa");
            goto end;
        }

    } else {
        ret = 0;
        goto end;
    }

 done_resp:

    if (respout) {
        if (!strcmp(respout, "\x2d"))
            derbio = BIO_new_fp(stdout, BIO_NOCLOSE);
        else
            derbio = BIO_new_file(respout, "\x77\x62");
        if (!derbio) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x6f\x70\x65\x6e\x69\x6e\x67\x20\x66\x69\x6c\x65\x20\x25\x73\xa", respout);
            goto end;
        }
        i2d_OCSP_RESPONSE_bio(derbio, resp);
        BIO_free(derbio);
    }

    i = OCSP_response_status(resp);

    if (i != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        BIO_printf(out, "\x52\x65\x73\x70\x6f\x6e\x64\x65\x72\x20\x45\x72\x72\x6f\x72\x3a\x20\x25\x73\x20\x28\x25\x64\x29\xa",
                   OCSP_response_status_str(i), i);
        if (ignore_err)
            goto redo_accept;
        ret = 0;
        goto end;
    }

    if (resp_text)
        OCSP_RESPONSE_print(out, resp, 0);

    /* If running as responder don't verify our own response */
    if (cbio) {
        if (accept_count > 0)
            accept_count--;
        /* Redo if more connections needed */
        if (accept_count) {
            BIO_free_all(cbio);
            cbio = NULL;
            OCSP_REQUEST_free(req);
            req = NULL;
            OCSP_RESPONSE_free(resp);
            resp = NULL;
            goto redo_accept;
        }
        ret = 0;
        goto end;
    } else if (ridx_filename) {
        ret = 0;
        goto end;
    }

    if (!store)
        store = setup_verify(bio_err, CAfile, CApath);
    if (!store)
        goto end;
    if (vpm)
        X509_STORE_set1_param(store, vpm);
    if (verify_certfile) {
        verify_other = load_certs(bio_err, verify_certfile, FORMAT_PEM,
                                  NULL, e, "\x76\x61\x6c\x69\x64\x61\x74\x6f\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65");
        if (!verify_other)
            goto end;
    }

    bs = OCSP_response_get1_basic(resp);

    if (!bs) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x70\x61\x72\x73\x69\x6e\x67\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\xa");
        goto end;
    }

    ret = 0;

    if (!noverify) {
        if (req && ((i = OCSP_check_nonce(req, bs)) <= 0)) {
            if (i == -1)
                BIO_printf(bio_err, "\x57\x41\x52\x4e\x49\x4e\x47\x3a\x20\x6e\x6f\x20\x6e\x6f\x6e\x63\x65\x20\x69\x6e\x20\x72\x65\x73\x70\x6f\x6e\x73\x65\xa");
            else {
                BIO_printf(bio_err, "\x4e\x6f\x6e\x63\x65\x20\x56\x65\x72\x69\x66\x79\x20\x65\x72\x72\x6f\x72\xa");
                ret = 1;
                goto end;
            }
        }

        i = OCSP_basic_verify(bs, verify_other, store, verify_flags);
        if (i <= 0) {
            BIO_printf(bio_err, "\x52\x65\x73\x70\x6f\x6e\x73\x65\x20\x56\x65\x72\x69\x66\x79\x20\x46\x61\x69\x6c\x75\x72\x65\xa");
            ERR_print_errors(bio_err);
            ret = 1;
        } else
            BIO_printf(bio_err, "\x52\x65\x73\x70\x6f\x6e\x73\x65\x20\x76\x65\x72\x69\x66\x79\x20\x4f\x4b\xa");

    }

    if (!print_ocsp_summary(out, bs, req, reqnames, ids, nsec, maxage))
        ret = 1;

 end:
    ERR_print_errors(bio_err);
    X509_free(signer);
    X509_STORE_free(store);
    if (vpm)
        X509_VERIFY_PARAM_free(vpm);
    EVP_PKEY_free(key);
    EVP_PKEY_free(rkey);
    X509_free(issuer);
    X509_free(cert);
    X509_free(rsigner);
    X509_free(rca_cert);
    free_index(rdb);
    BIO_free_all(cbio);
    BIO_free_all(acbio);
    BIO_free(out);
    OCSP_REQUEST_free(req);
    OCSP_RESPONSE_free(resp);
    OCSP_BASICRESP_free(bs);
    sk_OPENSSL_STRING_free(reqnames);
    sk_OCSP_CERTID_free(ids);
    sk_X509_pop_free(sign_other, X509_free);
    sk_X509_pop_free(verify_other, X509_free);
    sk_CONF_VALUE_pop_free(headers, X509V3_conf_free);

    if (thost)
        OPENSSL_free(thost);
    if (tport)
        OPENSSL_free(tport);
    if (tpath)
        OPENSSL_free(tpath);

    OPENSSL_EXIT(ret);
}

static int add_ocsp_cert(OCSP_REQUEST **req, X509 *cert,
                         const EVP_MD *cert_id_md, X509 *issuer,
                         STACK_OF(OCSP_CERTID) *ids)
{
    OCSP_CERTID *id;
    if (!issuer) {
        BIO_printf(bio_err, "\x4e\x6f\x20\x69\x73\x73\x75\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
        return 0;
    }
    if (!*req)
        *req = OCSP_REQUEST_new();
    if (!*req)
        goto err;
    id = OCSP_cert_to_id(cert_id_md, cert, issuer);
    if (!id || !sk_OCSP_CERTID_push(ids, id))
        goto err;
    if (!OCSP_request_add0_id(*req, id))
        goto err;
    return 1;

 err:
    BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x43\x72\x65\x61\x74\x69\x6e\x67\x20\x4f\x43\x53\x50\x20\x72\x65\x71\x75\x65\x73\x74\xa");
    return 0;
}

static int add_ocsp_serial(OCSP_REQUEST **req, char *serial,
                           const EVP_MD *cert_id_md, X509 *issuer,
                           STACK_OF(OCSP_CERTID) *ids)
{
    OCSP_CERTID *id;
    X509_NAME *iname;
    ASN1_BIT_STRING *ikey;
    ASN1_INTEGER *sno;
    if (!issuer) {
        BIO_printf(bio_err, "\x4e\x6f\x20\x69\x73\x73\x75\x65\x72\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
        return 0;
    }
    if (!*req)
        *req = OCSP_REQUEST_new();
    if (!*req)
        goto err;
    iname = X509_get_subject_name(issuer);
    ikey = X509_get0_pubkey_bitstr(issuer);
    sno = s2i_ASN1_INTEGER(NULL, serial);
    if (!sno) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x63\x6f\x6e\x76\x65\x72\x74\x69\x6e\x67\x20\x73\x65\x72\x69\x61\x6c\x20\x6e\x75\x6d\x62\x65\x72\x20\x25\x73\xa", serial);
        return 0;
    }
    id = OCSP_cert_id_new(cert_id_md, iname, ikey, sno);
    ASN1_INTEGER_free(sno);
    if (!id || !sk_OCSP_CERTID_push(ids, id))
        goto err;
    if (!OCSP_request_add0_id(*req, id))
        goto err;
    return 1;

 err:
    BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x43\x72\x65\x61\x74\x69\x6e\x67\x20\x4f\x43\x53\x50\x20\x72\x65\x71\x75\x65\x73\x74\xa");
    return 0;
}

static int print_ocsp_summary(BIO *out, OCSP_BASICRESP *bs, OCSP_REQUEST *req,
                              STACK_OF(OPENSSL_STRING) *names,
                              STACK_OF(OCSP_CERTID) *ids, long nsec,
                              long maxage)
{
    OCSP_CERTID *id;
    char *name;
    int i;

    int status, reason;

    ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;

    if (!bs || !req || !sk_OPENSSL_STRING_num(names)
        || !sk_OCSP_CERTID_num(ids))
        return 1;

    for (i = 0; i < sk_OCSP_CERTID_num(ids); i++) {
        id = sk_OCSP_CERTID_value(ids, i);
        name = sk_OPENSSL_STRING_value(names, i);
        BIO_printf(out, "\x25\x73\x3a\x20", name);

        if (!OCSP_resp_find_status(bs, id, &status, &reason,
                                   &rev, &thisupd, &nextupd)) {
            BIO_puts(out, "\x45\x52\x52\x4f\x52\x3a\x20\x4e\x6f\x20\x53\x74\x61\x74\x75\x73\x20\x66\x6f\x75\x6e\x64\x2e\xa");
            continue;
        }

        /*
         * Check validity: if invalid write to output BIO so we know which
         * response this refers to.
         */
        if (!OCSP_check_validity(thisupd, nextupd, nsec, maxage)) {
            BIO_puts(out, "\x57\x41\x52\x4e\x49\x4e\x47\x3a\x20\x53\x74\x61\x74\x75\x73\x20\x74\x69\x6d\x65\x73\x20\x69\x6e\x76\x61\x6c\x69\x64\x2e\xa");
            ERR_print_errors(out);
        }
        BIO_printf(out, "\x25\x73\xa", OCSP_cert_status_str(status));

        BIO_puts(out, "\x9\x54\x68\x69\x73\x20\x55\x70\x64\x61\x74\x65\x3a\x20");
        ASN1_GENERALIZEDTIME_print(out, thisupd);
        BIO_puts(out, "\xa");

        if (nextupd) {
            BIO_puts(out, "\x9\x4e\x65\x78\x74\x20\x55\x70\x64\x61\x74\x65\x3a\x20");
            ASN1_GENERALIZEDTIME_print(out, nextupd);
            BIO_puts(out, "\xa");
        }

        if (status != V_OCSP_CERTSTATUS_REVOKED)
            continue;

        if (reason != -1)
            BIO_printf(out, "\x9\x52\x65\x61\x73\x6f\x6e\x3a\x20\x25\x73\xa", OCSP_crl_reason_str(reason));

        BIO_puts(out, "\x9\x52\x65\x76\x6f\x63\x61\x74\x69\x6f\x6e\x20\x54\x69\x6d\x65\x3a\x20");
        ASN1_GENERALIZEDTIME_print(out, rev);
        BIO_puts(out, "\xa");
    }

    return 1;
}

static int make_ocsp_response(OCSP_RESPONSE **resp, OCSP_REQUEST *req,
                              CA_DB *db, X509 *ca, X509 *rcert,
                              EVP_PKEY *rkey, const EVP_MD *rmd,
                              STACK_OF(X509) *rother, unsigned long flags,
                              int nmin, int ndays, int badsig)
{
    ASN1_TIME *thisupd = NULL, *nextupd = NULL;
    OCSP_CERTID *cid, *ca_id = NULL;
    OCSP_BASICRESP *bs = NULL;
    int i, id_count, ret = 1;

    id_count = OCSP_request_onereq_count(req);

    if (id_count <= 0) {
        *resp =
            OCSP_response_create(OCSP_RESPONSE_STATUS_MALFORMEDREQUEST, NULL);
        goto end;
    }

    bs = OCSP_BASICRESP_new();
    thisupd = X509_gmtime_adj(NULL, 0);
    if (ndays != -1)
        nextupd = X509_time_adj_ex(NULL, ndays, nmin * 60, NULL);

    /* Examine each certificate id in the request */
    for (i = 0; i < id_count; i++) {
        OCSP_ONEREQ *one;
        ASN1_INTEGER *serial;
        char **inf;
        ASN1_OBJECT *cert_id_md_oid;
        const EVP_MD *cert_id_md;
        one = OCSP_request_onereq_get0(req, i);
        cid = OCSP_onereq_get0_id(one);

        OCSP_id_get0_info(NULL, &cert_id_md_oid, NULL, NULL, cid);

        cert_id_md = EVP_get_digestbyobj(cert_id_md_oid);
        if (!cert_id_md) {
            *resp = OCSP_response_create(OCSP_RESPONSE_STATUS_INTERNALERROR,
                                         NULL);
            goto end;
        }
        if (ca_id)
            OCSP_CERTID_free(ca_id);
        ca_id = OCSP_cert_to_id(cert_id_md, NULL, ca);

        /* Is this request about our CA? */
        if (OCSP_id_issuer_cmp(ca_id, cid)) {
            OCSP_basic_add1_status(bs, cid,
                                   V_OCSP_CERTSTATUS_UNKNOWN,
                                   0, NULL, thisupd, nextupd);
            continue;
        }
        OCSP_id_get0_info(NULL, NULL, NULL, &serial, cid);
        inf = lookup_serial(db, serial);
        if (!inf)
            OCSP_basic_add1_status(bs, cid,
                                   V_OCSP_CERTSTATUS_UNKNOWN,
                                   0, NULL, thisupd, nextupd);
        else if (inf[DB_type][0] == DB_TYPE_VAL)
            OCSP_basic_add1_status(bs, cid,
                                   V_OCSP_CERTSTATUS_GOOD,
                                   0, NULL, thisupd, nextupd);
        else if (inf[DB_type][0] == DB_TYPE_REV) {
            ASN1_OBJECT *inst = NULL;
            ASN1_TIME *revtm = NULL;
            ASN1_GENERALIZEDTIME *invtm = NULL;
            OCSP_SINGLERESP *single;
            int reason = -1;
            unpack_revinfo(&revtm, &reason, &inst, &invtm, inf[DB_rev_date]);
            single = OCSP_basic_add1_status(bs, cid,
                                            V_OCSP_CERTSTATUS_REVOKED,
                                            reason, revtm, thisupd, nextupd);
            if (invtm)
                OCSP_SINGLERESP_add1_ext_i2d(single, NID_invalidity_date,
                                             invtm, 0, 0);
            else if (inst)
                OCSP_SINGLERESP_add1_ext_i2d(single,
                                             NID_hold_instruction_code, inst,
                                             0, 0);
            ASN1_OBJECT_free(inst);
            ASN1_TIME_free(revtm);
            ASN1_GENERALIZEDTIME_free(invtm);
        }
    }

    OCSP_copy_nonce(bs, req);

    OCSP_basic_sign(bs, rcert, rkey, rmd, rother, flags);

    if (badsig)
        bs->signature->data[bs->signature->length - 1] ^= 0x1;

    *resp = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, bs);

 end:
    ASN1_TIME_free(thisupd);
    ASN1_TIME_free(nextupd);
    OCSP_CERTID_free(ca_id);
    OCSP_BASICRESP_free(bs);
    return ret;

}

static char **lookup_serial(CA_DB *db, ASN1_INTEGER *ser)
{
    int i;
    BIGNUM *bn = NULL;
    char *itmp, *row[DB_NUMBER], **rrow;
    for (i = 0; i < DB_NUMBER; i++)
        row[i] = NULL;
    bn = ASN1_INTEGER_to_BN(ser, NULL);
    OPENSSL_assert(bn);         /* FIXME: should report an error at this
                                 * point and abort */
    if (BN_is_zero(bn))
        itmp = BUF_strdup("\x30\x30");
    else
        itmp = BN_bn2hex(bn);
    row[DB_serial] = itmp;
    BN_free(bn);
    rrow = TXT_DB_get_by_index(db->db, DB_serial, row);
    OPENSSL_free(itmp);
    return rrow;
}

/* Quick and dirty OCSP server: read in and parse input request */

static BIO *init_responder(const char *port)
{
    BIO *acbio = NULL, *bufbio = NULL;
    bufbio = BIO_new(BIO_f_buffer());
    if (!bufbio)
        goto err;
# ifndef OPENSSL_NO_SOCK
    acbio = BIO_new_accept(port);
# else
    BIO_printf(bio_err,
               "\x45\x72\x72\x6f\x72\x20\x73\x65\x74\x74\x69\x6e\x67\x20\x75\x70\x20\x61\x63\x63\x65\x70\x74\x20\x42\x49\x4f\x20\x2d\x20\x73\x6f\x63\x6b\x65\x74\x73\x20\x6e\x6f\x74\x20\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x2e\xa");
# endif
    if (!acbio)
        goto err;
    BIO_set_accept_bios(acbio, bufbio);
    bufbio = NULL;

    if (BIO_do_accept(acbio) <= 0) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x73\x65\x74\x74\x69\x6e\x67\x20\x75\x70\x20\x61\x63\x63\x65\x70\x74\x20\x42\x49\x4f\xa");
        ERR_print_errors(bio_err);
        goto err;
    }

    return acbio;

 err:
    BIO_free_all(acbio);
    BIO_free(bufbio);
    return NULL;
}

static int do_responder(OCSP_REQUEST **preq, BIO **pcbio, BIO *acbio,
                        const char *port)
{
    int have_post = 0, len;
    OCSP_REQUEST *req = NULL;
    char inbuf[1024];
    BIO *cbio = NULL;

    if (BIO_do_accept(acbio) <= 0) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x61\x63\x63\x65\x70\x74\x69\x6e\x67\x20\x63\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\xa");
        ERR_print_errors(bio_err);
        return 0;
    }

    cbio = BIO_pop(acbio);
    *pcbio = cbio;

    for (;;) {
        len = BIO_gets(cbio, inbuf, sizeof(inbuf));
        if (len <= 0)
            return 1;
        /* Look for "POST" signalling start of query */
        if (!have_post) {
            if (strncmp(inbuf, "\x50\x4f\x53\x54", 4)) {
                BIO_printf(bio_err, "\x49\x6e\x76\x61\x6c\x69\x64\x20\x72\x65\x71\x75\x65\x73\x74\xa");
                return 1;
            }
            have_post = 1;
        }
        /* Look for end of headers */
        if ((inbuf[0] == '\xd') || (inbuf[0] == '\xa'))
            break;
    }

    /* Try to read OCSP request */

    req = d2i_OCSP_REQUEST_bio(cbio, NULL);

    if (!req) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x70\x61\x72\x73\x69\x6e\x67\x20\x4f\x43\x53\x50\x20\x72\x65\x71\x75\x65\x73\x74\xa");
        ERR_print_errors(bio_err);
    }

    *preq = req;

    return 1;

}

static int send_ocsp_response(BIO *cbio, OCSP_RESPONSE *resp)
{
    char http_resp[] =
        "\x48\x54\x54\x50\x2f\x31\x2e\x30\x20\x32\x30\x30\x20\x4f\x4b\xd\xaC\x6f\x6e\x74\x65\x6e\x74\x2d\x74\x79\x70\x65\x3a\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x6f\x63\x73\x70\x2d\x72\x65\x73\x70\x6f\x6e\x73\x65\xd\xa"
        "\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x4c\x65\x6e\x67\x74\x68\x3a\x20\x25\x64\xd\xa\xd\xa";
    if (!cbio)
        return 0;
    BIO_printf(cbio, http_resp, i2d_OCSP_RESPONSE(resp, NULL));
    i2d_OCSP_RESPONSE_bio(cbio, resp);
    (void)BIO_flush(cbio);
    return 1;
}

static OCSP_RESPONSE *query_responder(BIO *err, BIO *cbio, const char *path,
                                      const STACK_OF(CONF_VALUE) *headers,
                                      OCSP_REQUEST *req, int req_timeout)
{
    int fd;
    int rv;
    int i;
    OCSP_REQ_CTX *ctx = NULL;
    OCSP_RESPONSE *rsp = NULL;
    fd_set confds;
    struct timeval tv;

    if (req_timeout != -1)
        BIO_set_nbio(cbio, 1);

    rv = BIO_do_connect(cbio);

    if ((rv <= 0) && ((req_timeout == -1) || !BIO_should_retry(cbio))) {
        BIO_puts(err, "\x45\x72\x72\x6f\x72\x20\x63\x6f\x6e\x6e\x65\x63\x74\x69\x6e\x67\x20\x42\x49\x4f\xa");
        return NULL;
    }

    if (BIO_get_fd(cbio, &fd) < 0) {
        BIO_puts(bio_err, "\x43\x61\x6e\x27\x74\x20\x67\x65\x74\x20\x63\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x20\x66\x64\xa");
        goto err;
    }

    if (req_timeout != -1 && rv <= 0) {
        FD_ZERO(&confds);
        openssl_fdset(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec = req_timeout;
        rv = select(fd + 1, NULL, (void *)&confds, NULL, &tv);
        if (rv == 0) {
            BIO_puts(err, "\x54\x69\x6d\x65\x6f\x75\x74\x20\x6f\x6e\x20\x63\x6f\x6e\x6e\x65\x63\x74\xa");
            return NULL;
        }
    }

    ctx = OCSP_sendreq_new(cbio, path, NULL, -1);
    if (!ctx)
        return NULL;

    for (i = 0; i < sk_CONF_VALUE_num(headers); i++) {
        CONF_VALUE *hdr = sk_CONF_VALUE_value(headers, i);
        if (!OCSP_REQ_CTX_add1_header(ctx, hdr->name, hdr->value))
            goto err;
    }

    if (!OCSP_REQ_CTX_set1_req(ctx, req))
        goto err;

    for (;;) {
        rv = OCSP_sendreq_nbio(&rsp, ctx);
        if (rv != -1)
            break;
        if (req_timeout == -1)
            continue;
        FD_ZERO(&confds);
        openssl_fdset(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec = req_timeout;
        if (BIO_should_read(cbio))
            rv = select(fd + 1, (void *)&confds, NULL, NULL, &tv);
        else if (BIO_should_write(cbio))
            rv = select(fd + 1, NULL, (void *)&confds, NULL, &tv);
        else {
            BIO_puts(err, "\x55\x6e\x65\x78\x70\x65\x63\x74\x65\x64\x20\x72\x65\x74\x72\x79\x20\x63\x6f\x6e\x64\x69\x74\x69\x6f\x6e\xa");
            goto err;
        }
        if (rv == 0) {
            BIO_puts(err, "\x54\x69\x6d\x65\x6f\x75\x74\x20\x6f\x6e\x20\x72\x65\x71\x75\x65\x73\x74\xa");
            break;
        }
        if (rv == -1) {
            BIO_puts(err, "\x53\x65\x6c\x65\x63\x74\x20\x65\x72\x72\x6f\x72\xa");
            break;
        }

    }
 err:
    if (ctx)
        OCSP_REQ_CTX_free(ctx);

    return rsp;
}

OCSP_RESPONSE *process_responder(BIO *err, OCSP_REQUEST *req,
                                 const char *host, const char *path,
                                 const char *port, int use_ssl,
                                 const STACK_OF(CONF_VALUE) *headers,
                                 int req_timeout)
{
    BIO *cbio = NULL;
    SSL_CTX *ctx = NULL;
    OCSP_RESPONSE *resp = NULL;
    cbio = BIO_new_connect(host);
    if (!cbio) {
        BIO_printf(err, "\x45\x72\x72\x6f\x72\x20\x63\x72\x65\x61\x74\x69\x6e\x67\x20\x63\x6f\x6e\x6e\x65\x63\x74\x20\x42\x49\x4f\xa");
        goto end;
    }
    if (port)
        BIO_set_conn_port(cbio, port);
    if (use_ssl == 1) {
        BIO *sbio;
        ctx = SSL_CTX_new(SSLv23_client_method());
        if (ctx == NULL) {
            BIO_printf(err, "\x45\x72\x72\x6f\x72\x20\x63\x72\x65\x61\x74\x69\x6e\x67\x20\x53\x53\x4c\x20\x63\x6f\x6e\x74\x65\x78\x74\x2e\xa");
            goto end;
        }
        SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
        sbio = BIO_new_ssl(ctx, 1);
        cbio = BIO_push(sbio, cbio);
    }
    resp = query_responder(err, cbio, path, headers, req, req_timeout);
    if (!resp)
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x71\x75\x65\x72\x79\x69\x6e\x67\x20\x4f\x43\x53\x50\x20\x72\x65\x73\x70\x6f\x6e\x64\x65\x72\xa");
 end:
    if (cbio)
        BIO_free_all(cbio);
    if (ctx)
        SSL_CTX_free(ctx);
    return resp;
}

#endif

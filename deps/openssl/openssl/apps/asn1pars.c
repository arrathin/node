/* apps/asn1pars.c */
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
 * A nice addition from Dr Stephen Henson <steve@openssl.org> to add the
 * -strparse option which parses nested binary structures
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

/*-
 * -inform arg  - input format - default PEM (DER or PEM)
 * -in arg      - input file - default stdin
 * -i           - indent the details by depth
 * -offset      - where in the file to start
 * -length      - how many bytes to use
 * -oid file    - extra oid description file
 */

#undef PROG
#define PROG    asn1parse_main

int MAIN(int, char **);

static int do_generate(BIO *bio, char *genstr, char *genconf, BUF_MEM *buf);

int MAIN(int argc, char **argv)
{
    int i, badops = 0, offset = 0, ret = 1, j;
    unsigned int length = 0;
    long num, tmplen;
    BIO *in = NULL, *out = NULL, *b64 = NULL, *derout = NULL;
    int informat, indent = 0, noout = 0, dump = 0;
    char *infile = NULL, *str = NULL, *prog, *oidfile = NULL, *derfile = NULL;
    char *genstr = NULL, *genconf = NULL;
    unsigned char *tmpbuf;
    const unsigned char *ctmpbuf;
    BUF_MEM *buf = NULL;
    STACK_OF(OPENSSL_STRING) *osk = NULL;
    ASN1_TYPE *at = NULL;

    informat = FORMAT_PEM;

    apps_startup();

    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (!load_config(bio_err, NULL))
        goto end;

    prog = argv[0];
    argc--;
    argv++;
    if ((osk = sk_OPENSSL_STRING_new_null()) == NULL) {
        BIO_printf(bio_err, "\x4d\x65\x6d\x6f\x72\x79\x20\x61\x6c\x6c\x6f\x63\x61\x74\x69\x6f\x6e\x20\x66\x61\x69\x6c\x75\x72\x65\xa");
        goto end;
    }
    while (argc >= 1) {
        if (strcmp(*argv, "\x2d\x69\x6e\x66\x6f\x72\x6d") == 0) {
            if (--argc < 1)
                goto bad;
            informat = str2fmt(*(++argv));
        } else if (strcmp(*argv, "\x2d\x69\x6e") == 0) {
            if (--argc < 1)
                goto bad;
            infile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6f\x75\x74") == 0) {
            if (--argc < 1)
                goto bad;
            derfile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x69") == 0) {
            indent = 1;
        } else if (strcmp(*argv, "\x2d\x6e\x6f\x6f\x75\x74") == 0)
            noout = 1;
        else if (strcmp(*argv, "\x2d\x6f\x69\x64") == 0) {
            if (--argc < 1)
                goto bad;
            oidfile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6f\x66\x66\x73\x65\x74") == 0) {
            if (--argc < 1)
                goto bad;
            offset = atoi(*(++argv));
        } else if (strcmp(*argv, "\x2d\x6c\x65\x6e\x67\x74\x68") == 0) {
            if (--argc < 1)
                goto bad;
            length = atoi(*(++argv));
            if (length == 0)
                goto bad;
        } else if (strcmp(*argv, "\x2d\x64\x75\x6d\x70") == 0) {
            dump = -1;
        } else if (strcmp(*argv, "\x2d\x64\x6c\x69\x6d\x69\x74") == 0) {
            if (--argc < 1)
                goto bad;
            dump = atoi(*(++argv));
            if (dump <= 0)
                goto bad;
        } else if (strcmp(*argv, "\x2d\x73\x74\x72\x70\x61\x72\x73\x65") == 0) {
            if (--argc < 1)
                goto bad;
            sk_OPENSSL_STRING_push(osk, *(++argv));
        } else if (strcmp(*argv, "\x2d\x67\x65\x6e\x73\x74\x72") == 0) {
            if (--argc < 1)
                goto bad;
            genstr = *(++argv);
        } else if (strcmp(*argv, "\x2d\x67\x65\x6e\x63\x6f\x6e\x66") == 0) {
            if (--argc < 1)
                goto bad;
            genconf = *(++argv);
        } else {
            BIO_printf(bio_err, "\x75\x6e\x6b\x6e\x6f\x77\x6e\x20\x6f\x70\x74\x69\x6f\x6e\x20\x25\x73\xa", *argv);
            badops = 1;
            break;
        }
        argc--;
        argv++;
    }

    if (badops) {
 bad:
        BIO_printf(bio_err, "\x25\x73\x20\x5b\x6f\x70\x74\x69\x6f\x6e\x73\x5d\x20\x3c\x69\x6e\x66\x69\x6c\x65\xa", prog);
        BIO_printf(bio_err, "\x77\x68\x65\x72\x65\x20\x6f\x70\x74\x69\x6f\x6e\x73\x20\x61\x72\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x69\x6e\x66\x6f\x72\x6d\x20\x61\x72\x67\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x2d\x20\x6f\x6e\x65\x20\x6f\x66\x20\x44\x45\x52\x20\x50\x45\x4d\xa");
        BIO_printf(bio_err, "\x20\x2d\x69\x6e\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err,
                   "\x20\x2d\x6f\x75\x74\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x28\x6f\x75\x74\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x69\x73\x20\x61\x6c\x77\x61\x79\x73\x20\x44\x45\x52\xa");
        BIO_printf(bio_err, "\x20\x2d\x6e\x6f\x6f\x75\x74\x20\x61\x72\x67\x20\x20\x20\x20\x64\x6f\x6e\x27\x74\x20\x70\x72\x6f\x64\x75\x63\x65\x20\x61\x6e\x79\x20\x6f\x75\x74\x70\x75\x74\xa");
        BIO_printf(bio_err, "\x20\x2d\x6f\x66\x66\x73\x65\x74\x20\x61\x72\x67\x20\x20\x20\x6f\x66\x66\x73\x65\x74\x20\x69\x6e\x74\x6f\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x6c\x65\x6e\x67\x74\x68\x20\x61\x72\x67\x20\x20\x20\x6c\x65\x6e\x67\x74\x68\x20\x6f\x66\x20\x73\x65\x63\x74\x69\x6f\x6e\x20\x69\x6e\x20\x66\x69\x6c\x65\xa");
        BIO_printf(bio_err, "\x20\x2d\x69\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x69\x6e\x64\x65\x6e\x74\x20\x65\x6e\x74\x72\x69\x65\x73\xa");
        BIO_printf(bio_err, "\x20\x2d\x64\x75\x6d\x70\x20\x20\x20\x20\x20\x20\x20\x20\x20\x64\x75\x6d\x70\x20\x75\x6e\x6b\x6e\x6f\x77\x6e\x20\x64\x61\x74\x61\x20\x69\x6e\x20\x68\x65\x78\x20\x66\x6f\x72\x6d\xa");
        BIO_printf(bio_err,
                   "\x20\x2d\x64\x6c\x69\x6d\x69\x74\x20\x61\x72\x67\x20\x20\x20\x64\x75\x6d\x70\x20\x74\x68\x65\x20\x66\x69\x72\x73\x74\x20\x61\x72\x67\x20\x62\x79\x74\x65\x73\x20\x6f\x66\x20\x75\x6e\x6b\x6e\x6f\x77\x6e\x20\x64\x61\x74\x61\x20\x69\x6e\x20\x68\x65\x78\x20\x66\x6f\x72\x6d\xa");
        BIO_printf(bio_err, "\x20\x2d\x6f\x69\x64\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x20\x66\x69\x6c\x65\x20\x6f\x66\x20\x65\x78\x74\x72\x61\x20\x6f\x69\x64\x20\x64\x65\x66\x69\x6e\x69\x74\x69\x6f\x6e\x73\xa");
        BIO_printf(bio_err, "\x20\x2d\x73\x74\x72\x70\x61\x72\x73\x65\x20\x6f\x66\x66\x73\x65\x74\xa");
        BIO_printf(bio_err,
                   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x61\x20\x73\x65\x72\x69\x65\x73\x20\x6f\x66\x20\x74\x68\x65\x73\x65\x20\x63\x61\x6e\x20\x62\x65\x20\x75\x73\x65\x64\x20\x74\x6f\x20\x27\x64\x69\x67\x27\x20\x69\x6e\x74\x6f\x20\x6d\x75\x6c\x74\x69\x70\x6c\x65\xa");
        BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x41\x53\x4e\x31\x20\x62\x6c\x6f\x62\x20\x77\x72\x61\x70\x70\x69\x6e\x67\x73\xa");
        BIO_printf(bio_err,
                   "\x20\x2d\x67\x65\x6e\x73\x74\x72\x20\x73\x74\x72\x20\x20\x20\x73\x74\x72\x69\x6e\x67\x20\x74\x6f\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x20\x41\x53\x4e\x31\x20\x73\x74\x72\x75\x63\x74\x75\x72\x65\x20\x66\x72\x6f\x6d\xa");
        BIO_printf(bio_err,
                   "\x20\x2d\x67\x65\x6e\x63\x6f\x6e\x66\x20\x66\x69\x6c\x65\x20\x66\x69\x6c\x65\x20\x74\x6f\x20\x67\x65\x6e\x65\x72\x61\x74\x65\x20\x41\x53\x4e\x31\x20\x73\x74\x72\x75\x63\x74\x75\x72\x65\x20\x66\x72\x6f\x6d\xa");
        goto end;
    }

    ERR_load_crypto_strings();

    in = BIO_new(BIO_s_file());
    out = BIO_new(BIO_s_file());
    if ((in == NULL) || (out == NULL)) {
        ERR_print_errors(bio_err);
        goto end;
    }
    BIO_set_fp(out, stdout, BIO_NOCLOSE | BIO_FP_TEXT);
#ifdef OPENSSL_SYS_VMS
    {
        BIO *tmpbio = BIO_new(BIO_f_linebuffer());
        out = BIO_push(tmpbio, out);
    }
#endif

    if (oidfile != NULL) {
        if (BIO_read_filename(in, oidfile) <= 0) {
            BIO_printf(bio_err, "\x70\x72\x6f\x62\x6c\x65\x6d\x73\x20\x6f\x70\x65\x6e\x69\x6e\x67\x20\x25\x73\xa", oidfile);
            ERR_print_errors(bio_err);
            goto end;
        }
        OBJ_create_objects(in);
    }

    if (infile == NULL)
        BIO_set_fp(in, stdin, BIO_NOCLOSE);
    else {
        if (BIO_read_filename(in, infile) <= 0) {
            perror(infile);
            goto end;
        }
    }

    if (derfile) {
        if (!(derout = BIO_new_file(derfile, "\x77\x62"))) {
            BIO_printf(bio_err, "\x70\x72\x6f\x62\x6c\x65\x6d\x73\x20\x6f\x70\x65\x6e\x69\x6e\x67\x20\x25\x73\xa", derfile);
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if ((buf = BUF_MEM_new()) == NULL)
        goto end;
    if (!BUF_MEM_grow(buf, BUFSIZ * 8))
        goto end;               /* Pre-allocate :-) */

    if (genstr || genconf) {
        num = do_generate(bio_err, genstr, genconf, buf);
        if (num < 0) {
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    else {

        if (informat == FORMAT_PEM) {
            BIO *tmp;

            if ((b64 = BIO_new(BIO_f_base64())) == NULL)
                goto end;
            BIO_push(b64, in);
            tmp = in;
            in = b64;
            b64 = tmp;
        }

        num = 0;
        for (;;) {
            if (!BUF_MEM_grow(buf, (int)num + BUFSIZ))
                goto end;
            i = BIO_read(in, &(buf->data[num]), BUFSIZ);
            if (i <= 0)
                break;
            num += i;
        }
    }
    str = buf->data;

    /* If any structs to parse go through in sequence */

    if (sk_OPENSSL_STRING_num(osk)) {
        tmpbuf = (unsigned char *)str;
        tmplen = num;
        for (i = 0; i < sk_OPENSSL_STRING_num(osk); i++) {
            ASN1_TYPE *atmp;
            int typ;
            j = atoi(sk_OPENSSL_STRING_value(osk, i));
            if (j <= 0 || j >= tmplen) {
                BIO_printf(bio_err, "\x27\x25\x73\x27\x20\x69\x73\x20\x61\x6e\x20\x69\x6e\x76\x61\x6c\x69\x64\x20\x6e\x75\x6d\x62\x65\x72\xa",
                           sk_OPENSSL_STRING_value(osk, i));
                continue;
            }
            tmpbuf += j;
            tmplen -= j;
            atmp = at;
            ctmpbuf = tmpbuf;
            at = d2i_ASN1_TYPE(NULL, &ctmpbuf, tmplen);
            ASN1_TYPE_free(atmp);
            if (!at) {
                BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x70\x61\x72\x73\x69\x6e\x67\x20\x73\x74\x72\x75\x63\x74\x75\x72\x65\xa");
                ERR_print_errors(bio_err);
                goto end;
            }
            typ = ASN1_TYPE_get(at);
            if ((typ == V_ASN1_OBJECT)
                || (typ == V_ASN1_BOOLEAN)
                || (typ == V_ASN1_NULL)) {
                BIO_printf(bio_err, "\x43\x61\x6e\x27\x74\x20\x70\x61\x72\x73\x65\x20\x25\x73\x20\x74\x79\x70\x65\xa", ASN1_tag2str(typ));
                ERR_print_errors(bio_err);
                goto end;
            }
            /* hmm... this is a little evil but it works */
            tmpbuf = at->value.asn1_string->data;
            tmplen = at->value.asn1_string->length;
        }
        str = (char *)tmpbuf;
        num = tmplen;
    }

    if (offset < 0 || offset >= num) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x3a\x20\x6f\x66\x66\x73\x65\x74\x20\x6f\x75\x74\x20\x6f\x66\x20\x72\x61\x6e\x67\x65\xa");
        goto end;
    }

    num -= offset;

    if (length == 0 || length > (unsigned int)num)
        length = (unsigned int)num;
    if (derout) {
        if (BIO_write(derout, str + offset, length) != (int)length) {
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x77\x72\x69\x74\x69\x6e\x67\x20\x6f\x75\x74\x70\x75\x74\xa");
            ERR_print_errors(bio_err);
            goto end;
        }
    }
    if (!noout &&
        !ASN1_parse_dump(out, (unsigned char *)&(str[offset]), length,
                         indent, dump)) {
        ERR_print_errors(bio_err);
        goto end;
    }
    ret = 0;
 end:
    BIO_free(derout);
    if (in != NULL)
        BIO_free(in);
    if (out != NULL)
        BIO_free_all(out);
    if (b64 != NULL)
        BIO_free(b64);
    if (ret != 0)
        ERR_print_errors(bio_err);
    if (buf != NULL)
        BUF_MEM_free(buf);
    if (at != NULL)
        ASN1_TYPE_free(at);
    if (osk != NULL)
        sk_OPENSSL_STRING_free(osk);
    OBJ_cleanup();
    apps_shutdown();
    OPENSSL_EXIT(ret);
}

static int do_generate(BIO *bio, char *genstr, char *genconf, BUF_MEM *buf)
{
    CONF *cnf = NULL;
    int len;
    long errline = 0;
    unsigned char *p;
    ASN1_TYPE *atyp = NULL;

    if (genconf) {
        cnf = NCONF_new(NULL);
        if (!NCONF_load(cnf, genconf, &errline))
            goto conferr;
        if (!genstr)
            genstr = NCONF_get_string(cnf, "\x64\x65\x66\x61\x75\x6c\x74", "\x61\x73\x6e\x31");
        if (!genstr) {
            BIO_printf(bio, "\x43\x61\x6e\x27\x74\x20\x66\x69\x6e\x64\x20\x27\x61\x73\x6e\x31\x27\x20\x69\x6e\x20\x27\x25\x73\x27\xa", genconf);
            goto err;
        }
    }

    atyp = ASN1_generate_nconf(genstr, cnf);
    NCONF_free(cnf);
    cnf = NULL;

    if (!atyp)
        return -1;

    len = i2d_ASN1_TYPE(atyp, NULL);

    if (len <= 0)
        goto err;

    if (!BUF_MEM_grow(buf, len))
        goto err;

    p = (unsigned char *)buf->data;

    i2d_ASN1_TYPE(atyp, &p);

    ASN1_TYPE_free(atyp);
    return len;

 conferr:

    if (errline > 0)
        BIO_printf(bio, "\x45\x72\x72\x6f\x72\x20\x6f\x6e\x20\x6c\x69\x6e\x65\x20\x25\x6c\x64\x20\x6f\x66\x20\x63\x6f\x6e\x66\x69\x67\x20\x66\x69\x6c\x65\x20\x27\x25\x73\x27\xa",
                   errline, genconf);
    else
        BIO_printf(bio, "\x45\x72\x72\x6f\x72\x20\x6c\x6f\x61\x64\x69\x6e\x67\x20\x63\x6f\x6e\x66\x69\x67\x20\x66\x69\x6c\x65\x20\x27\x25\x73\x27\xa", genconf);

 err:
    NCONF_free(cnf);
    ASN1_TYPE_free(atyp);

    return -1;

}

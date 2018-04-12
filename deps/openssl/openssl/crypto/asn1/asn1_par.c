/* crypto/asn1/asn1_par.c */
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
#include "cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>

#ifndef ASN1_PARSE_MAXDEPTH
#define ASN1_PARSE_MAXDEPTH 128
#endif

static int asn1_print_info(BIO *bp, int tag, int xclass, int constructed,
                           int indent);
static int asn1_parse2(BIO *bp, const unsigned char **pp, long length,
                       int offset, int depth, int indent, int dump);
static int asn1_print_info(BIO *bp, int tag, int xclass, int constructed,
                           int indent)
{
    static const char fmt[] = "\x25\x2d\x31\x38\x73";
    char str[128];
    const char *p;

    if (constructed & V_ASN1_CONSTRUCTED)
        p = "\x63\x6f\x6e\x73\x3a\x20";
    else
        p = "\x70\x72\x69\x6d\x3a\x20";
    if (BIO_write(bp, p, 6) < 6)
        goto err;
    BIO_indent(bp, indent, 128);

    p = str;
    if ((xclass & V_ASN1_PRIVATE) == V_ASN1_PRIVATE)
        BIO_snprintf(str, sizeof(str), "\x70\x72\x69\x76\x20\x5b\x20\x25\x64\x20\x5d\x20", tag);
    else if ((xclass & V_ASN1_CONTEXT_SPECIFIC) == V_ASN1_CONTEXT_SPECIFIC)
        BIO_snprintf(str, sizeof(str), "\x63\x6f\x6e\x74\x20\x5b\x20\x25\x64\x20\x5d", tag);
    else if ((xclass & V_ASN1_APPLICATION) == V_ASN1_APPLICATION)
        BIO_snprintf(str, sizeof(str), "\x61\x70\x70\x6c\x20\x5b\x20\x25\x64\x20\x5d", tag);
    else if (tag > 30)
        BIO_snprintf(str, sizeof(str), "\x3c\x41\x53\x4e\x31\x20\x25\x64\x3e", tag);
    else
        p = ASN1_tag2str(tag);

    if (BIO_printf(bp, fmt, p) <= 0)
        goto err;
    return (1);
 err:
    return (0);
}

int ASN1_parse(BIO *bp, const unsigned char *pp, long len, int indent)
{
    return (asn1_parse2(bp, &pp, len, 0, 0, indent, 0));
}

int ASN1_parse_dump(BIO *bp, const unsigned char *pp, long len, int indent,
                    int dump)
{
    return (asn1_parse2(bp, &pp, len, 0, 0, indent, dump));
}

static int asn1_parse2(BIO *bp, const unsigned char **pp, long length,
                       int offset, int depth, int indent, int dump)
{
    const unsigned char *p, *ep, *tot, *op, *opp;
    long len;
    int tag, xclass, ret = 0;
    int nl, hl, j, r;
    ASN1_OBJECT *o = NULL;
    ASN1_OCTET_STRING *os = NULL;
    /* ASN1_BMPSTRING *bmp=NULL; */
    int dump_indent;

#if 0
    dump_indent = indent;
#else
    dump_indent = 6;            /* Because we know BIO_dump_indent() */
#endif

    if (depth > ASN1_PARSE_MAXDEPTH) {
            BIO_puts(bp, "\x42\x41\x44\x20\x52\x45\x43\x55\x52\x53\x49\x4f\x4e\x20\x44\x45\x50\x54\x48\xa");
            return 0;
    }

    p = *pp;
    tot = p + length;
    op = p - 1;
    while ((p < tot) && (op < p)) {
        op = p;
        j = ASN1_get_object(&p, &len, &tag, &xclass, length);
#ifdef LINT
        j = j;
#endif
        if (j & 0x80) {
            if (BIO_write(bp, "\x45\x72\x72\x6f\x72\x20\x69\x6e\x20\x65\x6e\x63\x6f\x64\x69\x6e\x67\xa", 18) <= 0)
                goto end;
            ret = 0;
            goto end;
        }
        hl = (p - op);
        length -= hl;
        /*
         * if j == 0x21 it is a constructed indefinite length object
         */
        if (BIO_printf(bp, "\x25\x35\x6c\x64\x3a", (long)offset + (long)(op - *pp))
            <= 0)
            goto end;

        if (j != (V_ASN1_CONSTRUCTED | 1)) {
            if (BIO_printf(bp, "\x64\x3d\x25\x2d\x32\x64\x20\x68\x6c\x3d\x25\x6c\x64\x20\x6c\x3d\x25\x34\x6c\x64\x20",
                           depth, (long)hl, len) <= 0)
                goto end;
        } else {
            if (BIO_printf(bp, "\x64\x3d\x25\x2d\x32\x64\x20\x68\x6c\x3d\x25\x6c\x64\x20\x6c\x3d\x69\x6e\x66\x20\x20", depth, (long)hl) <= 0)
                goto end;
        }
        if (!asn1_print_info(bp, tag, xclass, j, (indent) ? depth : 0))
            goto end;
        if (j & V_ASN1_CONSTRUCTED) {
            const unsigned char *sp;

            ep = p + len;
            if (BIO_write(bp, "\xa", 1) <= 0)
                goto end;
            if (len > length) {
                BIO_printf(bp, "\x6c\x65\x6e\x67\x74\x68\x20\x69\x73\x20\x67\x72\x65\x61\x74\x65\x72\x20\x74\x68\x61\x6e\x20\x25\x6c\x64\xa", length);
                ret = 0;
                goto end;
            }
            if ((j == 0x21) && (len == 0)) {
                sp = p;
                for (;;) {
                    r = asn1_parse2(bp, &p, (long)(tot - p),
                                    offset + (p - *pp), depth + 1,
                                    indent, dump);
                    if (r == 0) {
                        ret = 0;
                        goto end;
                    }
                    if ((r == 2) || (p >= tot)) {
                        len = p - sp;
                        break;
                    }
                }
            } else {
                long tmp = len;

                while (p < ep) {
                    sp = p;
                    r = asn1_parse2(bp, &p, tmp, offset + (p - *pp), depth + 1,
                                    indent, dump);
                    if (r == 0) {
                        ret = 0;
                        goto end;
                    }
                    tmp -= p - sp;
                }
            }
        } else if (xclass != 0) {
            p += len;
            if (BIO_write(bp, "\xa", 1) <= 0)
                goto end;
        } else {
            nl = 0;
            if ((tag == V_ASN1_PRINTABLESTRING) ||
                (tag == V_ASN1_T61STRING) ||
                (tag == V_ASN1_IA5STRING) ||
                (tag == V_ASN1_VISIBLESTRING) ||
                (tag == V_ASN1_NUMERICSTRING) ||
                (tag == V_ASN1_UTF8STRING) ||
                (tag == V_ASN1_UTCTIME) || (tag == V_ASN1_GENERALIZEDTIME)) {
                if (BIO_write(bp, "\x3a", 1) <= 0)
                    goto end;
                if ((len > 0) && BIO_write(bp, (const char *)p, (int)len)
                    != (int)len)
                    goto end;
            } else if (tag == V_ASN1_OBJECT) {
                opp = op;
                if (d2i_ASN1_OBJECT(&o, &opp, len + hl) != NULL) {
                    if (BIO_write(bp, "\x3a", 1) <= 0)
                        goto end;
                    i2a_ASN1_OBJECT(bp, o);
                } else {
                    if (BIO_write(bp, "\x3a\x42\x41\x44\x20\x4f\x42\x4a\x45\x43\x54", 11) <= 0)
                        goto end;
                }
            } else if (tag == V_ASN1_BOOLEAN) {
                int ii;

                opp = op;
                ii = d2i_ASN1_BOOLEAN(NULL, &opp, len + hl);
                if (ii < 0) {
                    if (BIO_write(bp, "\x42\x61\x64\x20\x62\x6f\x6f\x6c\x65\x61\x6e\xa", 12) <= 0)
                        goto end;
                }
                BIO_printf(bp, "\x3a\x25\x64", ii);
            } else if (tag == V_ASN1_BMPSTRING) {
                /* do the BMP thang */
            } else if (tag == V_ASN1_OCTET_STRING) {
                int i, printable = 1;

                opp = op;
                os = d2i_ASN1_OCTET_STRING(NULL, &opp, len + hl);
                if (os != NULL && os->length > 0) {
                    opp = os->data;
                    /*
                     * testing whether the octet string is printable
                     */
                    for (i = 0; i < os->length; i++) {
                        if (((opp[i] < '\x20') &&
                             (opp[i] != '\xa') &&
                             (opp[i] != '\xd') &&
                             (opp[i] != '\x9')) || (opp[i] > '\x7e')) {
                            printable = 0;
                            break;
                        }
                    }
                    if (printable)
                        /* printable string */
                    {
                        if (BIO_write(bp, "\x3a", 1) <= 0)
                            goto end;
                        if (BIO_write(bp, (const char *)opp, os->length) <= 0)
                            goto end;
                    } else if (!dump)
                        /*
                         * not printable => print octet string as hex dump
                         */
                    {
                        if (BIO_write(bp, "\x5b\x48\x45\x58\x20\x44\x55\x4d\x50\x5d\x3a", 11) <= 0)
                            goto end;
                        for (i = 0; i < os->length; i++) {
                            if (BIO_printf(bp, "\x25\x30\x32\x58", opp[i]) <= 0)
                                goto end;
                        }
                    } else
                        /* print the normal dump */
                    {
                        if (!nl) {
                            if (BIO_write(bp, "\xa", 1) <= 0)
                                goto end;
                        }
                        if (BIO_dump_indent(bp,
                                            (const char *)opp,
                                            ((dump == -1 || dump >
                                              os->
                                              length) ? os->length : dump),
                                            dump_indent) <= 0)
                            goto end;
                        nl = 1;
                    }
                }
                if (os != NULL) {
                    M_ASN1_OCTET_STRING_free(os);
                    os = NULL;
                }
            } else if (tag == V_ASN1_INTEGER) {
                ASN1_INTEGER *bs;
                int i;

                opp = op;
                bs = d2i_ASN1_INTEGER(NULL, &opp, len + hl);
                if (bs != NULL) {
                    if (BIO_write(bp, "\x3a", 1) <= 0)
                        goto end;
                    if (bs->type == V_ASN1_NEG_INTEGER)
                        if (BIO_write(bp, "\x2d", 1) <= 0)
                            goto end;
                    for (i = 0; i < bs->length; i++) {
                        if (BIO_printf(bp, "\x25\x30\x32\x58", bs->data[i]) <= 0)
                            goto end;
                    }
                    if (bs->length == 0) {
                        if (BIO_write(bp, "\x30\x30", 2) <= 0)
                            goto end;
                    }
                } else {
                    if (BIO_write(bp, "\x42\x41\x44\x20\x49\x4e\x54\x45\x47\x45\x52", 11) <= 0)
                        goto end;
                }
                M_ASN1_INTEGER_free(bs);
            } else if (tag == V_ASN1_ENUMERATED) {
                ASN1_ENUMERATED *bs;
                int i;

                opp = op;
                bs = d2i_ASN1_ENUMERATED(NULL, &opp, len + hl);
                if (bs != NULL) {
                    if (BIO_write(bp, "\x3a", 1) <= 0)
                        goto end;
                    if (bs->type == V_ASN1_NEG_ENUMERATED)
                        if (BIO_write(bp, "\x2d", 1) <= 0)
                            goto end;
                    for (i = 0; i < bs->length; i++) {
                        if (BIO_printf(bp, "\x25\x30\x32\x58", bs->data[i]) <= 0)
                            goto end;
                    }
                    if (bs->length == 0) {
                        if (BIO_write(bp, "\x30\x30", 2) <= 0)
                            goto end;
                    }
                } else {
                    if (BIO_write(bp, "\x42\x41\x44\x20\x45\x4e\x55\x4d\x45\x52\x41\x54\x45\x44", 14) <= 0)
                        goto end;
                }
                M_ASN1_ENUMERATED_free(bs);
            } else if (len > 0 && dump) {
                if (!nl) {
                    if (BIO_write(bp, "\xa", 1) <= 0)
                        goto end;
                }
                if (BIO_dump_indent(bp, (const char *)p,
                                    ((dump == -1 || dump > len) ? len : dump),
                                    dump_indent) <= 0)
                    goto end;
                nl = 1;
            }

            if (!nl) {
                if (BIO_write(bp, "\xa", 1) <= 0)
                    goto end;
            }
            p += len;
            if ((tag == V_ASN1_EOC) && (xclass == 0)) {
                ret = 2;        /* End of sequence */
                goto end;
            }
        }
        length -= len;
    }
    ret = 1;
 end:
    if (o != NULL)
        ASN1_OBJECT_free(o);
    if (os != NULL)
        M_ASN1_OCTET_STRING_free(os);
    *pp = p;
    return (ret);
}

const char *ASN1_tag2str(int tag)
{
    static const char *const tag2str[] = {
        /* 0-4 */
        "\x45\x4f\x43", "\x42\x4f\x4f\x4c\x45\x41\x4e", "\x49\x4e\x54\x45\x47\x45\x52", "\x42\x49\x54\x20\x53\x54\x52\x49\x4e\x47", "\x4f\x43\x54\x45\x54\x20\x53\x54\x52\x49\x4e\x47",
        /* 5-9 */
        "\x4e\x55\x4c\x4c", "\x4f\x42\x4a\x45\x43\x54", "\x4f\x42\x4a\x45\x43\x54\x20\x44\x45\x53\x43\x52\x49\x50\x54\x4f\x52", "\x45\x58\x54\x45\x52\x4e\x41\x4c", "\x52\x45\x41\x4c",
        /* 10-13 */
        "\x45\x4e\x55\x4d\x45\x52\x41\x54\x45\x44", "\x3c\x41\x53\x4e\x31\x20\x31\x31\x3e", "\x55\x54\x46\x38\x53\x54\x52\x49\x4e\x47", "\x3c\x41\x53\x4e\x31\x20\x31\x33\x3e",
        /* 15-17 */
        "\x3c\x41\x53\x4e\x31\x20\x31\x34\x3e", "\x3c\x41\x53\x4e\x31\x20\x31\x35\x3e", "\x53\x45\x51\x55\x45\x4e\x43\x45", "\x53\x45\x54",
        /* 18-20 */
        "\x4e\x55\x4d\x45\x52\x49\x43\x53\x54\x52\x49\x4e\x47", "\x50\x52\x49\x4e\x54\x41\x42\x4c\x45\x53\x54\x52\x49\x4e\x47", "\x54\x36\x31\x53\x54\x52\x49\x4e\x47",
        /* 21-24 */
        "\x56\x49\x44\x45\x4f\x54\x45\x58\x53\x54\x52\x49\x4e\x47", "\x49\x41\x35\x53\x54\x52\x49\x4e\x47", "\x55\x54\x43\x54\x49\x4d\x45", "\x47\x45\x4e\x45\x52\x41\x4c\x49\x5a\x45\x44\x54\x49\x4d\x45",
        /* 25-27 */
        "\x47\x52\x41\x50\x48\x49\x43\x53\x54\x52\x49\x4e\x47", "\x56\x49\x53\x49\x42\x4c\x45\x53\x54\x52\x49\x4e\x47", "\x47\x45\x4e\x45\x52\x41\x4c\x53\x54\x52\x49\x4e\x47",
        /* 28-30 */
        "\x55\x4e\x49\x56\x45\x52\x53\x41\x4c\x53\x54\x52\x49\x4e\x47", "\x3c\x41\x53\x4e\x31\x20\x32\x39\x3e", "\x42\x4d\x50\x53\x54\x52\x49\x4e\x47"
    };

    if ((tag == V_ASN1_NEG_INTEGER) || (tag == V_ASN1_NEG_ENUMERATED))
        tag &= ~0x100;

    if (tag < 0 || tag > 30)
        return "\x28\x75\x6e\x6b\x6e\x6f\x77\x6e\x29";
    return tag2str[tag];
}

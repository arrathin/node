/* apps/apps.c */
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
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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

#if !defined(_POSIX_C_SOURCE) && defined(OPENSSL_SYS_VMS)
/*
 * On VMS, you need to define this to get the declaration of fileno().  The
 * value 2 is to make sure no function defined in POSIX-2 is left undefined.
 */
# define _POSIX_C_SOURCE 2
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ui.h>
#include <openssl/safestack.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif
#ifndef OPENSSL_NO_RSA
# include <openssl/rsa.h>
#endif
#include <openssl/bn.h>
#ifndef OPENSSL_NO_JPAKE
# include <openssl/jpake.h>
#endif

#define NON_MAIN
#include "apps.h"
#undef NON_MAIN

#ifdef _WIN32
static int WIN32_rename(const char *from, const char *to);
# define rename(from,to) WIN32_rename((from),(to))
# ifdef fileno
#  undef fileno
# endif
# define fileno(a) (int)_fileno(a)
#endif

typedef struct {
    const char *name;
    unsigned long flag;
    unsigned long mask;
} NAME_EX_TBL;

static UI_METHOD *ui_method = NULL;

static int set_table_opts(unsigned long *flags, const char *arg,
                          const NAME_EX_TBL * in_tbl);
static int set_multi_opts(unsigned long *flags, const char *arg,
                          const NAME_EX_TBL * in_tbl);

#if !defined(OPENSSL_NO_RC4) && !defined(OPENSSL_NO_RSA)
/* Looks like this stuff is worth moving into separate function */
static EVP_PKEY *load_netscape_key(BIO *err, BIO *key, const char *file,
                                   const char *key_descrip, int format);
#endif

int app_init(long mesgwin);
#ifdef undef                    /* never finished - probably never will be
                                 * :-) */
int args_from_file(char *file, int *argc, char **argv[])
{
    FILE *fp;
    int num, i;
    unsigned int len;
    static char *buf = NULL;
    static char **arg = NULL;
    char *p;

    fp = fopen(file, "\x72");
    if (fp == NULL)
        return (0);

    if (fseek(fp, 0, SEEK_END) == 0)
        len = ftell(fp), rewind(fp);
    else
        len = -1;
    if (len <= 0) {
        fclose(fp);
        return (0);
    }

    *argc = 0;
    *argv = NULL;

    if (buf != NULL)
        OPENSSL_free(buf);
    buf = (char *)OPENSSL_malloc(len + 1);
    if (buf == NULL)
        return (0);

    len = fread(buf, 1, len, fp);
    if (len <= 1)
        return (0);
    buf[len] = '\x0';

    i = 0;
    for (p = buf; *p; p++)
        if (*p == '\xa')
            i++;
    if (arg != NULL)
        OPENSSL_free(arg);
    arg = (char **)OPENSSL_malloc(sizeof(char *) * (i * 2));
    if (arg == NULL)
        return 0;
    *argv = arg;
    num = 0;
    p = buf;
    for (;;) {
        if (!*p)
            break;
        if (*p == '\x23') {        /* comment line */
            while (*p && (*p != '\xa'))
                p++;
            continue;
        }
        /* else we have a line */
        *(arg++) = p;
        num++;
        while (*p && ((*p != '\x20') && (*p != '\x9') && (*p != '\xa')))
            p++;
        if (!*p)
            break;
        if (*p == '\xa') {
            *(p++) = '\x0';
            continue;
        }
        /* else it is a tab or space */
        p++;
        while (*p && ((*p == '\x20') || (*p == '\x9') || (*p == '\xa')))
            p++;
        if (!*p)
            break;
        if (*p == '\xa') {
            p++;
            continue;
        }
        *(arg++) = p++;
        num++;
        while (*p && (*p != '\xa'))
            p++;
        if (!*p)
            break;
        /* else *p == '\n' */
        *(p++) = '\x0';
    }
    *argc = num;
    return (1);
}
#endif

int str2fmt(char *s)
{
    if (s == NULL)
        return FORMAT_UNDEF;
    if ((*s == '\x44') || (*s == '\x64'))
        return (FORMAT_ASN1);
    else if ((*s == '\x54') || (*s == '\x74'))
        return (FORMAT_TEXT);
    else if ((*s == '\x4e') || (*s == '\x6e'))
        return (FORMAT_NETSCAPE);
    else if ((*s == '\x53') || (*s == '\x73'))
        return (FORMAT_SMIME);
    else if ((*s == '\x4d') || (*s == '\x6d'))
        return (FORMAT_MSBLOB);
    else if ((*s == '\x31')
             || (strcmp(s, "\x50\x4b\x43\x53\x31\x32") == 0) || (strcmp(s, "\x70\x6b\x63\x73\x31\x32") == 0)
             || (strcmp(s, "\x50\x31\x32") == 0) || (strcmp(s, "\x70\x31\x32") == 0))
        return (FORMAT_PKCS12);
    else if ((*s == '\x45') || (*s == '\x65'))
        return (FORMAT_ENGINE);
    else if ((*s == '\x48') || (*s == '\x68'))
        return FORMAT_HTTP;
    else if ((*s == '\x50') || (*s == '\x70')) {
        if (s[1] == '\x56' || s[1] == '\x76')
            return FORMAT_PVK;
        else
            return (FORMAT_PEM);
    } else
        return (FORMAT_UNDEF);
}

#if defined(OPENSSL_SYS_MSDOS) || defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_WIN16) || defined(OPENSSL_SYS_NETWARE)
void program_name(char *in, char *out, int size)
{
    int i, n;
    char *p = NULL;

    n = strlen(in);
    /* find the last '/', '\' or ':' */
    for (i = n - 1; i > 0; i--) {
        if ((in[i] == '\x2f') || (in[i] == '\x5c') || (in[i] == '\x3a')) {
            p = &(in[i + 1]);
            break;
        }
    }
    if (p == NULL)
        p = in;
    n = strlen(p);

# if defined(OPENSSL_SYS_NETWARE)
    /* strip off trailing .nlm if present. */
    if ((n > 4) && (p[n - 4] == '\x2e') &&
        ((p[n - 3] == '\x6e') || (p[n - 3] == '\x4e')) &&
        ((p[n - 2] == '\x6c') || (p[n - 2] == '\x4c')) &&
        ((p[n - 1] == '\x6d') || (p[n - 1] == '\x4d')))
        n -= 4;
# else
    /* strip off trailing .exe if present. */
    if ((n > 4) && (p[n - 4] == '\x2e') &&
        ((p[n - 3] == '\x65') || (p[n - 3] == '\x45')) &&
        ((p[n - 2] == '\x78') || (p[n - 2] == '\x58')) &&
        ((p[n - 1] == '\x65') || (p[n - 1] == '\x45')))
        n -= 4;
# endif

    if (n > size - 1)
        n = size - 1;

    for (i = 0; i < n; i++) {
        if ((p[i] >= '\x41') && (p[i] <= '\x5a'))
            out[i] = p[i] - '\x41' + '\x61';
        else
            out[i] = p[i];
    }
    out[n] = '\x0';
}
#else
# ifdef OPENSSL_SYS_VMS
void program_name(char *in, char *out, int size)
{
    char *p = in, *q;
    char *chars = "\x3a\x5d\x3e";

    while (*chars != '\x0') {
        q = strrchr(p, *chars);
        if (q > p)
            p = q + 1;
        chars++;
    }

    q = strrchr(p, '\x2e');
    if (q == NULL)
        q = p + strlen(p);
    strncpy(out, p, size - 1);
    if (q - p >= size) {
        out[size - 1] = '\x0';
    } else {
        out[q - p] = '\x0';
    }
}
# else
void program_name(char *in, char *out, int size)
{
    char *p;

    p = strrchr(in, '\x2f');
    if (p != NULL)
        p++;
    else
        p = in;
    BUF_strlcpy(out, p, size);
}
# endif
#endif

int chopup_args(ARGS *arg, char *buf, int *argc, char **argv[])
{
    int num, i;
    char *p;

    *argc = 0;
    *argv = NULL;

    i = 0;
    if (arg->count == 0) {
        arg->count = 20;
        arg->data = (char **)OPENSSL_malloc(sizeof(char *) * arg->count);
        if (arg->data == NULL)
            return 0;
    }
    for (i = 0; i < arg->count; i++)
        arg->data[i] = NULL;

    num = 0;
    p = buf;
    for (;;) {
        /* first scan over white space */
        if (!*p)
            break;
        while (*p && ((*p == '\x20') || (*p == '\x9') || (*p == '\xa')))
            p++;
        if (!*p)
            break;

        /* The start of something good :-) */
        if (num >= arg->count) {
            char **tmp_p;
            int tlen = arg->count + 20;
            tmp_p = (char **)OPENSSL_realloc(arg->data,
                                             sizeof(char *) * tlen);
            if (tmp_p == NULL)
                return 0;
            arg->data = tmp_p;
            arg->count = tlen;
            /* initialize newly allocated data */
            for (i = num; i < arg->count; i++)
                arg->data[i] = NULL;
        }
        arg->data[num++] = p;

        /* now look for the end of this */
        if ((*p == '\x27') || (*p == '\x22')) { /* scan for closing quote */
            i = *(p++);
            arg->data[num - 1]++; /* jump over quote */
            while (*p && (*p != i))
                p++;
            *p = '\x0';
        } else {
            while (*p && ((*p != '\x20') && (*p != '\x9') && (*p != '\xa')))
                p++;

            if (*p == '\x0')
                p--;
            else
                *p = '\x0';
        }
        p++;
    }
    *argc = num;
    *argv = arg->data;
    return (1);
}

#ifndef APP_INIT
int app_init(long mesgwin)
{
    return (1);
}
#endif

int dump_cert_text(BIO *out, X509 *x)
{
    char *p;

    p = X509_NAME_oneline(X509_get_subject_name(x), NULL, 0);
    BIO_puts(out, "\x73\x75\x62\x6a\x65\x63\x74\x3d");
    BIO_puts(out, p);
    OPENSSL_free(p);

    p = X509_NAME_oneline(X509_get_issuer_name(x), NULL, 0);
    BIO_puts(out, "\xa\x69\x73\x73\x75\x65\x72\x3d");
    BIO_puts(out, p);
    BIO_puts(out, "\xa");
    OPENSSL_free(p);

    return 0;
}

static int ui_open(UI *ui)
{
    return UI_method_get_opener(UI_OpenSSL())(ui);
}

static int ui_read(UI *ui, UI_STRING *uis)
{
    if (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD
        && UI_get0_user_data(ui)) {
        switch (UI_get_string_type(uis)) {
        case UIT_PROMPT:
        case UIT_VERIFY:
            {
                const char *password =
                    ((PW_CB_DATA *)UI_get0_user_data(ui))->password;
                if (password && password[0] != '\x0') {
                    UI_set_result(ui, uis, password);
                    return 1;
                }
            }
        default:
            break;
        }
    }
    return UI_method_get_reader(UI_OpenSSL())(ui, uis);
}

static int ui_write(UI *ui, UI_STRING *uis)
{
    if (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD
        && UI_get0_user_data(ui)) {
        switch (UI_get_string_type(uis)) {
        case UIT_PROMPT:
        case UIT_VERIFY:
            {
                const char *password =
                    ((PW_CB_DATA *)UI_get0_user_data(ui))->password;
                if (password && password[0] != '\x0')
                    return 1;
            }
        default:
            break;
        }
    }
    return UI_method_get_writer(UI_OpenSSL())(ui, uis);
}

static int ui_close(UI *ui)
{
    return UI_method_get_closer(UI_OpenSSL())(ui);
}

int setup_ui_method(void)
{
    ui_method = UI_create_method("\x4f\x70\x65\x6e\x53\x53\x4c\x20\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x20\x75\x73\x65\x72\x20\x69\x6e\x74\x65\x72\x66\x61\x63\x65");
    UI_method_set_opener(ui_method, ui_open);
    UI_method_set_reader(ui_method, ui_read);
    UI_method_set_writer(ui_method, ui_write);
    UI_method_set_closer(ui_method, ui_close);
    return 0;
}

void destroy_ui_method(void)
{
    if (ui_method) {
        UI_destroy_method(ui_method);
        ui_method = NULL;
    }
}

int password_callback(char *buf, int bufsiz, int verify, PW_CB_DATA *cb_tmp)
{
    UI *ui = NULL;
    int res = 0;
    const char *prompt_info = NULL;
    const char *password = NULL;
    PW_CB_DATA *cb_data = (PW_CB_DATA *)cb_tmp;

    if (cb_data) {
        if (cb_data->password)
            password = cb_data->password;
        if (cb_data->prompt_info)
            prompt_info = cb_data->prompt_info;
    }

    if (password) {
        res = strlen(password);
        if (res > bufsiz)
            res = bufsiz;
        memcpy(buf, password, res);
        return res;
    }

    ui = UI_new_method(ui_method);
    if (ui) {
        int ok = 0;
        char *buff = NULL;
        int ui_flags = 0;
        char *prompt = NULL;

        prompt = UI_construct_prompt(ui, "\x70\x61\x73\x73\x20\x70\x68\x72\x61\x73\x65", prompt_info);
        if (!prompt) {
            BIO_printf(bio_err, "\x4f\x75\x74\x20\x6f\x66\x20\x6d\x65\x6d\x6f\x72\x79\xa");
            UI_free(ui);
            return 0;
        }

        ui_flags |= UI_INPUT_FLAG_DEFAULT_PWD;
        UI_ctrl(ui, UI_CTRL_PRINT_ERRORS, 1, 0, 0);

        if (ok >= 0)
            ok = UI_add_input_string(ui, prompt, ui_flags, buf,
                                     PW_MIN_LENGTH, bufsiz - 1);
        if (ok >= 0 && verify) {
            buff = (char *)OPENSSL_malloc(bufsiz);
            if (!buff) {
                BIO_printf(bio_err, "\x4f\x75\x74\x20\x6f\x66\x20\x6d\x65\x6d\x6f\x72\x79\xa");
                UI_free(ui);
                OPENSSL_free(prompt);
                return 0;
            }
            ok = UI_add_verify_string(ui, prompt, ui_flags, buff,
                                      PW_MIN_LENGTH, bufsiz - 1, buf);
        }
        if (ok >= 0)
            do {
                ok = UI_process(ui);
            }
            while (ok < 0 && UI_ctrl(ui, UI_CTRL_IS_REDOABLE, 0, 0, 0));

        if (buff) {
            OPENSSL_cleanse(buff, (unsigned int)bufsiz);
            OPENSSL_free(buff);
        }

        if (ok >= 0)
            res = strlen(buf);
        if (ok == -1) {
            BIO_printf(bio_err, "\x55\x73\x65\x72\x20\x69\x6e\x74\x65\x72\x66\x61\x63\x65\x20\x65\x72\x72\x6f\x72\xa");
            ERR_print_errors(bio_err);
            OPENSSL_cleanse(buf, (unsigned int)bufsiz);
            res = 0;
        }
        if (ok == -2) {
            BIO_printf(bio_err, "\x61\x62\x6f\x72\x74\x65\x64\x21\xa");
            OPENSSL_cleanse(buf, (unsigned int)bufsiz);
            res = 0;
        }
        UI_free(ui);
        OPENSSL_free(prompt);
    }
    return res;
}

static char *app_get_pass(BIO *err, char *arg, int keepbio);

int app_passwd(BIO *err, char *arg1, char *arg2, char **pass1, char **pass2)
{
    int same;
    if (!arg2 || !arg1 || strcmp(arg1, arg2))
        same = 0;
    else
        same = 1;
    if (arg1) {
        *pass1 = app_get_pass(err, arg1, same);
        if (!*pass1)
            return 0;
    } else if (pass1)
        *pass1 = NULL;
    if (arg2) {
        *pass2 = app_get_pass(err, arg2, same ? 2 : 0);
        if (!*pass2)
            return 0;
    } else if (pass2)
        *pass2 = NULL;
    return 1;
}

static char *app_get_pass(BIO *err, char *arg, int keepbio)
{
    char *tmp, tpass[APP_PASS_LEN];
    static BIO *pwdbio = NULL;
    int i;
    if (!strncmp(arg, "\x70\x61\x73\x73\x3a", 5))
        return BUF_strdup(arg + 5);
    if (!strncmp(arg, "\x65\x6e\x76\x3a", 4)) {
        tmp = getenv(arg + 4);
        if (!tmp) {
            BIO_printf(err, "\x43\x61\x6e\x27\x74\x20\x72\x65\x61\x64\x20\x65\x6e\x76\x69\x72\x6f\x6e\x6d\x65\x6e\x74\x20\x76\x61\x72\x69\x61\x62\x6c\x65\x20\x25\x73\xa", arg + 4);
            return NULL;
        }
        return BUF_strdup(tmp);
    }
    if (!keepbio || !pwdbio) {
        if (!strncmp(arg, "\x66\x69\x6c\x65\x3a", 5)) {
            pwdbio = BIO_new_file(arg + 5, "\x72");
            if (!pwdbio) {
                BIO_printf(err, "\x43\x61\x6e\x27\x74\x20\x6f\x70\x65\x6e\x20\x66\x69\x6c\x65\x20\x25\x73\xa", arg + 5);
                return NULL;
            }
#if !defined(_WIN32)
            /*
             * Under _WIN32, which covers even Win64 and CE, file
             * descriptors referenced by BIO_s_fd are not inherited
             * by child process and therefore below is not an option.
             * It could have been an option if bss_fd.c was operating
             * on real Windows descriptors, such as those obtained
             * with CreateFile.
             */
        } else if (!strncmp(arg, "\x66\x64\x3a", 3)) {
            BIO *btmp;
            i = atoi(arg + 3);
            if (i >= 0)
                pwdbio = BIO_new_fd(i, BIO_NOCLOSE);
            if ((i < 0) || !pwdbio) {
                BIO_printf(err, "\x43\x61\x6e\x27\x74\x20\x61\x63\x63\x65\x73\x73\x20\x66\x69\x6c\x65\x20\x64\x65\x73\x63\x72\x69\x70\x74\x6f\x72\x20\x25\x73\xa", arg + 3);
                return NULL;
            }
            /*
             * Can't do BIO_gets on an fd BIO so add a buffering BIO
             */
            btmp = BIO_new(BIO_f_buffer());
            pwdbio = BIO_push(btmp, pwdbio);
#endif
        } else if (!strcmp(arg, "\x73\x74\x64\x69\x6e")) {
            pwdbio = BIO_new_fp(stdin, BIO_NOCLOSE);
            if (!pwdbio) {
                BIO_printf(err, "\x43\x61\x6e\x27\x74\x20\x6f\x70\x65\x6e\x20\x42\x49\x4f\x20\x66\x6f\x72\x20\x73\x74\x64\x69\x6e\xa");
                return NULL;
            }
        } else {
            BIO_printf(err, "\x49\x6e\x76\x61\x6c\x69\x64\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\x20\x22\x25\x73\x22\xa", arg);
            return NULL;
        }
    }
    i = BIO_gets(pwdbio, tpass, APP_PASS_LEN);
    if (keepbio != 1) {
        BIO_free_all(pwdbio);
        pwdbio = NULL;
    }
    if (i <= 0) {
        BIO_printf(err, "\x45\x72\x72\x6f\x72\x20\x72\x65\x61\x64\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x20\x66\x72\x6f\x6d\x20\x42\x49\x4f\xa");
        return NULL;
    }
    tmp = strchr(tpass, '\xa');
    if (tmp)
        *tmp = 0;
    return BUF_strdup(tpass);
}

int add_oid_section(BIO *err, CONF *conf)
{
    char *p;
    STACK_OF(CONF_VALUE) *sktmp;
    CONF_VALUE *cnf;
    int i;
    if (!(p = NCONF_get_string(conf, NULL, "\x6f\x69\x64\x5f\x73\x65\x63\x74\x69\x6f\x6e"))) {
        ERR_clear_error();
        return 1;
    }
    if (!(sktmp = NCONF_get_section(conf, p))) {
        BIO_printf(err, "\x70\x72\x6f\x62\x6c\x65\x6d\x20\x6c\x6f\x61\x64\x69\x6e\x67\x20\x6f\x69\x64\x20\x73\x65\x63\x74\x69\x6f\x6e\x20\x25\x73\xa", p);
        return 0;
    }
    for (i = 0; i < sk_CONF_VALUE_num(sktmp); i++) {
        cnf = sk_CONF_VALUE_value(sktmp, i);
        if (OBJ_create(cnf->value, cnf->name, cnf->name) == NID_undef) {
            BIO_printf(err, "\x70\x72\x6f\x62\x6c\x65\x6d\x20\x63\x72\x65\x61\x74\x69\x6e\x67\x20\x6f\x62\x6a\x65\x63\x74\x20\x25\x73\x3d\x25\x73\xa",
                       cnf->name, cnf->value);
            return 0;
        }
    }
    return 1;
}

static int load_pkcs12(BIO *err, BIO *in, const char *desc,
                       pem_password_cb *pem_cb, void *cb_data,
                       EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca)
{
    const char *pass;
    char tpass[PEM_BUFSIZE];
    int len, ret = 0;
    PKCS12 *p12;
    p12 = d2i_PKCS12_bio(in, NULL);
    if (p12 == NULL) {
        BIO_printf(err, "\x45\x72\x72\x6f\x72\x20\x6c\x6f\x61\x64\x69\x6e\x67\x20\x50\x4b\x43\x53\x31\x32\x20\x66\x69\x6c\x65\x20\x66\x6f\x72\x20\x25\x73\xa", desc);
        goto die;
    }
    /* See if an empty password will do */
    if (PKCS12_verify_mac(p12, "", 0) || PKCS12_verify_mac(p12, NULL, 0))
        pass = "";
    else {
        if (!pem_cb)
            pem_cb = (pem_password_cb *)password_callback;
        len = pem_cb(tpass, PEM_BUFSIZE, 0, cb_data);
        if (len < 0) {
            BIO_printf(err, "\x50\x61\x73\x73\x70\x68\x61\x72\x73\x65\x20\x63\x61\x6c\x6c\x62\x61\x63\x6b\x20\x65\x72\x72\x6f\x72\x20\x66\x6f\x72\x20\x25\x73\xa", desc);
            goto die;
        }
        if (len < PEM_BUFSIZE)
            tpass[len] = 0;
        if (!PKCS12_verify_mac(p12, tpass, len)) {
            BIO_printf(err,
                       "\x4d\x61\x63\x20\x76\x65\x72\x69\x66\x79\x20\x65\x72\x72\x6f\x72\x20\x28\x77\x72\x6f\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x3f\x29\x20\x69\x6e\x20\x50\x4b\x43\x53\x31\x32\x20\x66\x69\x6c\x65\x20\x66\x6f\x72\x20\x25\x73\xa",
                       desc);
            goto die;
        }
        pass = tpass;
    }
    ret = PKCS12_parse(p12, pass, pkey, cert, ca);
 die:
    if (p12)
        PKCS12_free(p12);
    return ret;
}

int load_cert_crl_http(const char *url, BIO *err,
                       X509 **pcert, X509_CRL **pcrl)
{
    char *host = NULL, *port = NULL, *path = NULL;
    BIO *bio = NULL;
    OCSP_REQ_CTX *rctx = NULL;
    int use_ssl, rv = 0;
    if (!OCSP_parse_url(url, &host, &port, &path, &use_ssl))
        goto err;
    if (use_ssl) {
        if (err)
            BIO_puts(err, "\x68\x74\x74\x70\x73\x20\x6e\x6f\x74\x20\x73\x75\x70\x70\x6f\x72\x74\x65\x64\xa");
        goto err;
    }
    bio = BIO_new_connect(host);
    if (!bio || !BIO_set_conn_port(bio, port))
        goto err;
    rctx = OCSP_REQ_CTX_new(bio, 1024);
    if (!rctx)
        goto err;
    if (!OCSP_REQ_CTX_http(rctx, "\x47\x45\x54", path))
        goto err;
    if (!OCSP_REQ_CTX_add1_header(rctx, "\x48\x6f\x73\x74", host))
        goto err;
    if (pcert) {
        do {
            rv = X509_http_nbio(rctx, pcert);
        }
        while (rv == -1);
    } else {
        do {
            rv = X509_CRL_http_nbio(rctx, pcrl);
        } while (rv == -1);
    }

 err:
    if (host)
        OPENSSL_free(host);
    if (path)
        OPENSSL_free(path);
    if (port)
        OPENSSL_free(port);
    if (bio)
        BIO_free_all(bio);
    if (rctx)
        OCSP_REQ_CTX_free(rctx);
    if (rv != 1) {
        if (bio && err)
            BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x6c\x6f\x61\x64\x69\x6e\x67\x20\x25\x73\x20\x66\x72\x6f\x6d\x20\x25\x73\xa",
                       pcert ? "\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65" : "\x43\x52\x4c", url);
        ERR_print_errors(bio_err);
    }
    return rv;
}

X509 *load_cert(BIO *err, const char *file, int format,
                const char *pass, ENGINE *e, const char *cert_descrip)
{
    X509 *x = NULL;
    BIO *cert;

    if (format == FORMAT_HTTP) {
        load_cert_crl_http(file, err, &x, NULL);
        return x;
    }

    if ((cert = BIO_new(BIO_s_file())) == NULL) {
        ERR_print_errors(err);
        goto end;
    }

    if (file == NULL) {
#ifdef _IONBF
# ifndef OPENSSL_NO_SETVBUF_IONBF
        setvbuf(stdin, NULL, _IONBF, 0);
# endif                         /* ndef OPENSSL_NO_SETVBUF_IONBF */
#endif
        BIO_set_fp(cert, stdin, BIO_NOCLOSE);
    } else {
        if (BIO_read_filename(cert, file) <= 0) {
            BIO_printf(err, "\x45\x72\x72\x6f\x72\x20\x6f\x70\x65\x6e\x69\x6e\x67\x20\x25\x73\x20\x25\x73\xa", cert_descrip, file);
            ERR_print_errors(err);
            goto end;
        }
    }

    if (format == FORMAT_ASN1)
        x = d2i_X509_bio(cert, NULL);
    else if (format == FORMAT_NETSCAPE) {
        NETSCAPE_X509 *nx;
        nx = ASN1_item_d2i_bio(ASN1_ITEM_rptr(NETSCAPE_X509), cert, NULL);
        if (nx == NULL)
            goto end;

        if ((strncmp(NETSCAPE_CERT_HDR, (char *)nx->header->data,
                     nx->header->length) != 0)) {
            NETSCAPE_X509_free(nx);
            BIO_printf(err, "\x45\x72\x72\x6f\x72\x20\x72\x65\x61\x64\x69\x6e\x67\x20\x68\x65\x61\x64\x65\x72\x20\x6f\x6e\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\xa");
            goto end;
        }
        x = nx->cert;
        nx->cert = NULL;
        NETSCAPE_X509_free(nx);
    } else if (format == FORMAT_PEM)
        x = PEM_read_bio_X509_AUX(cert, NULL,
                                  (pem_password_cb *)password_callback, NULL);
    else if (format == FORMAT_PKCS12) {
        if (!load_pkcs12(err, cert, cert_descrip, NULL, NULL, NULL, &x, NULL))
            goto end;
    } else {
        BIO_printf(err, "\x62\x61\x64\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20\x25\x73\xa", cert_descrip);
        goto end;
    }
 end:
    if (x == NULL) {
        BIO_printf(err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6c\x6f\x61\x64\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\xa");
        ERR_print_errors(err);
    }
    if (cert != NULL)
        BIO_free(cert);
    return (x);
}

X509_CRL *load_crl(const char *infile, int format)
{
    X509_CRL *x = NULL;
    BIO *in = NULL;

    if (format == FORMAT_HTTP) {
        load_cert_crl_http(infile, bio_err, NULL, &x);
        return x;
    }

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }

    if (infile == NULL)
        BIO_set_fp(in, stdin, BIO_NOCLOSE);
    else {
        if (BIO_read_filename(in, infile) <= 0) {
            perror(infile);
            goto end;
        }
    }
    if (format == FORMAT_ASN1)
        x = d2i_X509_CRL_bio(in, NULL);
    else if (format == FORMAT_PEM)
        x = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
    else {
        BIO_printf(bio_err, "\x62\x61\x64\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20\x69\x6e\x70\x75\x74\x20\x63\x72\x6c\xa");
        goto end;
    }
    if (x == NULL) {
        BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6c\x6f\x61\x64\x20\x43\x52\x4c\xa");
        ERR_print_errors(bio_err);
        goto end;
    }

 end:
    BIO_free(in);
    return (x);
}

EVP_PKEY *load_key(BIO *err, const char *file, int format, int maybe_stdin,
                   const char *pass, ENGINE *e, const char *key_descrip)
{
    BIO *key = NULL;
    EVP_PKEY *pkey = NULL;
    PW_CB_DATA cb_data;

    cb_data.password = pass;
    cb_data.prompt_info = file;

    if (file == NULL && (!maybe_stdin || format == FORMAT_ENGINE)) {
        BIO_printf(err, "\x6e\x6f\x20\x6b\x65\x79\x66\x69\x6c\x65\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
        goto end;
    }
#ifndef OPENSSL_NO_ENGINE
    if (format == FORMAT_ENGINE) {
        if (!e)
            BIO_printf(err, "\x6e\x6f\x20\x65\x6e\x67\x69\x6e\x65\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
        else {
            if (ENGINE_init(e)) {
                pkey = ENGINE_load_private_key(e, file, ui_method, &cb_data);
                ENGINE_finish(e);
            }
            if (!pkey) {
                BIO_printf(err, "\x63\x61\x6e\x6e\x6f\x74\x20\x6c\x6f\x61\x64\x20\x25\x73\x20\x66\x72\x6f\x6d\x20\x65\x6e\x67\x69\x6e\x65\xa", key_descrip);
                ERR_print_errors(err);
            }
        }
        goto end;
    }
#endif
    key = BIO_new(BIO_s_file());
    if (key == NULL) {
        ERR_print_errors(err);
        goto end;
    }
    if (file == NULL && maybe_stdin) {
#ifdef _IONBF
# ifndef OPENSSL_NO_SETVBUF_IONBF
        setvbuf(stdin, NULL, _IONBF, 0);
# endif                         /* ndef OPENSSL_NO_SETVBUF_IONBF */
#endif
        BIO_set_fp(key, stdin, BIO_NOCLOSE);
    } else if (BIO_read_filename(key, file) <= 0) {
        BIO_printf(err, "\x45\x72\x72\x6f\x72\x20\x6f\x70\x65\x6e\x69\x6e\x67\x20\x25\x73\x20\x25\x73\xa", key_descrip, file);
        ERR_print_errors(err);
        goto end;
    }
    if (format == FORMAT_ASN1) {
        pkey = d2i_PrivateKey_bio(key, NULL);
    } else if (format == FORMAT_PEM) {
        pkey = PEM_read_bio_PrivateKey(key, NULL,
                                       (pem_password_cb *)password_callback,
                                       &cb_data);
    }
#if !defined(OPENSSL_NO_RC4) && !defined(OPENSSL_NO_RSA)
    else if (format == FORMAT_NETSCAPE || format == FORMAT_IISSGC)
        pkey = load_netscape_key(err, key, file, key_descrip, format);
#endif
    else if (format == FORMAT_PKCS12) {
        if (!load_pkcs12(err, key, key_descrip,
                         (pem_password_cb *)password_callback, &cb_data,
                         &pkey, NULL, NULL))
            goto end;
    }
#if !defined(OPENSSL_NO_RSA) && !defined(OPENSSL_NO_DSA) && !defined (OPENSSL_NO_RC4)
    else if (format == FORMAT_MSBLOB)
        pkey = b2i_PrivateKey_bio(key);
    else if (format == FORMAT_PVK)
        pkey = b2i_PVK_bio(key, (pem_password_cb *)password_callback,
                           &cb_data);
#endif
    else {
        BIO_printf(err, "\x62\x61\x64\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20\x6b\x65\x79\x20\x66\x69\x6c\x65\xa");
        goto end;
    }
 end:
    if (key != NULL)
        BIO_free(key);
    if (pkey == NULL) {
        BIO_printf(err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6c\x6f\x61\x64\x20\x25\x73\xa", key_descrip);
        ERR_print_errors(err);
    }
    return (pkey);
}

EVP_PKEY *load_pubkey(BIO *err, const char *file, int format, int maybe_stdin,
                      const char *pass, ENGINE *e, const char *key_descrip)
{
    BIO *key = NULL;
    EVP_PKEY *pkey = NULL;
    PW_CB_DATA cb_data;

    cb_data.password = pass;
    cb_data.prompt_info = file;

    if (file == NULL && (!maybe_stdin || format == FORMAT_ENGINE)) {
        BIO_printf(err, "\x6e\x6f\x20\x6b\x65\x79\x66\x69\x6c\x65\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
        goto end;
    }
#ifndef OPENSSL_NO_ENGINE
    if (format == FORMAT_ENGINE) {
        if (!e)
            BIO_printf(bio_err, "\x6e\x6f\x20\x65\x6e\x67\x69\x6e\x65\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\xa");
        else
            pkey = ENGINE_load_public_key(e, file, ui_method, &cb_data);
        goto end;
    }
#endif
    key = BIO_new(BIO_s_file());
    if (key == NULL) {
        ERR_print_errors(err);
        goto end;
    }
    if (file == NULL && maybe_stdin) {
#ifdef _IONBF
# ifndef OPENSSL_NO_SETVBUF_IONBF
        setvbuf(stdin, NULL, _IONBF, 0);
# endif                         /* ndef OPENSSL_NO_SETVBUF_IONBF */
#endif
        BIO_set_fp(key, stdin, BIO_NOCLOSE);
    } else if (BIO_read_filename(key, file) <= 0) {
        BIO_printf(err, "\x45\x72\x72\x6f\x72\x20\x6f\x70\x65\x6e\x69\x6e\x67\x20\x25\x73\x20\x25\x73\xa", key_descrip, file);
        ERR_print_errors(err);
        goto end;
    }
    if (format == FORMAT_ASN1) {
        pkey = d2i_PUBKEY_bio(key, NULL);
    }
#ifndef OPENSSL_NO_RSA
    else if (format == FORMAT_ASN1RSA) {
        RSA *rsa;
        rsa = d2i_RSAPublicKey_bio(key, NULL);
        if (rsa) {
            pkey = EVP_PKEY_new();
            if (pkey)
                EVP_PKEY_set1_RSA(pkey, rsa);
            RSA_free(rsa);
        } else
            pkey = NULL;
    } else if (format == FORMAT_PEMRSA) {
        RSA *rsa;
        rsa = PEM_read_bio_RSAPublicKey(key, NULL,
                                        (pem_password_cb *)password_callback,
                                        &cb_data);
        if (rsa) {
            pkey = EVP_PKEY_new();
            if (pkey)
                EVP_PKEY_set1_RSA(pkey, rsa);
            RSA_free(rsa);
        } else
            pkey = NULL;
    }
#endif
    else if (format == FORMAT_PEM) {
        pkey = PEM_read_bio_PUBKEY(key, NULL,
                                   (pem_password_cb *)password_callback,
                                   &cb_data);
    }
#if !defined(OPENSSL_NO_RC4) && !defined(OPENSSL_NO_RSA)
    else if (format == FORMAT_NETSCAPE || format == FORMAT_IISSGC)
        pkey = load_netscape_key(err, key, file, key_descrip, format);
#endif
#if !defined(OPENSSL_NO_RSA) && !defined(OPENSSL_NO_DSA)
    else if (format == FORMAT_MSBLOB)
        pkey = b2i_PublicKey_bio(key);
#endif
    else {
        BIO_printf(err, "\x62\x61\x64\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20\x6b\x65\x79\x20\x66\x69\x6c\x65\xa");
        goto end;
    }
 end:
    if (key != NULL)
        BIO_free(key);
    if (pkey == NULL)
        BIO_printf(err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6c\x6f\x61\x64\x20\x25\x73\xa", key_descrip);
    return (pkey);
}

#if !defined(OPENSSL_NO_RC4) && !defined(OPENSSL_NO_RSA)
static EVP_PKEY *load_netscape_key(BIO *err, BIO *key, const char *file,
                                   const char *key_descrip, int format)
{
    EVP_PKEY *pkey;
    BUF_MEM *buf;
    RSA *rsa;
    const unsigned char *p;
    int size, i;

    buf = BUF_MEM_new();
    pkey = EVP_PKEY_new();
    size = 0;
    if (buf == NULL || pkey == NULL)
        goto error;
    for (;;) {
        if (!BUF_MEM_grow_clean(buf, size + 1024 * 10))
            goto error;
        i = BIO_read(key, &(buf->data[size]), 1024 * 10);
        size += i;
        if (i == 0)
            break;
        if (i < 0) {
            BIO_printf(err, "\x45\x72\x72\x6f\x72\x20\x72\x65\x61\x64\x69\x6e\x67\x20\x25\x73\x20\x25\x73", key_descrip, file);
            goto error;
        }
    }
    p = (unsigned char *)buf->data;
    rsa = d2i_RSA_NET(NULL, &p, (long)size, NULL,
                      (format == FORMAT_IISSGC ? 1 : 0));
    if (rsa == NULL)
        goto error;
    BUF_MEM_free(buf);
    EVP_PKEY_set1_RSA(pkey, rsa);
    return pkey;
 error:
    BUF_MEM_free(buf);
    EVP_PKEY_free(pkey);
    return NULL;
}
#endif                          /* ndef OPENSSL_NO_RC4 */

static int load_certs_crls(BIO *err, const char *file, int format,
                           const char *pass, ENGINE *e, const char *desc,
                           STACK_OF(X509) **pcerts,
                           STACK_OF(X509_CRL) **pcrls)
{
    int i;
    BIO *bio;
    STACK_OF(X509_INFO) *xis = NULL;
    X509_INFO *xi;
    PW_CB_DATA cb_data;
    int rv = 0;

    cb_data.password = pass;
    cb_data.prompt_info = file;

    if (format != FORMAT_PEM) {
        BIO_printf(err, "\x62\x61\x64\x20\x69\x6e\x70\x75\x74\x20\x66\x6f\x72\x6d\x61\x74\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x66\x6f\x72\x20\x25\x73\xa", desc);
        return 0;
    }

    if (file == NULL)
        bio = BIO_new_fp(stdin, BIO_NOCLOSE);
    else
        bio = BIO_new_file(file, "\x72");

    if (bio == NULL) {
        BIO_printf(err, "\x45\x72\x72\x6f\x72\x20\x6f\x70\x65\x6e\x69\x6e\x67\x20\x25\x73\x20\x25\x73\xa", desc, file ? file : "\x73\x74\x64\x69\x6e");
        ERR_print_errors(err);
        return 0;
    }

    xis = PEM_X509_INFO_read_bio(bio, NULL,
                                 (pem_password_cb *)password_callback,
                                 &cb_data);

    BIO_free(bio);

    if (pcerts) {
        *pcerts = sk_X509_new_null();
        if (!*pcerts)
            goto end;
    }

    if (pcrls) {
        *pcrls = sk_X509_CRL_new_null();
        if (!*pcrls)
            goto end;
    }

    for (i = 0; i < sk_X509_INFO_num(xis); i++) {
        xi = sk_X509_INFO_value(xis, i);
        if (xi->x509 && pcerts) {
            if (!sk_X509_push(*pcerts, xi->x509))
                goto end;
            xi->x509 = NULL;
        }
        if (xi->crl && pcrls) {
            if (!sk_X509_CRL_push(*pcrls, xi->crl))
                goto end;
            xi->crl = NULL;
        }
    }

    if (pcerts && sk_X509_num(*pcerts) > 0)
        rv = 1;

    if (pcrls && sk_X509_CRL_num(*pcrls) > 0)
        rv = 1;

 end:

    if (xis)
        sk_X509_INFO_pop_free(xis, X509_INFO_free);

    if (rv == 0) {
        if (pcerts) {
            sk_X509_pop_free(*pcerts, X509_free);
            *pcerts = NULL;
        }
        if (pcrls) {
            sk_X509_CRL_pop_free(*pcrls, X509_CRL_free);
            *pcrls = NULL;
        }
        BIO_printf(err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6c\x6f\x61\x64\x20\x25\x73\xa",
                   pcerts ? "\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x73" : "\x43\x52\x4c\x73");
        ERR_print_errors(err);
    }
    return rv;
}

STACK_OF(X509) *load_certs(BIO *err, const char *file, int format,
                           const char *pass, ENGINE *e, const char *desc)
{
    STACK_OF(X509) *certs;
    if (!load_certs_crls(err, file, format, pass, e, desc, &certs, NULL))
        return NULL;
    return certs;
}

STACK_OF(X509_CRL) *load_crls(BIO *err, const char *file, int format,
                              const char *pass, ENGINE *e, const char *desc)
{
    STACK_OF(X509_CRL) *crls;
    if (!load_certs_crls(err, file, format, pass, e, desc, NULL, &crls))
        return NULL;
    return crls;
}

#define X509V3_EXT_UNKNOWN_MASK         (0xfL << 16)
/* Return error for unknown extensions */
#define X509V3_EXT_DEFAULT              0
/* Print error for unknown extensions */
#define X509V3_EXT_ERROR_UNKNOWN        (1L << 16)
/* ASN1 parse unknown extensions */
#define X509V3_EXT_PARSE_UNKNOWN        (2L << 16)
/* BIO_dump unknown extensions */
#define X509V3_EXT_DUMP_UNKNOWN         (3L << 16)

#define X509_FLAG_CA (X509_FLAG_NO_ISSUER | X509_FLAG_NO_PUBKEY | \
                         X509_FLAG_NO_HEADER | X509_FLAG_NO_VERSION)

int set_cert_ex(unsigned long *flags, const char *arg)
{
    static const NAME_EX_TBL cert_tbl[] = {
        {"\x63\x6f\x6d\x70\x61\x74\x69\x62\x6c\x65", X509_FLAG_COMPAT, 0xffffffffl},
        {"\x63\x61\x5f\x64\x65\x66\x61\x75\x6c\x74", X509_FLAG_CA, 0xffffffffl},
        {"\x6e\x6f\x5f\x68\x65\x61\x64\x65\x72", X509_FLAG_NO_HEADER, 0},
        {"\x6e\x6f\x5f\x76\x65\x72\x73\x69\x6f\x6e", X509_FLAG_NO_VERSION, 0},
        {"\x6e\x6f\x5f\x73\x65\x72\x69\x61\x6c", X509_FLAG_NO_SERIAL, 0},
        {"\x6e\x6f\x5f\x73\x69\x67\x6e\x61\x6d\x65", X509_FLAG_NO_SIGNAME, 0},
        {"\x6e\x6f\x5f\x76\x61\x6c\x69\x64\x69\x74\x79", X509_FLAG_NO_VALIDITY, 0},
        {"\x6e\x6f\x5f\x73\x75\x62\x6a\x65\x63\x74", X509_FLAG_NO_SUBJECT, 0},
        {"\x6e\x6f\x5f\x69\x73\x73\x75\x65\x72", X509_FLAG_NO_ISSUER, 0},
        {"\x6e\x6f\x5f\x70\x75\x62\x6b\x65\x79", X509_FLAG_NO_PUBKEY, 0},
        {"\x6e\x6f\x5f\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x73", X509_FLAG_NO_EXTENSIONS, 0},
        {"\x6e\x6f\x5f\x73\x69\x67\x64\x75\x6d\x70", X509_FLAG_NO_SIGDUMP, 0},
        {"\x6e\x6f\x5f\x61\x75\x78", X509_FLAG_NO_AUX, 0},
        {"\x6e\x6f\x5f\x61\x74\x74\x72\x69\x62\x75\x74\x65\x73", X509_FLAG_NO_ATTRIBUTES, 0},
        {"\x65\x78\x74\x5f\x64\x65\x66\x61\x75\x6c\x74", X509V3_EXT_DEFAULT, X509V3_EXT_UNKNOWN_MASK},
        {"\x65\x78\x74\x5f\x65\x72\x72\x6f\x72", X509V3_EXT_ERROR_UNKNOWN, X509V3_EXT_UNKNOWN_MASK},
        {"\x65\x78\x74\x5f\x70\x61\x72\x73\x65", X509V3_EXT_PARSE_UNKNOWN, X509V3_EXT_UNKNOWN_MASK},
        {"\x65\x78\x74\x5f\x64\x75\x6d\x70", X509V3_EXT_DUMP_UNKNOWN, X509V3_EXT_UNKNOWN_MASK},
        {NULL, 0, 0}
    };
    return set_multi_opts(flags, arg, cert_tbl);
}

int set_name_ex(unsigned long *flags, const char *arg)
{
    static const NAME_EX_TBL ex_tbl[] = {
        {"\x65\x73\x63\x5f\x32\x32\x35\x33", ASN1_STRFLGS_ESC_2253, 0},
        {"\x65\x73\x63\x5f\x63\x74\x72\x6c", ASN1_STRFLGS_ESC_CTRL, 0},
        {"\x65\x73\x63\x5f\x6d\x73\x62", ASN1_STRFLGS_ESC_MSB, 0},
        {"\x75\x73\x65\x5f\x71\x75\x6f\x74\x65", ASN1_STRFLGS_ESC_QUOTE, 0},
        {"\x75\x74\x66\x38", ASN1_STRFLGS_UTF8_CONVERT, 0},
        {"\x69\x67\x6e\x6f\x72\x65\x5f\x74\x79\x70\x65", ASN1_STRFLGS_IGNORE_TYPE, 0},
        {"\x73\x68\x6f\x77\x5f\x74\x79\x70\x65", ASN1_STRFLGS_SHOW_TYPE, 0},
        {"\x64\x75\x6d\x70\x5f\x61\x6c\x6c", ASN1_STRFLGS_DUMP_ALL, 0},
        {"\x64\x75\x6d\x70\x5f\x6e\x6f\x73\x74\x72", ASN1_STRFLGS_DUMP_UNKNOWN, 0},
        {"\x64\x75\x6d\x70\x5f\x64\x65\x72", ASN1_STRFLGS_DUMP_DER, 0},
        {"\x63\x6f\x6d\x70\x61\x74", XN_FLAG_COMPAT, 0xffffffffL},
        {"\x73\x65\x70\x5f\x63\x6f\x6d\x6d\x61\x5f\x70\x6c\x75\x73", XN_FLAG_SEP_COMMA_PLUS, XN_FLAG_SEP_MASK},
        {"\x73\x65\x70\x5f\x63\x6f\x6d\x6d\x61\x5f\x70\x6c\x75\x73\x5f\x73\x70\x61\x63\x65", XN_FLAG_SEP_CPLUS_SPC, XN_FLAG_SEP_MASK},
        {"\x73\x65\x70\x5f\x73\x65\x6d\x69\x5f\x70\x6c\x75\x73\x5f\x73\x70\x61\x63\x65", XN_FLAG_SEP_SPLUS_SPC, XN_FLAG_SEP_MASK},
        {"\x73\x65\x70\x5f\x6d\x75\x6c\x74\x69\x6c\x69\x6e\x65", XN_FLAG_SEP_MULTILINE, XN_FLAG_SEP_MASK},
        {"\x64\x6e\x5f\x72\x65\x76", XN_FLAG_DN_REV, 0},
        {"\x6e\x6f\x66\x6e\x61\x6d\x65", XN_FLAG_FN_NONE, XN_FLAG_FN_MASK},
        {"\x73\x6e\x61\x6d\x65", XN_FLAG_FN_SN, XN_FLAG_FN_MASK},
        {"\x6c\x6e\x61\x6d\x65", XN_FLAG_FN_LN, XN_FLAG_FN_MASK},
        {"\x61\x6c\x69\x67\x6e", XN_FLAG_FN_ALIGN, 0},
        {"\x6f\x69\x64", XN_FLAG_FN_OID, XN_FLAG_FN_MASK},
        {"\x73\x70\x61\x63\x65\x5f\x65\x71", XN_FLAG_SPC_EQ, 0},
        {"\x64\x75\x6d\x70\x5f\x75\x6e\x6b\x6e\x6f\x77\x6e", XN_FLAG_DUMP_UNKNOWN_FIELDS, 0},
        {"\x52\x46\x43\x32\x32\x35\x33", XN_FLAG_RFC2253, 0xffffffffL},
        {"\x6f\x6e\x65\x6c\x69\x6e\x65", XN_FLAG_ONELINE, 0xffffffffL},
        {"\x6d\x75\x6c\x74\x69\x6c\x69\x6e\x65", XN_FLAG_MULTILINE, 0xffffffffL},
        {"\x63\x61\x5f\x64\x65\x66\x61\x75\x6c\x74", XN_FLAG_MULTILINE, 0xffffffffL},
        {NULL, 0, 0}
    };
    if (set_multi_opts(flags, arg, ex_tbl) == 0)
        return 0;
    if ((*flags & XN_FLAG_SEP_MASK) == 0)
        *flags |= XN_FLAG_SEP_CPLUS_SPC;
    return 1;
}

int set_ext_copy(int *copy_type, const char *arg)
{
    if (!strcasecmp(arg, "\x6e\x6f\x6e\x65"))
        *copy_type = EXT_COPY_NONE;
    else if (!strcasecmp(arg, "\x63\x6f\x70\x79"))
        *copy_type = EXT_COPY_ADD;
    else if (!strcasecmp(arg, "\x63\x6f\x70\x79\x61\x6c\x6c"))
        *copy_type = EXT_COPY_ALL;
    else
        return 0;
    return 1;
}

int copy_extensions(X509 *x, X509_REQ *req, int copy_type)
{
    STACK_OF(X509_EXTENSION) *exts = NULL;
    X509_EXTENSION *ext, *tmpext;
    ASN1_OBJECT *obj;
    int i, idx, ret = 0;
    if (!x || !req || (copy_type == EXT_COPY_NONE))
        return 1;
    exts = X509_REQ_get_extensions(req);

    for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        ext = sk_X509_EXTENSION_value(exts, i);
        obj = X509_EXTENSION_get_object(ext);
        idx = X509_get_ext_by_OBJ(x, obj, -1);
        /* Does extension exist? */
        if (idx != -1) {
            /* If normal copy don't override existing extension */
            if (copy_type == EXT_COPY_ADD)
                continue;
            /* Delete all extensions of same type */
            do {
                tmpext = X509_get_ext(x, idx);
                X509_delete_ext(x, idx);
                X509_EXTENSION_free(tmpext);
                idx = X509_get_ext_by_OBJ(x, obj, -1);
            } while (idx != -1);
        }
        if (!X509_add_ext(x, ext, -1))
            goto end;
    }

    ret = 1;

 end:

    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

    return ret;
}

static int set_multi_opts(unsigned long *flags, const char *arg,
                          const NAME_EX_TBL * in_tbl)
{
    STACK_OF(CONF_VALUE) *vals;
    CONF_VALUE *val;
    int i, ret = 1;
    if (!arg)
        return 0;
    vals = X509V3_parse_list(arg);
    for (i = 0; i < sk_CONF_VALUE_num(vals); i++) {
        val = sk_CONF_VALUE_value(vals, i);
        if (!set_table_opts(flags, val->name, in_tbl))
            ret = 0;
    }
    sk_CONF_VALUE_pop_free(vals, X509V3_conf_free);
    return ret;
}

static int set_table_opts(unsigned long *flags, const char *arg,
                          const NAME_EX_TBL * in_tbl)
{
    char c;
    const NAME_EX_TBL *ptbl;
    c = arg[0];

    if (c == '\x2d') {
        c = 0;
        arg++;
    } else if (c == '\x2b') {
        c = 1;
        arg++;
    } else
        c = 1;

    for (ptbl = in_tbl; ptbl->name; ptbl++) {
        if (!strcasecmp(arg, ptbl->name)) {
            *flags &= ~ptbl->mask;
            if (c)
                *flags |= ptbl->flag;
            else
                *flags &= ~ptbl->flag;
            return 1;
        }
    }
    return 0;
}

void print_name(BIO *out, const char *title, X509_NAME *nm,
                unsigned long lflags)
{
    char *buf;
    char mline = 0;
    int indent = 0;

    if (title)
        BIO_puts(out, title);
    if ((lflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE) {
        mline = 1;
        indent = 4;
    }
    if (lflags == XN_FLAG_COMPAT) {
        buf = X509_NAME_oneline(nm, 0, 0);
        BIO_puts(out, buf);
        BIO_puts(out, "\xa");
        OPENSSL_free(buf);
    } else {
        if (mline)
            BIO_puts(out, "\xa");
        X509_NAME_print_ex(out, nm, indent, lflags);
        BIO_puts(out, "\xa");
    }
}

X509_STORE *setup_verify(BIO *bp, char *CAfile, char *CApath)
{
    X509_STORE *store;
    X509_LOOKUP *lookup;
    if (!(store = X509_STORE_new()))
        goto end;
    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (lookup == NULL)
        goto end;
    if (CAfile) {
        if (!X509_LOOKUP_load_file(lookup, CAfile, X509_FILETYPE_PEM)) {
            BIO_printf(bp, "\x45\x72\x72\x6f\x72\x20\x6c\x6f\x61\x64\x69\x6e\x67\x20\x66\x69\x6c\x65\x20\x25\x73\xa", CAfile);
            goto end;
        }
    } else
        X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
    if (lookup == NULL)
        goto end;
    if (CApath) {
        if (!X509_LOOKUP_add_dir(lookup, CApath, X509_FILETYPE_PEM)) {
            BIO_printf(bp, "\x45\x72\x72\x6f\x72\x20\x6c\x6f\x61\x64\x69\x6e\x67\x20\x64\x69\x72\x65\x63\x74\x6f\x72\x79\x20\x25\x73\xa", CApath);
            goto end;
        }
    } else
        X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);

    ERR_clear_error();
    return store;
 end:
    X509_STORE_free(store);
    return NULL;
}

#ifndef OPENSSL_NO_ENGINE
/* Try to load an engine in a shareable library */
static ENGINE *try_load_engine(BIO *err, const char *engine, int debug)
{
    ENGINE *e = ENGINE_by_id("\x64\x79\x6e\x61\x6d\x69\x63");
    if (e) {
        if (!ENGINE_ctrl_cmd_string(e, "\x53\x4f\x5f\x50\x41\x54\x48", engine, 0)
            || !ENGINE_ctrl_cmd_string(e, "\x4c\x4f\x41\x44", NULL, 0)) {
            ENGINE_free(e);
            e = NULL;
        }
    }
    return e;
}
#endif

ENGINE *setup_engine(BIO *err, const char *engine, int debug)
{
    ENGINE *e = NULL;

#ifndef OPENSSL_NO_ENGINE
    if (engine) {
        if (strcmp(engine, "\x61\x75\x74\x6f") == 0) {
            BIO_printf(err, "\x65\x6e\x61\x62\x6c\x69\x6e\x67\x20\x61\x75\x74\x6f\x20\x45\x4e\x47\x49\x4e\x45\x20\x73\x75\x70\x70\x6f\x72\x74\xa");
            ENGINE_register_all_complete();
            return NULL;
        }
        if ((e = ENGINE_by_id(engine)) == NULL
            && (e = try_load_engine(err, engine, debug)) == NULL) {
            BIO_printf(err, "\x69\x6e\x76\x61\x6c\x69\x64\x20\x65\x6e\x67\x69\x6e\x65\x20\x22\x25\x73\x22\xa", engine);
            ERR_print_errors(err);
            return NULL;
        }
        if (debug) {
            ENGINE_ctrl(e, ENGINE_CTRL_SET_LOGSTREAM, 0, err, 0);
        }
        ENGINE_ctrl_cmd(e, "\x53\x45\x54\x5f\x55\x53\x45\x52\x5f\x49\x4e\x54\x45\x52\x46\x41\x43\x45", 0, ui_method, 0, 1);
        if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
            BIO_printf(err, "\x63\x61\x6e\x27\x74\x20\x75\x73\x65\x20\x74\x68\x61\x74\x20\x65\x6e\x67\x69\x6e\x65\xa");
            ERR_print_errors(err);
            ENGINE_free(e);
            return NULL;
        }

        BIO_printf(err, "\x65\x6e\x67\x69\x6e\x65\x20\x22\x25\x73\x22\x20\x73\x65\x74\x2e\xa", ENGINE_get_id(e));
    }
#endif
    return e;
}

void release_engine(ENGINE *e)
{
#ifndef OPENSSL_NO_ENGINE
    if (e != NULL)
        /* Free our "structural" reference. */
        ENGINE_free(e);
#endif
}

int load_config(BIO *err, CONF *cnf)
{
    static int load_config_called = 0;
    if (load_config_called)
        return 1;
    load_config_called = 1;
    if (!cnf)
        cnf = config;
    if (!cnf)
        return 1;

    OPENSSL_load_builtin_modules();

    if (CONF_modules_load(cnf, NULL, 0) <= 0) {
        BIO_printf(err, "\x45\x72\x72\x6f\x72\x20\x63\x6f\x6e\x66\x69\x67\x75\x72\x69\x6e\x67\x20\x4f\x70\x65\x6e\x53\x53\x4c\xa");
        ERR_print_errors(err);
        return 0;
    }
    return 1;
}

char *make_config_name()
{
    const char *t = X509_get_default_cert_area();
    size_t len;
    char *p;

    len = strlen(t) + strlen(OPENSSL_CONF) + 2;
    p = OPENSSL_malloc(len);
    if (p == NULL)
        return NULL;
    BUF_strlcpy(p, t, len);
#ifndef OPENSSL_SYS_VMS
    BUF_strlcat(p, "\x2f", len);
#endif
    BUF_strlcat(p, OPENSSL_CONF, len);

    return p;
}

static unsigned long index_serial_hash(const OPENSSL_CSTRING *a)
{
    const char *n;

    n = a[DB_serial];
    while (*n == '\x30')
        n++;
    return (lh_strhash(n));
}

static int index_serial_cmp(const OPENSSL_CSTRING *a,
                            const OPENSSL_CSTRING *b)
{
    const char *aa, *bb;

    for (aa = a[DB_serial]; *aa == '\x30'; aa++) ;
    for (bb = b[DB_serial]; *bb == '\x30'; bb++) ;
    return (strcmp(aa, bb));
}

static int index_name_qual(char **a)
{
    return (a[0][0] == '\x56');
}

static unsigned long index_name_hash(const OPENSSL_CSTRING *a)
{
    return (lh_strhash(a[DB_name]));
}

int index_name_cmp(const OPENSSL_CSTRING *a, const OPENSSL_CSTRING *b)
{
    return (strcmp(a[DB_name], b[DB_name]));
}

static IMPLEMENT_LHASH_HASH_FN(index_serial, OPENSSL_CSTRING)
static IMPLEMENT_LHASH_COMP_FN(index_serial, OPENSSL_CSTRING)
static IMPLEMENT_LHASH_HASH_FN(index_name, OPENSSL_CSTRING)
static IMPLEMENT_LHASH_COMP_FN(index_name, OPENSSL_CSTRING)
#undef BSIZE
#define BSIZE 256
BIGNUM *load_serial(char *serialfile, int create, ASN1_INTEGER **retai)
{
    BIO *in = NULL;
    BIGNUM *ret = NULL;
    MS_STATIC char buf[1024];
    ASN1_INTEGER *ai = NULL;

    ai = ASN1_INTEGER_new();
    if (ai == NULL)
        goto err;

    if ((in = BIO_new(BIO_s_file())) == NULL) {
        ERR_print_errors(bio_err);
        goto err;
    }

    if (BIO_read_filename(in, serialfile) <= 0) {
        if (!create) {
            perror(serialfile);
            goto err;
        } else {
            ret = BN_new();
            if (ret == NULL || !rand_serial(ret, ai))
                BIO_printf(bio_err, "\x4f\x75\x74\x20\x6f\x66\x20\x6d\x65\x6d\x6f\x72\x79\xa");
        }
    } else {
        if (!a2i_ASN1_INTEGER(in, ai, buf, 1024)) {
            BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6c\x6f\x61\x64\x20\x6e\x75\x6d\x62\x65\x72\x20\x66\x72\x6f\x6d\x20\x25\x73\xa",
                       serialfile);
            goto err;
        }
        ret = ASN1_INTEGER_to_BN(ai, NULL);
        if (ret == NULL) {
            BIO_printf(bio_err,
                       "\x65\x72\x72\x6f\x72\x20\x63\x6f\x6e\x76\x65\x72\x74\x69\x6e\x67\x20\x6e\x75\x6d\x62\x65\x72\x20\x66\x72\x6f\x6d\x20\x62\x69\x6e\x20\x74\x6f\x20\x42\x49\x47\x4e\x55\x4d\xa");
            goto err;
        }
    }

    if (ret && retai) {
        *retai = ai;
        ai = NULL;
    }
 err:
    if (in != NULL)
        BIO_free(in);
    if (ai != NULL)
        ASN1_INTEGER_free(ai);
    return (ret);
}

int save_serial(char *serialfile, char *suffix, BIGNUM *serial,
                ASN1_INTEGER **retai)
{
    char buf[1][BSIZE];
    BIO *out = NULL;
    int ret = 0;
    ASN1_INTEGER *ai = NULL;
    int j;

    if (suffix == NULL)
        j = strlen(serialfile);
    else
        j = strlen(serialfile) + strlen(suffix) + 1;
    if (j >= BSIZE) {
        BIO_printf(bio_err, "\x66\x69\x6c\x65\x20\x6e\x61\x6d\x65\x20\x74\x6f\x6f\x20\x6c\x6f\x6e\x67\xa");
        goto err;
    }

    if (suffix == NULL)
        BUF_strlcpy(buf[0], serialfile, BSIZE);
    else {
#ifndef OPENSSL_SYS_VMS
        j = BIO_snprintf(buf[0], sizeof(buf[0]), "\x25\x73\x2e\x25\x73", serialfile, suffix);
#else
        j = BIO_snprintf(buf[0], sizeof(buf[0]), "\x25\x73\x2d\x25\x73", serialfile, suffix);
#endif
    }
#ifdef RL_DEBUG
    BIO_printf(bio_err, "\x44\x45\x42\x55\x47\x3a\x20\x77\x72\x69\x74\x69\x6e\x67\x20\x22\x25\x73\x22\xa", buf[0]);
#endif
    out = BIO_new(BIO_s_file());
    if (out == NULL) {
        ERR_print_errors(bio_err);
        goto err;
    }
    if (BIO_write_filename(out, buf[0]) <= 0) {
        perror(serialfile);
        goto err;
    }

    if ((ai = BN_to_ASN1_INTEGER(serial, NULL)) == NULL) {
        BIO_printf(bio_err, "\x65\x72\x72\x6f\x72\x20\x63\x6f\x6e\x76\x65\x72\x74\x69\x6e\x67\x20\x73\x65\x72\x69\x61\x6c\x20\x74\x6f\x20\x41\x53\x4e\x2e\x31\x20\x66\x6f\x72\x6d\x61\x74\xa");
        goto err;
    }
    i2a_ASN1_INTEGER(out, ai);
    BIO_puts(out, "\xa");
    ret = 1;
    if (retai) {
        *retai = ai;
        ai = NULL;
    }
 err:
    if (out != NULL)
        BIO_free_all(out);
    if (ai != NULL)
        ASN1_INTEGER_free(ai);
    return (ret);
}

int rotate_serial(char *serialfile, char *new_suffix, char *old_suffix)
{
    char buf[5][BSIZE];
    int i, j;

    i = strlen(serialfile) + strlen(old_suffix);
    j = strlen(serialfile) + strlen(new_suffix);
    if (i > j)
        j = i;
    if (j + 1 >= BSIZE) {
        BIO_printf(bio_err, "\x66\x69\x6c\x65\x20\x6e\x61\x6d\x65\x20\x74\x6f\x6f\x20\x6c\x6f\x6e\x67\xa");
        goto err;
    }
#ifndef OPENSSL_SYS_VMS
    j = BIO_snprintf(buf[0], sizeof(buf[0]), "\x25\x73\x2e\x25\x73", serialfile, new_suffix);
#else
    j = BIO_snprintf(buf[0], sizeof(buf[0]), "\x25\x73\x2d\x25\x73", serialfile, new_suffix);
#endif
#ifndef OPENSSL_SYS_VMS
    j = BIO_snprintf(buf[1], sizeof(buf[1]), "\x25\x73\x2e\x25\x73", serialfile, old_suffix);
#else
    j = BIO_snprintf(buf[1], sizeof(buf[1]), "\x25\x73\x2d\x25\x73", serialfile, old_suffix);
#endif
#ifdef RL_DEBUG
    BIO_printf(bio_err, "\x44\x45\x42\x55\x47\x3a\x20\x72\x65\x6e\x61\x6d\x69\x6e\x67\x20\x22\x25\x73\x22\x20\x74\x6f\x20\x22\x25\x73\x22\xa",
               serialfile, buf[1]);
#endif
    if (rename(serialfile, buf[1]) < 0 && errno != ENOENT
#ifdef ENOTDIR
        && errno != ENOTDIR
#endif
        ) {
        BIO_printf(bio_err,
                   "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x72\x65\x6e\x61\x6d\x65\x20\x25\x73\x20\x74\x6f\x20\x25\x73\xa", serialfile, buf[1]);
        perror("\x72\x65\x61\x73\x6f\x6e");
        goto err;
    }
#ifdef RL_DEBUG
    BIO_printf(bio_err, "\x44\x45\x42\x55\x47\x3a\x20\x72\x65\x6e\x61\x6d\x69\x6e\x67\x20\x22\x25\x73\x22\x20\x74\x6f\x20\x22\x25\x73\x22\xa",
               buf[0], serialfile);
#endif
    if (rename(buf[0], serialfile) < 0) {
        BIO_printf(bio_err,
                   "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x72\x65\x6e\x61\x6d\x65\x20\x25\x73\x20\x74\x6f\x20\x25\x73\xa", buf[0], serialfile);
        perror("\x72\x65\x61\x73\x6f\x6e");
        rename(buf[1], serialfile);
        goto err;
    }
    return 1;
 err:
    return 0;
}

int rand_serial(BIGNUM *b, ASN1_INTEGER *ai)
{
    BIGNUM *btmp;
    int ret = 0;
    if (b)
        btmp = b;
    else
        btmp = BN_new();

    if (!btmp)
        return 0;

    if (!BN_pseudo_rand(btmp, SERIAL_RAND_BITS, 0, 0))
        goto error;
    if (ai && !BN_to_ASN1_INTEGER(btmp, ai))
        goto error;

    ret = 1;

 error:

    if (!b)
        BN_free(btmp);

    return ret;
}

CA_DB *load_index(char *dbfile, DB_ATTR *db_attr)
{
    CA_DB *retdb = NULL;
    TXT_DB *tmpdb = NULL;
    BIO *in = BIO_new(BIO_s_file());
    CONF *dbattr_conf = NULL;
    char buf[1][BSIZE];
    long errorline = -1;

    if (in == NULL) {
        ERR_print_errors(bio_err);
        goto err;
    }
    if (BIO_read_filename(in, dbfile) <= 0) {
        perror(dbfile);
        BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6f\x70\x65\x6e\x20\x27\x25\x73\x27\xa", dbfile);
        goto err;
    }
    if ((tmpdb = TXT_DB_read(in, DB_NUMBER)) == NULL)
        goto err;

#ifndef OPENSSL_SYS_VMS
    BIO_snprintf(buf[0], sizeof(buf[0]), "\x25\x73\x2e\x61\x74\x74\x72", dbfile);
#else
    BIO_snprintf(buf[0], sizeof(buf[0]), "\x25\x73\x2d\x61\x74\x74\x72", dbfile);
#endif
    dbattr_conf = NCONF_new(NULL);
    if (NCONF_load(dbattr_conf, buf[0], &errorline) <= 0) {
        if (errorline > 0) {
            BIO_printf(bio_err,
                       "\x65\x72\x72\x6f\x72\x20\x6f\x6e\x20\x6c\x69\x6e\x65\x20\x25\x6c\x64\x20\x6f\x66\x20\x64\x62\x20\x61\x74\x74\x72\x69\x62\x75\x74\x65\x20\x66\x69\x6c\x65\x20\x27\x25\x73\x27\xa",
                       errorline, buf[0]);
            goto err;
        } else {
            NCONF_free(dbattr_conf);
            dbattr_conf = NULL;
        }
    }

    if ((retdb = OPENSSL_malloc(sizeof(CA_DB))) == NULL) {
        fprintf(stderr, "\x4f\x75\x74\x20\x6f\x66\x20\x6d\x65\x6d\x6f\x72\x79\xa");
        goto err;
    }

    retdb->db = tmpdb;
    tmpdb = NULL;
    if (db_attr)
        retdb->attributes = *db_attr;
    else {
        retdb->attributes.unique_subject = 1;
    }

    if (dbattr_conf) {
        char *p = NCONF_get_string(dbattr_conf, NULL, "\x75\x6e\x69\x71\x75\x65\x5f\x73\x75\x62\x6a\x65\x63\x74");
        if (p) {
#ifdef RL_DEBUG
            BIO_printf(bio_err,
                       "\x44\x45\x42\x55\x47\x5b\x6c\x6f\x61\x64\x5f\x69\x6e\x64\x65\x78\x5d\x3a\x20\x75\x6e\x69\x71\x75\x65\x5f\x73\x75\x62\x6a\x65\x63\x74\x20\x3d\x20\x22\x25\x73\x22\xa", p);
#endif
            retdb->attributes.unique_subject = parse_yesno(p, 1);
        }
    }

 err:
    if (dbattr_conf)
        NCONF_free(dbattr_conf);
    if (tmpdb)
        TXT_DB_free(tmpdb);
    if (in)
        BIO_free_all(in);
    return retdb;
}

int index_index(CA_DB *db)
{
    if (!TXT_DB_create_index(db->db, DB_serial, NULL,
                             LHASH_HASH_FN(index_serial),
                             LHASH_COMP_FN(index_serial))) {
        BIO_printf(bio_err,
                   "\x65\x72\x72\x6f\x72\x20\x63\x72\x65\x61\x74\x69\x6e\x67\x20\x73\x65\x72\x69\x61\x6c\x20\x6e\x75\x6d\x62\x65\x72\x20\x69\x6e\x64\x65\x78\x3a\x28\x25\x6c\x64\x2c\x25\x6c\x64\x2c\x25\x6c\x64\x29\xa",
                   db->db->error, db->db->arg1, db->db->arg2);
        return 0;
    }

    if (db->attributes.unique_subject
        && !TXT_DB_create_index(db->db, DB_name, index_name_qual,
                                LHASH_HASH_FN(index_name),
                                LHASH_COMP_FN(index_name))) {
        BIO_printf(bio_err, "\x65\x72\x72\x6f\x72\x20\x63\x72\x65\x61\x74\x69\x6e\x67\x20\x6e\x61\x6d\x65\x20\x69\x6e\x64\x65\x78\x3a\x28\x25\x6c\x64\x2c\x25\x6c\x64\x2c\x25\x6c\x64\x29\xa",
                   db->db->error, db->db->arg1, db->db->arg2);
        return 0;
    }
    return 1;
}

int save_index(const char *dbfile, const char *suffix, CA_DB *db)
{
    char buf[3][BSIZE];
    BIO *out = BIO_new(BIO_s_file());
    int j;

    if (out == NULL) {
        ERR_print_errors(bio_err);
        goto err;
    }

    j = strlen(dbfile) + strlen(suffix);
    if (j + 6 >= BSIZE) {
        BIO_printf(bio_err, "\x66\x69\x6c\x65\x20\x6e\x61\x6d\x65\x20\x74\x6f\x6f\x20\x6c\x6f\x6e\x67\xa");
        goto err;
    }
#ifndef OPENSSL_SYS_VMS
    j = BIO_snprintf(buf[2], sizeof(buf[2]), "\x25\x73\x2e\x61\x74\x74\x72", dbfile);
#else
    j = BIO_snprintf(buf[2], sizeof(buf[2]), "\x25\x73\x2d\x61\x74\x74\x72", dbfile);
#endif
#ifndef OPENSSL_SYS_VMS
    j = BIO_snprintf(buf[1], sizeof(buf[1]), "\x25\x73\x2e\x61\x74\x74\x72\x2e\x25\x73", dbfile, suffix);
#else
    j = BIO_snprintf(buf[1], sizeof(buf[1]), "\x25\x73\x2d\x61\x74\x74\x72\x2d\x25\x73", dbfile, suffix);
#endif
#ifndef OPENSSL_SYS_VMS
    j = BIO_snprintf(buf[0], sizeof(buf[0]), "\x25\x73\x2e\x25\x73", dbfile, suffix);
#else
    j = BIO_snprintf(buf[0], sizeof(buf[0]), "\x25\x73\x2d\x25\x73", dbfile, suffix);
#endif
#ifdef RL_DEBUG
    BIO_printf(bio_err, "\x44\x45\x42\x55\x47\x3a\x20\x77\x72\x69\x74\x69\x6e\x67\x20\x22\x25\x73\x22\xa", buf[0]);
#endif
    if (BIO_write_filename(out, buf[0]) <= 0) {
        perror(dbfile);
        BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6f\x70\x65\x6e\x20\x27\x25\x73\x27\xa", dbfile);
        goto err;
    }
    j = TXT_DB_write(out, db->db);
    if (j <= 0)
        goto err;

    BIO_free(out);

    out = BIO_new(BIO_s_file());
#ifdef RL_DEBUG
    BIO_printf(bio_err, "\x44\x45\x42\x55\x47\x3a\x20\x77\x72\x69\x74\x69\x6e\x67\x20\x22\x25\x73\x22\xa", buf[1]);
#endif
    if (BIO_write_filename(out, buf[1]) <= 0) {
        perror(buf[2]);
        BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x6f\x70\x65\x6e\x20\x27\x25\x73\x27\xa", buf[2]);
        goto err;
    }
    BIO_printf(out, "\x75\x6e\x69\x71\x75\x65\x5f\x73\x75\x62\x6a\x65\x63\x74\x20\x3d\x20\x25\x73\xa",
               db->attributes.unique_subject ? "\x79\x65\x73" : "\x6e\x6f");
    BIO_free(out);

    return 1;
 err:
    return 0;
}

int rotate_index(const char *dbfile, const char *new_suffix,
                 const char *old_suffix)
{
    char buf[5][BSIZE];
    int i, j;

    i = strlen(dbfile) + strlen(old_suffix);
    j = strlen(dbfile) + strlen(new_suffix);
    if (i > j)
        j = i;
    if (j + 6 >= BSIZE) {
        BIO_printf(bio_err, "\x66\x69\x6c\x65\x20\x6e\x61\x6d\x65\x20\x74\x6f\x6f\x20\x6c\x6f\x6e\x67\xa");
        goto err;
    }
#ifndef OPENSSL_SYS_VMS
    j = BIO_snprintf(buf[4], sizeof(buf[4]), u8"%s.attr", dbfile);
#else
    j = BIO_snprintf(buf[4], sizeof(buf[4]), u8"%s-attr", dbfile);
#endif
#ifndef OPENSSL_SYS_VMS
    j = BIO_snprintf(buf[2], sizeof(buf[2]), u8"%s.attr.%s", dbfile, new_suffix);
#else
    j = BIO_snprintf(buf[2], sizeof(buf[2]), u8"%s-attr-%s", dbfile, new_suffix);
#endif
#ifndef OPENSSL_SYS_VMS
    j = BIO_snprintf(buf[0], sizeof(buf[0]), u8"%s.%s", dbfile, new_suffix);
#else
    j = BIO_snprintf(buf[0], sizeof(buf[0]), u8"%s-%s", dbfile, new_suffix);
#endif
#ifndef OPENSSL_SYS_VMS
    j = BIO_snprintf(buf[1], sizeof(buf[1]), u8"%s.%s", dbfile, old_suffix);
#else
    j = BIO_snprintf(buf[1], sizeof(buf[1]), u8"%s-%s", dbfile, old_suffix);
#endif
#ifndef OPENSSL_SYS_VMS
    j = BIO_snprintf(buf[3], sizeof(buf[3]), u8"%s.attr.%s", dbfile, old_suffix);
#else
    j = BIO_snprintf(buf[3], sizeof(buf[3]), u8"%s-attr-%s", dbfile, old_suffix);
#endif
#ifdef RL_DEBUG
    BIO_printf(bio_err, "\x44\x45\x42\x55\x47\x3a\x20\x72\x65\x6e\x61\x6d\x69\x6e\x67\x20\x22\x25\x73\x22\x20\x74\x6f\x20\x22\x25\x73\x22\xa", dbfile, buf[1]);
#endif
    if (rename(dbfile, buf[1]) < 0 && errno != ENOENT
#ifdef ENOTDIR
        && errno != ENOTDIR
#endif
        ) {
        BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x72\x65\x6e\x61\x6d\x65\x20\x25\x73\x20\x74\x6f\x20\x25\x73\xa", dbfile, buf[1]);
        perror("\x72\x65\x61\x73\x6f\x6e");
        goto err;
    }
#ifdef RL_DEBUG
    BIO_printf(bio_err, "\x44\x45\x42\x55\x47\x3a\x20\x72\x65\x6e\x61\x6d\x69\x6e\x67\x20\x22\x25\x73\x22\x20\x74\x6f\x20\x22\x25\x73\x22\xa", buf[0], dbfile);
#endif
    if (rename(buf[0], dbfile) < 0) {
        BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x72\x65\x6e\x61\x6d\x65\x20\x25\x73\x20\x74\x6f\x20\x25\x73\xa", buf[0], dbfile);
        perror("\x72\x65\x61\x73\x6f\x6e");
        rename(buf[1], dbfile);
        goto err;
    }
#ifdef RL_DEBUG
    BIO_printf(bio_err, "\x44\x45\x42\x55\x47\x3a\x20\x72\x65\x6e\x61\x6d\x69\x6e\x67\x20\x22\x25\x73\x22\x20\x74\x6f\x20\x22\x25\x73\x22\xa", buf[4], buf[3]);
#endif
    if (rename(buf[4], buf[3]) < 0 && errno != ENOENT
#ifdef ENOTDIR
        && errno != ENOTDIR
#endif
        ) {
        BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x72\x65\x6e\x61\x6d\x65\x20\x25\x73\x20\x74\x6f\x20\x25\x73\xa", buf[4], buf[3]);
        perror("\x72\x65\x61\x73\x6f\x6e");
        rename(dbfile, buf[0]);
        rename(buf[1], dbfile);
        goto err;
    }
#ifdef RL_DEBUG
    BIO_printf(bio_err, "\x44\x45\x42\x55\x47\x3a\x20\x72\x65\x6e\x61\x6d\x69\x6e\x67\x20\x22\x25\x73\x22\x20\x74\x6f\x20\x22\x25\x73\x22\xa", buf[2], buf[4]);
#endif
    if (rename(buf[2], buf[4]) < 0) {
        BIO_printf(bio_err, "\x75\x6e\x61\x62\x6c\x65\x20\x74\x6f\x20\x72\x65\x6e\x61\x6d\x65\x20\x25\x73\x20\x74\x6f\x20\x25\x73\xa", buf[2], buf[4]);
        perror("\x72\x65\x61\x73\x6f\x6e");
        rename(buf[3], buf[4]);
        rename(dbfile, buf[0]);
        rename(buf[1], dbfile);
        goto err;
    }
    return 1;
 err:
    return 0;
}

void free_index(CA_DB *db)
{
    if (db) {
        if (db->db)
            TXT_DB_free(db->db);
        OPENSSL_free(db);
    }
}

int parse_yesno(const char *str, int def)
{
    int ret = def;
    if (str) {
        switch (*str) {
        case '\x66':              /* false */
        case '\x46':              /* FALSE */
        case '\x6e':              /* no */
        case '\x4e':              /* NO */
        case '\x30':              /* 0 */
            ret = 0;
            break;
        case '\x74':              /* true */
        case '\x54':              /* TRUE */
        case '\x79':              /* yes */
        case '\x59':              /* YES */
        case '\x31':              /* 1 */
            ret = 1;
            break;
        default:
            ret = def;
            break;
        }
    }
    return ret;
}

/*
 * subject is expected to be in the format /type0=value0/type1=value1/type2=...
 * where characters may be escaped by \
 */
X509_NAME *parse_name(char *subject, long chtype, int multirdn)
{
    size_t buflen = strlen(subject) + 1; /* to copy the types and values
                                          * into. due to escaping, the copy
                                          * can only become shorter */
    char *buf = OPENSSL_malloc(buflen);
    size_t max_ne = buflen / 2 + 1; /* maximum number of name elements */
    char **ne_types = OPENSSL_malloc(max_ne * sizeof(char *));
    char **ne_values = OPENSSL_malloc(max_ne * sizeof(char *));
    int *mval = OPENSSL_malloc(max_ne * sizeof(int));

    char *sp = subject, *bp = buf;
    int i, ne_num = 0;

    X509_NAME *n = NULL;
    int nid;

    if (!buf || !ne_types || !ne_values || !mval) {
        BIO_printf(bio_err, "\x6d\x61\x6c\x6c\x6f\x63\x20\x65\x72\x72\x6f\x72\xa");
        goto error;
    }

    if (*subject != '\x2f') {
        BIO_printf(bio_err, "\x53\x75\x62\x6a\x65\x63\x74\x20\x64\x6f\x65\x73\x20\x6e\x6f\x74\x20\x73\x74\x61\x72\x74\x20\x77\x69\x74\x68\x20\x27\x2f\x27\x2e\xa");
        goto error;
    }
    sp++;                       /* skip leading / */

    /* no multivalued RDN by default */
    mval[ne_num] = 0;

    while (*sp) {
        /* collect type */
        ne_types[ne_num] = bp;
        while (*sp) {
            if (*sp == '\x5c') {  /* is there anything to escape in the
                                 * type...? */
                if (*++sp)
                    *bp++ = *sp++;
                else {
                    BIO_printf(bio_err,
                               "\x65\x73\x63\x61\x70\x65\x20\x63\x68\x61\x72\x61\x63\x74\x65\x72\x20\x61\x74\x20\x65\x6e\x64\x20\x6f\x66\x20\x73\x74\x72\x69\x6e\x67\xa");
                    goto error;
                }
            } else if (*sp == '\x3d') {
                sp++;
                *bp++ = '\x0';
                break;
            } else
                *bp++ = *sp++;
        }
        if (!*sp) {
            BIO_printf(bio_err,
                       "\x65\x6e\x64\x20\x6f\x66\x20\x73\x74\x72\x69\x6e\x67\x20\x65\x6e\x63\x6f\x75\x6e\x74\x65\x72\x65\x64\x20\x77\x68\x69\x6c\x65\x20\x70\x72\x6f\x63\x65\x73\x73\x69\x6e\x67\x20\x74\x79\x70\x65\x20\x6f\x66\x20\x73\x75\x62\x6a\x65\x63\x74\x20\x6e\x61\x6d\x65\x20\x65\x6c\x65\x6d\x65\x6e\x74\x20\x23\x25\x64\xa",
                       ne_num);
            goto error;
        }
        ne_values[ne_num] = bp;
        while (*sp) {
            if (*sp == '\x5c') {
                if (*++sp)
                    *bp++ = *sp++;
                else {
                    BIO_printf(bio_err,
                               "\x65\x73\x63\x61\x70\x65\x20\x63\x68\x61\x72\x61\x63\x74\x65\x72\x20\x61\x74\x20\x65\x6e\x64\x20\x6f\x66\x20\x73\x74\x72\x69\x6e\x67\xa");
                    goto error;
                }
            } else if (*sp == '\x2f') {
                sp++;
                /* no multivalued RDN by default */
                mval[ne_num + 1] = 0;
                break;
            } else if (*sp == '\x2b' && multirdn) {
                /*
                 * a not escaped + signals a mutlivalued RDN
                 */
                sp++;
                mval[ne_num + 1] = -1;
                break;
            } else
                *bp++ = *sp++;
        }
        *bp++ = '\x0';
        ne_num++;
    }

    if (!(n = X509_NAME_new()))
        goto error;

    for (i = 0; i < ne_num; i++) {
        if ((nid = OBJ_txt2nid(ne_types[i])) == NID_undef) {
            BIO_printf(bio_err,
                       "\x53\x75\x62\x6a\x65\x63\x74\x20\x41\x74\x74\x72\x69\x62\x75\x74\x65\x20\x25\x73\x20\x68\x61\x73\x20\x6e\x6f\x20\x6b\x6e\x6f\x77\x6e\x20\x4e\x49\x44\x2c\x20\x73\x6b\x69\x70\x70\x65\x64\xa",
                       ne_types[i]);
            continue;
        }

        if (!*ne_values[i]) {
            BIO_printf(bio_err,
                       "\x4e\x6f\x20\x76\x61\x6c\x75\x65\x20\x70\x72\x6f\x76\x69\x64\x65\x64\x20\x66\x6f\x72\x20\x53\x75\x62\x6a\x65\x63\x74\x20\x41\x74\x74\x72\x69\x62\x75\x74\x65\x20\x25\x73\x2c\x20\x73\x6b\x69\x70\x70\x65\x64\xa",
                       ne_types[i]);
            continue;
        }

        if (!X509_NAME_add_entry_by_NID
            (n, nid, chtype, (unsigned char *)ne_values[i], -1, -1, mval[i]))
            goto error;
    }

    OPENSSL_free(ne_values);
    OPENSSL_free(ne_types);
    OPENSSL_free(buf);
    OPENSSL_free(mval);
    return n;

 error:
    X509_NAME_free(n);
    if (ne_values)
        OPENSSL_free(ne_values);
    if (ne_types)
        OPENSSL_free(ne_types);
    if (mval)
        OPENSSL_free(mval);
    if (buf)
        OPENSSL_free(buf);
    return NULL;
}

int args_verify(char ***pargs, int *pargc,
                int *badarg, BIO *err, X509_VERIFY_PARAM **pm)
{
    ASN1_OBJECT *otmp = NULL;
    unsigned long flags = 0;
    int i;
    int purpose = 0, depth = -1;
    char **oldargs = *pargs;
    char *arg = **pargs, *argn = (*pargs)[1];
    time_t at_time = 0;
    char *hostname = NULL;
    char *email = NULL;
    char *ipasc = NULL;
    if (!strcmp(arg, "\x2d\x70\x6f\x6c\x69\x63\x79")) {
        if (!argn)
            *badarg = 1;
        else {
            otmp = OBJ_txt2obj(argn, 0);
            if (!otmp) {
                BIO_printf(err, "\x49\x6e\x76\x61\x6c\x69\x64\x20\x50\x6f\x6c\x69\x63\x79\x20\x22\x25\x73\x22\xa", argn);
                *badarg = 1;
            }
        }
        (*pargs)++;
    } else if (strcmp(arg, "\x2d\x70\x75\x72\x70\x6f\x73\x65") == 0) {
        X509_PURPOSE *xptmp;
        if (!argn)
            *badarg = 1;
        else {
            i = X509_PURPOSE_get_by_sname(argn);
            if (i < 0) {
                BIO_printf(err, "\x75\x6e\x72\x65\x63\x6f\x67\x6e\x69\x7a\x65\x64\x20\x70\x75\x72\x70\x6f\x73\x65\xa");
                *badarg = 1;
            } else {
                xptmp = X509_PURPOSE_get0(i);
                purpose = X509_PURPOSE_get_id(xptmp);
            }
        }
        (*pargs)++;
    } else if (strcmp(arg, "\x2d\x76\x65\x72\x69\x66\x79\x5f\x64\x65\x70\x74\x68") == 0) {
        if (!argn)
            *badarg = 1;
        else {
            depth = atoi(argn);
            if (depth < 0) {
                BIO_printf(err, "\x69\x6e\x76\x61\x6c\x69\x64\x20\x64\x65\x70\x74\x68\xa");
                *badarg = 1;
            }
        }
        (*pargs)++;
    } else if (strcmp(arg, "\x2d\x61\x74\x74\x69\x6d\x65") == 0) {
        if (!argn)
            *badarg = 1;
        else {
            long timestamp;
            /*
             * interpret the -attime argument as seconds since Epoch
             */
            if (sscanf(argn, "\x25\x6c\x69", &timestamp) != 1) {
                BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x70\x61\x72\x73\x69\x6e\x67\x20\x74\x69\x6d\x65\x73\x74\x61\x6d\x70\x20\x25\x73\xa", argn);
                *badarg = 1;
            }
            /* on some platforms time_t may be a float */
            at_time = (time_t)timestamp;
        }
        (*pargs)++;
    } else if (strcmp(arg, "\x2d\x76\x65\x72\x69\x66\x79\x5f\x68\x6f\x73\x74\x6e\x61\x6d\x65") == 0) {
        if (!argn)
            *badarg = 1;
        hostname = argn;
        (*pargs)++;
    } else if (strcmp(arg, "\x2d\x76\x65\x72\x69\x66\x79\x5f\x65\x6d\x61\x69\x6c") == 0) {
        if (!argn)
            *badarg = 1;
        email = argn;
        (*pargs)++;
    } else if (strcmp(arg, "\x2d\x76\x65\x72\x69\x66\x79\x5f\x69\x70") == 0) {
        if (!argn)
            *badarg = 1;
        ipasc = argn;
        (*pargs)++;
    } else if (!strcmp(arg, "\x2d\x69\x67\x6e\x6f\x72\x65\x5f\x63\x72\x69\x74\x69\x63\x61\x6c"))
        flags |= X509_V_FLAG_IGNORE_CRITICAL;
    else if (!strcmp(arg, "\x2d\x69\x73\x73\x75\x65\x72\x5f\x63\x68\x65\x63\x6b\x73"))
        flags |= X509_V_FLAG_CB_ISSUER_CHECK;
    else if (!strcmp(arg, "\x2d\x63\x72\x6c\x5f\x63\x68\x65\x63\x6b"))
        flags |= X509_V_FLAG_CRL_CHECK;
    else if (!strcmp(arg, "\x2d\x63\x72\x6c\x5f\x63\x68\x65\x63\x6b\x5f\x61\x6c\x6c"))
        flags |= X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL;
    else if (!strcmp(arg, "\x2d\x70\x6f\x6c\x69\x63\x79\x5f\x63\x68\x65\x63\x6b"))
        flags |= X509_V_FLAG_POLICY_CHECK;
    else if (!strcmp(arg, "\x2d\x65\x78\x70\x6c\x69\x63\x69\x74\x5f\x70\x6f\x6c\x69\x63\x79"))
        flags |= X509_V_FLAG_EXPLICIT_POLICY;
    else if (!strcmp(arg, "\x2d\x69\x6e\x68\x69\x62\x69\x74\x5f\x61\x6e\x79"))
        flags |= X509_V_FLAG_INHIBIT_ANY;
    else if (!strcmp(arg, "\x2d\x69\x6e\x68\x69\x62\x69\x74\x5f\x6d\x61\x70"))
        flags |= X509_V_FLAG_INHIBIT_MAP;
    else if (!strcmp(arg, "\x2d\x78\x35\x30\x39\x5f\x73\x74\x72\x69\x63\x74"))
        flags |= X509_V_FLAG_X509_STRICT;
    else if (!strcmp(arg, "\x2d\x65\x78\x74\x65\x6e\x64\x65\x64\x5f\x63\x72\x6c"))
        flags |= X509_V_FLAG_EXTENDED_CRL_SUPPORT;
    else if (!strcmp(arg, "\x2d\x75\x73\x65\x5f\x64\x65\x6c\x74\x61\x73"))
        flags |= X509_V_FLAG_USE_DELTAS;
    else if (!strcmp(arg, "\x2d\x70\x6f\x6c\x69\x63\x79\x5f\x70\x72\x69\x6e\x74"))
        flags |= X509_V_FLAG_NOTIFY_POLICY;
    else if (!strcmp(arg, "\x2d\x63\x68\x65\x63\x6b\x5f\x73\x73\x5f\x73\x69\x67"))
        flags |= X509_V_FLAG_CHECK_SS_SIGNATURE;
    else if (!strcmp(arg, "\x2d\x74\x72\x75\x73\x74\x65\x64\x5f\x66\x69\x72\x73\x74"))
        flags |= X509_V_FLAG_TRUSTED_FIRST;
    else if (!strcmp(arg, "\x2d\x73\x75\x69\x74\x65\x42\x5f\x31\x32\x38\x5f\x6f\x6e\x6c\x79"))
        flags |= X509_V_FLAG_SUITEB_128_LOS_ONLY;
    else if (!strcmp(arg, "\x2d\x73\x75\x69\x74\x65\x42\x5f\x31\x32\x38"))
        flags |= X509_V_FLAG_SUITEB_128_LOS;
    else if (!strcmp(arg, "\x2d\x73\x75\x69\x74\x65\x42\x5f\x31\x39\x32"))
        flags |= X509_V_FLAG_SUITEB_192_LOS;
    else if (!strcmp(arg, "\x2d\x70\x61\x72\x74\x69\x61\x6c\x5f\x63\x68\x61\x69\x6e"))
        flags |= X509_V_FLAG_PARTIAL_CHAIN;
    else if (!strcmp(arg, "\x2d\x6e\x6f\x5f\x61\x6c\x74\x5f\x63\x68\x61\x69\x6e\x73"))
        flags |= X509_V_FLAG_NO_ALT_CHAINS;
    else if (!strcmp(arg, "\x2d\x61\x6c\x6c\x6f\x77\x5f\x70\x72\x6f\x78\x79\x5f\x63\x65\x72\x74\x73"))
        flags |= X509_V_FLAG_ALLOW_PROXY_CERTS;
    else
        return 0;

    if (*badarg) {
        if (*pm)
            X509_VERIFY_PARAM_free(*pm);
        *pm = NULL;
        goto end;
    }

    if (!*pm && !(*pm = X509_VERIFY_PARAM_new())) {
        *badarg = 1;
        goto end;
    }

    if (otmp)
        X509_VERIFY_PARAM_add0_policy(*pm, otmp);
    if (flags)
        X509_VERIFY_PARAM_set_flags(*pm, flags);

    if (purpose)
        X509_VERIFY_PARAM_set_purpose(*pm, purpose);

    if (depth >= 0)
        X509_VERIFY_PARAM_set_depth(*pm, depth);

    if (at_time)
        X509_VERIFY_PARAM_set_time(*pm, at_time);

    if (hostname && !X509_VERIFY_PARAM_set1_host(*pm, hostname, 0))
        *badarg = 1;

    if (email && !X509_VERIFY_PARAM_set1_email(*pm, email, 0))
        *badarg = 1;

    if (ipasc && !X509_VERIFY_PARAM_set1_ip_asc(*pm, ipasc))
        *badarg = 1;

 end:

    (*pargs)++;

    if (pargc)
        *pargc -= *pargs - oldargs;

    return 1;

}

/*
 * Read whole contents of a BIO into an allocated memory buffer and return
 * it.
 */

int bio_to_mem(unsigned char **out, int maxlen, BIO *in)
{
    BIO *mem;
    int len, ret;
    unsigned char tbuf[1024];
    mem = BIO_new(BIO_s_mem());
    if (!mem)
        return -1;
    for (;;) {
        if ((maxlen != -1) && maxlen < 1024)
            len = maxlen;
        else
            len = 1024;
        len = BIO_read(in, tbuf, len);
        if (len < 0) {
            BIO_free(mem);
            return -1;
        }
        if (len == 0)
            break;
        if (BIO_write(mem, tbuf, len) != len) {
            BIO_free(mem);
            return -1;
        }
        maxlen -= len;

        if (maxlen == 0)
            break;
    }
    ret = BIO_get_mem_data(mem, (char **)out);
    BIO_set_flags(mem, BIO_FLAGS_MEM_RDONLY);
    BIO_free(mem);
    return ret;
}

int pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value)
{
    int rv;
    char *stmp, *vtmp = NULL;
    stmp = BUF_strdup(value);
    if (!stmp)
        return -1;
    vtmp = strchr(stmp, '\x3a');
    if (vtmp) {
        *vtmp = 0;
        vtmp++;
    }
    rv = EVP_PKEY_CTX_ctrl_str(ctx, stmp, vtmp);
    OPENSSL_free(stmp);
    return rv;
}

static void nodes_print(BIO *out, const char *name,
                        STACK_OF(X509_POLICY_NODE) *nodes)
{
    X509_POLICY_NODE *node;
    int i;
    BIO_printf(out, "\x25\x73\x20\x50\x6f\x6c\x69\x63\x69\x65\x73\x3a", name);
    if (nodes) {
        BIO_puts(out, "\xa");
        for (i = 0; i < sk_X509_POLICY_NODE_num(nodes); i++) {
            node = sk_X509_POLICY_NODE_value(nodes, i);
            X509_POLICY_NODE_print(out, node, 2);
        }
    } else
        BIO_puts(out, "\x20\x3c\x65\x6d\x70\x74\x79\x3e\xa");
}

void policies_print(BIO *out, X509_STORE_CTX *ctx)
{
    X509_POLICY_TREE *tree;
    int explicit_policy;
    int free_out = 0;
    if (out == NULL) {
        out = BIO_new_fp(stderr, BIO_NOCLOSE);
        free_out = 1;
    }
    tree = X509_STORE_CTX_get0_policy_tree(ctx);
    explicit_policy = X509_STORE_CTX_get_explicit_policy(ctx);

    BIO_printf(out, "\x52\x65\x71\x75\x69\x72\x65\x20\x65\x78\x70\x6c\x69\x63\x69\x74\x20\x50\x6f\x6c\x69\x63\x79\x3a\x20\x25\x73\xa",
               explicit_policy ? "\x54\x72\x75\x65" : "\x46\x61\x6c\x73\x65");

    nodes_print(out, "\x41\x75\x74\x68\x6f\x72\x69\x74\x79", X509_policy_tree_get0_policies(tree));
    nodes_print(out, "\x55\x73\x65\x72", X509_policy_tree_get0_user_policies(tree));
    if (free_out)
        BIO_free(out);
}

#if !defined(OPENSSL_NO_JPAKE) && !defined(OPENSSL_NO_PSK)

static JPAKE_CTX *jpake_init(const char *us, const char *them,
                             const char *secret)
{
    BIGNUM *p = NULL;
    BIGNUM *g = NULL;
    BIGNUM *q = NULL;
    BIGNUM *bnsecret = BN_new();
    JPAKE_CTX *ctx;

    /* Use a safe prime for p (that we found earlier) */
    BN_hex2bn(&p,
              "\x46\x39\x45\x35\x42\x33\x36\x35\x36\x36\x35\x45\x41\x37\x41\x30\x35\x41\x39\x43\x35\x33\x34\x35\x30\x32\x37\x38\x30\x46\x45\x45\x36\x46\x31\x41\x42\x35\x42\x44\x34\x46\x34\x39\x39\x34\x37\x46\x44\x30\x33\x36\x44\x42\x44\x37\x45\x39\x30\x35\x32\x36\x39\x41\x46\x34\x36\x45\x46\x32\x38\x42\x30\x46\x43\x30\x37\x34\x38\x37\x45\x45\x34\x46\x35\x44\x32\x30\x46\x42\x33\x43\x30\x41\x46\x38\x45\x37\x30\x30\x46\x33\x41\x32\x46\x41\x33\x34\x31\x34\x39\x37\x30\x43\x42\x45\x44\x34\x34\x46\x45\x44\x46\x46\x38\x30\x43\x45\x37\x38\x44\x38\x30\x30\x46\x31\x38\x34\x42\x42\x38\x32\x34\x33\x35\x44\x31\x33\x37\x41\x41\x44\x41\x32\x43\x36\x43\x31\x36\x35\x32\x33\x32\x34\x37\x39\x33\x30\x41\x36\x33\x42\x38\x35\x36\x36\x31\x44\x31\x46\x43\x38\x31\x37\x41\x35\x31\x41\x43\x44\x39\x36\x31\x36\x38\x45\x39\x35\x38\x39\x38\x41\x31\x46\x38\x33\x41\x37\x39\x46\x46\x42\x35\x32\x39\x33\x36\x38\x41\x41\x37\x38\x33\x33\x41\x42\x44\x31\x42\x30\x43\x33\x41\x45\x44\x44\x42\x31\x34\x44\x32\x45\x31\x41\x32\x46\x37\x31\x44\x39\x39\x46\x37\x36\x33\x46");
    g = BN_new();
    BN_set_word(g, 2);
    q = BN_new();
    BN_rshift1(q, p);

    BN_bin2bn((const unsigned char *)secret, strlen(secret), bnsecret);

    ctx = JPAKE_CTX_new(us, them, p, g, q, bnsecret);
    BN_free(bnsecret);
    BN_free(q);
    BN_free(g);
    BN_free(p);

    return ctx;
}

static void jpake_send_part(BIO *conn, const JPAKE_STEP_PART *p)
{
    BN_print(conn, p->gx);
    BIO_puts(conn, "\xa");
    BN_print(conn, p->zkpx.gr);
    BIO_puts(conn, "\xa");
    BN_print(conn, p->zkpx.b);
    BIO_puts(conn, "\xa");
}

static void jpake_send_step1(BIO *bconn, JPAKE_CTX *ctx)
{
    JPAKE_STEP1 s1;

    JPAKE_STEP1_init(&s1);
    JPAKE_STEP1_generate(&s1, ctx);
    jpake_send_part(bconn, &s1.p1);
    jpake_send_part(bconn, &s1.p2);
    (void)BIO_flush(bconn);
    JPAKE_STEP1_release(&s1);
}

static void jpake_send_step2(BIO *bconn, JPAKE_CTX *ctx)
{
    JPAKE_STEP2 s2;

    JPAKE_STEP2_init(&s2);
    JPAKE_STEP2_generate(&s2, ctx);
    jpake_send_part(bconn, &s2);
    (void)BIO_flush(bconn);
    JPAKE_STEP2_release(&s2);
}

static void jpake_send_step3a(BIO *bconn, JPAKE_CTX *ctx)
{
    JPAKE_STEP3A s3a;

    JPAKE_STEP3A_init(&s3a);
    JPAKE_STEP3A_generate(&s3a, ctx);
    BIO_write(bconn, s3a.hhk, sizeof(s3a.hhk));
    (void)BIO_flush(bconn);
    JPAKE_STEP3A_release(&s3a);
}

static void jpake_send_step3b(BIO *bconn, JPAKE_CTX *ctx)
{
    JPAKE_STEP3B s3b;

    JPAKE_STEP3B_init(&s3b);
    JPAKE_STEP3B_generate(&s3b, ctx);
    BIO_write(bconn, s3b.hk, sizeof(s3b.hk));
    (void)BIO_flush(bconn);
    JPAKE_STEP3B_release(&s3b);
}

static void readbn(BIGNUM **bn, BIO *bconn)
{
    char buf[10240];
    int l;

    l = BIO_gets(bconn, buf, sizeof(buf));
    assert(l > 0);
    assert(buf[l - 1] == '\xa');
    buf[l - 1] = '\x0';
    BN_hex2bn(bn, buf);
}

static void jpake_receive_part(JPAKE_STEP_PART *p, BIO *bconn)
{
    readbn(&p->gx, bconn);
    readbn(&p->zkpx.gr, bconn);
    readbn(&p->zkpx.b, bconn);
}

static void jpake_receive_step1(JPAKE_CTX *ctx, BIO *bconn)
{
    JPAKE_STEP1 s1;

    JPAKE_STEP1_init(&s1);
    jpake_receive_part(&s1.p1, bconn);
    jpake_receive_part(&s1.p2, bconn);
    if (!JPAKE_STEP1_process(ctx, &s1)) {
        ERR_print_errors(bio_err);
        exit(1);
    }
    JPAKE_STEP1_release(&s1);
}

static void jpake_receive_step2(JPAKE_CTX *ctx, BIO *bconn)
{
    JPAKE_STEP2 s2;

    JPAKE_STEP2_init(&s2);
    jpake_receive_part(&s2, bconn);
    if (!JPAKE_STEP2_process(ctx, &s2)) {
        ERR_print_errors(bio_err);
        exit(1);
    }
    JPAKE_STEP2_release(&s2);
}

static void jpake_receive_step3a(JPAKE_CTX *ctx, BIO *bconn)
{
    JPAKE_STEP3A s3a;
    int l;

    JPAKE_STEP3A_init(&s3a);
    l = BIO_read(bconn, s3a.hhk, sizeof(s3a.hhk));
    assert(l == sizeof(s3a.hhk));
    if (!JPAKE_STEP3A_process(ctx, &s3a)) {
        ERR_print_errors(bio_err);
        exit(1);
    }
    JPAKE_STEP3A_release(&s3a);
}

static void jpake_receive_step3b(JPAKE_CTX *ctx, BIO *bconn)
{
    JPAKE_STEP3B s3b;
    int l;

    JPAKE_STEP3B_init(&s3b);
    l = BIO_read(bconn, s3b.hk, sizeof(s3b.hk));
    assert(l == sizeof(s3b.hk));
    if (!JPAKE_STEP3B_process(ctx, &s3b)) {
        ERR_print_errors(bio_err);
        exit(1);
    }
    JPAKE_STEP3B_release(&s3b);
}

void jpake_client_auth(BIO *out, BIO *conn, const char *secret)
{
    JPAKE_CTX *ctx;
    BIO *bconn;

    BIO_puts(out, "\x41\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x69\x6e\x67\x20\x77\x69\x74\x68\x20\x4a\x50\x41\x4b\x45\xa");

    ctx = jpake_init("\x63\x6c\x69\x65\x6e\x74", "\x73\x65\x72\x76\x65\x72", secret);

    bconn = BIO_new(BIO_f_buffer());
    BIO_push(bconn, conn);

    jpake_send_step1(bconn, ctx);
    jpake_receive_step1(ctx, bconn);
    jpake_send_step2(bconn, ctx);
    jpake_receive_step2(ctx, bconn);
    jpake_send_step3a(bconn, ctx);
    jpake_receive_step3b(ctx, bconn);

    BIO_puts(out, "\x4a\x50\x41\x4b\x45\x20\x61\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x69\x6f\x6e\x20\x73\x75\x63\x63\x65\x65\x64\x65\x64\x2c\x20\x73\x65\x74\x74\x69\x6e\x67\x20\x50\x53\x4b\xa");

    if (psk_key)
        OPENSSL_free(psk_key);

    psk_key = BN_bn2hex(JPAKE_get_shared_key(ctx));

    BIO_pop(bconn);
    BIO_free(bconn);

    JPAKE_CTX_free(ctx);
}

void jpake_server_auth(BIO *out, BIO *conn, const char *secret)
{
    JPAKE_CTX *ctx;
    BIO *bconn;

    BIO_puts(out, "\x41\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x69\x6e\x67\x20\x77\x69\x74\x68\x20\x4a\x50\x41\x4b\x45\xa");

    ctx = jpake_init("\x73\x65\x72\x76\x65\x72", "\x63\x6c\x69\x65\x6e\x74", secret);

    bconn = BIO_new(BIO_f_buffer());
    BIO_push(bconn, conn);

    jpake_receive_step1(ctx, bconn);
    jpake_send_step1(bconn, ctx);
    jpake_receive_step2(ctx, bconn);
    jpake_send_step2(bconn, ctx);
    jpake_receive_step3a(ctx, bconn);
    jpake_send_step3b(bconn, ctx);

    BIO_puts(out, "\x4a\x50\x41\x4b\x45\x20\x61\x75\x74\x68\x65\x6e\x74\x69\x63\x61\x74\x69\x6f\x6e\x20\x73\x75\x63\x63\x65\x65\x64\x65\x64\x2c\x20\x73\x65\x74\x74\x69\x6e\x67\x20\x50\x53\x4b\xa");

    if (psk_key)
        OPENSSL_free(psk_key);

    psk_key = BN_bn2hex(JPAKE_get_shared_key(ctx));

    BIO_pop(bconn);
    BIO_free(bconn);

    JPAKE_CTX_free(ctx);
}

#endif

#ifndef OPENSSL_NO_TLSEXT
/*-
 * next_protos_parse parses a comma separated list of strings into a string
 * in a format suitable for passing to SSL_CTX_set_next_protos_advertised.
 *   outlen: (output) set to the length of the resulting buffer on success.
 *   err: (maybe NULL) on failure, an error message line is written to this BIO.
 *   in: a NUL termianted string like "abc,def,ghi"
 *
 *   returns: a malloced buffer or NULL on failure.
 */
unsigned char *next_protos_parse(unsigned short *outlen, const char *in)
{
    size_t len;
    unsigned char *out;
    size_t i, start = 0;

    len = strlen(in);
    if (len >= 65535)
        return NULL;

    out = OPENSSL_malloc(strlen(in) + 1);
    if (!out)
        return NULL;

    for (i = 0; i <= len; ++i) {
        if (i == len || in[i] == '\x2c') {
            if (i - start > 255) {
                OPENSSL_free(out);
                return NULL;
            }
            out[start] = (unsigned char)(i - start);
            start = i + 1;
        } else
            out[i + 1] = in[i];
    }

    *outlen = (unsigned char)(len + 1);
    return out;
}
#endif                          /* ndef OPENSSL_NO_TLSEXT */

void print_cert_checks(BIO *bio, X509 *x,
                       const char *checkhost,
                       const char *checkemail, const char *checkip)
{
    if (x == NULL)
        return;
    if (checkhost) {
        BIO_printf(bio, "\x48\x6f\x73\x74\x6e\x61\x6d\x65\x20\x25\x73\x20\x64\x6f\x65\x73\x25\x73\x20\x6d\x61\x74\x63\x68\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\xa",
                   checkhost, X509_check_host(x, checkhost, 0, 0, NULL) == 1
                   ? "" : "\x20\x4e\x4f\x54");
    }

    if (checkemail) {
        BIO_printf(bio, "\x45\x6d\x61\x69\x6c\x20\x25\x73\x20\x64\x6f\x65\x73\x25\x73\x20\x6d\x61\x74\x63\x68\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\xa",
                   checkemail, X509_check_email(x, checkemail, 0,
                                                0) ? "" : "\x20\x4e\x4f\x54");
    }

    if (checkip) {
        BIO_printf(bio, "\x49\x50\x20\x25\x73\x20\x64\x6f\x65\x73\x25\x73\x20\x6d\x61\x74\x63\x68\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\xa",
                   checkip, X509_check_ip_asc(x, checkip, 0) ? "" : "\x20\x4e\x4f\x54");
    }
}

/* Get first http URL from a DIST_POINT structure */

static const char *get_dp_url(DIST_POINT *dp)
{
    GENERAL_NAMES *gens;
    GENERAL_NAME *gen;
    int i, gtype;
    ASN1_STRING *uri;
    if (!dp->distpoint || dp->distpoint->type != 0)
        return NULL;
    gens = dp->distpoint->name.fullname;
    for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
        gen = sk_GENERAL_NAME_value(gens, i);
        uri = GENERAL_NAME_get0_value(gen, &gtype);
        if (gtype == GEN_URI && ASN1_STRING_length(uri) > 6) {
            char *uptr = (char *)ASN1_STRING_data(uri);
            if (!strncmp(uptr, "\x68\x74\x74\x70\x3a\x2f\x2f", 7))
                return uptr;
        }
    }
    return NULL;
}

/*
 * Look through a CRLDP structure and attempt to find an http URL to
 * downloads a CRL from.
 */

static X509_CRL *load_crl_crldp(STACK_OF(DIST_POINT) *crldp)
{
    int i;
    const char *urlptr = NULL;
    for (i = 0; i < sk_DIST_POINT_num(crldp); i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
        urlptr = get_dp_url(dp);
        if (urlptr)
            return load_crl(urlptr, FORMAT_HTTP);
    }
    return NULL;
}

/*
 * Example of downloading CRLs from CRLDP: not usable for real world as it
 * always downloads, doesn't support non-blocking I/O and doesn't cache
 * anything.
 */

static STACK_OF(X509_CRL) *crls_http_cb(X509_STORE_CTX *ctx, X509_NAME *nm)
{
    X509 *x;
    STACK_OF(X509_CRL) *crls = NULL;
    X509_CRL *crl;
    STACK_OF(DIST_POINT) *crldp;
    x = X509_STORE_CTX_get_current_cert(ctx);
    crldp = X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL);
    crl = load_crl_crldp(crldp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (!crl)
        return NULL;
    crls = sk_X509_CRL_new_null();
    sk_X509_CRL_push(crls, crl);
    /* Try to download delta CRL */
    crldp = X509_get_ext_d2i(x, NID_freshest_crl, NULL, NULL);
    crl = load_crl_crldp(crldp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    if (crl)
        sk_X509_CRL_push(crls, crl);
    return crls;
}

void store_setup_crl_download(X509_STORE *st)
{
    X509_STORE_set_lookup_crls_cb(st, crls_http_cb);
}

/*
 * Platform-specific sections
 */
#if defined(_WIN32)
# ifdef fileno
#  undef fileno
#  define fileno(a) (int)_fileno(a)
# endif

# include <windows.h>
# include <tchar.h>

static int WIN32_rename(const char *from, const char *to)
{
    TCHAR *tfrom = NULL, *tto;
    DWORD err;
    int ret = 0;

    if (sizeof(TCHAR) == 1) {
        tfrom = (TCHAR *)from;
        tto = (TCHAR *)to;
    } else {                    /* UNICODE path */

        size_t i, flen = strlen(from) + 1, tlen = strlen(to) + 1;
        tfrom = (TCHAR *)malloc(sizeof(TCHAR) * (flen + tlen));
        if (tfrom == NULL)
            goto err;
        tto = tfrom + flen;
# if !defined(_WIN32_WCE) || _WIN32_WCE>=101
        if (!MultiByteToWideChar(CP_ACP, 0, from, flen, (WCHAR *)tfrom, flen))
# endif
            for (i = 0; i < flen; i++)
                tfrom[i] = (TCHAR)from[i];
# if !defined(_WIN32_WCE) || _WIN32_WCE>=101
        if (!MultiByteToWideChar(CP_ACP, 0, to, tlen, (WCHAR *)tto, tlen))
# endif
            for (i = 0; i < tlen; i++)
                tto[i] = (TCHAR)to[i];
    }

    if (MoveFile(tfrom, tto))
        goto ok;
    err = GetLastError();
    if (err == ERROR_ALREADY_EXISTS || err == ERROR_FILE_EXISTS) {
        if (DeleteFile(tto) && MoveFile(tfrom, tto))
            goto ok;
        err = GetLastError();
    }
    if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
        errno = ENOENT;
    else if (err == ERROR_ACCESS_DENIED)
        errno = EACCES;
    else
        errno = EINVAL;         /* we could map more codes... */
 err:
    ret = -1;
 ok:
    if (tfrom != NULL && tfrom != (TCHAR *)from)
        free(tfrom);
    return ret;
}
#endif

/* app_tminterval section */
#if defined(_WIN32)
double app_tminterval(int stop, int usertime)
{
    FILETIME now;
    double ret = 0;
    static ULARGE_INTEGER tmstart;
    static int warning = 1;
# ifdef _WIN32_WINNT
    static HANDLE proc = NULL;

    if (proc == NULL) {
        if (check_winnt())
            proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE,
                               GetCurrentProcessId());
        if (proc == NULL)
            proc = (HANDLE) - 1;
    }

    if (usertime && proc != (HANDLE) - 1) {
        FILETIME junk;
        GetProcessTimes(proc, &junk, &junk, &junk, &now);
    } else
# endif
    {
        SYSTEMTIME systime;

        if (usertime && warning) {
            BIO_printf(bio_err, "\x54\x6f\x20\x67\x65\x74\x20\x6d\x65\x61\x6e\x69\x6e\x67\x66\x75\x6c\x20\x72\x65\x73\x75\x6c\x74\x73\x2c\x20\x72\x75\x6e\x20"
                       "\x74\x68\x69\x73\x20\x70\x72\x6f\x67\x72\x61\x6d\x20\x6f\x6e\x20\x69\x64\x6c\x65\x20\x73\x79\x73\x74\x65\x6d\x2e\xa");
            warning = 0;
        }
        GetSystemTime(&systime);
        SystemTimeToFileTime(&systime, &now);
    }

    if (stop == TM_START) {
        tmstart.u.LowPart = now.dwLowDateTime;
        tmstart.u.HighPart = now.dwHighDateTime;
    } else {
        ULARGE_INTEGER tmstop;

        tmstop.u.LowPart = now.dwLowDateTime;
        tmstop.u.HighPart = now.dwHighDateTime;

        ret = (__int64)(tmstop.QuadPart - tmstart.QuadPart) * 1e-7;
    }

    return (ret);
}

#elif defined(OPENSSL_SYS_NETWARE)
# include <time.h>

double app_tminterval(int stop, int usertime)
{
    double ret = 0;
    static clock_t tmstart;
    static int warning = 1;

    if (usertime && warning) {
        BIO_printf(bio_err, "\x54\x6f\x20\x67\x65\x74\x20\x6d\x65\x61\x6e\x69\x6e\x67\x66\x75\x6c\x20\x72\x65\x73\x75\x6c\x74\x73\x2c\x20\x72\x75\x6e\x20"
                   "\x74\x68\x69\x73\x20\x70\x72\x6f\x67\x72\x61\x6d\x20\x6f\x6e\x20\x69\x64\x6c\x65\x20\x73\x79\x73\x74\x65\x6d\x2e\xa");
        warning = 0;
    }

    if (stop == TM_START)
        tmstart = clock();
    else
        ret = (clock() - tmstart) / (double)CLOCKS_PER_SEC;

    return (ret);
}

#elif defined(OPENSSL_SYSTEM_VXWORKS)
# include <time.h>

double app_tminterval(int stop, int usertime)
{
    double ret = 0;
# ifdef CLOCK_REALTIME
    static struct timespec tmstart;
    struct timespec now;
# else
    static unsigned long tmstart;
    unsigned long now;
# endif
    static int warning = 1;

    if (usertime && warning) {
        BIO_printf(bio_err, "\x54\x6f\x20\x67\x65\x74\x20\x6d\x65\x61\x6e\x69\x6e\x67\x66\x75\x6c\x20\x72\x65\x73\x75\x6c\x74\x73\x2c\x20\x72\x75\x6e\x20"
                   "\x74\x68\x69\x73\x20\x70\x72\x6f\x67\x72\x61\x6d\x20\x6f\x6e\x20\x69\x64\x6c\x65\x20\x73\x79\x73\x74\x65\x6d\x2e\xa");
        warning = 0;
    }
# ifdef CLOCK_REALTIME
    clock_gettime(CLOCK_REALTIME, &now);
    if (stop == TM_START)
        tmstart = now;
    else
        ret = ((now.tv_sec + now.tv_nsec * 1e-9)
               - (tmstart.tv_sec + tmstart.tv_nsec * 1e-9));
# else
    now = tickGet();
    if (stop == TM_START)
        tmstart = now;
    else
        ret = (now - tmstart) / (double)sysClkRateGet();
# endif
    return (ret);
}

#elif defined(OPENSSL_SYSTEM_VMS)
# include <time.h>
# include <times.h>

double app_tminterval(int stop, int usertime)
{
    static clock_t tmstart;
    double ret = 0;
    clock_t now;
# ifdef __TMS
    struct tms rus;

    now = times(&rus);
    if (usertime)
        now = rus.tms_utime;
# else
    if (usertime)
        now = clock();          /* sum of user and kernel times */
    else {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        now = (clock_t)((unsigned long long)tv.tv_sec * CLK_TCK +
                        (unsigned long long)tv.tv_usec * (1000000 / CLK_TCK)
            );
    }
# endif
    if (stop == TM_START)
        tmstart = now;
    else
        ret = (now - tmstart) / (double)(CLK_TCK);

    return (ret);
}

#elif defined(_SC_CLK_TCK)      /* by means of unistd.h */
# include <sys/times.h>

double app_tminterval(int stop, int usertime)
{
    double ret = 0;
    struct tms rus;
    clock_t now = times(&rus);
    static clock_t tmstart;

    if (usertime)
        now = rus.tms_utime;

    if (stop == TM_START)
        tmstart = now;
    else {
        long int tck = sysconf(_SC_CLK_TCK);
        ret = (now - tmstart) / (double)tck;
    }

    return (ret);
}

#else
# include <sys/time.h>
# include <sys/resource.h>

double app_tminterval(int stop, int usertime)
{
    double ret = 0;
    struct rusage rus;
    struct timeval now;
    static struct timeval tmstart;

    if (usertime)
        getrusage(RUSAGE_SELF, &rus), now = rus.ru_utime;
    else
        gettimeofday(&now, NULL);

    if (stop == TM_START)
        tmstart = now;
    else
        ret = ((now.tv_sec + now.tv_usec * 1e-6)
               - (tmstart.tv_sec + tmstart.tv_usec * 1e-6));

    return ret;
}
#endif

/* app_isdir section */
#ifdef _WIN32
int app_isdir(const char *name)
{
    HANDLE hList;
    WIN32_FIND_DATA FileData;
# if defined(UNICODE) || defined(_UNICODE)
    size_t i, len_0 = strlen(name) + 1;

    if (len_0 > sizeof(FileData.cFileName) / sizeof(FileData.cFileName[0]))
        return -1;

#  if !defined(_WIN32_WCE) || _WIN32_WCE>=101
    if (!MultiByteToWideChar
        (CP_ACP, 0, name, len_0, FileData.cFileName, len_0))
#  endif
        for (i = 0; i < len_0; i++)
            FileData.cFileName[i] = (WCHAR)name[i];

    hList = FindFirstFile(FileData.cFileName, &FileData);
# else
    hList = FindFirstFile(name, &FileData);
# endif
    if (hList == INVALID_HANDLE_VALUE)
        return -1;
    FindClose(hList);
    return ((FileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
}
#else
# include <sys/stat.h>
# ifndef S_ISDIR
#  if defined(_S_IFMT) && defined(_S_IFDIR)
#   define S_ISDIR(a)   (((a) & _S_IFMT) == _S_IFDIR)
#  else
#   define S_ISDIR(a)   (((a) & S_IFMT) == S_IFDIR)
#  endif
# endif

int app_isdir(const char *name)
{
# if defined(S_ISDIR)
    struct stat st;

    if (stat(name, &st) == 0)
        return S_ISDIR(st.st_mode);
    else
        return -1;
# else
    return -1;
# endif
}
#endif

/* raw_read|write section */
#if defined(__VMS)
# include "vms_term_sock.h"
static int stdin_sock = -1;

static void close_stdin_sock(void)
{
    TerminalSocket (TERM_SOCK_DELETE, &stdin_sock);
}

int fileno_stdin(void)
{
    if (stdin_sock == -1) {
        TerminalSocket(TERM_SOCK_CREATE, &stdin_sock);
        atexit(close_stdin_sock);
    }

    return stdin_sock;
}
#else
int fileno_stdin(void)
{
    return fileno(stdin);
}
#endif

int fileno_stdout(void)
{
    return fileno(stdout);
}

#if defined(_WIN32) && defined(STD_INPUT_HANDLE)
int raw_read_stdin(void *buf, int siz)
{
    DWORD n;
    if (ReadFile(GetStdHandle(STD_INPUT_HANDLE), buf, siz, &n, NULL))
        return (n);
    else
        return (-1);
}
#elif defined(__VMS)
#include <sys/socket.h>

int raw_read_stdin(void *buf, int siz)
{
    return recv(fileno_stdin(), buf, siz, 0);
}
#else
int raw_read_stdin(void *buf, int siz)
{
    return read(fileno_stdin(), buf, siz);
}
#endif

#if defined(_WIN32) && defined(STD_OUTPUT_HANDLE)
int raw_write_stdout(const void *buf, int siz)
{
    DWORD n;
    if (WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, siz, &n, NULL))
        return (n);
    else
        return (-1);
}
#else
int raw_write_stdout(const void *buf, int siz)
{
    return write(fileno_stdout(), buf, siz);
}
#endif

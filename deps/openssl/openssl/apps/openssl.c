/* apps/openssl.c */
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
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define OPENSSL_C               /* tells apps.h to use complete
                                 * apps_startup() */
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/lhash.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif
#define USE_SOCKETS             /* needed for the _O_BINARY defs in the MS
                                 * world */
#include "progs.h"
#include "s_apps.h"
#include <openssl/err.h>
#ifdef OPENSSL_FIPS
# include <openssl/fips.h>
#endif

/*
 * The LHASH callbacks ("hash" & "cmp") have been replaced by functions with
 * the base prototypes (we cast each variable inside the function to the
 * required type of "FUNCTION*"). This removes the necessity for
 * macro-generated wrapper functions.
 */

static LHASH_OF(FUNCTION) *prog_init(void);
static int do_cmd(LHASH_OF(FUNCTION) *prog, int argc, char *argv[]);
static void list_pkey(BIO *out);
static void list_cipher(BIO *out);
static void list_md(BIO *out);
char *default_config_file = NULL;

/* Make sure there is only one when MONOLITH is defined */
#ifdef MONOLITH
CONF *config = NULL;
BIO *bio_err = NULL;
#endif

static void lock_dbg_cb(int mode, int type, const char *file, int line)
{
    static int modes[CRYPTO_NUM_LOCKS]; /* = {0, 0, ... } */
    const char *errstr = NULL;
    int rw;

    rw = mode & (CRYPTO_READ | CRYPTO_WRITE);
    if (!((rw == CRYPTO_READ) || (rw == CRYPTO_WRITE))) {
        errstr = "\x69\x6e\x76\x61\x6c\x69\x64\x20\x6d\x6f\x64\x65";
        goto err;
    }

    if (type < 0 || type >= CRYPTO_NUM_LOCKS) {
        errstr = "\x74\x79\x70\x65\x20\x6f\x75\x74\x20\x6f\x66\x20\x62\x6f\x75\x6e\x64\x73";
        goto err;
    }

    if (mode & CRYPTO_LOCK) {
        if (modes[type]) {
            errstr = "\x61\x6c\x72\x65\x61\x64\x79\x20\x6c\x6f\x63\x6b\x65\x64";
            /*
             * must not happen in a single-threaded program (would deadlock)
             */
            goto err;
        }

        modes[type] = rw;
    } else if (mode & CRYPTO_UNLOCK) {
        if (!modes[type]) {
            errstr = "\x6e\x6f\x74\x20\x6c\x6f\x63\x6b\x65\x64";
            goto err;
        }

        if (modes[type] != rw) {
            errstr = (rw == CRYPTO_READ) ?
                "\x43\x52\x59\x50\x54\x4f\x5f\x72\x5f\x75\x6e\x6c\x6f\x63\x6b\x20\x6f\x6e\x20\x77\x72\x69\x74\x65\x20\x6c\x6f\x63\x6b" :
                "\x43\x52\x59\x50\x54\x4f\x5f\x77\x5f\x75\x6e\x6c\x6f\x63\x6b\x20\x6f\x6e\x20\x72\x65\x61\x64\x20\x6c\x6f\x63\x6b";
        }

        modes[type] = 0;
    } else {
        errstr = "\x69\x6e\x76\x61\x6c\x69\x64\x20\x6d\x6f\x64\x65";
        goto err;
    }

 err:
    if (errstr) {
        /* we cannot use bio_err here */
        fprintf(stderr,
                "\x6f\x70\x65\x6e\x73\x73\x6c\x20\x28\x6c\x6f\x63\x6b\x5f\x64\x62\x67\x5f\x63\x62\x29\x3a\x20\x25\x73\x20\x28\x6d\x6f\x64\x65\x3d\x25\x64\x2c\x20\x74\x79\x70\x65\x3d\x25\x64\x29\x20\x61\x74\x20\x25\x73\x3a\x25\x64\xa",
                errstr, mode, type, file, line);
    }
}

#if defined( OPENSSL_SYS_VMS) && (__INITIAL_POINTER_SIZE == 64)
# define ARGV _Argv
#else
# define ARGV Argv
#endif

int main(int Argc, char *ARGV[])
{
    ARGS arg;
#define PROG_NAME_SIZE  39
    char pname[PROG_NAME_SIZE + 1];
    FUNCTION f, *fp;
    MS_STATIC const char *prompt;
    MS_STATIC char buf[1024];
    char *to_free = NULL;
    int n, i, ret = 0;
    int argc;
    char **argv, *p;
    LHASH_OF(FUNCTION) *prog = NULL;
    long errline;

#if defined( OPENSSL_SYS_VMS) && (__INITIAL_POINTER_SIZE == 64)
    /*-
     * 2011-03-22 SMS.
     * If we have 32-bit pointers everywhere, then we're safe, and
     * we bypass this mess, as on non-VMS systems.  (See ARGV,
     * above.)
     * Problem 1: Compaq/HP C before V7.3 always used 32-bit
     * pointers for argv[].
     * Fix 1: For a 32-bit argv[], when we're using 64-bit pointers
     * everywhere else, we always allocate and use a 64-bit
     * duplicate of argv[].
     * Problem 2: Compaq/HP C V7.3 (Alpha, IA64) before ECO1 failed
     * to NULL-terminate a 64-bit argv[].  (As this was written, the
     * compiler ECO was available only on IA64.)
     * Fix 2: Unless advised not to (VMS_TRUST_ARGV), we test a
     * 64-bit argv[argc] for NULL, and, if necessary, use a
     * (properly) NULL-terminated (64-bit) duplicate of argv[].
     * The same code is used in either case to duplicate argv[].
     * Some of these decisions could be handled in preprocessing,
     * but the code tends to get even uglier, and the penalty for
     * deciding at compile- or run-time is tiny.
     */
    char **Argv = NULL;
    int free_Argv = 0;

    if ((sizeof(_Argv) < 8)     /* 32-bit argv[]. */
# if !defined( VMS_TRUST_ARGV)
        || (_Argv[Argc] != NULL) /* Untrusted argv[argc] not NULL. */
# endif
        ) {
        int i;
        Argv = OPENSSL_malloc((Argc + 1) * sizeof(char *));
        if (Argv == NULL) {
            ret = -1;
            goto end;
        }
        for (i = 0; i < Argc; i++)
            Argv[i] = _Argv[i];
        Argv[Argc] = NULL;      /* Certain NULL termination. */
        free_Argv = 1;
    } else {
        /*
         * Use the known-good 32-bit argv[] (which needs the type cast to
         * satisfy the compiler), or the trusted or tested-good 64-bit argv[]
         * as-is.
         */
        Argv = (char **)_Argv;
    }
#endif                          /* defined( OPENSSL_SYS_VMS) &&
                                 * (__INITIAL_POINTER_SIZE == 64) */

    arg.data = NULL;
    arg.count = 0;

    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (getenv("\x4f\x50\x45\x4e\x53\x53\x4c\x5f\x44\x45\x42\x55\x47\x5f\x4d\x45\x4d\x4f\x52\x59") != NULL) { /* if not defined, use
                                                   * compiled-in library
                                                   * defaults */
        if (!(0 == strcmp(getenv("\x4f\x50\x45\x4e\x53\x53\x4c\x5f\x44\x45\x42\x55\x47\x5f\x4d\x45\x4d\x4f\x52\x59"), "\x6f\x66\x66"))) {
            CRYPTO_malloc_debug_init();
            CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
        } else {
            /* OPENSSL_DEBUG_MEMORY=off */
            CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
        }
    }
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

#if 0
    if (getenv("\x4f\x50\x45\x4e\x53\x53\x4c\x5f\x44\x45\x42\x55\x47\x5f\x4c\x4f\x43\x4b\x49\x4e\x47") != NULL)
#endif
    {
        CRYPTO_set_locking_callback(lock_dbg_cb);
    }

    if (getenv("\x4f\x50\x45\x4e\x53\x53\x4c\x5f\x46\x49\x50\x53")) {
#ifdef OPENSSL_FIPS
        if (!FIPS_mode_set(1)) {
            ERR_load_crypto_strings();
            ERR_print_errors(BIO_new_fp(stderr, BIO_NOCLOSE));
            EXIT(1);
        }
#else
        fprintf(stderr, "\x46\x49\x50\x53\x20\x6d\x6f\x64\x65\x20\x6e\x6f\x74\x20\x73\x75\x70\x70\x6f\x72\x74\x65\x64\x2e\xa");
        EXIT(1);
#endif
    }

    apps_startup();

    /* Lets load up our environment a little */
    p = getenv("\x4f\x50\x45\x4e\x53\x53\x4c\x5f\x43\x4f\x4e\x46");
    if (p == NULL)
        p = getenv("\x53\x53\x4c\x45\x41\x59\x5f\x43\x4f\x4e\x46");
    if (p == NULL)
        p = to_free = make_config_name();

    default_config_file = p;

    config = NCONF_new(NULL);
    i = NCONF_load(config, p, &errline);
    if (i == 0) {
        if (ERR_GET_REASON(ERR_peek_last_error())
            == CONF_R_NO_SUCH_FILE) {
            BIO_printf(bio_err, "\x57\x41\x52\x4e\x49\x4e\x47\x3a\x20\x63\x61\x6e\x27\x74\x20\x6f\x70\x65\x6e\x20\x63\x6f\x6e\x66\x69\x67\x20\x66\x69\x6c\x65\x3a\x20\x25\x73\xa", p);
            ERR_clear_error();
            NCONF_free(config);
            config = NULL;
        } else {
            ERR_print_errors(bio_err);
            NCONF_free(config);
            exit(1);
        }
    }

    prog = prog_init();

    /* first check the program name */
    program_name(Argv[0], pname, sizeof(pname));

    f.name = pname;
    fp = lh_FUNCTION_retrieve(prog, &f);
    if (fp != NULL) {
        Argv[0] = pname;
        ret = fp->func(Argc, Argv);
        goto end;
    }

    /*
     * ok, now check that there are not arguments, if there are, run with
     * them, shifting the ssleay off the front
     */
    if (Argc != 1) {
        Argc--;
        Argv++;
        ret = do_cmd(prog, Argc, Argv);
        if (ret < 0)
            ret = 0;
        goto end;
    }

    /* ok, lets enter the old 'OpenSSL>' mode */

    for (;;) {
        ret = 0;
        p = buf;
        n = sizeof(buf);
        i = 0;
        for (;;) {
            p[0] = '\x0';
            if (i++)
                prompt = "\x3e";
            else
                prompt = "\x4f\x70\x65\x6e\x53\x53\x4c\x3e\x20";
            fputs(prompt, stdout);
            fflush(stdout);
            if (!fgets(p, n, stdin))
                goto end;
            if (p[0] == '\x0')
                goto end;
            i = strlen(p);
            if (i <= 1)
                break;
            if (p[i - 2] != '\x5c')
                break;
            i -= 2;
            p += i;
            n -= i;
        }
        if (!chopup_args(&arg, buf, &argc, &argv))
            break;

        ret = do_cmd(prog, argc, argv);
        if (ret < 0) {
            ret = 0;
            goto end;
        }
        if (ret != 0)
            BIO_printf(bio_err, "\x65\x72\x72\x6f\x72\x20\x69\x6e\x20\x25\x73\xa", argv[0]);
        (void)BIO_flush(bio_err);
    }
    BIO_printf(bio_err, "\x62\x61\x64\x20\x65\x78\x69\x74\xa");
    ret = 1;
 end:
    if (to_free)
        OPENSSL_free(to_free);
    if (config != NULL) {
        NCONF_free(config);
        config = NULL;
    }
    if (prog != NULL)
        lh_FUNCTION_free(prog);
    if (arg.data != NULL)
        OPENSSL_free(arg.data);

#if defined( OPENSSL_SYS_VMS) && (__INITIAL_POINTER_SIZE == 64)
    /* Free any duplicate Argv[] storage. */
    if (free_Argv) {
        OPENSSL_free(Argv);
    }
#endif
    apps_shutdown();
    CRYPTO_mem_leaks(bio_err);
    if (bio_err != NULL) {
        BIO_free(bio_err);
        bio_err = NULL;
    }

    OPENSSL_EXIT(ret);
}

#define LIST_STANDARD_COMMANDS "\x6c\x69\x73\x74\x2d\x73\x74\x61\x6e\x64\x61\x72\x64\x2d\x63\x6f\x6d\x6d\x61\x6e\x64\x73"
#define LIST_MESSAGE_DIGEST_COMMANDS "\x6c\x69\x73\x74\x2d\x6d\x65\x73\x73\x61\x67\x65\x2d\x64\x69\x67\x65\x73\x74\x2d\x63\x6f\x6d\x6d\x61\x6e\x64\x73"
#define LIST_MESSAGE_DIGEST_ALGORITHMS "\x6c\x69\x73\x74\x2d\x6d\x65\x73\x73\x61\x67\x65\x2d\x64\x69\x67\x65\x73\x74\x2d\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x73"
#define LIST_CIPHER_COMMANDS "\x6c\x69\x73\x74\x2d\x63\x69\x70\x68\x65\x72\x2d\x63\x6f\x6d\x6d\x61\x6e\x64\x73"
#define LIST_CIPHER_ALGORITHMS "\x6c\x69\x73\x74\x2d\x63\x69\x70\x68\x65\x72\x2d\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x73"
#define LIST_PUBLIC_KEY_ALGORITHMS "\x6c\x69\x73\x74\x2d\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79\x2d\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x73"

static int do_cmd(LHASH_OF(FUNCTION) *prog, int argc, char *argv[])
{
    FUNCTION f, *fp;
    int i, ret = 1, tp, nl;

    if ((argc <= 0) || (argv[0] == NULL)) {
        ret = 0;
        goto end;
    }
    f.name = argv[0];
    fp = lh_FUNCTION_retrieve(prog, &f);
    if (fp == NULL) {
        if (EVP_get_digestbyname(argv[0])) {
            f.type = FUNC_TYPE_MD;
            f.func = dgst_main;
            fp = &f;
        } else if (EVP_get_cipherbyname(argv[0])) {
            f.type = FUNC_TYPE_CIPHER;
            f.func = enc_main;
            fp = &f;
        }
    }
    if (fp != NULL) {
        ret = fp->func(argc, argv);
    } else if ((strncmp(argv[0], "\x6e\x6f\x2d", 3)) == 0) {
        BIO *bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);
#ifdef OPENSSL_SYS_VMS
        {
            BIO *tmpbio = BIO_new(BIO_f_linebuffer());
            bio_stdout = BIO_push(tmpbio, bio_stdout);
        }
#endif
        f.name = argv[0] + 3;
        ret = (lh_FUNCTION_retrieve(prog, &f) != NULL);
        if (!ret)
            BIO_printf(bio_stdout, "\x25\x73\xa", argv[0]);
        else
            BIO_printf(bio_stdout, "\x25\x73\xa", argv[0] + 3);
        BIO_free_all(bio_stdout);
        goto end;
    } else if ((strcmp(argv[0], "\x71\x75\x69\x74") == 0) ||
               (strcmp(argv[0], "\x71") == 0) ||
               (strcmp(argv[0], "\x65\x78\x69\x74") == 0) ||
               (strcmp(argv[0], "\x62\x79\x65") == 0)) {
        ret = -1;
        goto end;
    } else if ((strcmp(argv[0], LIST_STANDARD_COMMANDS) == 0) ||
               (strcmp(argv[0], LIST_MESSAGE_DIGEST_COMMANDS) == 0) ||
               (strcmp(argv[0], LIST_MESSAGE_DIGEST_ALGORITHMS) == 0) ||
               (strcmp(argv[0], LIST_CIPHER_COMMANDS) == 0) ||
               (strcmp(argv[0], LIST_CIPHER_ALGORITHMS) == 0) ||
               (strcmp(argv[0], LIST_PUBLIC_KEY_ALGORITHMS) == 0)) {
        int list_type;
        BIO *bio_stdout;

        if (strcmp(argv[0], LIST_STANDARD_COMMANDS) == 0)
            list_type = FUNC_TYPE_GENERAL;
        else if (strcmp(argv[0], LIST_MESSAGE_DIGEST_COMMANDS) == 0)
            list_type = FUNC_TYPE_MD;
        else if (strcmp(argv[0], LIST_MESSAGE_DIGEST_ALGORITHMS) == 0)
            list_type = FUNC_TYPE_MD_ALG;
        else if (strcmp(argv[0], LIST_PUBLIC_KEY_ALGORITHMS) == 0)
            list_type = FUNC_TYPE_PKEY;
        else if (strcmp(argv[0], LIST_CIPHER_ALGORITHMS) == 0)
            list_type = FUNC_TYPE_CIPHER_ALG;
        else                    /* strcmp(argv[0],LIST_CIPHER_COMMANDS) == 0 */
            list_type = FUNC_TYPE_CIPHER;
        bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);
#ifdef OPENSSL_SYS_VMS
        {
            BIO *tmpbio = BIO_new(BIO_f_linebuffer());
            bio_stdout = BIO_push(tmpbio, bio_stdout);
        }
#endif

        if (!load_config(bio_err, NULL))
            goto end;

        if (list_type == FUNC_TYPE_PKEY)
            list_pkey(bio_stdout);
        if (list_type == FUNC_TYPE_MD_ALG)
            list_md(bio_stdout);
        if (list_type == FUNC_TYPE_CIPHER_ALG)
            list_cipher(bio_stdout);
        else {
            for (fp = functions; fp->name != NULL; fp++)
                if (fp->type == list_type)
                    BIO_printf(bio_stdout, "\x25\x73\xa", fp->name);
        }
        BIO_free_all(bio_stdout);
        ret = 0;
        goto end;
    } else {
        BIO_printf(bio_err, "\x6f\x70\x65\x6e\x73\x73\x6c\x3a\x45\x72\x72\x6f\x72\x3a\x20\x27\x25\x73\x27\x20\x69\x73\x20\x61\x6e\x20\x69\x6e\x76\x61\x6c\x69\x64\x20\x63\x6f\x6d\x6d\x61\x6e\x64\x2e\xa",
                   argv[0]);
        BIO_printf(bio_err, "\xa\x53\x74\x61\x6e\x64\x61\x72\x64\x20\x63\x6f\x6d\x6d\x61\x6e\x64\x73");
        i = 0;
        tp = 0;
        for (fp = functions; fp->name != NULL; fp++) {
            nl = 0;
#ifdef OPENSSL_NO_CAMELLIA
            if (((i++) % 5) == 0)
#else
            if (((i++) % 4) == 0)
#endif
            {
                BIO_printf(bio_err, "\xa");
                nl = 1;
            }
            if (fp->type != tp) {
                tp = fp->type;
                if (!nl)
                    BIO_printf(bio_err, "\xa");
                if (tp == FUNC_TYPE_MD) {
                    i = 1;
                    BIO_printf(bio_err,
                               "\xa\x4d\x65\x73\x73\x61\x67\x65\x20\x44\x69\x67\x65\x73\x74\x20\x63\x6f\x6d\x6d\x61\x6e\x64\x73\x20\x28\x73\x65\x65\x20\x74\x68\x65\x20\x60\x64\x67\x73\x74\x27\x20\x63\x6f\x6d\x6d\x61\x6e\x64\x20\x66\x6f\x72\x20\x6d\x6f\x72\x65\x20\x64\x65\x74\x61\x69\x6c\x73\x29\xa");
                } else if (tp == FUNC_TYPE_CIPHER) {
                    i = 1;
                    BIO_printf(bio_err,
                               "\xaC\x69\x70\x68\x65\x72\x20\x63\x6f\x6d\x6d\x61\x6e\x64\x73\x20\x28\x73\x65\x65\x20\x74\x68\x65\x20\x60\x65\x6e\x63\x27\x20\x63\x6f\x6d\x6d\x61\x6e\x64\x20\x66\x6f\x72\x20\x6d\x6f\x72\x65\x20\x64\x65\x74\x61\x69\x6c\x73\x29\xa");
                }
            }
#ifdef OPENSSL_NO_CAMELLIA
            BIO_printf(bio_err, "\x25\x2d\x31\x35\x73", fp->name);
#else
            BIO_printf(bio_err, "\x25\x2d\x31\x38\x73", fp->name);
#endif
        }
        BIO_printf(bio_err, "\xa\xa");
        ret = 0;
    }
 end:
    return (ret);
}

static int SortFnByName(const void *_f1, const void *_f2)
{
    const FUNCTION *f1 = _f1;
    const FUNCTION *f2 = _f2;

    if (f1->type != f2->type)
        return f1->type - f2->type;
    return strcmp(f1->name, f2->name);
}

static void list_pkey(BIO *out)
{
    int i;
    for (i = 0; i < EVP_PKEY_asn1_get_count(); i++) {
        const EVP_PKEY_ASN1_METHOD *ameth;
        int pkey_id, pkey_base_id, pkey_flags;
        const char *pinfo, *pem_str;
        ameth = EVP_PKEY_asn1_get0(i);
        EVP_PKEY_asn1_get0_info(&pkey_id, &pkey_base_id, &pkey_flags,
                                &pinfo, &pem_str, ameth);
        if (pkey_flags & ASN1_PKEY_ALIAS) {
            BIO_printf(out, "\x4e\x61\x6d\x65\x3a\x20\x25\x73\xa", OBJ_nid2ln(pkey_id));
            BIO_printf(out, "\x9\x54\x79\x70\x65\x3a\x20\x41\x6c\x69\x61\x73\x20\x74\x6f\x20\x25\x73\xa",
                       OBJ_nid2ln(pkey_base_id));
        } else {
            BIO_printf(out, "\x4e\x61\x6d\x65\x3a\x20\x25\x73\xa", pinfo);
            BIO_printf(out, "\x9\x54\x79\x70\x65\x3a\x20\x25\x73\x20\x41\x6c\x67\x6f\x72\x69\x74\x68\x6d\xa",
                       pkey_flags & ASN1_PKEY_DYNAMIC ?
                       "\x45\x78\x74\x65\x72\x6e\x61\x6c" : "\x42\x75\x69\x6c\x74\x69\x6e");
            BIO_printf(out, "\x9\x4f\x49\x44\x3a\x20\x25\x73\xa", OBJ_nid2ln(pkey_id));
            if (pem_str == NULL)
                pem_str = "\x28\x6e\x6f\x6e\x65\x29";
            BIO_printf(out, "\x9\x50\x45\x4d\x20\x73\x74\x72\x69\x6e\x67\x3a\x20\x25\x73\xa", pem_str);
        }

    }
}

static void list_cipher_fn(const EVP_CIPHER *c,
                           const char *from, const char *to, void *arg)
{
    if (c)
        BIO_printf(arg, "\x25\x73\xa", EVP_CIPHER_name(c));
    else {
        if (!from)
            from = "\x3c\x75\x6e\x64\x65\x66\x69\x6e\x65\x64\x3e";
        if (!to)
            to = "\x3c\x75\x6e\x64\x65\x66\x69\x6e\x65\x64\x3e";
        BIO_printf(arg, "\x25\x73\x20\x3d\x3e\x20\x25\x73\xa", from, to);
    }
}

static void list_cipher(BIO *out)
{
    EVP_CIPHER_do_all_sorted(list_cipher_fn, out);
}

static void list_md_fn(const EVP_MD *m,
                       const char *from, const char *to, void *arg)
{
    if (m)
        BIO_printf(arg, "\x25\x73\xa", EVP_MD_name(m));
    else {
        if (!from)
            from = "\x3c\x75\x6e\x64\x65\x66\x69\x6e\x65\x64\x3e";
        if (!to)
            to = "\x3c\x75\x6e\x64\x65\x66\x69\x6e\x65\x64\x3e";
        BIO_printf(arg, "\x25\x73\x20\x3d\x3e\x20\x25\x73\xa", from, to);
    }
}

static void list_md(BIO *out)
{
    EVP_MD_do_all_sorted(list_md_fn, out);
}

static int MS_CALLBACK function_cmp(const FUNCTION * a, const FUNCTION * b)
{
    return strncmp(a->name, b->name, 8);
}

static IMPLEMENT_LHASH_COMP_FN(function, FUNCTION)

static unsigned long MS_CALLBACK function_hash(const FUNCTION * a)
{
    return lh_strhash(a->name);
}

static IMPLEMENT_LHASH_HASH_FN(function, FUNCTION)

static LHASH_OF(FUNCTION) *prog_init(void)
{
    LHASH_OF(FUNCTION) *ret;
    FUNCTION *f;
    size_t i;

    /* Purely so it looks nice when the user hits ? */
    for (i = 0, f = functions; f->name != NULL; ++f, ++i) ;
    qsort(functions, i, sizeof(*functions), SortFnByName);

    if ((ret = lh_FUNCTION_new()) == NULL)
        return (NULL);

    for (f = functions; f->name != NULL; f++)
        (void)lh_FUNCTION_insert(ret, f);
    return (ret);
}

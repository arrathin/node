/* apps/srp.c */
/*
 * Written by Peter Sylvester (peter.sylvester@edelweb.fr) for the EdelKey
 * project and contributed to the OpenSSL project 2004.
 */
/* ====================================================================
 * Copyright (c) 2004 The OpenSSL Project.  All rights reserved.
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
#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_SRP
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <openssl/conf.h>
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/txt_db.h>
# include <openssl/buffer.h>
# include <openssl/srp.h>

# include "apps.h"

# undef PROG
# define PROG srp_main

# define BASE_SECTION    "\x73\x72\x70"
# define CONFIG_FILE "\x6f\x70\x65\x6e\x73\x73\x6c\x2e\x63\x6e\x66"

# define ENV_RANDFILE            "\x52\x41\x4e\x44\x46\x49\x4c\x45"

# define ENV_DATABASE            "\x73\x72\x70\x76\x66\x69\x6c\x65"
# define ENV_DEFAULT_SRP         "\x64\x65\x66\x61\x75\x6c\x74\x5f\x73\x72\x70"

static char *srp_usage[] = {
    "\x75\x73\x61\x67\x65\x3a\x20\x73\x72\x70\x20\x5b\x61\x72\x67\x73\x5d\x20\x5b\x75\x73\x65\x72\x5d\x20\xa",
    "\xa",
    "\x20\x2d\x76\x65\x72\x62\x6f\x73\x65\x20\x20\x20\x20\x20\x20\x20\x20\x54\x61\x6c\x6b\x20\x61\x6c\x6f\x74\x20\x77\x68\x69\x6c\x65\x20\x64\x6f\x69\x6e\x67\x20\x74\x68\x69\x6e\x67\x73\xa",
    "\x20\x2d\x63\x6f\x6e\x66\x69\x67\x20\x66\x69\x6c\x65\x20\x20\x20\x20\x41\x20\x63\x6f\x6e\x66\x69\x67\x20\x66\x69\x6c\x65\xa",
    "\x20\x2d\x6e\x61\x6d\x65\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x54\x68\x65\x20\x70\x61\x72\x74\x69\x63\x75\x6c\x61\x72\x20\x73\x72\x70\x20\x64\x65\x66\x69\x6e\x69\x74\x69\x6f\x6e\x20\x74\x6f\x20\x75\x73\x65\xa",
    "\x20\x2d\x73\x72\x70\x76\x66\x69\x6c\x65\x20\x61\x72\x67\x20\x20\x20\x54\x68\x65\x20\x73\x72\x70\x20\x76\x65\x72\x69\x66\x69\x65\x72\x20\x66\x69\x6c\x65\x20\x6e\x61\x6d\x65\xa",
    "\x20\x2d\x61\x64\x64\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x61\x64\x64\x20\x61\x6e\x20\x75\x73\x65\x72\x20\x61\x6e\x64\x20\x73\x72\x70\x20\x76\x65\x72\x69\x66\x69\x65\x72\xa",
    "\x20\x2d\x6d\x6f\x64\x69\x66\x79\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6d\x6f\x64\x69\x66\x79\x20\x74\x68\x65\x20\x73\x72\x70\x20\x76\x65\x72\x69\x66\x69\x65\x72\x20\x6f\x66\x20\x61\x6e\x20\x65\x78\x69\x73\x74\x69\x6e\x67\x20\x75\x73\x65\x72\xa",
    "\x20\x2d\x64\x65\x6c\x65\x74\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x64\x65\x6c\x65\x74\x65\x20\x75\x73\x65\x72\x20\x66\x72\x6f\x6d\x20\x76\x65\x72\x69\x66\x69\x65\x72\x20\x66\x69\x6c\x65\xa",
    "\x20\x2d\x6c\x69\x73\x74\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6c\x69\x73\x74\x20\x75\x73\x65\x72\xa",
    "\x20\x2d\x67\x6e\x20\x61\x72\x67\x20\x20\x20\x20\x20\x20\x20\x20\x20\x67\x20\x61\x6e\x64\x20\x4e\x20\x76\x61\x6c\x75\x65\x73\x20\x74\x6f\x20\x62\x65\x20\x75\x73\x65\x64\x20\x66\x6f\x72\x20\x6e\x65\x77\x20\x76\x65\x72\x69\x66\x69\x65\x72\xa",
    "\x20\x2d\x75\x73\x65\x72\x69\x6e\x66\x6f\x20\x61\x72\x67\x20\x20\x20\x61\x64\x64\x69\x74\x69\x6f\x6e\x61\x6c\x20\x69\x6e\x66\x6f\x20\x74\x6f\x20\x62\x65\x20\x73\x65\x74\x20\x66\x6f\x72\x20\x75\x73\x65\x72\xa",
    "\x20\x2d\x70\x61\x73\x73\x69\x6e\x20\x61\x72\x67\x20\x20\x20\x20\x20\x69\x6e\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x70\x61\x73\x73\x20\x70\x68\x72\x61\x73\x65\x20\x73\x6f\x75\x72\x63\x65\xa",
    "\x20\x2d\x70\x61\x73\x73\x6f\x75\x74\x20\x61\x72\x67\x20\x20\x20\x20\x6f\x75\x74\x70\x75\x74\x20\x66\x69\x6c\x65\x20\x70\x61\x73\x73\x20\x70\x68\x72\x61\x73\x65\x20\x73\x6f\x75\x72\x63\x65\xa",
# ifndef OPENSSL_NO_ENGINE
    "\x20\x2d\x65\x6e\x67\x69\x6e\x65\x20\x65\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2d\x20\x75\x73\x65\x20\x65\x6e\x67\x69\x6e\x65\x20\x65\x2c\x20\x70\x6f\x73\x73\x69\x62\x6c\x79\x20\x61\x20\x68\x61\x72\x64\x77\x61\x72\x65\x20\x64\x65\x76\x69\x63\x65\x2e\xa",
# endif
    NULL
};

# ifdef EFENCE
extern int EF_PROTECT_FREE;
extern int EF_PROTECT_BELOW;
extern int EF_ALIGNMENT;
# endif

static CONF *conf = NULL;
static char *section = NULL;

# define VERBOSE if (verbose)
# define VVERBOSE if (verbose>1)

int MAIN(int, char **);

static int get_index(CA_DB *db, char *id, char type)
{
    char **pp;
    int i;
    if (id == NULL)
        return -1;
    if (type == DB_SRP_INDEX) {
        for (i = 0; i < sk_OPENSSL_PSTRING_num(db->db->data); i++) {
            pp = sk_OPENSSL_PSTRING_value(db->db->data, i);
            if (pp[DB_srptype][0] == DB_SRP_INDEX
                && !strcmp(id, pp[DB_srpid]))
                return i;
        }
    } else {
        for (i = 0; i < sk_OPENSSL_PSTRING_num(db->db->data); i++) {
            pp = sk_OPENSSL_PSTRING_value(db->db->data, i);

            if (pp[DB_srptype][0] != DB_SRP_INDEX
                && !strcmp(id, pp[DB_srpid]))
                return i;
        }
    }

    return -1;
}

static void print_entry(CA_DB *db, BIO *bio, int indx, int verbose, char *s)
{
    if (indx >= 0 && verbose) {
        int j;
        char **pp = sk_OPENSSL_PSTRING_value(db->db->data, indx);
        BIO_printf(bio, "\x25\x73\x20\x22\x25\x73\x22\xa", s, pp[DB_srpid]);
        for (j = 0; j < DB_NUMBER; j++) {
            BIO_printf(bio_err, "\x20\x20\x25\x64\x20\x3d\x20\x22\x25\x73\x22\xa", j, pp[j]);
        }
    }
}

static void print_index(CA_DB *db, BIO *bio, int indexindex, int verbose)
{
    print_entry(db, bio, indexindex, verbose, "\x67\x20\x4e\x20\x65\x6e\x74\x72\x79");
}

static void print_user(CA_DB *db, BIO *bio, int userindex, int verbose)
{
    if (verbose > 0) {
        char **pp = sk_OPENSSL_PSTRING_value(db->db->data, userindex);

        if (pp[DB_srptype][0] != '\x49') {
            print_entry(db, bio, userindex, verbose, "\x55\x73\x65\x72\x20\x65\x6e\x74\x72\x79");
            print_entry(db, bio, get_index(db, pp[DB_srpgN], '\x49'), verbose,
                        "\x67\x20\x4e\x20\x65\x6e\x74\x72\x79");
        }

    }
}

static int update_index(CA_DB *db, BIO *bio, char **row)
{
    char **irow;
    int i;

    irow = (char **)OPENSSL_malloc(sizeof(char *) * (DB_NUMBER + 1));
    if (irow == NULL) {
        BIO_printf(bio_err, "\x4d\x65\x6d\x6f\x72\x79\x20\x61\x6c\x6c\x6f\x63\x61\x74\x69\x6f\x6e\x20\x66\x61\x69\x6c\x75\x72\x65\xa");
        return 0;
    }

    for (i = 0; i < DB_NUMBER; i++)
        irow[i] = row[i];
    irow[DB_NUMBER] = NULL;

    if (!TXT_DB_insert(db->db, irow)) {
        BIO_printf(bio, "\x66\x61\x69\x6c\x65\x64\x20\x74\x6f\x20\x75\x70\x64\x61\x74\x65\x20\x73\x72\x70\x76\x66\x69\x6c\x65\xa");
        BIO_printf(bio, "\x54\x58\x54\x5f\x44\x42\x20\x65\x72\x72\x6f\x72\x20\x6e\x75\x6d\x62\x65\x72\x20\x25\x6c\x64\xa", db->db->error);
        OPENSSL_free(irow);
        return 0;
    }
    return 1;
}

static void lookup_fail(const char *name, char *tag)
{
    BIO_printf(bio_err, "\x76\x61\x72\x69\x61\x62\x6c\x65\x20\x6c\x6f\x6f\x6b\x75\x70\x20\x66\x61\x69\x6c\x65\x64\x20\x66\x6f\x72\x20\x25\x73\x3a\x3a\x25\x73\xa", name, tag);
}

static char *srp_verify_user(const char *user, const char *srp_verifier,
                             char *srp_usersalt, const char *g, const char *N,
                             const char *passin, BIO *bio, int verbose)
{
    char password[1025];
    PW_CB_DATA cb_tmp;
    char *verifier = NULL;
    char *gNid = NULL;
    int len;

    cb_tmp.prompt_info = user;
    cb_tmp.password = passin;

    len = password_callback(password, sizeof(password)-1, 0, &cb_tmp);
    if (len > 0) {
        password[len] = 0;
        VERBOSE BIO_printf(bio,
                           "\x56\x61\x6c\x69\x64\x61\x74\x69\x6e\x67\xa\x20\x20\x20\x75\x73\x65\x72\x3d\x22\x25\x73\x22\xa\x20\x73\x72\x70\x5f\x76\x65\x72\x69\x66\x69\x65\x72\x3d\x22\x25\x73\x22\xa\x20\x73\x72\x70\x5f\x75\x73\x65\x72\x73\x61\x6c\x74\x3d\x22\x25\x73\x22\xa\x20\x67\x3d\x22\x25\x73\x22\xa\x20\x4e\x3d\x22\x25\x73\x22\xa",
                           user, srp_verifier, srp_usersalt, g, N);
        VVERBOSE BIO_printf(bio, "\x50\x61\x73\x73\x20\x25\x73\x0a", password);

        if (!(gNid = SRP_create_verifier(user, password, &srp_usersalt,
                                         &verifier, N, g))) {
            BIO_printf(bio, "\x49\x6e\x74\x65\x72\x6e\x61\x6c\x20\x65\x72\x72\x6f\x72\x20\x76\x61\x6c\x69\x64\x61\x74\x69\x6e\x67\x20\x53\x52\x50\x20\x76\x65\x72\x69\x66\x69\x65\x72\xa");
        } else {
            if (strcmp(verifier, srp_verifier))
                gNid = NULL;
            OPENSSL_free(verifier);
        }
        OPENSSL_cleanse(password, len);
    }
    return gNid;
}

static char *srp_create_user(char *user, char **srp_verifier,
                             char **srp_usersalt, char *g, char *N,
                             char *passout, BIO *bio, int verbose)
{
    char password[1025];
    PW_CB_DATA cb_tmp;
    char *gNid = NULL;
    char *salt = NULL;
    int len;
    cb_tmp.prompt_info = user;
    cb_tmp.password = passout;

    len = password_callback(password, sizeof(password)-1, 1, &cb_tmp);
    if (len > 0) {
        password[len] = 0;
        VERBOSE BIO_printf(bio,
                           "\x43\x72\x65\x61\x74\x69\x6e\x67\xa\x20\x75\x73\x65\x72\x3d\x22\x25\x73\x22\xa\x20\x67\x3d\x22\x25\x73\x22\xa\x20\x4e\x3d\x22\x25\x73\x22\xa",
                           user, g, N);
        if (!(gNid = SRP_create_verifier(user, password, &salt,
                                         srp_verifier, N, g))) {
            BIO_printf(bio, "\x49\x6e\x74\x65\x72\x6e\x61\x6c\x20\x65\x72\x72\x6f\x72\x20\x63\x72\x65\x61\x74\x69\x6e\x67\x20\x53\x52\x50\x20\x76\x65\x72\x69\x66\x69\x65\x72\xa");
        } else {
            *srp_usersalt = salt;
        }
        OPENSSL_cleanse(password, len);
        VVERBOSE BIO_printf(bio, "\x67\x4e\x69\x64\x3d\x25\x73\x20\x73\x61\x6c\x74\x20\x3d\x22\x25\x73\x22\xa\x20\x76\x65\x72\x69\x66\x69\x65\x72\x20\x3d\x22\x25\x73\x22\xa",
                            gNid, salt, *srp_verifier);

    }
    return gNid;
}

int MAIN(int argc, char **argv)
{
    int add_user = 0;
    int list_user = 0;
    int delete_user = 0;
    int modify_user = 0;
    char *user = NULL;

    char *passargin = NULL, *passargout = NULL;
    char *passin = NULL, *passout = NULL;
    char *gN = NULL;
    int gNindex = -1;
    char **gNrow = NULL;
    int maxgN = -1;

    char *userinfo = NULL;

    int badops = 0;
    int ret = 1;
    int errors = 0;
    int verbose = 0;
    int doupdatedb = 0;
    char *configfile = NULL;
    char *dbfile = NULL;
    CA_DB *db = NULL;
    char **pp;
    int i;
    long errorline = -1;
    char *randfile = NULL;
    ENGINE *e = NULL;
    char *engine = NULL;
    char *tofree = NULL;
    DB_ATTR db_attr;

# ifdef EFENCE
    EF_PROTECT_FREE = 1;
    EF_PROTECT_BELOW = 1;
    EF_ALIGNMENT = 0;
# endif

    apps_startup();

    conf = NULL;
    section = NULL;

    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    argc--;
    argv++;
    while (argc >= 1 && badops == 0) {
        if (strcmp(*argv, "\x2d\x76\x65\x72\x62\x6f\x73\x65") == 0) {
            verbose++;
        } else if (strcmp(*argv, "\x2d\x63\x6f\x6e\x66\x69\x67") == 0) {
            if (--argc < 1)
                goto bad;
            configfile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x6e\x61\x6d\x65") == 0) {
            if (--argc < 1)
                goto bad;
            section = *(++argv);
        } else if (strcmp(*argv, "\x2d\x73\x72\x70\x76\x66\x69\x6c\x65") == 0) {
            if (--argc < 1)
                goto bad;
            dbfile = *(++argv);
        } else if (strcmp(*argv, "\x2d\x61\x64\x64") == 0) {
            add_user = 1;
        } else if (strcmp(*argv, "\x2d\x64\x65\x6c\x65\x74\x65") == 0) {
            delete_user = 1;
        } else if (strcmp(*argv, "\x2d\x6d\x6f\x64\x69\x66\x79") == 0) {
            modify_user = 1;
        } else if (strcmp(*argv, "\x2d\x6c\x69\x73\x74") == 0) {
            list_user = 1;
        } else if (strcmp(*argv, "\x2d\x67\x6e") == 0) {
            if (--argc < 1)
                goto bad;
            gN = *(++argv);
        } else if (strcmp(*argv, "\x2d\x75\x73\x65\x72\x69\x6e\x66\x6f") == 0) {
            if (--argc < 1)
                goto bad;
            userinfo = *(++argv);
        } else if (strcmp(*argv, "\x2d\x70\x61\x73\x73\x69\x6e") == 0) {
            if (--argc < 1)
                goto bad;
            passargin = *(++argv);
        } else if (strcmp(*argv, "\x2d\x70\x61\x73\x73\x6f\x75\x74") == 0) {
            if (--argc < 1)
                goto bad;
            passargout = *(++argv);
        }
# ifndef OPENSSL_NO_ENGINE
        else if (strcmp(*argv, "\x2d\x65\x6e\x67\x69\x6e\x65") == 0) {
            if (--argc < 1)
                goto bad;
            engine = *(++argv);
        }
# endif

        else if (**argv == '\x2d') {
 bad:
            BIO_printf(bio_err, "\x75\x6e\x6b\x6e\x6f\x77\x6e\x20\x6f\x70\x74\x69\x6f\x6e\x20\x25\x73\xa", *argv);
            badops = 1;
            break;
        } else {
            break;
        }

        argc--;
        argv++;
    }

    if (dbfile && configfile) {
        BIO_printf(bio_err,
                   "\x2d\x64\x62\x66\x69\x6c\x65\x20\x61\x6e\x64\x20\x2d\x63\x6f\x6e\x66\x69\x67\x66\x69\x6c\x65\x20\x63\x61\x6e\x6e\x6f\x74\x20\x62\x65\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x20\x74\x6f\x67\x65\x74\x68\x65\x72\x2e\xa");
        badops = 1;
    }
    if (add_user + delete_user + modify_user + list_user != 1) {
        BIO_printf(bio_err,
                   "\x45\x78\x61\x63\x74\x6c\x79\x20\x6f\x6e\x65\x20\x6f\x66\x20\x74\x68\x65\x20\x6f\x70\x74\x69\x6f\x6e\x73\x20\x2d\x61\x64\x64\x2c\x20\x2d\x64\x65\x6c\x65\x74\x65\x2c\x20\x2d\x6d\x6f\x64\x69\x66\x79\x20\x2d\x6c\x69\x73\x74\x20\x6d\x75\x73\x74\x20\x62\x65\x20\x73\x70\x65\x63\x69\x66\x69\x65\x64\x2e\xa");
        badops = 1;
    }
    if (delete_user + modify_user + delete_user == 1 && argc <= 0) {
        BIO_printf(bio_err,
                   "\x4e\x65\x65\x64\x20\x61\x74\x20\x6c\x65\x61\x73\x74\x20\x6f\x6e\x65\x20\x75\x73\x65\x72\x20\x66\x6f\x72\x20\x6f\x70\x74\x69\x6f\x6e\x73\x20\x2d\x61\x64\x64\x2c\x20\x2d\x64\x65\x6c\x65\x74\x65\x2c\x20\x2d\x6d\x6f\x64\x69\x66\x79\x2e\x20\xa");
        badops = 1;
    }
    if ((passargin || passargout) && argc != 1) {
        BIO_printf(bio_err,
                   "\x2d\x70\x61\x73\x73\x69\x6e\x2c\x20\x2d\x70\x61\x73\x73\x6f\x75\x74\x20\x61\x72\x67\x75\x6d\x65\x6e\x74\x73\x20\x6f\x6e\x6c\x79\x20\x76\x61\x6c\x69\x64\x20\x77\x69\x74\x68\x20\x6f\x6e\x65\x20\x75\x73\x65\x72\x2e\xa");
        badops = 1;
    }

    if (badops) {
        for (pp = srp_usage; (*pp != NULL); pp++)
            BIO_printf(bio_err, "\x25\x73", *pp);

        BIO_printf(bio_err, "\x20\x2d\x72\x61\x6e\x64\x20\x66\x69\x6c\x65\x25\x63\x66\x69\x6c\x65\x25\x63\x2e\x2e\x2e\xa", LIST_SEPARATOR_CHAR,
                   LIST_SEPARATOR_CHAR);
        BIO_printf(bio_err,
                   "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6c\x6f\x61\x64\x20\x74\x68\x65\x20\x66\x69\x6c\x65\x20\x28\x6f\x72\x20\x74\x68\x65\x20\x66\x69\x6c\x65\x73\x20\x69\x6e\x20\x74\x68\x65\x20\x64\x69\x72\x65\x63\x74\x6f\x72\x79\x29\x20\x69\x6e\x74\x6f\xa");
        BIO_printf(bio_err, "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x74\x68\x65\x20\x72\x61\x6e\x64\x6f\x6d\x20\x6e\x75\x6d\x62\x65\x72\x20\x67\x65\x6e\x65\x72\x61\x74\x6f\x72\xa");
        goto err;
    }

    ERR_load_crypto_strings();

    e = setup_engine(bio_err, engine, 0);

    if (!app_passwd(bio_err, passargin, passargout, &passin, &passout)) {
        BIO_printf(bio_err, "\x45\x72\x72\x6f\x72\x20\x67\x65\x74\x74\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x73\xa");
        goto err;
    }

    if (!dbfile) {

        /*****************************************************************/
        tofree = NULL;
        if (configfile == NULL)
            configfile = getenv("\x4f\x50\x45\x4e\x53\x53\x4c\x5f\x43\x4f\x4e\x46");
        if (configfile == NULL)
            configfile = getenv("\x53\x53\x4c\x45\x41\x59\x5f\x43\x4f\x4e\x46");
        if (configfile == NULL) {
            const char *s = X509_get_default_cert_area();
            size_t len;

# ifdef OPENSSL_SYS_VMS
            len = strlen(s) + sizeof(CONFIG_FILE);
            tofree = OPENSSL_malloc(len);
            if (!tofree) {
                BIO_printf(bio_err, "\x4f\x75\x74\x20\x6f\x66\x20\x6d\x65\x6d\x6f\x72\x79\xa");
                goto err;
            }
            strcpy(tofree, s);
# else
            len = strlen(s) + sizeof(CONFIG_FILE) + 1;
            tofree = OPENSSL_malloc(len);
            if (!tofree) {
                BIO_printf(bio_err, "\x4f\x75\x74\x20\x6f\x66\x20\x6d\x65\x6d\x6f\x72\x79\xa");
                goto err;
            }
            BUF_strlcpy(tofree, s, len);
            BUF_strlcat(tofree, "\x2f", len);
# endif
            BUF_strlcat(tofree, CONFIG_FILE, len);
            configfile = tofree;
        }

        VERBOSE BIO_printf(bio_err, "\x55\x73\x69\x6e\x67\x20\x63\x6f\x6e\x66\x69\x67\x75\x72\x61\x74\x69\x6f\x6e\x20\x66\x72\x6f\x6d\x20\x25\x73\xa",
                           configfile);
        conf = NCONF_new(NULL);
        if (NCONF_load(conf, configfile, &errorline) <= 0) {
            if (errorline <= 0)
                BIO_printf(bio_err, "\x65\x72\x72\x6f\x72\x20\x6c\x6f\x61\x64\x69\x6e\x67\x20\x74\x68\x65\x20\x63\x6f\x6e\x66\x69\x67\x20\x66\x69\x6c\x65\x20\x27\x25\x73\x27\xa",
                           configfile);
            else
                BIO_printf(bio_err, "\x65\x72\x72\x6f\x72\x20\x6f\x6e\x20\x6c\x69\x6e\x65\x20\x25\x6c\x64\x20\x6f\x66\x20\x63\x6f\x6e\x66\x69\x67\x20\x66\x69\x6c\x65\x20\x27\x25\x73\x27\xa",
                           errorline, configfile);
            goto err;
        }
        if (tofree) {
            OPENSSL_free(tofree);
            tofree = NULL;
        }

        if (!load_config(bio_err, conf))
            goto err;

        /* Lets get the config section we are using */
        if (section == NULL) {
            VERBOSE BIO_printf(bio_err,
                               "\x74\x72\x79\x69\x6e\x67\x20\x74\x6f\x20\x72\x65\x61\x64\x20" ENV_DEFAULT_SRP
                               "\x20\x69\x6e\x20\x22\x20\x42\x41\x53\x45\x5f\x53\x45\x43\x54\x49\x4f\x4e\x20\x22\xa");

            section = NCONF_get_string(conf, BASE_SECTION, ENV_DEFAULT_SRP);
            if (section == NULL) {
                lookup_fail(BASE_SECTION, ENV_DEFAULT_SRP);
                goto err;
            }
        }

        if (randfile == NULL && conf)
            randfile = NCONF_get_string(conf, BASE_SECTION, "\x52\x41\x4e\x44\x46\x49\x4c\x45");

        VERBOSE BIO_printf(bio_err,
                           "\x74\x72\x79\x69\x6e\x67\x20\x74\x6f\x20\x72\x65\x61\x64\x20" ENV_DATABASE
                           "\x20\x69\x6e\x20\x73\x65\x63\x74\x69\x6f\x6e\x20\x22\x25\x73\x22\xa", section);

        if ((dbfile = NCONF_get_string(conf, section, ENV_DATABASE)) == NULL) {
            lookup_fail(section, ENV_DATABASE);
            goto err;
        }

    }
    if (randfile == NULL)
        ERR_clear_error();
    else
        app_RAND_load_file(randfile, bio_err, 0);

    VERBOSE BIO_printf(bio_err, "\x54\x72\x79\x69\x6e\x67\x20\x74\x6f\x20\x72\x65\x61\x64\x20\x53\x52\x50\x20\x76\x65\x72\x69\x66\x69\x65\x72\x20\x66\x69\x6c\x65\x20\x22\x25\x73\x22\xa",
                       dbfile);

    db = load_index(dbfile, &db_attr);
    if (db == NULL)
        goto err;

    /* Lets check some fields */
    for (i = 0; i < sk_OPENSSL_PSTRING_num(db->db->data); i++) {
        pp = sk_OPENSSL_PSTRING_value(db->db->data, i);

        if (pp[DB_srptype][0] == DB_SRP_INDEX) {
            maxgN = i;
            if (gNindex < 0 && gN != NULL && !strcmp(gN, pp[DB_srpid]))
                gNindex = i;

            print_index(db, bio_err, i, verbose > 1);
        }
    }

    VERBOSE BIO_printf(bio_err, "\x44\x61\x74\x61\x62\x61\x73\x65\x20\x69\x6e\x69\x74\x69\x61\x6c\x69\x73\x65\x64\xa");

    if (gNindex >= 0) {
        gNrow = sk_OPENSSL_PSTRING_value(db->db->data, gNindex);
        print_entry(db, bio_err, gNindex, verbose > 1, "\x44\x65\x66\x61\x75\x6c\x74\x20\x67\x20\x61\x6e\x64\x20\x4e");
    } else if (maxgN > 0 && !SRP_get_default_gN(gN)) {
        BIO_printf(bio_err, "\x4e\x6f\x20\x67\x20\x61\x6e\x64\x20\x4e\x20\x76\x61\x6c\x75\x65\x20\x66\x6f\x72\x20\x69\x6e\x64\x65\x78\x20\x22\x25\x73\x22\xa", gN);
        goto err;
    } else {
        VERBOSE BIO_printf(bio_err, "\x44\x61\x74\x61\x62\x61\x73\x65\x20\x68\x61\x73\x20\x6e\x6f\x20\x67\x20\x4e\x20\x69\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e\x2e\xa");
        gNrow = NULL;
    }

    VVERBOSE BIO_printf(bio_err, "\x53\x74\x61\x72\x74\x69\x6e\x67\x20\x75\x73\x65\x72\x20\x70\x72\x6f\x63\x65\x73\x73\x69\x6e\x67\xa");

    if (argc > 0)
        user = *(argv++);

    while (list_user || user) {
        int userindex = -1;
        if (user)
            VVERBOSE BIO_printf(bio_err, "\x50\x72\x6f\x63\x65\x73\x73\x69\x6e\x67\x20\x75\x73\x65\x72\x20\x22\x25\x73\x22\xa", user);
        if ((userindex = get_index(db, user, '\x55')) >= 0) {
            print_user(db, bio_err, userindex, (verbose > 0) || list_user);
        }

        if (list_user) {
            if (user == NULL) {
                BIO_printf(bio_err, "\x4c\x69\x73\x74\x20\x61\x6c\x6c\x20\x75\x73\x65\x72\x73\xa");

                for (i = 0; i < sk_OPENSSL_PSTRING_num(db->db->data); i++) {
                    print_user(db, bio_err, i, 1);
                }
                list_user = 0;
            } else if (userindex < 0) {
                BIO_printf(bio_err,
                           "\x75\x73\x65\x72\x20\x22\x25\x73\x22\x20\x64\x6f\x65\x73\x20\x6e\x6f\x74\x20\x65\x78\x69\x73\x74\x2c\x20\x69\x67\x6e\x6f\x72\x65\x64\x2e\x20\x74\xa", user);
                errors++;
            }
        } else if (add_user) {
            if (userindex >= 0) {
                /* reactivation of a new user */
                char **row =
                    sk_OPENSSL_PSTRING_value(db->db->data, userindex);
                BIO_printf(bio_err, "\x75\x73\x65\x72\x20\x22\x25\x73\x22\x20\x72\x65\x61\x63\x74\x69\x76\x61\x74\x65\x64\x2e\xa", user);
                row[DB_srptype][0] = '\x56';

                doupdatedb = 1;
            } else {
                char *row[DB_NUMBER];
                char *gNid;
                row[DB_srpverifier] = NULL;
                row[DB_srpsalt] = NULL;
                row[DB_srpinfo] = NULL;
                if (!
                    (gNid =
                     srp_create_user(user, &(row[DB_srpverifier]),
                                     &(row[DB_srpsalt]),
                                     gNrow ? gNrow[DB_srpsalt] : gN,
                                     gNrow ? gNrow[DB_srpverifier] : NULL,
                                     passout, bio_err, verbose))) {
                    BIO_printf(bio_err,
                               "\x43\x61\x6e\x6e\x6f\x74\x20\x63\x72\x65\x61\x74\x65\x20\x73\x72\x70\x20\x76\x65\x72\x69\x66\x69\x65\x72\x20\x66\x6f\x72\x20\x75\x73\x65\x72\x20\x22\x25\x73\x22\x2c\x20\x6f\x70\x65\x72\x61\x74\x69\x6f\x6e\x20\x61\x62\x61\x6e\x64\x6f\x6e\x65\x64\x20\x2e\xa",
                               user);
                    errors++;
                    goto err;
                }
                row[DB_srpid] = BUF_strdup(user);
                row[DB_srptype] = BUF_strdup("\x76");
                row[DB_srpgN] = BUF_strdup(gNid);

                if (!row[DB_srpid] || !row[DB_srpgN] || !row[DB_srptype]
                    || !row[DB_srpverifier] || !row[DB_srpsalt] || (userinfo
                                                                    &&
                                                                    (!(row
                                                                       [DB_srpinfo]
                                                                       =
                                                                       BUF_strdup
                                                                       (userinfo))))
                    || !update_index(db, bio_err, row)) {
                    if (row[DB_srpid])
                        OPENSSL_free(row[DB_srpid]);
                    if (row[DB_srpgN])
                        OPENSSL_free(row[DB_srpgN]);
                    if (row[DB_srpinfo])
                        OPENSSL_free(row[DB_srpinfo]);
                    if (row[DB_srptype])
                        OPENSSL_free(row[DB_srptype]);
                    if (row[DB_srpverifier])
                        OPENSSL_free(row[DB_srpverifier]);
                    if (row[DB_srpsalt])
                        OPENSSL_free(row[DB_srpsalt]);
                    goto err;
                }
                doupdatedb = 1;
            }
        } else if (modify_user) {
            if (userindex < 0) {
                BIO_printf(bio_err,
                           "\x75\x73\x65\x72\x20\x22\x25\x73\x22\x20\x64\x6f\x65\x73\x20\x6e\x6f\x74\x20\x65\x78\x69\x73\x74\x2c\x20\x6f\x70\x65\x72\x61\x74\x69\x6f\x6e\x20\x69\x67\x6e\x6f\x72\x65\x64\x2e\xa",
                           user);
                errors++;
            } else {

                char **row =
                    sk_OPENSSL_PSTRING_value(db->db->data, userindex);
                char type = row[DB_srptype][0];
                if (type == '\x76') {
                    BIO_printf(bio_err,
                               "\x75\x73\x65\x72\x20\x22\x25\x73\x22\x20\x61\x6c\x72\x65\x61\x64\x79\x20\x75\x70\x64\x61\x74\x65\x64\x2c\x20\x6f\x70\x65\x72\x61\x74\x69\x6f\x6e\x20\x69\x67\x6e\x6f\x72\x65\x64\x2e\xa",
                               user);
                    errors++;
                } else {
                    char *gNid;

                    if (row[DB_srptype][0] == '\x56') {
                        int user_gN;
                        char **irow = NULL;
                        VERBOSE BIO_printf(bio_err,
                                           "\x56\x65\x72\x69\x66\x79\x69\x6e\x67\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x20\x66\x6f\x72\x20\x75\x73\x65\x72\x20\x22\x25\x73\x22\xa",
                                           user);
                        if ((user_gN =
                             get_index(db, row[DB_srpgN], DB_SRP_INDEX)) >= 0)
                            irow =
                                (char **)sk_OPENSSL_PSTRING_value(db->
                                                                  db->data,
                                                                  userindex);

                        if (!srp_verify_user
                            (user, row[DB_srpverifier], row[DB_srpsalt],
                             irow ? irow[DB_srpsalt] : row[DB_srpgN],
                             irow ? irow[DB_srpverifier] : NULL, passin,
                             bio_err, verbose)) {
                            BIO_printf(bio_err,
                                       "\x49\x6e\x76\x61\x6c\x69\x64\x20\x70\x61\x73\x73\x77\x6f\x72\x64\x20\x66\x6f\x72\x20\x75\x73\x65\x72\x20\x22\x25\x73\x22\x2c\x20\x6f\x70\x65\x72\x61\x74\x69\x6f\x6e\x20\x61\x62\x61\x6e\x64\x6f\x6e\x65\x64\x2e\xa",
                                       user);
                            errors++;
                            goto err;
                        }
                    }
                    VERBOSE BIO_printf(bio_err,
                                       "\x50\x61\x73\x73\x77\x6f\x72\x64\x20\x66\x6f\x72\x20\x75\x73\x65\x72\x20\x22\x25\x73\x22\x20\x6f\x6b\x2e\xa",
                                       user);

                    if (!
                        (gNid =
                         srp_create_user(user, &(row[DB_srpverifier]),
                                         &(row[DB_srpsalt]),
                                         gNrow ? gNrow[DB_srpsalt] : NULL,
                                         gNrow ? gNrow[DB_srpverifier] : NULL,
                                         passout, bio_err, verbose))) {
                        BIO_printf(bio_err,
                                   "\x43\x61\x6e\x6e\x6f\x74\x20\x63\x72\x65\x61\x74\x65\x20\x73\x72\x70\x20\x76\x65\x72\x69\x66\x69\x65\x72\x20\x66\x6f\x72\x20\x75\x73\x65\x72\x20\x22\x25\x73\x22\x2c\x20\x6f\x70\x65\x72\x61\x74\x69\x6f\x6e\x20\x61\x62\x61\x6e\x64\x6f\x6e\x65\x64\x2e\xa",
                                   user);
                        errors++;
                        goto err;
                    }

                    row[DB_srptype][0] = '\x76';
                    row[DB_srpgN] = BUF_strdup(gNid);

                    if (!row[DB_srpid] || !row[DB_srpgN] || !row[DB_srptype]
                        || !row[DB_srpverifier] || !row[DB_srpsalt]
                        || (userinfo
                            && (!(row[DB_srpinfo] = BUF_strdup(userinfo)))))
                        goto err;

                    doupdatedb = 1;
                }
            }
        } else if (delete_user) {
            if (userindex < 0) {
                BIO_printf(bio_err,
                           "\x75\x73\x65\x72\x20\x22\x25\x73\x22\x20\x64\x6f\x65\x73\x20\x6e\x6f\x74\x20\x65\x78\x69\x73\x74\x2c\x20\x6f\x70\x65\x72\x61\x74\x69\x6f\x6e\x20\x69\x67\x6e\x6f\x72\x65\x64\x2e\x20\x74\xa",
                           user);
                errors++;
            } else {
                char **xpp =
                    sk_OPENSSL_PSTRING_value(db->db->data, userindex);
                BIO_printf(bio_err, "\x75\x73\x65\x72\x20\x22\x25\x73\x22\x20\x72\x65\x76\x6f\x6b\x65\x64\x2e\x20\x74\xa", user);

                xpp[DB_srptype][0] = '\x52';

                doupdatedb = 1;
            }
        }
        if (--argc > 0) {
            user = *(argv++);
        } else {
            user = NULL;
            list_user = 0;
        }
    }

    VERBOSE BIO_printf(bio_err, "\x55\x73\x65\x72\x20\x70\x72\x6f\x63\x65\x73\x73\x69\x6f\x6e\x20\x64\x6f\x6e\x65\x2e\xa");

    if (doupdatedb) {
        /* Lets check some fields */
        for (i = 0; i < sk_OPENSSL_PSTRING_num(db->db->data); i++) {
            pp = sk_OPENSSL_PSTRING_value(db->db->data, i);

            if (pp[DB_srptype][0] == '\x76') {
                pp[DB_srptype][0] = '\x56';
                print_user(db, bio_err, i, verbose);
            }
        }

        VERBOSE BIO_printf(bio_err, "\x54\x72\x79\x69\x6e\x67\x20\x74\x6f\x20\x75\x70\x64\x61\x74\x65\x20\x73\x72\x70\x76\x66\x69\x6c\x65\x2e\xa");
        if (!save_index(dbfile, "\x6e\x65\x77", db))
            goto err;

        VERBOSE BIO_printf(bio_err, "\x54\x65\x6d\x70\x6f\x72\x61\x72\x79\x20\x73\x72\x70\x76\x66\x69\x6c\x65\x20\x63\x72\x65\x61\x74\x65\x64\x2e\xa");
        if (!rotate_index(dbfile, "\x6e\x65\x77", "\x6f\x6c\x64"))
            goto err;

        VERBOSE BIO_printf(bio_err, "\x73\x72\x70\x76\x66\x69\x6c\x65\x20\x75\x70\x64\x61\x74\x65\x64\x2e\xa");
    }

    ret = (errors != 0);
 err:
    if (errors != 0)
        VERBOSE BIO_printf(bio_err, "\x55\x73\x65\x72\x20\x65\x72\x72\x6f\x72\x73\x20\x25\x64\x2e\xa", errors);

    VERBOSE BIO_printf(bio_err, "\x53\x52\x50\x20\x74\x65\x72\x6d\x69\x6e\x61\x74\x69\x6e\x67\x20\x77\x69\x74\x68\x20\x63\x6f\x64\x65\x20\x25\x64\x2e\xa", ret);
    if (tofree)
        OPENSSL_free(tofree);
    if (ret)
        ERR_print_errors(bio_err);
    if (randfile)
        app_RAND_write_file(randfile, bio_err);
    if (conf)
        NCONF_free(conf);
    if (db)
        free_index(db);

    release_engine(e);
    OBJ_cleanup();
    apps_shutdown();
    OPENSSL_EXIT(ret);
}

#else
static void *dummy = &dummy;
#endif

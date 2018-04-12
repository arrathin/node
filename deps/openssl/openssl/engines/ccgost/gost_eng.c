/**********************************************************************
 *                          gost_eng.c                                *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *              Main file of GOST engine                              *
 *       for OpenSSL                                                  *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/obj_mac.h>
#include "e_gost_err.h"
#include "gost_lcl.h"
static const char *engine_gost_id = "\x67\x6f\x73\x74";
static const char *engine_gost_name =
    "\x52\x65\x66\x65\x72\x65\x6e\x63\x65\x20\x69\x6d\x70\x6c\x65\x6d\x65\x6e\x74\x61\x74\x69\x6f\x6e\x20\x6f\x66\x20\x47\x4f\x53\x54\x20\x65\x6e\x67\x69\x6e\x65";

/* Symmetric cipher and digest function registrar */

static int gost_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                        const int **nids, int nid);

static int gost_digests(ENGINE *e, const EVP_MD **digest,
                        const int **nids, int ind);

static int gost_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                           const int **nids, int nid);

static int gost_pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth,
                                const int **nids, int nid);

static int gost_cipher_nids[] = { NID_id_Gost28147_89, NID_gost89_cnt, 0 };

static int gost_digest_nids[] =
    { NID_id_GostR3411_94, NID_id_Gost28147_89_MAC, 0 };

static int gost_pkey_meth_nids[] = { NID_id_GostR3410_94,
    NID_id_GostR3410_2001, NID_id_Gost28147_89_MAC, 0
};

static EVP_PKEY_METHOD *pmeth_GostR3410_94 = NULL,
    *pmeth_GostR3410_2001 = NULL, *pmeth_Gost28147_MAC = NULL;

static EVP_PKEY_ASN1_METHOD *ameth_GostR3410_94 = NULL,
    *ameth_GostR3410_2001 = NULL, *ameth_Gost28147_MAC = NULL;

static int gost_engine_init(ENGINE *e)
{
    return 1;
}

static int gost_engine_finish(ENGINE *e)
{
    return 1;
}

static int gost_engine_destroy(ENGINE *e)
{
    gost_param_free();

    pmeth_GostR3410_94 = NULL;
    pmeth_GostR3410_2001 = NULL;
    pmeth_Gost28147_MAC = NULL;
    ameth_GostR3410_94 = NULL;
    ameth_GostR3410_2001 = NULL;
    ameth_Gost28147_MAC = NULL;
    return 1;
}

static int bind_gost(ENGINE *e, const char *id)
{
    int ret = 0;
    if (id && strcmp(id, engine_gost_id))
        return 0;
    if (ameth_GostR3410_94) {
        printf("\x47\x4f\x53\x54\x20\x65\x6e\x67\x69\x6e\x65\x20\x61\x6c\x72\x65\x61\x64\x79\x20\x6c\x6f\x61\x64\x65\x64\xa");
        goto end;
    }

    if (!ENGINE_set_id(e, engine_gost_id)) {
        printf("\x45\x4e\x47\x49\x4e\x45\x5f\x73\x65\x74\x5f\x69\x64\x20\x66\x61\x69\x6c\x65\x64\xa");
        goto end;
    }
    if (!ENGINE_set_name(e, engine_gost_name)) {
        printf("\x45\x4e\x47\x49\x4e\x45\x5f\x73\x65\x74\x5f\x6e\x61\x6d\x65\x20\x66\x61\x69\x6c\x65\x64\xa");
        goto end;
    }
    if (!ENGINE_set_digests(e, gost_digests)) {
        printf("\x45\x4e\x47\x49\x4e\x45\x5f\x73\x65\x74\x5f\x64\x69\x67\x65\x73\x74\x73\x20\x66\x61\x69\x6c\x65\x64\xa");
        goto end;
    }
    if (!ENGINE_set_ciphers(e, gost_ciphers)) {
        printf("\x45\x4e\x47\x49\x4e\x45\x5f\x73\x65\x74\x5f\x63\x69\x70\x68\x65\x72\x73\x20\x66\x61\x69\x6c\x65\x64\xa");
        goto end;
    }
    if (!ENGINE_set_pkey_meths(e, gost_pkey_meths)) {
        printf("\x45\x4e\x47\x49\x4e\x45\x5f\x73\x65\x74\x5f\x70\x6b\x65\x79\x5f\x6d\x65\x74\x68\x73\x20\x66\x61\x69\x6c\x65\x64\xa");
        goto end;
    }
    if (!ENGINE_set_pkey_asn1_meths(e, gost_pkey_asn1_meths)) {
        printf("\x45\x4e\x47\x49\x4e\x45\x5f\x73\x65\x74\x5f\x70\x6b\x65\x79\x5f\x61\x73\x6e\x31\x5f\x6d\x65\x74\x68\x73\x20\x66\x61\x69\x6c\x65\x64\xa");
        goto end;
    }
    /* Control function and commands */
    if (!ENGINE_set_cmd_defns(e, gost_cmds)) {
        fprintf(stderr, "\x45\x4e\x47\x49\x4e\x45\x5f\x73\x65\x74\x5f\x63\x6d\x64\x5f\x64\x65\x66\x6e\x73\x20\x66\x61\x69\x6c\x65\x64\xa");
        goto end;
    }
    if (!ENGINE_set_ctrl_function(e, gost_control_func)) {
        fprintf(stderr, "\x45\x4e\x47\x49\x4e\x45\x5f\x73\x65\x74\x5f\x63\x74\x72\x6c\x5f\x66\x75\x6e\x63\x20\x66\x61\x69\x6c\x65\x64\xa");
        goto end;
    }
    if (!ENGINE_set_destroy_function(e, gost_engine_destroy)
        || !ENGINE_set_init_function(e, gost_engine_init)
        || !ENGINE_set_finish_function(e, gost_engine_finish)) {
        goto end;
    }

    if (!register_ameth_gost
        (NID_id_GostR3410_94, &ameth_GostR3410_94, "\x47\x4f\x53\x54\x39\x34",
         "\x47\x4f\x53\x54\x20\x52\x20\x33\x34\x2e\x31\x30\x2d\x39\x34"))
        goto end;
    if (!register_ameth_gost
        (NID_id_GostR3410_2001, &ameth_GostR3410_2001, "\x47\x4f\x53\x54\x32\x30\x30\x31",
         "\x47\x4f\x53\x54\x20\x52\x20\x33\x34\x2e\x31\x30\x2d\x32\x30\x30\x31"))
        goto end;
    if (!register_ameth_gost(NID_id_Gost28147_89_MAC, &ameth_Gost28147_MAC,
                             "\x47\x4f\x53\x54\x2d\x4d\x41\x43", "\x47\x4f\x53\x54\x20\x32\x38\x31\x34\x37\x2d\x38\x39\x20\x4d\x41\x43"))
        goto end;

    if (!register_pmeth_gost(NID_id_GostR3410_94, &pmeth_GostR3410_94, 0))
        goto end;
    if (!register_pmeth_gost(NID_id_GostR3410_2001, &pmeth_GostR3410_2001, 0))
        goto end;
    if (!register_pmeth_gost
        (NID_id_Gost28147_89_MAC, &pmeth_Gost28147_MAC, 0))
        goto end;
    if (!ENGINE_register_ciphers(e)
        || !ENGINE_register_digests(e)
        || !ENGINE_register_pkey_meths(e)
        /* These two actually should go in LIST_ADD command */
        || !EVP_add_cipher(&cipher_gost)
        || !EVP_add_cipher(&cipher_gost_cpacnt)
        || !EVP_add_digest(&digest_gost)
        || !EVP_add_digest(&imit_gost_cpa)
        ) {
        goto end;
    }

    ERR_load_GOST_strings();
    ret = 1;
 end:
    return ret;
}

static int gost_digests(ENGINE *e, const EVP_MD **digest,
                        const int **nids, int nid)
{
    int ok = 1;
    if (!digest) {
        *nids = gost_digest_nids;
        return 2;
    }
    /*
     * printf("Digest no %d requested\n",nid);
     */
    if (nid == NID_id_GostR3411_94) {
        *digest = &digest_gost;
    } else if (nid == NID_id_Gost28147_89_MAC) {
        *digest = &imit_gost_cpa;
    } else {
        ok = 0;
        *digest = NULL;
    }
    return ok;
}

static int gost_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                        const int **nids, int nid)
{
    int ok = 1;
    if (!cipher) {
        *nids = gost_cipher_nids;
        return 2;               /* two ciphers are supported */
    }

    if (nid == NID_id_Gost28147_89) {
        *cipher = &cipher_gost;
    } else if (nid == NID_gost89_cnt) {
        *cipher = &cipher_gost_cpacnt;
    } else {
        ok = 0;
        *cipher = NULL;
    }
    return ok;
}

static int gost_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                           const int **nids, int nid)
{
    if (!pmeth) {
        *nids = gost_pkey_meth_nids;
        return 3;
    }

    switch (nid) {
    case NID_id_GostR3410_94:
        *pmeth = pmeth_GostR3410_94;
        return 1;
    case NID_id_GostR3410_2001:
        *pmeth = pmeth_GostR3410_2001;
        return 1;
    case NID_id_Gost28147_89_MAC:
        *pmeth = pmeth_Gost28147_MAC;
        return 1;
    default:;
    }

    *pmeth = NULL;
    return 0;
}

static int gost_pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth,
                                const int **nids, int nid)
{
    if (!ameth) {
        *nids = gost_pkey_meth_nids;
        return 3;
    }
    switch (nid) {
    case NID_id_GostR3410_94:
        *ameth = ameth_GostR3410_94;
        return 1;
    case NID_id_GostR3410_2001:
        *ameth = ameth_GostR3410_2001;
        return 1;
    case NID_id_Gost28147_89_MAC:
        *ameth = ameth_Gost28147_MAC;
        return 1;

    default:;
    }

    *ameth = NULL;
    return 0;
}

#ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *engine_gost(void)
{
    ENGINE *ret = ENGINE_new();
    if (!ret)
        return NULL;
    if (!bind_gost(ret, engine_gost_id)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void ENGINE_load_gost(void)
{
    ENGINE *toadd;
    if (pmeth_GostR3410_94)
        return;
    toadd = engine_gost();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}
#else
IMPLEMENT_DYNAMIC_BIND_FN(bind_gost)
IMPLEMENT_DYNAMIC_CHECK_FN()
#endif

/* crypto/bio/bss_log.c */
/* ====================================================================
 * Copyright (c) 1999-2018 The OpenSSL Project.  All rights reserved.
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

/*
 * Why BIO_s_log?
 *
 * BIO_s_log is useful for system daemons (or services under NT). It is
 * one-way BIO, it sends all stuff to syslogd (on system that commonly use
 * that), or event log (on NT), or OPCOM (on OpenVMS).
 *
 */

#include <stdio.h>
#include <errno.h>

#include "cryptlib.h"

#if defined(OPENSSL_SYS_WINCE)
#elif defined(OPENSSL_SYS_WIN32)
#elif defined(OPENSSL_SYS_VMS)
# include <opcdef.h>
# include <descrip.h>
# include <lib$routines.h>
# include <starlet.h>
/* Some compiler options may mask the declaration of "_malloc32". */
# if __INITIAL_POINTER_SIZE && defined _ANSI_C_SOURCE
#  if __INITIAL_POINTER_SIZE == 64
#   pragma pointer_size save
#   pragma pointer_size 32
void *_malloc32(__size_t);
#   pragma pointer_size restore
#  endif                        /* __INITIAL_POINTER_SIZE == 64 */
# endif                         /* __INITIAL_POINTER_SIZE && defined
                                 * _ANSI_C_SOURCE */
#elif defined(__ultrix)
# include <sys/syslog.h>
#elif defined(OPENSSL_SYS_NETWARE)
# define NO_SYSLOG
#elif (!defined(MSDOS) || defined(WATT32)) && !defined(OPENSSL_SYS_VXWORKS) && !defined(NO_SYSLOG)
# include <syslog.h>
#endif

#include <openssl/buffer.h>
#include <openssl/err.h>

#ifndef NO_SYSLOG

# if defined(OPENSSL_SYS_WIN32)
#  define LOG_EMERG       0
#  define LOG_ALERT       1
#  define LOG_CRIT        2
#  define LOG_ERR         3
#  define LOG_WARNING     4
#  define LOG_NOTICE      5
#  define LOG_INFO        6
#  define LOG_DEBUG       7

#  define LOG_DAEMON      (3<<3)
# elif defined(OPENSSL_SYS_VMS)
/* On VMS, we don't really care about these, but we need them to compile */
#  define LOG_EMERG       0
#  define LOG_ALERT       1
#  define LOG_CRIT        2
#  define LOG_ERR         3
#  define LOG_WARNING     4
#  define LOG_NOTICE      5
#  define LOG_INFO        6
#  define LOG_DEBUG       7

#  define LOG_DAEMON      OPC$M_NM_NTWORK
# endif

static int MS_CALLBACK slg_write(BIO *h, const char *buf, int num);
static int MS_CALLBACK slg_puts(BIO *h, const char *str);
static long MS_CALLBACK slg_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int MS_CALLBACK slg_new(BIO *h);
static int MS_CALLBACK slg_free(BIO *data);
static void xopenlog(BIO *bp, char *name, int level);
static void xsyslog(BIO *bp, int priority, const char *string);
static void xcloselog(BIO *bp);

static BIO_METHOD methods_slg = {
    BIO_TYPE_MEM, "\x73\x79\x73\x6c\x6f\x67",
    slg_write,
    NULL,
    slg_puts,
    NULL,
    slg_ctrl,
    slg_new,
    slg_free,
    NULL,
};

BIO_METHOD *BIO_s_log(void)
{
    return (&methods_slg);
}

static int MS_CALLBACK slg_new(BIO *bi)
{
    bi->init = 1;
    bi->num = 0;
    bi->ptr = NULL;
    xopenlog(bi, "\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e", LOG_DAEMON);
    return (1);
}

static int MS_CALLBACK slg_free(BIO *a)
{
    if (a == NULL)
        return (0);
    xcloselog(a);
    return (1);
}

static int MS_CALLBACK slg_write(BIO *b, const char *in, int inl)
{
    int ret = inl;
    char *buf;
    char *pp;
    int priority, i;
    static const struct {
        int strl;
        char str[10];
        int log_level;
    } mapping[] = {
        {
            6, "\x50\x41\x4e\x49\x43\x20", LOG_EMERG
        },
        {
            6, "\x45\x4d\x45\x52\x47\x20", LOG_EMERG
        },
        {
            4, "\x45\x4d\x52\x20", LOG_EMERG
        },
        {
            6, "\x41\x4c\x45\x52\x54\x20", LOG_ALERT
        },
        {
            4, "\x41\x4c\x52\x20", LOG_ALERT
        },
        {
            5, "\x43\x52\x49\x54\x20", LOG_CRIT
        },
        {
            4, "\x43\x52\x49\x20", LOG_CRIT
        },
        {
            6, "\x45\x52\x52\x4f\x52\x20", LOG_ERR
        },
        {
            4, "\x45\x52\x52\x20", LOG_ERR
        },
        {
            8, "\x57\x41\x52\x4e\x49\x4e\x47\x20", LOG_WARNING
        },
        {
            5, "\x57\x41\x52\x4e\x20", LOG_WARNING
        },
        {
            4, "\x57\x41\x52\x20", LOG_WARNING
        },
        {
            7, "\x4e\x4f\x54\x49\x43\x45\x20", LOG_NOTICE
        },
        {
            5, "\x4e\x4f\x54\x45\x20", LOG_NOTICE
        },
        {
            4, "\x4e\x4f\x54\x20", LOG_NOTICE
        },
        {
            5, "\x49\x4e\x46\x4f\x20", LOG_INFO
        },
        {
            4, "\x49\x4e\x46\x20", LOG_INFO
        },
        {
            6, "\x44\x45\x42\x55\x47\x20", LOG_DEBUG
        },
        {
            4, "\x44\x42\x47\x20", LOG_DEBUG
        },
        {
            0, "", LOG_ERR
        }
        /* The default */
    };

    if ((buf = (char *)OPENSSL_malloc(inl + 1)) == NULL) {
        return (0);
    }
    memcpy(buf, in, inl);
    buf[inl] = '\x0';

    i = 0;
    while (strncmp(buf, mapping[i].str, mapping[i].strl) != 0)
        i++;
    priority = mapping[i].log_level;
    pp = buf + mapping[i].strl;

    xsyslog(b, priority, pp);

    OPENSSL_free(buf);
    return (ret);
}

static long MS_CALLBACK slg_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    switch (cmd) {
    case BIO_CTRL_SET:
        xcloselog(b);
        xopenlog(b, ptr, num);
        break;
    default:
        break;
    }
    return (0);
}

static int MS_CALLBACK slg_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = slg_write(bp, str, n);
    return (ret);
}

# if defined(OPENSSL_SYS_WIN32)

static void xopenlog(BIO *bp, char *name, int level)
{
    if (check_winnt())
        bp->ptr = RegisterEventSourceA(NULL, name);
    else
        bp->ptr = NULL;
}

static void xsyslog(BIO *bp, int priority, const char *string)
{
    LPCSTR lpszStrings[2];
    WORD evtype = EVENTLOG_ERROR_TYPE;
    char pidbuf[DECIMAL_SIZE(DWORD) + 4];

    if (bp->ptr == NULL)
        return;

    switch (priority) {
    case LOG_EMERG:
    case LOG_ALERT:
    case LOG_CRIT:
    case LOG_ERR:
        evtype = EVENTLOG_ERROR_TYPE;
        break;
    case LOG_WARNING:
        evtype = EVENTLOG_WARNING_TYPE;
        break;
    case LOG_NOTICE:
    case LOG_INFO:
    case LOG_DEBUG:
        evtype = EVENTLOG_INFORMATION_TYPE;
        break;
    default:
        /*
         * Should never happen, but set it
         * as error anyway.
         */
        evtype = EVENTLOG_ERROR_TYPE;
        break;
    }

    sprintf(pidbuf, "\x5b\x25\x75\x5d\x20", GetCurrentProcessId());
    lpszStrings[0] = pidbuf;
    lpszStrings[1] = string;

    ReportEventA(bp->ptr, evtype, 0, 1024, NULL, 2, 0, lpszStrings, NULL);
}

static void xcloselog(BIO *bp)
{
    if (bp->ptr)
        DeregisterEventSource((HANDLE) (bp->ptr));
    bp->ptr = NULL;
}

# elif defined(OPENSSL_SYS_VMS)

static int VMS_OPC_target = LOG_DAEMON;

static void xopenlog(BIO *bp, char *name, int level)
{
    VMS_OPC_target = level;
}

static void xsyslog(BIO *bp, int priority, const char *string)
{
    struct dsc$descriptor_s opc_dsc;

/* Arrange 32-bit pointer to opcdef buffer and malloc(), if needed. */
#  if __INITIAL_POINTER_SIZE == 64
#   pragma pointer_size save
#   pragma pointer_size 32
#   define OPCDEF_TYPE __char_ptr32
#   define OPCDEF_MALLOC _malloc32
#  else                         /* __INITIAL_POINTER_SIZE == 64 */
#   define OPCDEF_TYPE char *
#   define OPCDEF_MALLOC OPENSSL_malloc
#  endif                        /* __INITIAL_POINTER_SIZE == 64 [else] */

    struct opcdef *opcdef_p;

#  if __INITIAL_POINTER_SIZE == 64
#   pragma pointer_size restore
#  endif                        /* __INITIAL_POINTER_SIZE == 64 */

    char buf[10240];
    unsigned int len;
    struct dsc$descriptor_s buf_dsc;
    $DESCRIPTOR(fao_cmd, "\x21\x41\x5a\x3a\x20\x21\x41\x5a");
    char *priority_tag;

    switch (priority) {
    case LOG_EMERG:
        priority_tag = "\x45\x6d\x65\x72\x67\x65\x6e\x63\x79";
        break;
    case LOG_ALERT:
        priority_tag = "\x41\x6c\x65\x72\x74";
        break;
    case LOG_CRIT:
        priority_tag = "\x43\x72\x69\x74\x69\x63\x61\x6c";
        break;
    case LOG_ERR:
        priority_tag = "\x45\x72\x72\x6f\x72";
        break;
    case LOG_WARNING:
        priority_tag = "\x57\x61\x72\x6e\x69\x6e\x67";
        break;
    case LOG_NOTICE:
        priority_tag = "\x4e\x6f\x74\x69\x63\x65";
        break;
    case LOG_INFO:
        priority_tag = "\x49\x6e\x66\x6f";
        break;
    case LOG_DEBUG:
        priority_tag = "\x44\x45\x42\x55\x47";
        break;
    }

    buf_dsc.dsc$b_dtype = DSC$K_DTYPE_T;
    buf_dsc.dsc$b_class = DSC$K_CLASS_S;
    buf_dsc.dsc$a_pointer = buf;
    buf_dsc.dsc$w_length = sizeof(buf) - 1;

    lib$sys_fao(&fao_cmd, &len, &buf_dsc, priority_tag, string);

    /* We know there's an 8-byte header.  That's documented. */
    opcdef_p = OPCDEF_MALLOC(8 + len);
    opcdef_p->opc$b_ms_type = OPC$_RQ_RQST;
    memcpy(opcdef_p->opc$z_ms_target_classes, &VMS_OPC_target, 3);
    opcdef_p->opc$l_ms_rqstid = 0;
    memcpy(&opcdef_p->opc$l_ms_text, buf, len);

    opc_dsc.dsc$b_dtype = DSC$K_DTYPE_T;
    opc_dsc.dsc$b_class = DSC$K_CLASS_S;
    opc_dsc.dsc$a_pointer = (OPCDEF_TYPE) opcdef_p;
    opc_dsc.dsc$w_length = len + 8;

    sys$sndopr(opc_dsc, 0);

    OPENSSL_free(opcdef_p);
}

static void xcloselog(BIO *bp)
{
}

# else                          /* Unix/Watt32 */

static void xopenlog(BIO *bp, char *name, int level)
{
#  ifdef WATT32                 /* djgpp/DOS */
    openlog(name, LOG_PID | LOG_CONS | LOG_NDELAY, level);
#  else
    openlog(name, LOG_PID | LOG_CONS, level);
#  endif
}

static void xsyslog(BIO *bp, int priority, const char *string)
{
    syslog(priority, "\x25\x73", string);
}

static void xcloselog(BIO *bp)
{
    closelog();
}

# endif                         /* Unix */

#endif                          /* NO_SYSLOG */

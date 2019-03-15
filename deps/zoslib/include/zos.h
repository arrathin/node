#ifndef __ZOS_H_
#define __ZOS_H_
//-------------------------------------------------------------------------------------
//
// external interface:
//
#include <_Nascii.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
extern int __debug_mode;
#define __ZOS_CC
#ifdef __cplusplus
extern "C" {
#endif
extern void *_convert_e2a(void *dst, const void *src, size_t size);
extern void *_convert_a2e(void *dst, const void *src, size_t size);
extern char **__get_environ_np(void);
extern void __xfer_env(void);
extern int __chgfdccsid(int fd, unsigned short ccsid);
extern size_t __e2a_l(char *bufptr, size_t szLen);
extern size_t __a2e_l(char *bufptr, size_t szLen);
extern size_t __e2a_s(char *string);
extern size_t __a2e_s(char *string);
extern int dprintf(int fd, const char *, ...);
extern int vdprintf(int fd, const char *, va_list ap);
extern void __xfer_env(void);
extern int __chgfdccsid(int fd, unsigned short ccsid);
extern void __dump(int fd, const void *addr, size_t len, size_t bw);
extern int backtrace(void **buffer, int size);
extern char **backtrace_symbols(void *const *buffer, int size);
extern void backtrace_symbols_fd(void *const *buffer, int size, int fd);

#ifdef __cplusplus
}
#endif

#define _str_e2a(_str)                                                         \
  ({                                                                           \
    const char *src = (const char *)(_str);                                    \
    int len = strlen(src) + 1;                                                 \
    char *tgt = (char *)alloca(len);                                           \
    (char *)_convert_e2a(tgt, src, len);                                       \
  })

#define AEWRAP(_rc, _x)                                                        \
  (__isASCII() ? ((_rc) = (_x), 0)                                             \
               : (__ae_thread_swapmode(__AE_ASCII_MODE), ((_rc) = (_x)),       \
                  __ae_thread_swapmode(__AE_EBCDIC_MODE), 1))

#define AEWRAP_VOID(_x)                                                        \
  (__isASCII() ? ((_x), 0)                                                     \
               : (__ae_thread_swapmode(__AE_ASCII_MODE), (_x),                 \
                  __ae_thread_swapmode(__AE_EBCDIC_MODE), 1))

#ifdef __cplusplus
class __auto_ascii {
  int ascii_mode;

public:
  __auto_ascii();
  ~__auto_ascii();
};

#endif

#endif

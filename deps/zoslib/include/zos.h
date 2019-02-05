#ifndef __ZOS_H_
#define __ZOS_H_
//-------------------------------------------------------------------------------------
//
// external interface:
//
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <_Nascii.h>
#ifdef __cplusplus
extern "C" {
#endif
extern void *_convert_e2a(void *dst, const void *src, size_t size);
#ifdef __cplusplus
}
#endif

#define _str_e2a(_str)                                                         \
  ({                                                                           \
    const char *src = (const char *)(_str);                                    \
    int len = strlen(src) + 1;                                                 \
    char *tgt = alloca(len);                                                   \
    _convert_e2a(tgt, src, len);                                               \
  })


#define AEWRAP(_rc, _x)                                                        \
  (__isASCII() ? ((_rc) = (_x), 0)                                             \
               : (__ae_thread_swapmode(__AE_ASCII_MODE), ((_rc) = (_x)),       \
                  __ae_thread_swapmode(__AE_EBCDIC_MODE), 1))

#define AEWRAP_VOID(_x)                                                        \
  (__isASCII() ? ((_x), 0)                                                     \
               : (__ae_thread_swapmode(__AE_ASCII_MODE), (_x),                 \
                  __ae_thread_swapmode(__AE_EBCDIC_MODE), 1))

extern "C" void __xfer_env(void);
extern "C" int __chgfdccsid(int fd, unsigned short ccsid);

#endif

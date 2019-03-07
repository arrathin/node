#define _AE_BIMODAL 1
#undef _ENHANCED_ASCII_EXT
#define _ENHANCED_ASCII_EXT 0x42020010
#define _XOPEN_SOURCE 600
#define _OPEN_SYS_FILE_EXT 1
#define __ZOS_CC
#include "zos.h"
#include <_Nascii.h>
#include <__le_api.h>
#include <ctest.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
int __debug_mode = 0;

static inline void *__convert_one_to_one(const void *table, void *dst,
                                         size_t size, const void *src) {
  void *rst = dst;
  __asm(" troo 2,%2,b'0001' \n jo *-4 \n"
        : "+NR:r3"(size), "+NR:r2"(dst), "+r"(src)
        : "NR:r1"(table)
        : "r0", "r1", "r2", "r3");
  return rst;
}
static inline unsigned strlen_ae(const unsigned char *str, int *code_page,
                                 int max_len) {
  static int last_ccsid = 819;
  static const unsigned char _tab_a[256] __attribute__((aligned(8))) = {
      1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  };
  static const unsigned char _tab_e[256] __attribute__((aligned(8))) = {
      1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1,
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
      0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1,
      1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1,
      1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1,
  };
  unsigned long bytes;
  unsigned long code_out;
  const unsigned char *start;

  bytes = max_len;
  code_out = 0;
  start = str;
  __asm(" trte %1,%3,b'0000'\n"
        " jo *-4\n"
        : "+NR:r3"(bytes), "+NR:r2"(str), "+r"(bytes), "+r"(code_out)
        : "NR:r1"(_tab_a)
        : "r1", "r2", "r3");
  unsigned a_len = str - start;

  bytes = max_len;
  code_out = 0;
  str = start;
  __asm(" trte %1,%3,b'0000'\n"
        " jo *-4\n"
        : "+NR:r3"(bytes), "+NR:r2"(str), "+r"(bytes), "+r"(code_out)
        : "NR:r1"(_tab_e)
        : "r1", "r2", "r3");
  unsigned e_len = str - start;
  if (a_len > e_len) {
    *code_page = 819;
    last_ccsid = 819;
    return a_len;
  } else if (e_len > a_len) {
    *code_page = 1047;
    last_ccsid = 1047;
    return e_len;
  }
  *code_page = last_ccsid;
  return a_len;
}

static const unsigned char __ibm1047_iso88591[256]
    __attribute__((aligned(8))) = {
        0x00, 0x01, 0x02, 0x03, 0x9c, 0x09, 0x86, 0x7f, 0x97, 0x8d, 0x8e, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x9d, 0x0a, 0x08, 0x87,
        0x18, 0x19, 0x92, 0x8f, 0x1c, 0x1d, 0x1e, 0x1f, 0x80, 0x81, 0x82, 0x83,
        0x84, 0x85, 0x17, 0x1b, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x05, 0x06, 0x07,
        0x90, 0x91, 0x16, 0x93, 0x94, 0x95, 0x96, 0x04, 0x98, 0x99, 0x9a, 0x9b,
        0x14, 0x15, 0x9e, 0x1a, 0x20, 0xa0, 0xe2, 0xe4, 0xe0, 0xe1, 0xe3, 0xe5,
        0xe7, 0xf1, 0xa2, 0x2e, 0x3c, 0x28, 0x2b, 0x7c, 0x26, 0xe9, 0xea, 0xeb,
        0xe8, 0xed, 0xee, 0xef, 0xec, 0xdf, 0x21, 0x24, 0x2a, 0x29, 0x3b, 0x5e,
        0x2d, 0x2f, 0xc2, 0xc4, 0xc0, 0xc1, 0xc3, 0xc5, 0xc7, 0xd1, 0xa6, 0x2c,
        0x25, 0x5f, 0x3e, 0x3f, 0xf8, 0xc9, 0xca, 0xcb, 0xc8, 0xcd, 0xce, 0xcf,
        0xcc, 0x60, 0x3a, 0x23, 0x40, 0x27, 0x3d, 0x22, 0xd8, 0x61, 0x62, 0x63,
        0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0xab, 0xbb, 0xf0, 0xfd, 0xfe, 0xb1,
        0xb0, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xaa, 0xba,
        0xe6, 0xb8, 0xc6, 0xa4, 0xb5, 0x7e, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
        0x79, 0x7a, 0xa1, 0xbf, 0xd0, 0x5b, 0xde, 0xae, 0xac, 0xa3, 0xa5, 0xb7,
        0xa9, 0xa7, 0xb6, 0xbc, 0xbd, 0xbe, 0xdd, 0xa8, 0xaf, 0x5d, 0xb4, 0xd7,
        0x7b, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0xad, 0xf4,
        0xf6, 0xf2, 0xf3, 0xf5, 0x7d, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
        0x51, 0x52, 0xb9, 0xfb, 0xfc, 0xf9, 0xfa, 0xff, 0x5c, 0xf7, 0x53, 0x54,
        0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0xb2, 0xd4, 0xd6, 0xd2, 0xd3, 0xd5,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xb3, 0xdb,
        0xdc, 0xd9, 0xda, 0x9f};

static const unsigned char __iso88591_ibm1047[256]
    __attribute__((aligned(8))) = {
        0x00, 0x01, 0x02, 0x03, 0x37, 0x2d, 0x2e, 0x2f, 0x16, 0x05, 0x15, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x3c, 0x3d, 0x32, 0x26,
        0x18, 0x19, 0x3f, 0x27, 0x1c, 0x1d, 0x1e, 0x1f, 0x40, 0x5a, 0x7f, 0x7b,
        0x5b, 0x6c, 0x50, 0x7d, 0x4d, 0x5d, 0x5c, 0x4e, 0x6b, 0x60, 0x4b, 0x61,
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0x7a, 0x5e,
        0x4c, 0x7e, 0x6e, 0x6f, 0x7c, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        0xc8, 0xc9, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xe2,
        0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xad, 0xe0, 0xbd, 0x5f, 0x6d,
        0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x91, 0x92,
        0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6,
        0xa7, 0xa8, 0xa9, 0xc0, 0x4f, 0xd0, 0xa1, 0x07, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x06, 0x17, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x09, 0x0a, 0x1b,
        0x30, 0x31, 0x1a, 0x33, 0x34, 0x35, 0x36, 0x08, 0x38, 0x39, 0x3a, 0x3b,
        0x04, 0x14, 0x3e, 0xff, 0x41, 0xaa, 0x4a, 0xb1, 0x9f, 0xb2, 0x6a, 0xb5,
        0xbb, 0xb4, 0x9a, 0x8a, 0xb0, 0xca, 0xaf, 0xbc, 0x90, 0x8f, 0xea, 0xfa,
        0xbe, 0xa0, 0xb6, 0xb3, 0x9d, 0xda, 0x9b, 0x8b, 0xb7, 0xb8, 0xb9, 0xab,
        0x64, 0x65, 0x62, 0x66, 0x63, 0x67, 0x9e, 0x68, 0x74, 0x71, 0x72, 0x73,
        0x78, 0x75, 0x76, 0x77, 0xac, 0x69, 0xed, 0xee, 0xeb, 0xef, 0xec, 0xbf,
        0x80, 0xfd, 0xfe, 0xfb, 0xfc, 0xba, 0xae, 0x59, 0x44, 0x45, 0x42, 0x46,
        0x43, 0x47, 0x9c, 0x48, 0x54, 0x51, 0x52, 0x53, 0x58, 0x55, 0x56, 0x57,
        0x8c, 0x49, 0xcd, 0xce, 0xcb, 0xcf, 0xcc, 0xe1, 0x70, 0xdd, 0xde, 0xdb,
        0xdc, 0x8d, 0x8e, 0xdf};

extern "C" void *_convert_e2a(void *dst, const void *src, size_t size) {
  int ccsid;
  unsigned len = strlen_ae((unsigned char *)src, &ccsid, size);
  if (ccsid == 819) {
    memcpy(dst, src, size);
    return dst;
  }
  return __convert_one_to_one(__ibm1047_iso88591, dst, size, src);
}
extern "C" void *_convert_a2e(void *dst, const void *src, size_t size) {
  int ccsid;
  unsigned len = strlen_ae((unsigned char *)src, &ccsid, size);
  if (ccsid == 1047) {
    memcpy(dst, src, size);
    return dst;
  }
  return __convert_one_to_one(__iso88591_ibm1047, dst, size, src);
}

extern char **environ; // this would be the ebcdic one

extern "C" char **__get_environ_np(void) {
  static char **__environ = 0;
  static long __environ_size = 0;
  char **start = environ;
  int cnt = 0;
  int size = 0;
  int len = 0;
  int arysize = 0;
  while (*start) {
    size += (strlen(*start) + 1);
    ++start;
    ++cnt;
  }
  arysize = (cnt + 1) * sizeof(void *);
  size += arysize;
  if (__environ) {
    if (__environ_size < size) {
      free(__environ);
      __environ_size = size;
      __environ = (char **)malloc(__environ_size);
    }
  } else {
    __environ_size = size;
    __environ = (char **)malloc(__environ_size);
  }
  char *p = (char *)__environ;
  p += arysize;
  int i;
  start = environ;
  for (i = 0; i < cnt; ++i) {
    __environ[i] = p;
    len = strlen(*start) + 1;
    __convert_one_to_one(__ibm1047_iso88591, p, len, *start);
    p += len;
    ++start;
  }
  __environ[i] = 0;
  return __environ;
}

int __setenv_a(const char *, const char *, int);
#pragma map(__setenv_a, "\174\174A00188")
extern "C" void __xfer_env(void) {
  char **start = __get_environ_np();
  int i;
  int len;
  char *str;
  char *a_str;
  while (*start) {
    str = *start;
    len = strlen(str);
    a_str = (char *)alloca(len + 1);
    memcpy(a_str, str, len);
    a_str[len] = 0;
    for (i = 0; i < len; ++i) {
      if (a_str[i] == u'=') {
        a_str[i] = 0;
        break;
      }
    }
    if (i < len) {
      int rc = __setenv_a(a_str, a_str + i + 1, 1);
      if (rc != 0) {
        __auto_ascii _a;
        __printf_a("__setenv_a %s=%s failed rc=%d\n", a_str, a_str + i + 1, rc);
      }
    }
    ++start;
  }
}

extern "C" int __chgfdccsid(int fd, unsigned short ccsid) {
  attrib_t attr;
  memset(&attr, 0, sizeof(attr));
  attr.att_filetagchg = 1;
  attr.att_filetag.ft_ccsid = ccsid;
  attr.att_filetag.ft_txtflag = 1;
  return __fchattr(fd, &attr, sizeof(attr));
}
static void ledump(const char *title) {
  __auto_ascii _a;
  __cdump_a((char *)title);
}
extern "C" size_t __e2a_l(char *bufptr, size_t szLen) {
  int ccsid;
  if (0 == bufptr) {
    errno = EINVAL;
    return -1;
  }
  unsigned len = strlen_ae((const unsigned char *)bufptr, &ccsid, szLen);

  if (ccsid == 819) {
    if (__debug_mode) {
      dprintf(2, "Attempt convert from ASCII to ASCII\n");
      ledump((char *)"Attempt convert from ASCII to ASCII");
    }
    // return szLen; restore to convert
  }

  __convert_one_to_one(__ibm1047_iso88591, bufptr, szLen, bufptr);
  return szLen;
}
extern "C" size_t __a2e_l(char *bufptr, size_t szLen) {
  int ccsid;
  if (0 == bufptr) {
    errno = EINVAL;
    return -1;
  }
  unsigned len = strlen_ae((const unsigned char *)bufptr, &ccsid, szLen);

  if (ccsid == 1047) {
    if (__debug_mode) {
      dprintf(2, "Attempt convert from EBCDIC to EBCDIC\n");
      ledump((char *)"Attempt convert from EBCDIC to EBCDIC");
    }
    // return szLen; restore to convert
  }
  __convert_one_to_one(__iso88591_ibm1047, bufptr, szLen, bufptr);
  return szLen;
}
extern "C" size_t __e2a_s(char *string) {
  if (0 == string) {
    errno = EINVAL;
    return -1;
  }
  return __e2a_l(string, strlen(string));
}
extern "C" size_t __a2e_s(char *string) {
  if (0 == string) {
    errno = EINVAL;
    return -1;
  }
  return __a2e_l(string, strlen(string));
}
extern "C" int dprintf(int fd, const char *fmt, ...) {
  va_list ap;
  char *buf;
  int len;
  va_start(ap, fmt);
  va_list ap1;
  va_list ap2;
  va_copy(ap1, ap);
  va_copy(ap2, ap);
  int bytes;
  int ccsid;
  strlen_ae((const unsigned char *)fmt, &ccsid, strlen(fmt) + 1);
  int mode;
  if (ccsid == 819) {
    mode = __ae_thread_swapmode(__AE_ASCII_MODE);
    bytes = __vsnprintf_a(0, 0, fmt, ap1);
    buf = (char *)alloca(bytes + 1);
    len = __vsnprintf_a(buf, bytes + 1, fmt, ap2);
  } else {
    mode = __ae_thread_swapmode(__AE_EBCDIC_MODE);
    bytes = __vsnprintf_e(0, 0, fmt, ap1);
    buf = (char *)alloca(bytes + 1);
    len = __vsnprintf_e(buf, bytes + 1, fmt, ap2);
  }
  va_end(ap2);
  va_end(ap1);
  va_end(ap);
  if (len == -1)
    goto quit;
  len = write(fd, buf, len);
quit:
  __ae_thread_swapmode(mode);
  return len;
}
extern void __dump(int fd, const void *addr, size_t len, size_t bw) {
  static const unsigned char *atbl = (unsigned char *)"................"
                                                      "................"
                                                      " !\"#$%&'()*+,-./"
                                                      "0123456789:;<=>?"
                                                      "@ABCDEFGHIJKLMNO"
                                                      "PQRSTUVWXYZ[\\]^_"
                                                      "`abcdefghijklmno"
                                                      "pqrstuvwxyz{|}~."
                                                      "................"
                                                      "................"
                                                      "................"
                                                      "................"
                                                      "................"
                                                      "................"
                                                      "................"
                                                      "................";
  static const unsigned char *etbl = (unsigned char *)"................"
                                                      "................"
                                                      "................"
                                                      "................"
                                                      " ...........<(+|"
                                                      "&.........!$*);^"
                                                      "-/.........,%_>?"
                                                      ".........`:#@'=\""
                                                      ".abcdefghi......"
                                                      ".jklmnopqr......"
                                                      ".~stuvwxyz...[.."
                                                      ".............].."
                                                      "{ABCDEFGHI......"
                                                      "}JKLMNOPQR......"
                                                      "\\.STUVWXYZ......"
                                                      "0123456789......";
  const unsigned char *p = (const unsigned char *)addr;
  dprintf(fd, "Dump: \"Address: Content in Hexdecimal, ASCII, EBCDIC\"\n");
  if (bw < 16 && bw > 64) {
    bw = 16;
  }
  unsigned char line[2048];
  const unsigned char *buffer;
  long offset = 0;
  long sz = 0;
  long b = 0;
  long i, j;
  int c;
  __auto_ascii _a;
  while (len > 0) {
    sz = (len > (bw - 1)) ? bw : len;
    buffer = p + offset;
    b = 0;
    b += __snprintf_a((char *)line + b, 2048 - b, "%*p:", 16, buffer);
    for (i = 0; i < sz; ++i) {
      if ((i & 3) == 0)
        line[b++] = ' ';
      c = buffer[i];
      line[b++] = "0123456789abcdef"[(0xf0 & c) >> 4];
      line[b++] = "0123456789abcdef"[(0x0f & c)];
    }
    for (; i < bw; ++i) {
      if ((i & 3) == 0)
        line[b++] = ' ';
      line[b++] = ' ';
      line[b++] = ' ';
    }
    line[b++] = ' ';
    line[b++] = '|';
    for (i = 0; i < sz; ++i) {
      c = buffer[i];
      if (c == -1) {
        line[b++] = '*';
      } else {
        line[b++] = atbl[c];
      }
    }
    for (; i < bw; ++i) {
      line[b++] = ' ';
    }
    line[b++] = '|';
    line[b++] = ' ';
    line[b++] = '|';
    for (i = 0; i < sz; ++i) {
      c = buffer[i];
      if (c == -1) {
        line[b++] = '*';
      } else {
        line[b++] = etbl[c];
      }
    }
    for (; i < bw; ++i) {
      line[b++] = ' ';
    }
    line[b++] = '|';
    line[b++] = 0;
    dprintf(fd, "%-.*s\n", b, line);
    offset += sz;
    len -= sz;
  }
}

__auto_ascii::__auto_ascii(void) {
  ascii_mode = __isASCII();
  if (ascii_mode == 0)
    __ae_thread_swapmode(__AE_ASCII_MODE);
}
__auto_ascii::~__auto_ascii(void) {
  if (ascii_mode == 0)
    __ae_thread_swapmode(__AE_EBCDIC_MODE);
}

static void init_tf_parms_t(__tf_parms_t *parm, char *pu_name_buf, size_t len1,
                            char *entry_name_buf, size_t len2,
                            char *stmt_id_buf, size_t len3) {
  parm->__tf_pu_name.__tf_buff = pu_name_buf;
  parm->__tf_pu_name.__tf_bufflen = len1;
  parm->__tf_entry_name.__tf_buff = entry_name_buf;
  parm->__tf_entry_name.__tf_bufflen = len2;
  parm->__tf_statement_id.__tf_buff = stmt_id_buf;
  parm->__tf_statement_id.__tf_bufflen = len3;
  parm->__tf_dsa_addr = 0;
  parm->__tf_caa_addr = 0;
  parm->__tf_call_instruction = 0;
}

static int backtrace_w(void **buffer, int size);

int backtrace(void **buffer, int size) {
  int mode;
  int result;
  mode = __ae_thread_swapmode(__AE_ASCII_MODE);
  result = backtrace_w(buffer, size);
  __ae_thread_swapmode(mode);
  return result;
}

static int backtrace_w(void **buffer, int size) {
  __tf_parms_t tbck_parms;
  _FEEDBACK fc;
  int rc = 0;
  init_tf_parms_t(&tbck_parms, 0, 0, 0, 0, 0, 0);
  int skip = 2;
  while (size > 0 && !tbck_parms.__tf_is_main) {
    ____le_traceback_a(__TRACEBACK_FIELDS, &tbck_parms, &fc);
    if (fc.tok_sev >= 2) {
      __fprintf_a(stderr, "____le_traceback_a() service failed\n");
      return 0;
    }
    *buffer = tbck_parms.__tf_dsa_addr;
    tbck_parms.__tf_dsa_addr = tbck_parms.__tf_caller_dsa_addr;
    tbck_parms.__tf_call_instruction = tbck_parms.__tf_caller_call_instruction;
    if (skip > 0)
      --skip;
    else {
      ++buffer;
      --size;
      ++rc;
    }
  }
  return rc;
}

static char **backtrace_symbols_w(void *const *buffer, int size);

char **backtrace_symbols(void *const *buffer, int size) {
  int mode;
  char **result;
  mode = __ae_thread_swapmode(__AE_ASCII_MODE);
  result = backtrace_symbols_w(buffer, size);
  __ae_thread_swapmode(mode);
  return result;
}

static char **backtrace_symbols_w(void *const *buffer, int size) {
  int sz;
  char *return_buff;
  char **table;
  char *stringpool;
  char *buff_end;
  __tf_parms_t tbck_parms;
  char pu_name[256];
  char entry_name[256];
  char stmt_id[256];
  char *return_addr;
  _FEEDBACK fc;
  int rc = 0;
  int i;
  int cnt;
  int inst;
  void *caller_dsa = 0;
  void *caller_inst = 0;

  init_tf_parms_t(&tbck_parms, pu_name, 256, entry_name, 256, stmt_id, 256);
  sz = (size * 300); // estimate
  return_buff = (char *)malloc(sz);

  while (return_buff != 0) {
    table = (char **)return_buff;
    stringpool = return_buff + (size * sizeof(void *));
    buff_end = return_buff + sz;
    for (i = 0; i < size; ++i) {
      tbck_parms.__tf_dsa_addr = buffer[i];
      if (tbck_parms.__tf_dsa_addr == caller_dsa) {
        tbck_parms.__tf_call_instruction = caller_inst;
      } else {
        tbck_parms.__tf_call_instruction = 0;
      }
      ____le_traceback_a(__TRACEBACK_FIELDS, &tbck_parms, &fc);
      if (fc.tok_sev >= 2) {
        __fprintf_a(stderr, "____le_traceback_a() service failed\n");
        free(return_buff);
        return 0;
      }
      caller_dsa = tbck_parms.__tf_caller_dsa_addr;
      caller_inst = tbck_parms.__tf_caller_call_instruction;
      inst = *(char *)(tbck_parms.__tf_caller_call_instruction);

      if (inst == 0xa7) {
        // BRAS
        return_addr = 6 + (char *)tbck_parms.__tf_caller_call_instruction;
      } else {
        // BASR
        return_addr = 4 + (char *)tbck_parms.__tf_caller_call_instruction;
      }
      if (tbck_parms.__tf_call_instruction) {
        if (pu_name[0]) {

          cnt = __snprintf_a(stringpool, buff_end - stringpool,
                             "%s:%s (%s+0x%lx) [0x%p]", pu_name, stmt_id,
                             entry_name,
                             (char *)tbck_parms.__tf_call_instruction -
                                 (char *)tbck_parms.__tf_entry_addr,
                             return_addr);
        } else {
          cnt = __snprintf_a(stringpool, buff_end - stringpool,
                             "(%s+0x%lx) [0x%p]", entry_name,
                             (char *)tbck_parms.__tf_call_instruction -
                                 (char *)tbck_parms.__tf_entry_addr,
                             return_addr);
        }
      } else {
        if (pu_name[0]) {
          cnt = __snprintf_a(stringpool, buff_end - stringpool,
                             "%s:%s (%s) [0x%p]", pu_name, stmt_id, entry_name,
                             return_addr);
        } else {
          cnt = __snprintf_a(stringpool, buff_end - stringpool, "(%s) [0x%p]",
                             entry_name, return_addr);
        }
      }
      if (cnt < 0 || cnt >= (buff_end - stringpool)) {
        // out of space
        break;
      }
      table[i] = stringpool;
      stringpool += (cnt + 1);
    }
    if (i == size)
      return &table[0];
    free(return_buff);
    sz += (size * 300);
    return_buff = (char *)malloc(sz);
  }
  return 0;
}
static void backtrace_symbols_fd_w(void *const *buffer, int size, int fd);

void backtrace_symbols_fd(void *const *buffer, int size, int fd) {
  int mode;
  mode = __ae_thread_swapmode(__AE_ASCII_MODE);
  backtrace_symbols_fd_w(buffer, size, fd);
  __ae_thread_swapmode(mode);
}

static void backtrace_symbols_fd_w(void *const *buffer, int size, int fd) {
  __tf_parms_t tbck_parms;
  char pu_name[256];
  char entry_name[256];
  char stmt_id[256];
  char *return_addr;
  char out[4096];
  _FEEDBACK fc;
  int rc = 0;
  int i;
  int inst;
  int cnt;
  void *caller_dsa = 0;
  void *caller_inst = 0;

  init_tf_parms_t(&tbck_parms, pu_name, 256, entry_name, 256, stmt_id, 256);

  for (i = 0; i < size; ++i) {
    tbck_parms.__tf_dsa_addr = buffer[i];
    if (tbck_parms.__tf_dsa_addr == caller_dsa) {
      tbck_parms.__tf_call_instruction = caller_inst;
    } else {
      tbck_parms.__tf_call_instruction = 0;
    }
    ____le_traceback_a(__TRACEBACK_FIELDS, &tbck_parms, &fc);
    if (fc.tok_sev >= 2) {
      write(fd, "____le_traceback_a() service failed\n",
            sizeof("____le_traceback_a() service failed\n") - 1);
      return;
    }
    caller_dsa = tbck_parms.__tf_caller_dsa_addr;
    caller_inst = tbck_parms.__tf_caller_call_instruction;
    inst = *(char *)(tbck_parms.__tf_caller_call_instruction);
    if (inst == 0xa7) {
      // BRAS
      return_addr = 6 + (char *)tbck_parms.__tf_caller_call_instruction;
    } else {
      // BASR
      return_addr = 4 + (char *)tbck_parms.__tf_caller_call_instruction;
    }
    //
    if (tbck_parms.__tf_call_instruction) {
      if (pu_name[0]) {

        cnt = __snprintf_a(out, 4096, "%s:%s (%s+0x%lx) [0x%p]", pu_name,
                           stmt_id, entry_name,
                           (char *)tbck_parms.__tf_call_instruction -
                               (char *)tbck_parms.__tf_entry_addr,
                           return_addr);
      } else {
        cnt = __snprintf_a(out, 4096, "(%s+0x%lx) [0x%p]", entry_name,
                           (char *)tbck_parms.__tf_call_instruction -
                               (char *)tbck_parms.__tf_entry_addr,
                           return_addr);
      }
    } else {
      if (pu_name[0]) {
        cnt = __snprintf_a(out, 4096, "%s:%s (%s) [0x%p]", pu_name, stmt_id,
                           entry_name, return_addr);
      } else {
        cnt = __snprintf_a(out, 4096, "(%s) [0x%p]", entry_name, return_addr);
      }
    }
    if (cnt > 0) {
      write(fd, out, cnt);
      write(fd, "\n", 1);
    }
  }
}

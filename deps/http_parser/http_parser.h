/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifndef http_parser_h
#define http_parser_h
#ifdef __cplusplus
extern "C" {
#endif

/* Also update SONAME in the Makefile whenever you change these. */
#define HTTP_PARSER_VERSION_MAJOR 2
#define HTTP_PARSER_VERSION_MINOR 3
#define HTTP_PARSER_VERSION_PATCH 2

#include <sys/types.h>
#if defined(_WIN32) && !defined(__MINGW32__) && (!defined(_MSC_VER) || _MSC_VER<1600)
#include <BaseTsd.h>
#include <stddef.h>
typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
#else
#include <stdint.h>
#endif

/* Compile with -DHTTP_PARSER_STRICT=0 to make less checks, but run
 * faster
 */
#ifndef HTTP_PARSER_STRICT
# define HTTP_PARSER_STRICT 1
#endif

/* Maximium header size allowed */
#define HTTP_MAX_HEADER_SIZE (80*1024)


typedef struct http_parser http_parser;
typedef struct http_parser_settings http_parser_settings;


/* Callbacks should return non-zero to indicate an error. The parser will
 * then halt execution.
 *
 * The one exception is on_headers_complete. In a HTTP_RESPONSE parser
 * returning '1' from on_headers_complete will tell the parser that it
 * should not expect a body. This is used when receiving a response to a
 * HEAD request which may contain 'Content-Length' or 'Transfer-Encoding:
 * chunked' headers that indicate the presence of a body.
 *
 * http_data_cb does not return data chunks. It will be call arbitrarally
 * many times for each string. E.G. you might get 10 callbacks for "on_url"
 * each providing just a few characters more data.
 */
typedef int (*http_data_cb) (http_parser*, const char *at, size_t length);
typedef int (*http_cb) (http_parser*);


/* Request Methods */
#define HTTP_METHOD_MAP(XX)         \
  XX(0,  DELETE,      DELETE)       \
  XX(1,  GET,         GET)          \
  XX(2,  HEAD,        HEAD)         \
  XX(3,  POST,        POST)         \
  XX(4,  PUT,         PUT)          \
  /* pathological */                \
  XX(5,  CONNECT,     CONNECT)      \
  XX(6,  OPTIONS,     OPTIONS)      \
  XX(7,  TRACE,       TRACE)        \
  /* webdav */                      \
  XX(8,  COPY,        COPY)         \
  XX(9,  LOCK,        LOCK)         \
  XX(10, MKCOL,       MKCOL)        \
  XX(11, MOVE,        MOVE)         \
  XX(12, PROPFIND,    PROPFIND)     \
  XX(13, PROPPATCH,   PROPPATCH)    \
  XX(14, SEARCH,      SEARCH)       \
  XX(15, UNLOCK,      UNLOCK)       \
  /* subversion */                  \
  XX(16, REPORT,      REPORT)       \
  XX(17, MKACTIVITY,  MKACTIVITY)   \
  XX(18, CHECKOUT,    CHECKOUT)     \
  XX(19, MERGE,       MERGE)        \
  /* upnp */                        \
  XX(20, MSEARCH,     M-SEARCH)     \
  XX(21, NOTIFY,      NOTIFY)       \
  XX(22, SUBSCRIBE,   SUBSCRIBE)    \
  XX(23, UNSUBSCRIBE, UNSUBSCRIBE)  \
  /* RFC-5789 */                    \
  XX(24, PATCH,       PATCH)        \
  XX(25, PURGE,       PURGE)        \

enum http_method
  {
#define XX(num, name, string) HTTP_##name = num,
  HTTP_METHOD_MAP(XX)
#undef XX
  };


enum http_parser_type { HTTP_REQUEST, HTTP_RESPONSE, HTTP_BOTH };


/* Flag values for http_parser.flags field */
enum flags
  { F_CHUNKED               = 1 << 0
  , F_CONNECTION_KEEP_ALIVE = 1 << 1
  , F_CONNECTION_CLOSE      = 1 << 2
  , F_TRAILING              = 1 << 3
  , F_UPGRADE               = 1 << 4
  , F_SKIPBODY              = 1 << 5
  , F_CONTENTLENGTH         = 1 << 6
  };


/* Map for errno-related constants
 * 
 * The provided argument should be a macro that takes 2 arguments.
 */
#define HTTP_ERRNO_MAP(XX)                                           \
  /* No error */                                                     \
  XX(OK, "\x73\x75\x63\x63\x65\x73\x73")                                                  \
                                                                     \
  /* Callback-related errors */                                      \
  XX(CB_message_begin, "\x74\x68\x65\x20\x6f\x6e\x5f\x6d\x65\x73\x73\x61\x67\x65\x5f\x62\x65\x67\x69\x6e\x20\x63\x61\x6c\x6c\x62\x61\x63\x6b\x20\x66\x61\x69\x6c\x65\x64")       \
  XX(CB_url, "\x74\x68\x65\x20\x6f\x6e\x5f\x75\x72\x6c\x20\x63\x61\x6c\x6c\x62\x61\x63\x6b\x20\x66\x61\x69\x6c\x65\x64")                           \
  XX(CB_header_field, "\x74\x68\x65\x20\x6f\x6e\x5f\x68\x65\x61\x64\x65\x72\x5f\x66\x69\x65\x6c\x64\x20\x63\x61\x6c\x6c\x62\x61\x63\x6b\x20\x66\x61\x69\x6c\x65\x64")         \
  XX(CB_header_value, "\x74\x68\x65\x20\x6f\x6e\x5f\x68\x65\x61\x64\x65\x72\x5f\x76\x61\x6c\x75\x65\x20\x63\x61\x6c\x6c\x62\x61\x63\x6b\x20\x66\x61\x69\x6c\x65\x64")         \
  XX(CB_headers_complete, "\x74\x68\x65\x20\x6f\x6e\x5f\x68\x65\x61\x64\x65\x72\x73\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\x20\x63\x61\x6c\x6c\x62\x61\x63\x6b\x20\x66\x61\x69\x6c\x65\x64") \
  XX(CB_body, "\x74\x68\x65\x20\x6f\x6e\x5f\x62\x6f\x64\x79\x20\x63\x61\x6c\x6c\x62\x61\x63\x6b\x20\x66\x61\x69\x6c\x65\x64")                         \
  XX(CB_message_complete, "\x74\x68\x65\x20\x6f\x6e\x5f\x6d\x65\x73\x73\x61\x67\x65\x5f\x63\x6f\x6d\x70\x6c\x65\x74\x65\x20\x63\x61\x6c\x6c\x62\x61\x63\x6b\x20\x66\x61\x69\x6c\x65\x64") \
  XX(CB_status, "\x74\x68\x65\x20\x6f\x6e\x5f\x73\x74\x61\x74\x75\x73\x20\x63\x61\x6c\x6c\x62\x61\x63\x6b\x20\x66\x61\x69\x6c\x65\x64")                     \
                                                                     \
  /* Parsing-related errors */                                       \
  XX(INVALID_EOF_STATE, "\x73\x74\x72\x65\x61\x6d\x20\x65\x6e\x64\x65\x64\x20\x61\x74\x20\x61\x6e\x20\x75\x6e\x65\x78\x70\x65\x63\x74\x65\x64\x20\x74\x69\x6d\x65")        \
  XX(HEADER_OVERFLOW,                                                \
     "\x74\x6f\x6f\x20\x6d\x61\x6e\x79\x20\x68\x65\x61\x64\x65\x72\x20\x62\x79\x74\x65\x73\x20\x73\x65\x65\x6e\x3b\x20\x6f\x76\x65\x72\x66\x6c\x6f\x77\x20\x64\x65\x74\x65\x63\x74\x65\x64")                \
  XX(CLOSED_CONNECTION,                                              \
     "\x64\x61\x74\x61\x20\x72\x65\x63\x65\x69\x76\x65\x64\x20\x61\x66\x74\x65\x72\x20\x63\x6f\x6d\x70\x6c\x65\x74\x65\x64\x20\x63\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x3a\x20\x63\x6c\x6f\x73\x65\x20\x6d\x65\x73\x73\x61\x67\x65")      \
  XX(INVALID_VERSION, "\x69\x6e\x76\x61\x6c\x69\x64\x20\x48\x54\x54\x50\x20\x76\x65\x72\x73\x69\x6f\x6e")                        \
  XX(INVALID_STATUS, "\x69\x6e\x76\x61\x6c\x69\x64\x20\x48\x54\x54\x50\x20\x73\x74\x61\x74\x75\x73\x20\x63\x6f\x64\x65")                     \
  XX(INVALID_METHOD, "\x69\x6e\x76\x61\x6c\x69\x64\x20\x48\x54\x54\x50\x20\x6d\x65\x74\x68\x6f\x64")                          \
  XX(INVALID_URL, "\x69\x6e\x76\x61\x6c\x69\x64\x20\x55\x52\x4c")                                     \
  XX(INVALID_HOST, "\x69\x6e\x76\x61\x6c\x69\x64\x20\x68\x6f\x73\x74")                                   \
  XX(INVALID_PORT, "\x69\x6e\x76\x61\x6c\x69\x64\x20\x70\x6f\x72\x74")                                   \
  XX(INVALID_PATH, "\x69\x6e\x76\x61\x6c\x69\x64\x20\x70\x61\x74\x68")                                   \
  XX(INVALID_QUERY_STRING, "\x69\x6e\x76\x61\x6c\x69\x64\x20\x71\x75\x65\x72\x79\x20\x73\x74\x72\x69\x6e\x67")                   \
  XX(INVALID_FRAGMENT, "\x69\x6e\x76\x61\x6c\x69\x64\x20\x66\x72\x61\x67\x6d\x65\x6e\x74")                           \
  XX(LF_EXPECTED, "\x4c\x46\x20\x63\x68\x61\x72\x61\x63\x74\x65\x72\x20\x65\x78\x70\x65\x63\x74\x65\x64")                           \
  XX(INVALID_HEADER_TOKEN, "\x69\x6e\x76\x61\x6c\x69\x64\x20\x63\x68\x61\x72\x61\x63\x74\x65\x72\x20\x69\x6e\x20\x68\x65\x61\x64\x65\x72")            \
  XX(INVALID_CONTENT_LENGTH,                                         \
     "\x69\x6e\x76\x61\x6c\x69\x64\x20\x63\x68\x61\x72\x61\x63\x74\x65\x72\x20\x69\x6e\x20\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x6c\x65\x6e\x67\x74\x68\x20\x68\x65\x61\x64\x65\x72")                   \
  XX(UNEXPECTED_CONTENT_LENGTH,                                      \
     "\x75\x6e\x65\x78\x70\x65\x63\x74\x65\x64\x20\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x6c\x65\x6e\x67\x74\x68\x20\x68\x65\x61\x64\x65\x72")                             \
  XX(INVALID_CHUNK_SIZE,                                             \
     "\x69\x6e\x76\x61\x6c\x69\x64\x20\x63\x68\x61\x72\x61\x63\x74\x65\x72\x20\x69\x6e\x20\x63\x68\x75\x6e\x6b\x20\x73\x69\x7a\x65\x20\x68\x65\x61\x64\x65\x72")                       \
  XX(INVALID_CONSTANT, "\x69\x6e\x76\x61\x6c\x69\x64\x20\x63\x6f\x6e\x73\x74\x61\x6e\x74\x20\x73\x74\x72\x69\x6e\x67")                    \
  XX(INVALID_INTERNAL_STATE, "\x65\x6e\x63\x6f\x75\x6e\x74\x65\x72\x65\x64\x20\x75\x6e\x65\x78\x70\x65\x63\x74\x65\x64\x20\x69\x6e\x74\x65\x72\x6e\x61\x6c\x20\x73\x74\x61\x74\x65")\
  XX(STRICT, "\x73\x74\x72\x69\x63\x74\x20\x6d\x6f\x64\x65\x20\x61\x73\x73\x65\x72\x74\x69\x6f\x6e\x20\x66\x61\x69\x6c\x65\x64")                         \
  XX(PAUSED, "\x70\x61\x72\x73\x65\x72\x20\x69\x73\x20\x70\x61\x75\x73\x65\x64")                                     \
  XX(UNKNOWN, "\x61\x6e\x20\x75\x6e\x6b\x6e\x6f\x77\x6e\x20\x65\x72\x72\x6f\x72\x20\x6f\x63\x63\x75\x72\x72\x65\x64")


/* Define HPE_* values for each errno value above */
#define HTTP_ERRNO_GEN(n, s) HPE_##n,
enum http_errno {
  HTTP_ERRNO_MAP(HTTP_ERRNO_GEN)
};
#undef HTTP_ERRNO_GEN


/* Get an http_errno value from an http_parser */
#define HTTP_PARSER_ERRNO(p)            ((enum http_errno) (p)->http_errno)


struct http_parser {
  /** PRIVATE **/
  unsigned int type : 2;         /* enum http_parser_type */
  unsigned int flags : 7;        /* F_* values from 'flags' enum; semi-public */
  unsigned int state : 8;        /* enum state from http_parser.c */
  unsigned int header_state : 7; /* enum header_state from http_parser.c */
  unsigned int index : 7;        /* index into current matcher */
  unsigned int lenient_http_headers : 1;

  uint32_t nread;          /* # bytes read in various scenarios */
  uint64_t content_length; /* # bytes in body (0 if no Content-Length header) */

  /** READ-ONLY **/
  unsigned short http_major;
  unsigned short http_minor;
  unsigned int status_code : 16; /* responses only */
  unsigned int method : 8;       /* requests only */
  unsigned int http_errno : 7;

  /* 1 = Upgrade header was present and the parser has exited because of that.
   * 0 = No upgrade header present.
   * Should be checked when http_parser_execute() returns in addition to
   * error checking.
   */
  unsigned int upgrade : 1;

  /** PUBLIC **/
  void *data; /* A pointer to get hook to the "\x63\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e" or "\x73\x6f\x63\x6b\x65\x74" object */
};


struct http_parser_settings {
  http_cb      on_message_begin;
  http_data_cb on_url;
  http_data_cb on_status;
  http_data_cb on_header_field;
  http_data_cb on_header_value;
  http_cb      on_headers_complete;
  http_data_cb on_body;
  http_cb      on_message_complete;
};


enum http_parser_url_fields
  { UF_SCHEMA           = 0
  , UF_HOST             = 1
  , UF_PORT             = 2
  , UF_PATH             = 3
  , UF_QUERY            = 4
  , UF_FRAGMENT         = 5
  , UF_USERINFO         = 6
  , UF_MAX              = 7
  };


/* Result structure for http_parser_parse_url().
 *
 * Callers should index into field_data[] with UF_* values iff field_set
 * has the relevant (1 << UF_*) bit set. As a courtesy to clients (and
 * because we probably have padding left over), we convert any port to
 * a uint16_t.
 */
struct http_parser_url {
  uint16_t field_set;           /* Bitmask of (1 << UF_*) values */
  uint16_t port;                /* Converted UF_PORT string */

  struct {
    uint16_t off;               /* Offset into buffer in which field starts */
    uint16_t len;               /* Length of run in buffer */
  } field_data[UF_MAX];
};


/* Returns the library version. Bits 16-23 contain the major version number,
 * bits 8-15 the minor version number and bits 0-7 the patch level.
 * Usage example:
 *
 *   unsigned long version = http_parser_version();
 *   unsigned major = (version >> 16) & 255;
 *   unsigned minor = (version >> 8) & 255;
 *   unsigned patch = version & 255;
 *   printf("http_parser v%u.%u.%u\n", major, minor, version);
 */
unsigned long http_parser_version(void);

void http_parser_init(http_parser *parser, enum http_parser_type type);


size_t http_parser_execute(http_parser *parser,
                           const http_parser_settings *settings,
                           const char *data,
                           size_t len);


/* If http_should_keep_alive() in the on_headers_complete or
 * on_message_complete callback returns 0, then this should be
 * the last message on the connection.
 * If you are the server, respond with the "Connection: close" header.
 * If you are the client, close the connection.
 */
int http_should_keep_alive(const http_parser *parser);

/* Returns a string version of the HTTP method. */
const char *http_method_str(enum http_method m);

/* Return a string name of the given error */
const char *http_errno_name(enum http_errno err);

/* Return a string description of the given error */
const char *http_errno_description(enum http_errno err);

/* Parse a URL; return nonzero on failure */
int http_parser_parse_url(const char *buf, size_t buflen,
                          int is_connect,
                          struct http_parser_url *u);

/* Pause or un-pause the parser; a nonzero value pauses */
void http_parser_pause(http_parser *parser, int paused);

/* Checks if this is the final chunk of the body. */
int http_body_is_final(const http_parser *parser);

#ifdef __cplusplus
}
#endif
#endif

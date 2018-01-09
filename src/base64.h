#ifndef SRC_BASE64_H_
#define SRC_BASE64_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "util.h"

#include <stddef.h>
#include <stdint.h>

namespace node {
//// Base 64 ////
#define base64_encoded_size(size) ((size + 2 - ((size + 2) % 3)) / 3 * 4)


// Doesn't check for padding at the end.  Can be 1-2 bytes over.
static inline size_t base64_decoded_size_fast(size_t size) {
  size_t remainder = size % 4;

  size = (size / 4) * 3;
  if (remainder) {
    if (size == 0 && remainder == 1) {
      // special case: 1-byte input cannot be decoded
      size = 0;
    } else {
      // non-padded input, add 1 or 2 extra bytes
      size += 1 + (remainder == 3);
    }
  }

  return size;
}

template <typename TypeName>
size_t base64_decoded_size(const TypeName* src, size_t size) {
  if (size == 0)
    return 0;

  if (src[size - 1] == '\x3d')
    size--;
  if (size > 0 && src[size - 1] == '\x3d')
    size--;

  return base64_decoded_size_fast(size);
}


extern const int8_t unbase64_table[256];


#define unbase64(x)                                                           \
  static_cast<uint8_t>(unbase64_table[static_cast<uint8_t>(x)])


template <typename TypeName>
size_t base64_decode_slow(char* dst, size_t dstlen,
                          const TypeName* src, size_t srclen) {
  uint8_t hi;
  uint8_t lo;
  size_t i = 0;
  size_t k = 0;
  for (;;) {
#define V(expr)                                                               \
    for (;;) {                                                                \
      const uint8_t c = src[i];                                               \
      lo = unbase64(c);                                                       \
      i += 1;                                                                 \
      if (lo < 64)                                                            \
        break;  /* Legal character. */                                        \
      if (c == '\x3d' || i >= srclen)                                            \
        return k;                                                             \
    }                                                                         \
    expr;                                                                     \
    if (i >= srclen)                                                          \
      return k;                                                               \
    if (k >= dstlen)                                                          \
      return k;                                                               \
    hi = lo;
    V(/* Nothing. */);
    V(dst[k++] = ((hi & 0x3F) << 2) | ((lo & 0x30) >> 4));
    V(dst[k++] = ((hi & 0x0F) << 4) | ((lo & 0x3C) >> 2));
    V(dst[k++] = ((hi & 0x03) << 6) | ((lo & 0x3F) >> 0));
#undef V
  }
  UNREACHABLE();
}


template <typename TypeName>
size_t base64_decode_fast(char* const dst, const size_t dstlen,
                          const TypeName* const src, const size_t srclen,
                          const size_t decoded_size) {
  const size_t available = dstlen < decoded_size ? dstlen : decoded_size;
  const size_t max_i = srclen / 4 * 4;
  const size_t max_k = available / 3 * 3;
  size_t i = 0;
  size_t k = 0;
  while (i < max_i && k < max_k) {
    const uint32_t v =
        unbase64(src[i + 0]) << 24 |
        unbase64(src[i + 1]) << 16 |
        unbase64(src[i + 2]) << 8 |
        unbase64(src[i + 3]);
    // If MSB is set, input contains whitespace or is not valid base64.
    if (v & 0x80808080) {
      break;
    }
    dst[k + 0] = ((v >> 22) & 0xFC) | ((v >> 20) & 0x03);
    dst[k + 1] = ((v >> 12) & 0xF0) | ((v >> 10) & 0x0F);
    dst[k + 2] = ((v >>  2) & 0xC0) | ((v >>  0) & 0x3F);
    i += 4;
    k += 3;
  }
  if (i < srclen && k < dstlen) {
    return k + base64_decode_slow(dst + k, dstlen - k, src + i, srclen - i);
  }
  return k;
}


template <typename TypeName>
size_t base64_decode(char* const dst, const size_t dstlen,
                     const TypeName* const src, const size_t srclen) {
  const size_t decoded_size = base64_decoded_size(src, srclen);
  return base64_decode_fast(dst, dstlen, src, srclen, decoded_size);
}

static size_t base64_encode(const char* src,
                            size_t slen,
                            char* dst,
                            size_t dlen) {
  // We know how much we'll write, just make sure that there's space.
  CHECK(dlen >= base64_encoded_size(slen) &&
        "\x6e\x6f\x74\x20\x65\x6e\x6f\x75\x67\x68\x20\x73\x70\x61\x63\x65\x20\x70\x72\x6f\x76\x69\x64\x65\x64\x20\x66\x6f\x72\x20\x62\x61\x73\x65\x36\x34\x20\x65\x6e\x63\x6f\x64\x65");

  dlen = base64_encoded_size(slen);

  unsigned a;
  unsigned b;
  unsigned c;
  unsigned i;
  unsigned k;
  unsigned n;

  static const char table[] = "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a"
                              "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a"
                              "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x2b\x2f";

  i = 0;
  k = 0;
  n = slen / 3 * 3;

  while (i < n) {
    a = src[i + 0] & 0xff;
    b = src[i + 1] & 0xff;
    c = src[i + 2] & 0xff;

    dst[k + 0] = table[a >> 2];
    dst[k + 1] = table[((a & 3) << 4) | (b >> 4)];
    dst[k + 2] = table[((b & 0x0f) << 2) | (c >> 6)];
    dst[k + 3] = table[c & 0x3f];

    i += 3;
    k += 4;
  }

  if (n != slen) {
    switch (slen - n) {
      case 1:
        a = src[i + 0] & 0xff;
        dst[k + 0] = table[a >> 2];
        dst[k + 1] = table[(a & 3) << 4];
        dst[k + 2] = '\x3d';
        dst[k + 3] = '\x3d';
        break;

      case 2:
        a = src[i + 0] & 0xff;
        b = src[i + 1] & 0xff;
        dst[k + 0] = table[a >> 2];
        dst[k + 1] = table[((a & 3) << 4) | (b >> 4)];
        dst[k + 2] = table[(b & 0x0f) << 2];
        dst[k + 3] = '\x3d';
        break;
    }
  }

  return dlen;
}
}  // namespace node


#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_BASE64_H_

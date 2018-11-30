#include "../bn_lcl.h"
#if !(defined(__GNUC__) && __GNUC__>=2)
# include "../bn_asm.c"         /* kind of dirty hack for Sun Studio */
#else
/*-
 * x86_64 BIGNUM accelerator version 0.1, December 2002.
 *
 * Implemented by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
 * project.
 *
 * Rights for redistribution and usage in source and binary forms are
 * granted according to the OpenSSL license. Warranty of any kind is
 * disclaimed.
 *
 * Q. Version 0.1? It doesn't sound like Andy, he used to assign real
 *    versions, like 1.0...
 * A. Well, that's because this code is basically a quick-n-dirty
 *    proof-of-concept hack. As you can see it's implemented with
 *    inline assembler, which means that you're bound to GCC and that
 *    there might be enough room for further improvement.
 *
 * Q. Why inline assembler?
 * A. x86_64 features own ABI which I'm not familiar with. This is
 *    why I decided to let the compiler take care of subroutine
 *    prologue/epilogue as well as register allocation. For reference.
 *    Win64 implements different ABI for AMD64, different from Linux.
 *
 * Q. How much faster does it get?
 * A. 'apps/openssl speed rsa dsa' output with no-asm:
 *
 *                        sign    verify    sign/s verify/s
 *      rsa  512 bits   0.0006s   0.0001s   1683.8  18456.2
 *      rsa 1024 bits   0.0028s   0.0002s    356.0   6407.0
 *      rsa 2048 bits   0.0172s   0.0005s     58.0   1957.8
 *      rsa 4096 bits   0.1155s   0.0018s      8.7    555.6
 *                        sign    verify    sign/s verify/s
 *      dsa  512 bits   0.0005s   0.0006s   2100.8   1768.3
 *      dsa 1024 bits   0.0014s   0.0018s    692.3    559.2
 *      dsa 2048 bits   0.0049s   0.0061s    204.7    165.0
 *
 *    'apps/openssl speed rsa dsa' output with this module:
 *
 *                        sign    verify    sign/s verify/s
 *      rsa  512 bits   0.0004s   0.0000s   2767.1  33297.9
 *      rsa 1024 bits   0.0012s   0.0001s    867.4  14674.7
 *      rsa 2048 bits   0.0061s   0.0002s    164.0   5270.0
 *      rsa 4096 bits   0.0384s   0.0006s     26.1   1650.8
 *                        sign    verify    sign/s verify/s
 *      dsa  512 bits   0.0002s   0.0003s   4442.2   3786.3
 *      dsa 1024 bits   0.0005s   0.0007s   1835.1   1497.4
 *      dsa 2048 bits   0.0016s   0.0020s    620.4    504.6
 *
 *    For the reference. IA-32 assembler implementation performs
 *    very much like 64-bit code compiled with no-asm on the same
 *    machine.
 */

# undef mul
# undef mul_add

/*-
 * "m"(a), "+m"(r)      is the way to favor DirectPath µ-code;
 * "g"(0)               let the compiler to decide where does it
 *                      want to keep the value of zero;
 */
# define mul_add(r,a,word,carry) do {   \
        register BN_ULONG high,low;     \
        asm ("\x6d\x75\x6c\x71\x20\x25\x33"                  \
                : "\x3d\x61"(low),"\x3d\x64"(high)  \
                : "\x61"(word),"\x6d"(a)      \
                : "\x63\x63");                \
        asm ("\x61\x64\x64\x71\x20\x25\x32\x2c\x25\x30\x3b\x20\x61\x64\x63\x71\x20\x25\x33\x2c\x25\x31"   \
                : "\x2b\x72"(carry),"\x2b\x64"(high)\
                : "\x61"(low),"\x67"(0)       \
                : "\x63\x63");                \
        asm ("\x61\x64\x64\x71\x20\x25\x32\x2c\x25\x30\x3b\x20\x61\x64\x63\x71\x20\x25\x33\x2c\x25\x31"   \
                : "\x2b\x6d"(r),"\x2b\x64"(high)    \
                : "\x72"(carry),"\x67"(0)     \
                : "\x63\x63");                \
        carry=high;                     \
        } while (0)

# define mul(r,a,word,carry) do {       \
        register BN_ULONG high,low;     \
        asm ("\x6d\x75\x6c\x71\x20\x25\x33"                  \
                : "\x3d\x61"(low),"\x3d\x64"(high)  \
                : "\x61"(word),"\x67"(a)      \
                : "\x63\x63");                \
        asm ("\x61\x64\x64\x71\x20\x25\x32\x2c\x25\x30\x3b\x20\x61\x64\x63\x71\x20\x25\x33\x2c\x25\x31"   \
                : "\x2b\x72"(carry),"\x2b\x64"(high)\
                : "\x61"(low),"\x67"(0)       \
                : "\x63\x63");                \
        (r)=carry, carry=high;          \
        } while (0)
# undef sqr
# define sqr(r0,r1,a)                   \
        asm ("\x6d\x75\x6c\x71\x20\x25\x32"                  \
                : "\x3d\x61"(r0),"\x3d\x64"(r1)     \
                : "\x61"(a)                \
                : "\x63\x63");

BN_ULONG bn_mul_add_words(BN_ULONG *rp, const BN_ULONG *ap, int num,
                          BN_ULONG w)
{
    BN_ULONG c1 = 0;

    if (num <= 0)
        return (c1);

    while (num & ~3) {
        mul_add(rp[0], ap[0], w, c1);
        mul_add(rp[1], ap[1], w, c1);
        mul_add(rp[2], ap[2], w, c1);
        mul_add(rp[3], ap[3], w, c1);
        ap += 4;
        rp += 4;
        num -= 4;
    }
    if (num) {
        mul_add(rp[0], ap[0], w, c1);
        if (--num == 0)
            return c1;
        mul_add(rp[1], ap[1], w, c1);
        if (--num == 0)
            return c1;
        mul_add(rp[2], ap[2], w, c1);
        return c1;
    }

    return (c1);
}

BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
{
    BN_ULONG c1 = 0;

    if (num <= 0)
        return (c1);

    while (num & ~3) {
        mul(rp[0], ap[0], w, c1);
        mul(rp[1], ap[1], w, c1);
        mul(rp[2], ap[2], w, c1);
        mul(rp[3], ap[3], w, c1);
        ap += 4;
        rp += 4;
        num -= 4;
    }
    if (num) {
        mul(rp[0], ap[0], w, c1);
        if (--num == 0)
            return c1;
        mul(rp[1], ap[1], w, c1);
        if (--num == 0)
            return c1;
        mul(rp[2], ap[2], w, c1);
    }
    return (c1);
}

void bn_sqr_words(BN_ULONG *r, const BN_ULONG *a, int n)
{
    if (n <= 0)
        return;

    while (n & ~3) {
        sqr(r[0], r[1], a[0]);
        sqr(r[2], r[3], a[1]);
        sqr(r[4], r[5], a[2]);
        sqr(r[6], r[7], a[3]);
        a += 4;
        r += 8;
        n -= 4;
    }
    if (n) {
        sqr(r[0], r[1], a[0]);
        if (--n == 0)
            return;
        sqr(r[2], r[3], a[1]);
        if (--n == 0)
            return;
        sqr(r[4], r[5], a[2]);
    }
}

BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d)
{
    BN_ULONG ret, waste;

 asm("\x64\x69\x76\x71\x20\x20\x20\x20\x20\x20\x25\x34":"\x3d\x61"(ret), "\x3d\x64"(waste)
 :     "\x61"(l), "\x64"(h), "\x72"(d)
 :     "\x63\x63");

    return ret;
}

BN_ULONG bn_add_words(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,
                      int n)
{
    BN_ULONG ret;
    size_t i = 0;

    if (n <= 0)
        return 0;

    asm volatile ("\x20\x20\x20\x20\x20\x20\x20\x73\x75\x62\x71\x20\x20\x20\x20\x25\x30\x2c\x25\x30\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\xa" /* clear carry */
                  "\x20\x20\x20\x20\x20\x20\x20\x6a\x6d\x70\x20\x20\x20\x20\x20\x31\x66\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\xa"
                  "\x2e\x70\x32\x61\x6c\x69\x67\x6e\x20\x34\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\xa"
                  "\x31\x3a\x20\x20\x20\x20\x20\x6d\x6f\x76\x71\x20\x20\x20\x20\x28\x25\x34\x2c\x25\x32\x2c\x38\x29\x2c\x25\x30\x20\x20\x20\x20\xa"
                  "\x20\x20\x20\x20\x20\x20\x20\x61\x64\x63\x71\x20\x20\x20\x20\x28\x25\x35\x2c\x25\x32\x2c\x38\x29\x2c\x25\x30\x20\x20\x20\x20\xa"
                  "\x20\x20\x20\x20\x20\x20\x20\x6d\x6f\x76\x71\x20\x20\x20\x20\x25\x30\x2c\x28\x25\x33\x2c\x25\x32\x2c\x38\x29\x20\x20\x20\x20\xa"
                  "\x20\x20\x20\x20\x20\x20\x20\x6c\x65\x61\x20\x20\x20\x20\x20\x31\x28\x25\x32\x29\x2c\x25\x32\x20\x20\x20\x20\x20\x20\x20\x20\xa"
                  "\x20\x20\x20\x20\x20\x20\x20\x6c\x6f\x6f\x70\x20\x20\x20\x20\x31\x62\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\xa"
                  "\x20\x20\x20\x20\x20\x20\x20\x73\x62\x62\x71\x20\x20\x20\x20\x25\x30\x2c\x25\x30\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\xa":"\x3d\x26\x72" (ret), "\x2b\x63"(n),
                  "\x2b\x72"(i)
                  :"\x72"(rp), "\x72"(ap), "\x72"(bp)
                  :"\x63\x63", "\x6d\x65\x6d\x6f\x72\x79");

    return ret & 1;
}

# ifndef SIMICS
BN_ULONG bn_sub_words(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,
                      int n)
{
    BN_ULONG ret;
    size_t i = 0;

    if (n <= 0)
        return 0;

    asm volatile ("\x20\x20\x20\x20\x20\x20\x20\x73\x75\x62\x71\x20\x20\x20\x20\x25\x30\x2c\x25\x30\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\xa" /* clear borrow */
                  "\x20\x20\x20\x20\x20\x20\x20\x6a\x6d\x70\x20\x20\x20\x20\x20\x31\x66\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\xa"
                  "\x2e\x70\x32\x61\x6c\x69\x67\x6e\x20\x34\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\xa"
                  "\x31\x3a\x20\x20\x20\x20\x20\x6d\x6f\x76\x71\x20\x20\x20\x20\x28\x25\x34\x2c\x25\x32\x2c\x38\x29\x2c\x25\x30\x20\x20\x20\x20\xa"
                  "\x20\x20\x20\x20\x20\x20\x20\x73\x62\x62\x71\x20\x20\x20\x20\x28\x25\x35\x2c\x25\x32\x2c\x38\x29\x2c\x25\x30\x20\x20\x20\x20\xa"
                  "\x20\x20\x20\x20\x20\x20\x20\x6d\x6f\x76\x71\x20\x20\x20\x20\x25\x30\x2c\x28\x25\x33\x2c\x25\x32\x2c\x38\x29\x20\x20\x20\x20\xa"
                  "\x20\x20\x20\x20\x20\x20\x20\x6c\x65\x61\x20\x20\x20\x20\x20\x31\x28\x25\x32\x29\x2c\x25\x32\x20\x20\x20\x20\x20\x20\x20\x20\xa"
                  "\x20\x20\x20\x20\x20\x20\x20\x6c\x6f\x6f\x70\x20\x20\x20\x20\x31\x62\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\xa"
                  "\x20\x20\x20\x20\x20\x20\x20\x73\x62\x62\x71\x20\x20\x20\x20\x25\x30\x2c\x25\x30\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\xa":"\x3d\x26\x72" (ret), "\x2b\x63"(n),
                  "\x2b\x72"(i)
                  :"\x72"(rp), "\x72"(ap), "\x72"(bp)
                  :"\x63\x63", "\x6d\x65\x6d\x6f\x72\x79");

    return ret & 1;
}
# else
/* Simics 1.4<7 has buggy sbbq:-( */
#  define BN_MASK2 0xffffffffffffffffL
BN_ULONG bn_sub_words(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b, int n)
{
    BN_ULONG t1, t2;
    int c = 0;

    if (n <= 0)
        return ((BN_ULONG)0);

    for (;;) {
        t1 = a[0];
        t2 = b[0];
        r[0] = (t1 - t2 - c) & BN_MASK2;
        if (t1 != t2)
            c = (t1 < t2);
        if (--n <= 0)
            break;

        t1 = a[1];
        t2 = b[1];
        r[1] = (t1 - t2 - c) & BN_MASK2;
        if (t1 != t2)
            c = (t1 < t2);
        if (--n <= 0)
            break;

        t1 = a[2];
        t2 = b[2];
        r[2] = (t1 - t2 - c) & BN_MASK2;
        if (t1 != t2)
            c = (t1 < t2);
        if (--n <= 0)
            break;

        t1 = a[3];
        t2 = b[3];
        r[3] = (t1 - t2 - c) & BN_MASK2;
        if (t1 != t2)
            c = (t1 < t2);
        if (--n <= 0)
            break;

        a += 4;
        b += 4;
        r += 4;
    }
    return (c);
}
# endif

/* mul_add_c(a,b,c0,c1,c2)  -- c+=a*b for three word number c=(c2,c1,c0) */
/* mul_add_c2(a,b,c0,c1,c2) -- c+=2*a*b for three word number c=(c2,c1,c0) */
/* sqr_add_c(a,i,c0,c1,c2)  -- c+=a[i]^2 for three word number c=(c2,c1,c0) */
/*
 * sqr_add_c2(a,i,c0,c1,c2) -- c+=2*a[i]*a[j] for three word number
 * c=(c2,c1,c0)
 */

/*
 * Keep in mind that carrying into high part of multiplication result
 * can not overflow, because it cannot be all-ones.
 */
# if 0
/* original macros are kept for reference purposes */
#  define mul_add_c(a,b,c0,c1,c2)       do {    \
        BN_ULONG ta = (a), tb = (b);            \
        BN_ULONG lo, hi;                        \
        BN_UMULT_LOHI(lo,hi,ta,tb);             \
        c0 += lo; hi += (c0<lo)?1:0;            \
        c1 += hi; c2 += (c1<hi)?1:0;            \
        } while(0)

#  define mul_add_c2(a,b,c0,c1,c2)      do {    \
        BN_ULONG ta = (a), tb = (b);            \
        BN_ULONG lo, hi, tt;                    \
        BN_UMULT_LOHI(lo,hi,ta,tb);             \
        c0 += lo; tt = hi+((c0<lo)?1:0);        \
        c1 += tt; c2 += (c1<tt)?1:0;            \
        c0 += lo; hi += (c0<lo)?1:0;            \
        c1 += hi; c2 += (c1<hi)?1:0;            \
        } while(0)

#  define sqr_add_c(a,i,c0,c1,c2)       do {    \
        BN_ULONG ta = (a)[i];                   \
        BN_ULONG lo, hi;                        \
        BN_UMULT_LOHI(lo,hi,ta,ta);             \
        c0 += lo; hi += (c0<lo)?1:0;            \
        c1 += hi; c2 += (c1<hi)?1:0;            \
        } while(0)
# else
#  define mul_add_c(a,b,c0,c1,c2) do {  \
        BN_ULONG t1,t2;                 \
        asm ("\x6d\x75\x6c\x71\x20\x25\x33"                  \
                : "\x3d\x61"(t1),"\x3d\x64"(t2)     \
                : "\x61"(a),"\x6d"(b)         \
                : "\x63\x63");                \
        asm ("\x61\x64\x64\x71\x20\x25\x33\x2c\x25\x30\x3b\x20\x61\x64\x63\x71\x20\x25\x34\x2c\x25\x31\x3b\x20\x61\x64\x63\x71\x20\x25\x35\x2c\x25\x32"       \
                : "\x2b\x72"(c0),"\x2b\x72"(c1),"\x2b\x72"(c2)            \
                : "\x72"(t1),"\x72"(t2),"\x67"(0)                \
                : "\x63\x63");                                \
        } while (0)

#  define sqr_add_c(a,i,c0,c1,c2) do {  \
        BN_ULONG t1,t2;                 \
        asm ("\x6d\x75\x6c\x71\x20\x25\x32"                  \
                : "\x3d\x61"(t1),"\x3d\x64"(t2)     \
                : "\x61"(a[i])             \
                : "\x63\x63");                \
        asm ("\x61\x64\x64\x71\x20\x25\x33\x2c\x25\x30\x3b\x20\x61\x64\x63\x71\x20\x25\x34\x2c\x25\x31\x3b\x20\x61\x64\x63\x71\x20\x25\x35\x2c\x25\x32"       \
                : "\x2b\x72"(c0),"\x2b\x72"(c1),"\x2b\x72"(c2)            \
                : "\x72"(t1),"\x72"(t2),"\x67"(0)                \
                : "\x63\x63");                                \
        } while (0)

#  define mul_add_c2(a,b,c0,c1,c2) do { \
        BN_ULONG t1,t2;                 \
        asm ("\x6d\x75\x6c\x71\x20\x25\x33"                  \
                : "\x3d\x61"(t1),"\x3d\x64"(t2)     \
                : "\x61"(a),"\x6d"(b)         \
                : "\x63\x63");                \
        asm ("\x61\x64\x64\x71\x20\x25\x33\x2c\x25\x30\x3b\x20\x61\x64\x63\x71\x20\x25\x34\x2c\x25\x31\x3b\x20\x61\x64\x63\x71\x20\x25\x35\x2c\x25\x32"       \
                : "\x2b\x72"(c0),"\x2b\x72"(c1),"\x2b\x72"(c2)            \
                : "\x72"(t1),"\x72"(t2),"\x67"(0)                \
                : "\x63\x63");                                \
        asm ("\x61\x64\x64\x71\x20\x25\x33\x2c\x25\x30\x3b\x20\x61\x64\x63\x71\x20\x25\x34\x2c\x25\x31\x3b\x20\x61\x64\x63\x71\x20\x25\x35\x2c\x25\x32"       \
                : "\x2b\x72"(c0),"\x2b\x72"(c1),"\x2b\x72"(c2)            \
                : "\x72"(t1),"\x72"(t2),"\x67"(0)                \
                : "\x63\x63");                                \
        } while (0)
# endif

# define sqr_add_c2(a,i,j,c0,c1,c2)      \
        mul_add_c2((a)[i],(a)[j],c0,c1,c2)

void bn_mul_comba8(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b)
{
    BN_ULONG c1, c2, c3;

    c1 = 0;
    c2 = 0;
    c3 = 0;
    mul_add_c(a[0], b[0], c1, c2, c3);
    r[0] = c1;
    c1 = 0;
    mul_add_c(a[0], b[1], c2, c3, c1);
    mul_add_c(a[1], b[0], c2, c3, c1);
    r[1] = c2;
    c2 = 0;
    mul_add_c(a[2], b[0], c3, c1, c2);
    mul_add_c(a[1], b[1], c3, c1, c2);
    mul_add_c(a[0], b[2], c3, c1, c2);
    r[2] = c3;
    c3 = 0;
    mul_add_c(a[0], b[3], c1, c2, c3);
    mul_add_c(a[1], b[2], c1, c2, c3);
    mul_add_c(a[2], b[1], c1, c2, c3);
    mul_add_c(a[3], b[0], c1, c2, c3);
    r[3] = c1;
    c1 = 0;
    mul_add_c(a[4], b[0], c2, c3, c1);
    mul_add_c(a[3], b[1], c2, c3, c1);
    mul_add_c(a[2], b[2], c2, c3, c1);
    mul_add_c(a[1], b[3], c2, c3, c1);
    mul_add_c(a[0], b[4], c2, c3, c1);
    r[4] = c2;
    c2 = 0;
    mul_add_c(a[0], b[5], c3, c1, c2);
    mul_add_c(a[1], b[4], c3, c1, c2);
    mul_add_c(a[2], b[3], c3, c1, c2);
    mul_add_c(a[3], b[2], c3, c1, c2);
    mul_add_c(a[4], b[1], c3, c1, c2);
    mul_add_c(a[5], b[0], c3, c1, c2);
    r[5] = c3;
    c3 = 0;
    mul_add_c(a[6], b[0], c1, c2, c3);
    mul_add_c(a[5], b[1], c1, c2, c3);
    mul_add_c(a[4], b[2], c1, c2, c3);
    mul_add_c(a[3], b[3], c1, c2, c3);
    mul_add_c(a[2], b[4], c1, c2, c3);
    mul_add_c(a[1], b[5], c1, c2, c3);
    mul_add_c(a[0], b[6], c1, c2, c3);
    r[6] = c1;
    c1 = 0;
    mul_add_c(a[0], b[7], c2, c3, c1);
    mul_add_c(a[1], b[6], c2, c3, c1);
    mul_add_c(a[2], b[5], c2, c3, c1);
    mul_add_c(a[3], b[4], c2, c3, c1);
    mul_add_c(a[4], b[3], c2, c3, c1);
    mul_add_c(a[5], b[2], c2, c3, c1);
    mul_add_c(a[6], b[1], c2, c3, c1);
    mul_add_c(a[7], b[0], c2, c3, c1);
    r[7] = c2;
    c2 = 0;
    mul_add_c(a[7], b[1], c3, c1, c2);
    mul_add_c(a[6], b[2], c3, c1, c2);
    mul_add_c(a[5], b[3], c3, c1, c2);
    mul_add_c(a[4], b[4], c3, c1, c2);
    mul_add_c(a[3], b[5], c3, c1, c2);
    mul_add_c(a[2], b[6], c3, c1, c2);
    mul_add_c(a[1], b[7], c3, c1, c2);
    r[8] = c3;
    c3 = 0;
    mul_add_c(a[2], b[7], c1, c2, c3);
    mul_add_c(a[3], b[6], c1, c2, c3);
    mul_add_c(a[4], b[5], c1, c2, c3);
    mul_add_c(a[5], b[4], c1, c2, c3);
    mul_add_c(a[6], b[3], c1, c2, c3);
    mul_add_c(a[7], b[2], c1, c2, c3);
    r[9] = c1;
    c1 = 0;
    mul_add_c(a[7], b[3], c2, c3, c1);
    mul_add_c(a[6], b[4], c2, c3, c1);
    mul_add_c(a[5], b[5], c2, c3, c1);
    mul_add_c(a[4], b[6], c2, c3, c1);
    mul_add_c(a[3], b[7], c2, c3, c1);
    r[10] = c2;
    c2 = 0;
    mul_add_c(a[4], b[7], c3, c1, c2);
    mul_add_c(a[5], b[6], c3, c1, c2);
    mul_add_c(a[6], b[5], c3, c1, c2);
    mul_add_c(a[7], b[4], c3, c1, c2);
    r[11] = c3;
    c3 = 0;
    mul_add_c(a[7], b[5], c1, c2, c3);
    mul_add_c(a[6], b[6], c1, c2, c3);
    mul_add_c(a[5], b[7], c1, c2, c3);
    r[12] = c1;
    c1 = 0;
    mul_add_c(a[6], b[7], c2, c3, c1);
    mul_add_c(a[7], b[6], c2, c3, c1);
    r[13] = c2;
    c2 = 0;
    mul_add_c(a[7], b[7], c3, c1, c2);
    r[14] = c3;
    r[15] = c1;
}

void bn_mul_comba4(BN_ULONG *r, BN_ULONG *a, BN_ULONG *b)
{
    BN_ULONG c1, c2, c3;

    c1 = 0;
    c2 = 0;
    c3 = 0;
    mul_add_c(a[0], b[0], c1, c2, c3);
    r[0] = c1;
    c1 = 0;
    mul_add_c(a[0], b[1], c2, c3, c1);
    mul_add_c(a[1], b[0], c2, c3, c1);
    r[1] = c2;
    c2 = 0;
    mul_add_c(a[2], b[0], c3, c1, c2);
    mul_add_c(a[1], b[1], c3, c1, c2);
    mul_add_c(a[0], b[2], c3, c1, c2);
    r[2] = c3;
    c3 = 0;
    mul_add_c(a[0], b[3], c1, c2, c3);
    mul_add_c(a[1], b[2], c1, c2, c3);
    mul_add_c(a[2], b[1], c1, c2, c3);
    mul_add_c(a[3], b[0], c1, c2, c3);
    r[3] = c1;
    c1 = 0;
    mul_add_c(a[3], b[1], c2, c3, c1);
    mul_add_c(a[2], b[2], c2, c3, c1);
    mul_add_c(a[1], b[3], c2, c3, c1);
    r[4] = c2;
    c2 = 0;
    mul_add_c(a[2], b[3], c3, c1, c2);
    mul_add_c(a[3], b[2], c3, c1, c2);
    r[5] = c3;
    c3 = 0;
    mul_add_c(a[3], b[3], c1, c2, c3);
    r[6] = c1;
    r[7] = c2;
}

void bn_sqr_comba8(BN_ULONG *r, const BN_ULONG *a)
{
    BN_ULONG c1, c2, c3;

    c1 = 0;
    c2 = 0;
    c3 = 0;
    sqr_add_c(a, 0, c1, c2, c3);
    r[0] = c1;
    c1 = 0;
    sqr_add_c2(a, 1, 0, c2, c3, c1);
    r[1] = c2;
    c2 = 0;
    sqr_add_c(a, 1, c3, c1, c2);
    sqr_add_c2(a, 2, 0, c3, c1, c2);
    r[2] = c3;
    c3 = 0;
    sqr_add_c2(a, 3, 0, c1, c2, c3);
    sqr_add_c2(a, 2, 1, c1, c2, c3);
    r[3] = c1;
    c1 = 0;
    sqr_add_c(a, 2, c2, c3, c1);
    sqr_add_c2(a, 3, 1, c2, c3, c1);
    sqr_add_c2(a, 4, 0, c2, c3, c1);
    r[4] = c2;
    c2 = 0;
    sqr_add_c2(a, 5, 0, c3, c1, c2);
    sqr_add_c2(a, 4, 1, c3, c1, c2);
    sqr_add_c2(a, 3, 2, c3, c1, c2);
    r[5] = c3;
    c3 = 0;
    sqr_add_c(a, 3, c1, c2, c3);
    sqr_add_c2(a, 4, 2, c1, c2, c3);
    sqr_add_c2(a, 5, 1, c1, c2, c3);
    sqr_add_c2(a, 6, 0, c1, c2, c3);
    r[6] = c1;
    c1 = 0;
    sqr_add_c2(a, 7, 0, c2, c3, c1);
    sqr_add_c2(a, 6, 1, c2, c3, c1);
    sqr_add_c2(a, 5, 2, c2, c3, c1);
    sqr_add_c2(a, 4, 3, c2, c3, c1);
    r[7] = c2;
    c2 = 0;
    sqr_add_c(a, 4, c3, c1, c2);
    sqr_add_c2(a, 5, 3, c3, c1, c2);
    sqr_add_c2(a, 6, 2, c3, c1, c2);
    sqr_add_c2(a, 7, 1, c3, c1, c2);
    r[8] = c3;
    c3 = 0;
    sqr_add_c2(a, 7, 2, c1, c2, c3);
    sqr_add_c2(a, 6, 3, c1, c2, c3);
    sqr_add_c2(a, 5, 4, c1, c2, c3);
    r[9] = c1;
    c1 = 0;
    sqr_add_c(a, 5, c2, c3, c1);
    sqr_add_c2(a, 6, 4, c2, c3, c1);
    sqr_add_c2(a, 7, 3, c2, c3, c1);
    r[10] = c2;
    c2 = 0;
    sqr_add_c2(a, 7, 4, c3, c1, c2);
    sqr_add_c2(a, 6, 5, c3, c1, c2);
    r[11] = c3;
    c3 = 0;
    sqr_add_c(a, 6, c1, c2, c3);
    sqr_add_c2(a, 7, 5, c1, c2, c3);
    r[12] = c1;
    c1 = 0;
    sqr_add_c2(a, 7, 6, c2, c3, c1);
    r[13] = c2;
    c2 = 0;
    sqr_add_c(a, 7, c3, c1, c2);
    r[14] = c3;
    r[15] = c1;
}

void bn_sqr_comba4(BN_ULONG *r, const BN_ULONG *a)
{
    BN_ULONG c1, c2, c3;

    c1 = 0;
    c2 = 0;
    c3 = 0;
    sqr_add_c(a, 0, c1, c2, c3);
    r[0] = c1;
    c1 = 0;
    sqr_add_c2(a, 1, 0, c2, c3, c1);
    r[1] = c2;
    c2 = 0;
    sqr_add_c(a, 1, c3, c1, c2);
    sqr_add_c2(a, 2, 0, c3, c1, c2);
    r[2] = c3;
    c3 = 0;
    sqr_add_c2(a, 3, 0, c1, c2, c3);
    sqr_add_c2(a, 2, 1, c1, c2, c3);
    r[3] = c1;
    c1 = 0;
    sqr_add_c(a, 2, c2, c3, c1);
    sqr_add_c2(a, 3, 1, c2, c3, c1);
    r[4] = c2;
    c2 = 0;
    sqr_add_c2(a, 3, 2, c3, c1, c2);
    r[5] = c3;
    c3 = 0;
    sqr_add_c(a, 3, c1, c2, c3);
    r[6] = c1;
    r[7] = c2;
}
#endif

#ifndef __UTILS_H
#define __UTILS_H

#include "common.h"

static __always_inline __u32 rol32(__u32 word, __u32 shift) {
    return (word << shift) | (word >> (32 - shift));
}

static __always_inline void jhash_mix(__u32 *a, __u32 *b, __u32 *c) {
    *a -= *c;  *a ^= rol32(*c, 4);  *c += *b;
    *b -= *a;  *b ^= rol32(*a, 6);  *a += *c;
    *c -= *b;  *c ^= rol32(*b, 8);  *b += *a;
    *a -= *c;  *a ^= rol32(*c,16);  *c += *b;
    *b -= *a;  *b ^= rol32(*a,19);  *a += *c;
    *c -= *b;  *c ^= rol32(*b, 4);  *b += *a;
}

static __always_inline __u32 jhash(const void *key, __u32 len, __u32 initval) {
    const __u8 *k = key;
    __u32 a, b, c;
    a = b = c = 0xdeadbeef + len + initval;

    __u32 k0 = 0, k1 = 0, k2 = 0;

    if (len > 0) k0 |= k[0];
    if (len > 1) k0 |= k[1] << 8;
    if (len > 2) k0 |= k[2] << 16;
    if (len > 3) k0 |= k[3] << 24;
    if (len > 4) k1 |= k[4];
    if (len > 5) k1 |= k[5] << 8;
    if (len > 6) k1 |= k[6] << 16;
    if (len > 7) k1 |= k[7] << 24;
    if (len > 8) k2 |= k[8];
    if (len > 9) k2 |= k[9] << 8;
    if (len > 10) k2 |= k[10] << 16;
    if (len > 11) k2 |= k[11] << 24;

    a += k0;
    b += k1;
    c += k2;

    jhash_mix(&a, &b, &c);

    return c;
}

#endif /* __UTILS_H */

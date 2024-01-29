/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
    From: https://www.rfc-editor.org/rfc/rfc1320.html
    Legal: "Derived from the RSA Data Security, Inc. MD4 Message-Digest Algorithm"
*/

#include <qcrypto/hash/md4.h>
#include <qcrypto/macro.h>
#include <string.h>

#define S11 3
#define S12 7
#define S13 11
#define S14 19
#define S21 3
#define S22 5
#define S23 9
#define S24 13
#define S31 3
#define S32 9
#define S33 11
#define S34 15

#define A 0x67452301
#define B 0xefcdab89
#define C 0x98badcfe
#define D 0x10325476

static uint8_t md5_padding[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

/* F, G and H are basic MD4 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* FF, GG and HH are transformations for rounds 1, 2 and 3 */
/* Rotation is separate from addition to prevent recomputation */

#define FF(a, b, c, d, x, s)           \
    {                                  \
        (a) += F((b), (c), (d)) + (x); \
        (a) = ROTATE_LEFT((a), (s));   \
    }
#define GG(a, b, c, d, x, s)                                  \
    {                                                         \
        (a) += G((b), (c), (d)) + (x) + (uint32_t)0x5a827999; \
        (a) = ROTATE_LEFT((a), (s));                          \
    }
#define HH(a, b, c, d, x, s)                                  \
    {                                                         \
        (a) += H((b), (c), (d)) + (x) + (uint32_t)0x6ed9eba1; \
        (a) = ROTATE_LEFT((a), (s));                          \
    }

QC_EXPORT void qc_md4_init(qc_md4_t *ctx, void *x)
{
    (void)x;

    ctx->count[0] = ctx->count[1] = 0;

    ctx->state[0] = A;
    ctx->state[1] = B;
    ctx->state[2] = C;
    ctx->state[3] = D;
}

static inline void qc_md4_block(qc_md4_t *ctx, const uint8_t block[16])
{
    uint8_t i;
    uint32_t a, b, c, d;

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];

    for (i = 0; i < 16; i++)
    {
        ctx->x[i] = block[i * 4] & 0xff;
        ctx->x[i] |= (block[i * 4 + 1] << 8) & 0xff00;
        ctx->x[i] |= (block[i * 4 + 2] << 16) & 0xff0000;
        ctx->x[i] |= (block[i * 4 + 3] << 24) & 0xff000000;
    }

    /* Round 1 */
    FF(a, b, c, d, ctx->x[0], S11);  /* 1 */
    FF(d, a, b, c, ctx->x[1], S12);  /* 2 */
    FF(c, d, a, b, ctx->x[2], S13);  /* 3 */
    FF(b, c, d, a, ctx->x[3], S14);  /* 4 */
    FF(a, b, c, d, ctx->x[4], S11);  /* 5 */
    FF(d, a, b, c, ctx->x[5], S12);  /* 6 */
    FF(c, d, a, b, ctx->x[6], S13);  /* 7 */
    FF(b, c, d, a, ctx->x[7], S14);  /* 8 */
    FF(a, b, c, d, ctx->x[8], S11);  /* 9 */
    FF(d, a, b, c, ctx->x[9], S12);  /* 10 */
    FF(c, d, a, b, ctx->x[10], S13); /* 11 */
    FF(b, c, d, a, ctx->x[11], S14); /* 12 */
    FF(a, b, c, d, ctx->x[12], S11); /* 13 */
    FF(d, a, b, c, ctx->x[13], S12); /* 14 */
    FF(c, d, a, b, ctx->x[14], S13); /* 15 */
    FF(b, c, d, a, ctx->x[15], S14); /* 16 */

    /* Round 2 */
    GG(a, b, c, d, ctx->x[0], S21);  /* 17 */
    GG(d, a, b, c, ctx->x[4], S22);  /* 18 */
    GG(c, d, a, b, ctx->x[8], S23);  /* 19 */
    GG(b, c, d, a, ctx->x[12], S24); /* 20 */
    GG(a, b, c, d, ctx->x[1], S21);  /* 21 */
    GG(d, a, b, c, ctx->x[5], S22);  /* 22 */
    GG(c, d, a, b, ctx->x[9], S23);  /* 23 */
    GG(b, c, d, a, ctx->x[13], S24); /* 24 */
    GG(a, b, c, d, ctx->x[2], S21);  /* 25 */
    GG(d, a, b, c, ctx->x[6], S22);  /* 26 */
    GG(c, d, a, b, ctx->x[10], S23); /* 27 */
    GG(b, c, d, a, ctx->x[14], S24); /* 28 */
    GG(a, b, c, d, ctx->x[3], S21);  /* 29 */
    GG(d, a, b, c, ctx->x[7], S22);  /* 30 */
    GG(c, d, a, b, ctx->x[11], S23); /* 31 */
    GG(b, c, d, a, ctx->x[15], S24); /* 32 */

    /* Round 3 */
    HH(a, b, c, d, ctx->x[0], S31);  /* 33 */
    HH(d, a, b, c, ctx->x[8], S32);  /* 34 */
    HH(c, d, a, b, ctx->x[4], S33);  /* 35 */
    HH(b, c, d, a, ctx->x[12], S34); /* 36 */
    HH(a, b, c, d, ctx->x[2], S31);  /* 37 */
    HH(d, a, b, c, ctx->x[10], S32); /* 38 */
    HH(c, d, a, b, ctx->x[6], S33);  /* 39 */
    HH(b, c, d, a, ctx->x[14], S34); /* 40 */
    HH(a, b, c, d, ctx->x[1], S31);  /* 41 */
    HH(d, a, b, c, ctx->x[9], S32);  /* 42 */
    HH(c, d, a, b, ctx->x[5], S33);  /* 43 */
    HH(b, c, d, a, ctx->x[13], S34); /* 44 */
    HH(a, b, c, d, ctx->x[3], S31);  /* 45 */
    HH(d, a, b, c, ctx->x[11], S32); /* 46 */
    HH(c, d, a, b, ctx->x[7], S33);  /* 47 */
    HH(b, c, d, a, ctx->x[15], S34); /* 48 */

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
}

QC_EXPORT void qc_md4_update(qc_md4_t *ctx, const uint8_t *data, size_t size)
{
    uint8_t i, j, index, n;

    /* Compute number of bytes mod 64 */
    index = ((ctx->count[0] >> 3) & 0x3F);
    /* Update number of bits */
    if ((ctx->count[0] += ((uint32_t)size << 3)) < ((uint32_t)size << 3))
        ctx->count[1]++;
    ctx->count[1] += ((uint32_t)size >> 29);

    n = 64 - index;

    /* Transform if there is enough bytes */
    if (size >= n)
    {
        for (i = 0; i < n; i++)
            ctx->buffer[index + i] = data[i];
        qc_md4_block(ctx, ctx->buffer);

        for (i = n; i + 63U < size; i += 64)
            qc_md4_block(ctx, data + i);

        index = 0;
    }
    else
    {
        i = 0;
    }

    /* Buffer remaining input */
    for (j = 0; j < size - i; j++)
        ctx->buffer[index + j] = data[i + j];
}

QC_EXPORT void qc_md4_final(qc_md4_t *ctx, uint8_t *out)
{
    uint8_t bits[8], index, plen;

    /* Save number of bits */
    for (int i = 0; i < 8; i++)
        bits[i] = (uint8_t)((ctx->count[0] >> (i * 8)) & 0xff);

    /* Pad out to 56 mod 64. */
    index = (uint32_t)((ctx->count[0] >> 3) & 0x3f);
    plen = (index < 56) ? (56 - index) : (120 - index);
    qc_md4_update(ctx, md5_padding, plen);

    /* Append length (before padding) */
    qc_md4_update(ctx, bits, 8);

    /* Store state in digest */
    memcpy(out, ctx->state, 16);
}
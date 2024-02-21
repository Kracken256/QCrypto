/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
    From: https://www.rfc-editor.org/rfc/rfc3174.html
*/

#include <qcrypto/hash/sha1.h>
#include <qcrypto/macro.h>
#include <string.h>

#define INIT_A 0x67452301
#define INIT_B 0xEFCDAB89
#define INIT_C 0x98BADCFE
#define INIT_D 0x10325476
#define INIT_E 0xC3D2E1F0

#define ROTATE(bits, word) \
    (((word) << (bits)) | ((word) >> (32 - (bits))))

void qc_sha1_init(qc_sha1_t *ctx, void *x)
{
    (void)x;

    ctx->length = 0;
    ctx->idx = 0;

    ctx->state[0] = INIT_A;
    ctx->state[1] = INIT_B;
    ctx->state[2] = INIT_C;
    ctx->state[3] = INIT_D;
    ctx->state[4] = INIT_E;
}

static inline void SHA1ProcessMessageBlock(qc_sha1_t *ctx)
{
    const uint32_t K[] = {/* Constants defined in SHA-1   */
                          0x5A827999,
                          0x6ED9EBA1,
                          0x8F1BBCDC,
                          0xCA62C1D6};
    int t;                  /* Loop counter                */
    uint32_t temp;          /* Temporary word value        */
    uint32_t W[80];         /* Word sequence               */
    uint32_t A, B, C, D, E; /* Word buffers                */

    /*
     *  Initialize the first 16 words in the array W
     */
    for (t = 0; t < 16; t++)
    {
        W[t] = ctx->block[t * 4] << 24;
        W[t] |= ctx->block[t * 4 + 1] << 16;
        W[t] |= ctx->block[t * 4 + 2] << 8;
        W[t] |= ctx->block[t * 4 + 3];
    }

    for (t = 16; t < 80; t++)
    {
        W[t] = ROTATE(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
    }

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];

    for (t = 0; t < 20; t++)
    {
        temp = ROTATE(5, A) +
               ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        E = D;
        D = C;
        C = ROTATE(30, B);
        B = A;
        A = temp;
    }

    for (t = 20; t < 40; t++)
    {
        temp = ROTATE(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = ROTATE(30, B);
        B = A;
        A = temp;
    }

    for (t = 40; t < 60; t++)
    {
        temp = ROTATE(5, A) +
               ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        E = D;
        D = C;
        C = ROTATE(30, B);
        B = A;
        A = temp;
    }

    for (t = 60; t < 80; t++)
    {
        temp = ROTATE(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = ROTATE(30, B);
        B = A;
        A = temp;
    }

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;

    ctx->idx = 0;
}

void qc_sha1_update(qc_sha1_t *ctx, const uint8_t *data, size_t size)
{
    while (size--)
    {
        ctx->block[ctx->idx++] =
            (*data & 0xFF);

        ctx->length += 8;

        if (ctx->idx == 64)
            SHA1ProcessMessageBlock(ctx);

        data++;
    }
}

static inline void SHA1PadMessage(qc_sha1_t *ctx)
{
    /*
     *  Check to see if the current message block is too small to hold
     *  the initial padding bits and length.  If so, we will pad the
     *  block, process it, and then continue padding into a second
     *  block.
     */
    if (ctx->idx > 55)
    {
        ctx->block[ctx->idx++] = 0x80;
        while (ctx->idx < 64)
        {
            ctx->block[ctx->idx++] = 0;
        }

        SHA1ProcessMessageBlock(ctx);

        while (ctx->idx < 56)
        {
            ctx->block[ctx->idx++] = 0;
        }
    }
    else
    {
        ctx->block[ctx->idx++] = 0x80;
        while (ctx->idx < 56)
        {
            ctx->block[ctx->idx++] = 0;
        }
    }

    *(uint64_t *)&ctx->block[56] = QC_BE64(ctx->length);

    SHA1ProcessMessageBlock(ctx);
}

void qc_sha1_final(qc_sha1_t *ctx, uint8_t *out)
{
    int i;

    SHA1PadMessage(ctx);

    ctx->length = 0;

    for (i = 0; i < 20; ++i)
        out[i] = ctx->state[i >> 2] >> 8 * (3 - (i & 0x03));
}
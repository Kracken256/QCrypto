/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
    From: https://www.rfc-editor.org/rfc/rfc4634.html
*/

#include <qcrypto/hash/sha224.h>
#include <qcrypto/macro.h>
#include <string.h>

/* Define the SHA shift, rotate left and rotate right macro */
#define SHA224_SHR(bits, word) ((word) >> (bits))
#define SHA224_ROTL(bits, word) \
    (((word) << (bits)) | ((word) >> (32 - (bits))))
#define SHA224_ROTR(bits, word) \
    (((word) >> (bits)) | ((word) << (32 - (bits))))

/* Define the SHA SIGMA and sigma macros */
#define SHA224_SIGMA0(word) \
    (SHA224_ROTR(2, word) ^ SHA224_ROTR(13, word) ^ SHA224_ROTR(22, word))
#define SHA224_SIGMA1(word) \
    (SHA224_ROTR(6, word) ^ SHA224_ROTR(11, word) ^ SHA224_ROTR(25, word))
#define SHA224_sigma0(word) \
    (SHA224_ROTR(7, word) ^ SHA224_ROTR(18, word) ^ SHA224_SHR(3, word))
#define SHA224_sigma1(word) \
    (SHA224_ROTR(17, word) ^ SHA224_ROTR(19, word) ^ SHA224_SHR(10, word))

#define SHA_Ch(x, y, z) (((x) & ((y) ^ (z))) ^ (z))
#define SHA_Maj(x, y, z) (((x) & ((y) | (z))) | ((y) & (z)))

/* Initial Hash Values: FIPS-180-2 section 5.3.2 */
static uint32_t SHA224_H0[8] = {
    0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
    0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4
};

QC_EXPORT void qc_sha224_init(qc_sha224_t *ctx, void *x)
{
    (void)x;

    ctx->length = 0;
    ctx->index = 0;

    ctx->state[0] = SHA224_H0[0];
    ctx->state[1] = SHA224_H0[1];
    ctx->state[2] = SHA224_H0[2];
    ctx->state[3] = SHA224_H0[3];
    ctx->state[4] = SHA224_H0[4];
    ctx->state[5] = SHA224_H0[5];
    ctx->state[6] = SHA224_H0[6];
    ctx->state[7] = SHA224_H0[7];
}

static inline void qc_sha224_transform(qc_sha224_t *ctx)
{
    /* Constants defined in FIPS-180-2, section 4.2.2 */
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
        0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
        0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
        0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
        0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
        0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
        0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    int t, t4;                       /* Loop counter */
    uint32_t temp1, temp2;           /* Temporary word value */
    uint32_t W[64];                  /* Word sequence */
    uint32_t A, B, C, D, E, F, G, H; /* Word buffers */

    for (t = t4 = 0; t < 16; t++, t4 += 4)
        W[t] = (((uint32_t)ctx->block[t4]) << 24) |
               (((uint32_t)ctx->block[t4 + 1]) << 16) |
               (((uint32_t)ctx->block[t4 + 2]) << 8) |
               (((uint32_t)ctx->block[t4 + 3]));

    for (t = 16; t < 64; t++)
        W[t] = SHA224_sigma1(W[t - 2]) + W[t - 7] +
               SHA224_sigma0(W[t - 15]) + W[t - 16];

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

    for (t = 0; t < 64; t++)
    {
        temp1 = H + SHA224_SIGMA1(E) + SHA_Ch(E, F, G) + K[t] + W[t];
        temp2 = SHA224_SIGMA0(A) + SHA_Maj(A, B, C);
        H = G;
        G = F;
        F = E;
        E = D + temp1;
        D = C;
        C = B;
        B = A;
        A = temp1 + temp2;
    }

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
    ctx->state[5] += F;
    ctx->state[6] += G;
    ctx->state[7] += H;

    ctx->index = 0;
}

QC_EXPORT void qc_sha224_update(qc_sha224_t *ctx, const uint8_t *data, size_t size)
{
    while (size--)
    {
        ctx->block[ctx->index++] =
            (*data & 0xFF);

        ctx->length += 8;
        if (ctx->index == 64)
        {
            qc_sha224_transform(ctx);
            ctx->index = 0;
        }

        data++;
    }
}

QC_EXPORT void qc_sha224_final(qc_sha224_t *ctx, uint8_t *out)
{
    int i;

    if (ctx->index >= (64 - 8))
    {
        ctx->block[ctx->index++] = 0x80;
        while (ctx->index < 64)
            ctx->block[ctx->index++] = 0;
        qc_sha224_transform(ctx);
    }
    else
        ctx->block[ctx->index++] = 0x80;

    while (ctx->index < (64 - 8))
        ctx->block[ctx->index++] = 0;

    uint64_t length = QC_BE64(ctx->length);
    memcpy(ctx->block + 56, &length, 8);

    qc_sha224_transform(ctx);

    ctx->length = 0;

    for (i = 0; i < 28; ++i)
        out[i] = (uint8_t)(ctx->state[i >> 2] >> 8 * (3 - (i & 0x03)));
}
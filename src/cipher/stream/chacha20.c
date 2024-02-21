/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#include <qcrypto/cipher/stream/chacha20.h>
#include <qcrypto/macro.h>
#include <stdarg.h>
#include <string.h>

static inline uint32_t rotl32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

static inline uint32_t pack4(const uint8_t *a)
{
    uint32_t res = 0;
    res |= (uint32_t)a[0] << 0 * 8;
    res |= (uint32_t)a[1] << 1 * 8;
    res |= (uint32_t)a[2] << 2 * 8;
    res |= (uint32_t)a[3] << 3 * 8;
    return res;
}

static void chacha20_block_next(struct qc_chacha20_t *ctx)
{
    // This is where the crazy voodoo magic happens.
    // Mix the bytes a lot and hope that nobody finds out how to undo it.
    for (int i = 0; i < 16; i++)
        ctx->keystream32[i] = ctx->state[i];

#define CHACHA20_QUARTERROUND(x, a, b, c, d) \
    x[a] += x[b];                            \
    x[d] = rotl32(x[d] ^ x[a], 16);          \
    x[c] += x[d];                            \
    x[b] = rotl32(x[b] ^ x[c], 12);          \
    x[a] += x[b];                            \
    x[d] = rotl32(x[d] ^ x[a], 8);           \
    x[c] += x[d];                            \
    x[b] = rotl32(x[b] ^ x[c], 7);

    for (int i = 0; i < 10; i++)
    {
        CHACHA20_QUARTERROUND(ctx->keystream32, 0, 4, 8, 12)
        CHACHA20_QUARTERROUND(ctx->keystream32, 1, 5, 9, 13)
        CHACHA20_QUARTERROUND(ctx->keystream32, 2, 6, 10, 14)
        CHACHA20_QUARTERROUND(ctx->keystream32, 3, 7, 11, 15)
        CHACHA20_QUARTERROUND(ctx->keystream32, 0, 5, 10, 15)
        CHACHA20_QUARTERROUND(ctx->keystream32, 1, 6, 11, 12)
        CHACHA20_QUARTERROUND(ctx->keystream32, 2, 7, 8, 13)
        CHACHA20_QUARTERROUND(ctx->keystream32, 3, 4, 9, 14)
    }

    for (int i = 0; i < 16; i++)
        ctx->keystream32[i] += ctx->state[i];

    uint32_t *counter = ctx->state + 12;
    // increment counter
    counter[0]++;
    if (0 == counter[0])
    {
        // wrap around occured, increment higher 32 bits of counter
        counter[1]++;
    }
}

int qc_chacha20_init(qc_chacha20_t *ctx, void *x)
{
    va_list args;
    memcpy(args, x, sizeof(va_list));
    memset(ctx, 0, sizeof(qc_chacha20_t));

    ctx->counter = va_arg(args, uint64_t);

    return 1;
}

int qc_chacha20_setup(qc_chacha20_t *ctx, const uint8_t *key, const uint8_t *nonce)
{
    memcpy(ctx->key, key, sizeof(ctx->key));
    memcpy(ctx->nonce, nonce, sizeof(ctx->nonce));

    const uint8_t *magic_constant = (uint8_t *)"expand 32-byte k";
    ctx->state[0] = pack4(magic_constant + 0 * 4);
    ctx->state[1] = pack4(magic_constant + 1 * 4);
    ctx->state[2] = pack4(magic_constant + 2 * 4);
    ctx->state[3] = pack4(magic_constant + 3 * 4);
    ctx->state[4] = pack4(key + 0 * 4);
    ctx->state[5] = pack4(key + 1 * 4);
    ctx->state[6] = pack4(key + 2 * 4);
    ctx->state[7] = pack4(key + 3 * 4);
    ctx->state[8] = pack4(key + 4 * 4);
    ctx->state[9] = pack4(key + 5 * 4);
    ctx->state[10] = pack4(key + 6 * 4);
    ctx->state[11] = pack4(key + 7 * 4);
    // 64 bit counter initialized to zero by default.
    ctx->state[12] = 0;
    ctx->state[13] = pack4(nonce + 0 * 4);
    ctx->state[14] = pack4(nonce + 1 * 4);
    ctx->state[15] = pack4(nonce + 2 * 4);

    memcpy(ctx->nonce, nonce, sizeof(ctx->nonce));

    ctx->state[12] = (uint32_t)ctx->counter;
    ctx->state[13] = pack4(ctx->nonce + 0 * 4) + (uint32_t)(ctx->counter >> 32);

    ctx->position = 64;

    return 1;
}

int qc_chacha20_crypt(qc_chacha20_t *ctx, const uint8_t *in, uint64_t in_size, uint8_t *out, uint64_t *out_size)
{
    uint8_t *keystream8 = (uint8_t *)ctx->keystream32;

    memmove(out, in, in_size);

    for (size_t i = 0; i < in_size; i++)
    {
        if (ctx->position >= 64)
        {
            chacha20_block_next(ctx);
            ctx->position = 0;
        }
        out[i] ^= keystream8[ctx->position];
        ctx->position++;
    }

    *out_size = in_size;

    return 1;
}
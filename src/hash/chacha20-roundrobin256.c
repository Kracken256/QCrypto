/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#include <qcrypto/hash/chacha20-roundrobin256.h>
#include <qcrypto/macro.h>
#include <stdarg.h>
#include <string.h>

static const uint8_t chacha20_roundrobin256_key[32] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

static const uint8_t chacha20_roundrobin256_iv[12] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

static void wrapper(qc_chacha20_t *ctx, ...)
{
    va_list args;
    va_start(args, ctx);

    qc_chacha20_init(ctx, args);
    qc_chacha20_setup(ctx, chacha20_roundrobin256_key, chacha20_roundrobin256_iv);

    va_end(args);
}

// not needed
static uint64_t out_size = 0;

void qc_chacha20_roundrobin256_init(qc_chacha20_roundrobin256_t *ctx, void *x)
{
    (void)x;

    wrapper(&ctx->inner, 0);

    memset(ctx->state.state, 0, sizeof(ctx->state));

    ctx->dgst_size = QC_CHACHA20_ROUNDROBIN256_DIGEST_SIZE;
    ctx->index = 0;
    ctx->length = 0;
}

int printf(const char *format, ...);

static inline void qc_chacha20_roundrobin256_transform(qc_chacha20_roundrobin256_t *ctx)
{
    qc_chacha20_crypt(&ctx->inner, ctx->block, sizeof(ctx->block), ctx->block, &out_size);

    // XOR block into state
    for (size_t i = 0; i < sizeof(ctx->state); i++)
        ctx->state.state[i] ^= ctx->block[i];
}

void qc_chacha20_roundrobin256_update(qc_chacha20_roundrobin256_t *ctx, const uint8_t *data, size_t size)
{
    while (size--)
    {
        ctx->block[ctx->index++] = (*data & 0xFF);

        if (ctx->index == sizeof(ctx->block))
        {
            ctx->length += sizeof(ctx->block);
            qc_chacha20_roundrobin256_transform(ctx);
            ctx->index = 0;
        }

        data++;
    }
}

void qc_chacha20_roundrobin256_final(qc_chacha20_roundrobin256_t *ctx, uint8_t *out)
{
    ctx->length += ctx->index;

    /* Pad last block */
    ctx->block[ctx->index] = 0x80;
    memset(ctx->block + ctx->index + 1, ctx->index, sizeof(ctx->block) - ctx->index - 1);
    qc_chacha20_roundrobin256_transform(ctx);

    // XOR last 20 bytes of state into first 20 bytes of state
    for (size_t i = 0; i < 20; i++)
        ctx->state.state[i] ^= ctx->state.state[i + 44];

    /* The digest is the first 256 bits of the ChaCha20 keystream when inititialized with the state. */
    memset(out, 0, ctx->dgst_size);

    wrapper(&ctx->inner, QC_BE64(ctx->length));
    qc_chacha20_setup(&ctx->inner, ctx->state.m.key, ctx->state.m.iv);
    qc_chacha20_crypt(&ctx->inner, out, ctx->dgst_size, out, &out_size);
}
/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
    From: https://www.rfc-editor.org/rfc/rfc1319.html
    Legal: "Derived from the RSA Data Security, Inc. MD2 Message Digest Algorithm"
*/

#include <qcrypto/hash/md2.h>
#include <qcrypto/macro.h>
#include <string.h>

#define MD2_BLOCK_SIZE 16
#define MD2_ROUND_COUNT 18

static uint8_t md2_sbox[256] = {
    0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01, 0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13,
    0x62, 0xA7, 0x05, 0xF3, 0xC0, 0xC7, 0x73, 0x8C, 0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C, 0x82, 0xCA,
    0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16, 0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12,
    0xBE, 0x4E, 0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49, 0xA0, 0xFB, 0xF5, 0x8E, 0xBB, 0x2F, 0xEE, 0x7A,
    0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2, 0x07, 0x3F, 0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21,
    0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27, 0x35, 0x3E, 0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03,
    0xFF, 0x19, 0x30, 0xB3, 0x48, 0xA5, 0xB5, 0xD1, 0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56, 0xAA, 0xC6,
    0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6, 0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1,
    0x45, 0x9D, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20, 0x86, 0x5B, 0xCF, 0x65, 0xE6, 0x2D, 0xA8, 0x02,
    0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0, 0xB9, 0xF6, 0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F,
    0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A, 0xC3, 0x5C, 0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26,
    0x2C, 0x53, 0x0D, 0x6E, 0x85, 0x28, 0x84, 0x09, 0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81, 0x4D, 0x52,
    0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA, 0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A,
    0x78, 0x88, 0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D, 0xE9, 0xCB, 0xD5, 0xFE, 0x3B, 0x00, 0x1D, 0x39,
    0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58, 0xD0, 0xE4, 0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A,
    0x31, 0x44, 0x50, 0xB4, 0x8F, 0xED, 0x1F, 0x1A, 0xDB, 0x99, 0x8D, 0x33, 0x9F, 0x11, 0x83, 0x14};

static uint8_t *md2_padding[] = {
    (uint8_t *)"",
    (uint8_t *)"\001",
    (uint8_t *)"\002\002",
    (uint8_t *)"\003\003\003",
    (uint8_t *)"\004\004\004\004",
    (uint8_t *)"\005\005\005\005\005",
    (uint8_t *)"\006\006\006\006\006\006",
    (uint8_t *)"\007\007\007\007\007\007\007",
    (uint8_t *)"\010\010\010\010\010\010\010\010",
    (uint8_t *)"\011\011\011\011\011\011\011\011\011",
    (uint8_t *)"\012\012\012\012\012\012\012\012\012\012",
    (uint8_t *)"\013\013\013\013\013\013\013\013\013\013\013",
    (uint8_t *)"\014\014\014\014\014\014\014\014\014\014\014\014",
    (uint8_t *)"\015\015\015\015\015\015\015\015\015\015\015\015\015",
    (uint8_t *)"\016\016\016\016\016\016\016\016\016\016\016\016\016\016",
    (uint8_t *)"\017\017\017\017\017\017\017\017\017\017\017\017\017\017\017",
    (uint8_t *)"\020\020\020\020\020\020\020\020\020\020\020\020\020\020\020\020"};

QC_EXPORT void qc_md2_init(qc_md2_t *ctx, void *x)
{
    (void)x;

    /* Initialize state to 0 */
    memset(ctx->state, 0, 48);

    /* Initialize checksum to 0 */
    memset(ctx->checksum, 0, 16);

    /* Count is the number of bytes, mod 16 */
    ctx->count = 0;
}

static inline void qc_md2_block(qc_md2_t *ctx, const uint8_t block[16])
{
    uint8_t i, j, t;

    /* Copy block into X */
    for (i = 0; i < 16; i++)
    {
        ctx->x[i] = ctx->state[i];
        ctx->x[i + 16] = block[i];
        ctx->x[i + 32] = ctx->state[i] ^ block[i];
    }

    t = 0;

    /* Do 18 rounds */
    for (i = 0; i < MD2_ROUND_COUNT; i++)
    {
        /* Round i */
        for (j = 0; j < 48; j++)
        {
            t = ctx->x[j] ^= md2_sbox[t];
        }

        t = (t + i) & 0xff;
    }

    /* Update checksum */
    t = ctx->checksum[15];

    for (i = 0; i < 16; i++)
    {
        ctx->state[i] = ctx->x[i];
        t = ctx->checksum[i] ^= md2_sbox[block[i] ^ t];
    }
}

QC_EXPORT void qc_md2_update(qc_md2_t *ctx, const uint8_t *data, size_t size)
{
    uint8_t i, j, index, n;

    /* Compute number of bytes mod 16 */
    index = ctx->count;
    ctx->count = (index + size) & 0xf;

    n = 16 - index;

    /* Transform if there is enough bytes */
    if (size >= n)
    {
        for (i = 0; i < n; i++)
            ctx->buffer[index + i] = data[i];
        qc_md2_block(ctx, ctx->buffer);

        for (i = n; i + 15U < size; i += 16)
            qc_md2_block(ctx, data + i);

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

QC_EXPORT void qc_md2_final(qc_md2_t *ctx, uint8_t *out)
{
    uint8_t index, plen;

    /* Apply padding */
    index = ctx->count;
    plen = 16 - index;
    qc_md2_update(ctx, md2_padding[plen], plen);

    /* Extend with checksum */
    qc_md2_update(ctx, ctx->checksum, 16);

    /* Store state in digest */
    memcpy(out, ctx->state, 16);
}
/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#include <qcrypto/hash/crc.h>
#include <qcrypto/macro.h>
#include <stdarg.h>
#include <string.h>

/*
    Implementation was tested against the following CRC implementations:
        - http://www.sunshine2k.de/coding/javascript/crc/crc_js.html
*/

static uint64_t mask_table[64] = {
    0x0000000000000001ULL, 0x0000000000000003ULL, 0x0000000000000007ULL, 0x000000000000000fULL,
    0x000000000000001fULL, 0x000000000000003fULL, 0x000000000000007fULL, 0x00000000000000ffULL,
    0x00000000000001ffULL, 0x00000000000003ffULL, 0x00000000000007ffULL, 0x0000000000000fffULL,
    0x0000000000001fffULL, 0x0000000000003fffULL, 0x0000000000007fffULL, 0x000000000000ffffULL,
    0x000000000001ffffULL, 0x000000000003ffffULL, 0x000000000007ffffULL, 0x00000000000fffffULL,
    0x00000000001fffffULL, 0x00000000003fffffULL, 0x00000000007fffffULL, 0x0000000000ffffffULL,
    0x0000000001ffffffULL, 0x0000000003ffffffULL, 0x0000000007ffffffULL, 0x000000000fffffffULL,
    0x000000001fffffffULL, 0x000000003fffffffULL, 0x000000007fffffffULL, 0x00000000ffffffffULL,
    0x00000001ffffffffULL, 0x00000003ffffffffULL, 0x00000007ffffffffULL, 0x0000000fffffffffULL,
    0x0000001fffffffffULL, 0x0000003fffffffffULL, 0x0000007fffffffffULL, 0x000000ffffffffffULL,
    0x000001ffffffffffULL, 0x000003ffffffffffULL, 0x000007ffffffffffULL, 0x00000fffffffffffULL,
    0x00001fffffffffffULL, 0x00003fffffffffffULL, 0x00007fffffffffffULL, 0x0000ffffffffffffULL,
    0x0001ffffffffffffULL, 0x0003ffffffffffffULL, 0x0007ffffffffffffULL, 0x000fffffffffffffULL,
    0x001fffffffffffffULL, 0x003fffffffffffffULL, 0x007fffffffffffffULL, 0x00ffffffffffffffULL,
    0x01ffffffffffffffULL, 0x03ffffffffffffffULL, 0x07ffffffffffffffULL, 0x0fffffffffffffffULL,
    0x1fffffffffffffffULL, 0x3fffffffffffffffULL, 0x7fffffffffffffffULL, 0xffffffffffffffffULL};

static void qc_crc_generate_table(qc_crc_t *ctx)
{
    uint64_t i, j;

    for (i = 0; i < 256; i++)
    {
        ctx->table[i] = i;
        for (j = 0; j < 8; j++)
        {
            if (ctx->table[i] & 1)
                ctx->table[i] = (ctx->table[i] >> 1) ^ ctx->poly;
            else
                ctx->table[i] >>= 1;
        }

        /// TODO: Check if this is redundant
        ctx->table[i] &= ctx->mask;
    }
}

static inline uint64_t qc_reflect(uint64_t x, uint8_t bits)
{
    uint64_t y = 0;

    for (uint8_t i = 0; i < bits; i++)
    {
        y <<= 1;
        y |= (x & 1);
        x >>= 1;
    }

    return y;
}

void qc_crc_init(qc_crc_t *ctx, void *x)
{
    va_list args;
    uint64_t poly, init, xor_out;
    uint8_t bits;

    memcpy(args, x, sizeof(va_list));

    bits = va_arg(args, int);
    poly = va_arg(args, uint64_t);
    init = va_arg(args, uint64_t);
    xor_out = va_arg(args, uint64_t);

    if (bits < 1 || bits > 64)
        return; // invalid bits

    if (poly == 0)
        return; // invalid polynomial

    ctx->poly = qc_reflect(poly, bits);
    ctx->init = qc_reflect(init, bits);
    ctx->xor_out = xor_out;
    ctx->num_bits = bits;
    ctx->mask = mask_table[bits - 1];
    ctx->s = ctx->init;

    qc_crc_generate_table(ctx);
}

void qc_crc_update(qc_crc_t *ctx, const uint8_t *data, size_t size)
{
    if (ctx->table == NULL)
        return; // invalid context

    for (size_t i = 0; i < size; i++)
    {
        ctx->s = ctx->table[(ctx->s ^ data[i]) & 0xFF] ^ (ctx->s >> 8);
    }
}

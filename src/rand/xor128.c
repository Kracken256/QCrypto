/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#include <qcrypto/rand/xor128.h>
#include <qcrypto/macro.h>
#include <string.h>
#include <stdint.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

QC_EXPORT void qc_xor128_seed(qc_xor128_t *lsfr, const uint8_t *seed, size_t n)
{
    memcpy(lsfr->state, seed, MIN(n, 16));

    if (n < 16)
    {
        memset(lsfr->state + n, 0, 16 - n);
    }

    lsfr->state[0]++; // state[0] != state[1]

    lsfr->seed[0] = lsfr->state[0];
    lsfr->seed[1] = lsfr->state[1];
}

QC_EXPORT void qc_xor128_reset(qc_xor128_t *lsfr)
{
    lsfr->state[0] = lsfr->seed[0];
    lsfr->state[1] = lsfr->seed[1];
}

static inline uint64_t next64(uint64_t s)
{
    s ^= s >> 12;
    s ^= s << 25;
    s ^= s >> 27;

    return s;
}

QC_EXPORT uint32_t qc_xor128_next32(qc_xor128_t *lsfr)
{
    uint32_t r;

    lsfr->state[0] = next64(lsfr->state[0]);
    lsfr->state[1] = next64(lsfr->state[1]);

    r = (lsfr->state[0] & 0xFFFFFFFF) ^ (lsfr->state[1] & 0xFFFFFFFF);

    return r;
}
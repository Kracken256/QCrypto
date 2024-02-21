/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#ifndef __QCRYPTO_RAND_XOR128_H__
#define __QCRYPTO_RAND_XOR128_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "../types.h"

    typedef struct qc_xor128_t
    {
        uint64_t seed[2];
        uint64_t state[2];
    } qc_xor128_t;

    void qc_xor128_seed(qc_xor128_t *lsfr, const uint8_t *seed, size_t n);

    void qc_xor128_reset(qc_xor128_t *lsfr);

    uint32_t qc_xor128_next32(qc_xor128_t *lsfr);

#ifdef __cplusplus
}
#endif

#endif // __QCRYPTO_RAND_XOR128_H__
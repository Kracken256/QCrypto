/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#ifndef __QCRYPTO_HASH_SHA224_H__
#define __QCRYPTO_HASH_SHA224_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "../types.h"
#include "../macro.h"

    /*
        Algorithm: SHA224 message-digest algorithm
        Description:
        Pros: Fast, secure
        Cons: Slower than SHA1
    */

    typedef struct qc_sha224_t
    {
        uint32_t state[8];
        uint64_t length;
        int16_t index;
        uint8_t block[64];
    } qc_sha224_t;

    /// @brief Initialize the SHA224 context
    /// @param ctx The SHA224 context
    void qc_sha224_init(qc_sha224_t *ctx, void *);

    /// @brief Update the SHA224 context with some data
    /// @param ctx The SHA224 context
    /// @param data The data to update the context with
    /// @param size The length of the data
    void qc_sha224_update(qc_sha224_t *ctx, const uint8_t *data, size_t size);

    /// @brief Finalize the SHA224 context and output the hash
    /// @param ctx The SHA224 context
    /// @param hash The output hash
    void qc_sha224_final(qc_sha224_t *ctx, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif // __QCRYPTO_HASH_SHA224_H__
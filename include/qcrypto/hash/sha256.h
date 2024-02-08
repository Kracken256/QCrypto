/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#ifndef __QCRYPTO_HASH_SHA256_H__
#define __QCRYPTO_HASH_SHA256_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "../types.h"
#include "../macro.h"

    /*
        Algorithm: SHA256 message-digest algorithm
        Description:
        Pros: Fast, secure
        Cons: Slower than SHA1
    */

    typedef struct qc_sha256_t
    {
        uint32_t state[8];
        uint64_t length;
        int16_t index;
        uint8_t block[64];
    } qc_sha256_t;

    /// @brief Initialize the SHA256 context
    /// @param ctx The SHA256 context
    void qc_sha256_init(qc_sha256_t *ctx, void *);

    /// @brief Update the SHA256 context with some data
    /// @param ctx The SHA256 context
    /// @param data The data to update the context with
    /// @param size The length of the data
    void qc_sha256_update(qc_sha256_t *ctx, const uint8_t *data, size_t size);

    /// @brief Finalize the SHA256 context and output the hash
    /// @param ctx The SHA256 context
    /// @param hash The output hash
    void qc_sha256_final(qc_sha256_t *ctx, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif // __QCRYPTO_HASH_SHA256_H__
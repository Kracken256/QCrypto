/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#ifndef __QCRYPTO_HASH_SHA1_H__
#define __QCRYPTO_HASH_SHA1_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "../types.h"
#include "../macro.h"

    /*
        Algorithm: SHA1 message-digest algorithm
        Description:
        Pros: Fast, simple, easy to implement.
        Cons: It was deemed to be insecure. It is no longer recommended for use.
    */

    typedef struct qc_sha1_t
    {
        uint32_t Intermediate_Hash[20 / 4];

        uint32_t Length_Low;
        uint32_t Length_High;
        int16_t Message_Block_Index;
        uint8_t Message_Block[64];
    } qc_sha1_t;

    /// @brief Initialize the SHA1 context
    /// @param ctx The SHA1 context
    void qc_sha1_init(qc_sha1_t *ctx, void *);

    /// @brief Update the SHA1 context with some data
    /// @param ctx The SHA1 context
    /// @param data The data to update the context with
    /// @param size The length of the data
    void qc_sha1_update(qc_sha1_t *ctx, const uint8_t *data, size_t size);

    /// @brief Finalize the SHA1 context and output the hash
    /// @param ctx The SHA1 context
    /// @param hash The output hash
    void qc_sha1_final(qc_sha1_t *ctx, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif // __QCRYPTO_HASH_SHA1_H__
/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#ifndef __QCRYPTO_HASH_MD4_H__
#define __QCRYPTO_HASH_MD4_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "../types.h"
#include "../macro.h"

    /*
        Algorithm: MD4 message-digest algorithm
        Description: The MD4 Message-Digest Algorithm is a cryptographic hash function 
            developed by Ronald Rivest in 1990.[3] The digest length is 128 bits. - Wikipedia
        Pros: Fast, simple, easy to implement.
        Cons: It was deemed to be insecure. It is no longer recommended for use.
    */

    typedef struct qc_md4_t
    {
        uint32_t state[4];
        uint32_t x[16];
        uint32_t count[2];
        uint8_t buffer[64];
    } qc_md4_t;

    /// @brief Initialize the MD4 context
    /// @param ctx The MD4 context
    void qc_md4_init(qc_md4_t *ctx, void *);

    /// @brief Update the MD4 context with some data
    /// @param ctx The MD4 context
    /// @param data The data to update the context with
    /// @param size The length of the data
    void qc_md4_update(qc_md4_t *ctx, const uint8_t *data, size_t size);

    /// @brief Finalize the MD4 context and output the hash
    /// @param ctx The MD4 context
    /// @param hash The output hash
    void qc_md4_final(qc_md4_t *ctx, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif // __QCRYPTO_HASH_MD4_H__
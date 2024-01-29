/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#ifndef __QCRYPTO_HASH_MD5_H__
#define __QCRYPTO_HASH_MD5_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "../types.h"
#include "../macro.h"

    /*
        Algorithm: MD5 message-digest algorithm
        Description: The MD5 Message-Digest Algorithm is a cryptographic hash function 
            developed by Ronald Rivest in 1990.[3] The digest length is 128 bits. - Wikipedia
        Pros: Fast, simple, easy to implement.
        Cons: It was deemed to be insecure. It is no longer recommended for use.
    */

    typedef struct qc_md5_t
    {
        uint32_t state[4];
        uint32_t x[16];
        uint32_t count[2];
        uint8_t buffer[64];
    } qc_md5_t;

    /// @brief Initialize the MD5 context
    /// @param ctx The MD5 context
    void qc_md5_init(qc_md5_t *ctx, void *);

    /// @brief Update the MD5 context with some data
    /// @param ctx The MD5 context
    /// @param data The data to update the context with
    /// @param size The length of the data
    void qc_md5_update(qc_md5_t *ctx, const uint8_t *data, size_t size);

    /// @brief Finalize the MD5 context and output the hash
    /// @param ctx The MD5 context
    /// @param hash The output hash
    void qc_md5_final(qc_md5_t *ctx, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif // __QCRYPTO_HASH_MD5_H__
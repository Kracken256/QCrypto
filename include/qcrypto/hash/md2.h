/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#ifndef __QCRYPTO_HASH_MD2_H__
#define __QCRYPTO_HASH_MD2_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "../types.h"
#include "../macro.h"

    /*
        Algorithm: MD2 message-digest algorithm
        Description: The MD2 Message-Digest Algorithm is a cryptographic hash function developed by 
            Ronald Rivest in 1989.[2] The algorithm is optimized for 8-bit computers. MD2 is specified 
            in IETF RFC 1319.[3] The "MD" in MD2 stands for "Message Digest". - Wikipedia
        Pros: Fast on 8-bit computers
        Cons: It was deemed to be insecure. It is no longer recommended for use.
    */

    typedef struct qc_md2_t
    {
        uint8_t state[16];
        uint8_t x[48];
        uint8_t checksum[16];
        uint8_t buffer[16];
        uint8_t count;
    } qc_md2_t;

    /// @brief Initialize the MD2 context
    /// @param ctx The MD2 context
    void qc_md2_init(qc_md2_t *ctx, void *);

    /// @brief Update the MD2 context with some data
    /// @param ctx The MD2 context
    /// @param data The data to update the context with
    /// @param size The length of the data
    void qc_md2_update(qc_md2_t *ctx, const uint8_t *data, size_t size);

    /// @brief Finalize the MD2 context and output the hash
    /// @param ctx The MD2 context
    /// @param hash The output hash
    void qc_md2_final(qc_md2_t *ctx, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif // __QCRYPTO_HASH_MD2_H__
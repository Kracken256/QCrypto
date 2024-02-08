/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#ifndef __QCRYPTO_HASH_CHACHA20_ROUNDROBIN256_H__
#define __QCRYPTO_HASH_CHACHA20_ROUNDROBIN256_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "../types.h"
#include "../macro.h"
#include "../cipher/stream/chacha20.h"

    /*
        Algorithm: CHACHA20_ROUNDROBIN256 message-digest algorithm
        Description:
    */

    typedef struct qc_chacha20_roundrobin256_t
    {
        qc_chacha20_t inner;
        union
        {
            uint8_t state[44];
            struct
            {
                uint8_t key[32];
                uint8_t iv[12];
            } __attribute__((packed)) m;
        } __attribute__((packed)) state;
        uint8_t block[64];
        uint8_t index;
        uint64_t dgst_size;
        uint64_t length;
    } qc_chacha20_roundrobin256_t;

    #define QC_CHACHA20_ROUNDROBIN256_DIGEST_SIZE 32

    /// @brief Initialize the CHACHA20_ROUNDROBIN256 context
    /// @param ctx The CHACHA20_ROUNDROBIN256 context
    void qc_chacha20_roundrobin256_init(qc_chacha20_roundrobin256_t *ctx, void *);

    /// @brief Update the CHACHA20_ROUNDROBIN256 context with some data
    /// @param ctx The CHACHA20_ROUNDROBIN256 context
    /// @param data The data to update the context with
    /// @param size The length of the data
    void qc_chacha20_roundrobin256_update(qc_chacha20_roundrobin256_t *ctx, const uint8_t *data, size_t size);

    /// @brief Finalize the CHACHA20_ROUNDROBIN256 context and output the hash
    /// @param ctx The CHACHA20_ROUNDROBIN256 context
    /// @param hash The output hash
    void qc_chacha20_roundrobin256_final(qc_chacha20_roundrobin256_t *ctx, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif // __QCRYPTO_HASH_CHACHA20_ROUNDROBIN256_H__
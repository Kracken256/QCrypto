/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#ifndef __QCRYPTO_HASH_CRC64_H__
#define __QCRYPTO_HASH_CRC64_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "../types.h"

    /*
        Algorithm: CRC64
        Description: A 64-bit checksum algorithm.
        Pros: Very fast, constant space complexity, very low-cost to implement.
        Cons: Not cryptographicly secure, not preimage resistant, not collision resistant.
        Implementation notes: This implementation uses a lookup table to speed up the algorithm.
    */

    typedef struct qx_crc64_t
    {
        /// @brief Algorithm state
        uint64_t s;
    } qx_crc64_t;

    /// @brief Initialize a CRC64 context
    /// @param ctx The context to initialize
    /// @note ECMA-182 variant
    static inline void qx_crc64_goiso_init(qx_crc64_t *ctx)
    {
        ctx->s = 0xFFFFFFFFFFFFFFFF; // Initial value for CRC64 algorithm
    }

    /// @brief Update a CRC64 context with data
    /// @param ctx The context to update
    /// @param data The data to update the context with
    /// @param size The size of the data
    void qx_crc64_goiso_update(qx_crc64_t *ctx, const uint8_t *data, size_t size);

    /// @brief Finalize a CRC64 context
    /// @param ctx The context to finalize
    /// @return The CRC64 hash
    static inline uint64_t qx_crc64_goiso_final(qx_crc64_t *ctx)
    {
        // A nice property of CRC64 is that the nil digest is always 0x0000000000000000
        return ctx->s ^ 0xFFFFFFFFFFFFFFFF;
    }

    static inline uint64_t qx_crc64_goiso(const uint8_t *data, size_t size)
    {
        qx_crc64_t ctx;
        qx_crc64_goiso_init(&ctx);
        qx_crc64_goiso_update(&ctx, data, size);
        return qx_crc64_goiso_final(&ctx);
    }

#ifdef __cplusplus
}
#endif

#endif // __QCRYPTO_HASH_CRC64_H__
/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#ifndef __QCRYPTO_HASH_CRC32_H__
#define __QCRYPTO_HASH_CRC32_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "../types.h"

    /*
        Algorithm: CRC32
        Description: A 32-bit checksum algorithm invented by W. Wesley Peterson in 1961.
        Pros: Very fast, constant space complexity, very low-cost to implement.
        Cons: Not cryptographicly secure, not preimage resistant, not collision resistant.
        Implementation notes: This implementation uses a lookup table to speed up the algorithm.
    */

    typedef struct qx_crc32_t
    {
        /// @brief Algorithm state
        uint32_t s;
    } qx_crc32_t;

    /// @brief Initialize a CRC32 context
    /// @param ctx The context to initialize
    static inline void qx_crc32_init(qx_crc32_t *ctx)
    {
        ctx->s = 0xFFFFFFFF; // Initial value for CRC32 algorithm
    }

    /// @brief Update a CRC32 context with data
    /// @param ctx The context to update
    /// @param data The data to update the context with
    /// @param size The size of the data
    void qx_crc32_update(qx_crc32_t *ctx, const uint8_t *data, size_t size);

    /// @brief Finalize a CRC32 context
    /// @param ctx The context to finalize
    /// @return The CRC32 hash
    static inline uint32_t qx_crc32_final(qx_crc32_t *ctx)
    {
        // A nice property of CRC32 is that the nil digest is always 0x00000000
        return ctx->s ^ 0xFFFFFFFF;
    }

    static inline uint32_t qx_crc32(const uint8_t *data, size_t size)
    {
        qx_crc32_t ctx;
        qx_crc32_init(&ctx);
        qx_crc32_update(&ctx, data, size);
        return qx_crc32_final(&ctx);
    }

#ifdef __cplusplus
}
#endif

#endif // __QCRYPTO_HASH_CRC32_H__
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
#include "../macro.h"

    /*
        Algorithm: CRC32
        Description: A 32-bit checksum algorithm invented by W. Wesley Peterson in 1961.
        Pros: Very fast, constant space complexity, very low-cost to implement.
        Cons: Not cryptographicly secure, not preimage resistant, not collision resistant.
        Implementation notes: This implementation uses a lookup table to speed up the algorithm.
    */

    typedef struct qc_crc32_t
    {
        /// @brief Algorithm state
        uint32_t s;
    } qc_crc32_t;

    /// @brief Initialize a CRC32 context
    /// @param ctx The context to initialize
    static inline void qc_crc32_init(qc_crc32_t *ctx, void *x)
    {
        (void)x;
        ctx->s = 0xFFFFFFFF; // Initial value for CRC32 algorithm
    }

    /// @brief Update a CRC32 context with data
    /// @param ctx The context to update
    /// @param data The data to update the context with
    /// @param size The size of the data
    void qc_crc32_update(qc_crc32_t *ctx, const uint8_t *data, size_t size);

    /// @brief Finalize a CRC32 context
    /// @param ctx The context to finalize
    /// @return The CRC32 hash
    static inline void qc_crc32_final(qc_crc32_t *ctx, uint8_t *out)
    {
        // A nice property of CRC32 is that the nil digest is always 0x00000000
        ctx->s = QC_BE32(ctx->s ^ 0xFFFFFFFF);

        out[0] = (uint8_t)(ctx->s >> 24);
        out[1] = (uint8_t)(ctx->s >> 16);
        out[2] = (uint8_t)(ctx->s >> 8);
        out[3] = (uint8_t)(ctx->s);
    }

    static inline uint32_t qc_crc32(const uint8_t *data, size_t size)
    {
        qc_crc32_t ctx;
        uint32_t out;
        qc_crc32_init(&ctx, NULL);
        qc_crc32_update(&ctx, data, size);
        qc_crc32_final(&ctx, (uint8_t *)&out);

        return out;
    }

#ifdef __cplusplus
}
#endif

#endif // __QCRYPTO_HASH_CRC32_H__
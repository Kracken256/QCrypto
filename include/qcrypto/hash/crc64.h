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
#include "../macro.h"

    /*
        Algorithm: CRC64
        Description: A 64-bit checksum algorithm.
        Pros: Very fast, constant space complexity, very low-cost to implement.
        Cons: Not cryptographicly secure, not preimage resistant, not collision resistant.
        Implementation notes: This implementation uses a lookup table to speed up the algorithm.
    */

    typedef struct qc_crc64_t
    {
        /// @brief Algorithm state
        uint64_t s;
    } qc_crc64_t;

    /// @brief Initialize a CRC64 context
    /// @param ctx The context to initialize
    /// @note ECMA-182 variant
    static inline void qc_crc64_goiso_init(qc_crc64_t *ctx, void *x)
    {
        (void)x;
        ctx->s = 0xFFFFFFFFFFFFFFFF; // Initial value for CRC64 algorithm
    }

    /// @brief Update a CRC64 context with data
    /// @param ctx The context to update
    /// @param data The data to update the context with
    /// @param size The size of the data
    void qc_crc64_goiso_update(qc_crc64_t *ctx, const uint8_t *data, size_t size);

    /// @brief Finalize a CRC64 context
    /// @param ctx The context to finalize
    /// @return The CRC64 hash
    static inline void qc_crc64_goiso_final(qc_crc64_t *ctx, uint8_t *out)
    {
        // A nice property of CRC64 is that the nil digest is always 0x0000000000000000
        ctx->s = QC_BE64(ctx->s ^ 0xFFFFFFFFFFFFFFFF);

        out[0] = (uint8_t)(ctx->s >> 56);
        out[1] = (uint8_t)(ctx->s >> 48);
        out[2] = (uint8_t)(ctx->s >> 40);
        out[3] = (uint8_t)(ctx->s >> 32);
        out[4] = (uint8_t)(ctx->s >> 24);
        out[5] = (uint8_t)(ctx->s >> 16);
        out[6] = (uint8_t)(ctx->s >> 8);
        out[7] = (uint8_t)(ctx->s);
    }

    static inline uint64_t qc_crc64_goiso(const uint8_t *data, size_t size)
    {
        qc_crc64_t ctx;
        uint64_t out;
        qc_crc64_goiso_init(&ctx, NULL);
        qc_crc64_goiso_update(&ctx, data, size);
        qc_crc64_goiso_final(&ctx, (uint8_t *)&out);

        return out;
    }

#ifdef __cplusplus
}
#endif

#endif // __QCRYPTO_HASH_CRC64_H__
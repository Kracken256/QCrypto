/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#ifndef __QCRYPTO_HASH_CRC16_H__
#define __QCRYPTO_HASH_CRC16_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "../types.h"
#include "../macro.h"

    /*
        Algorithm: CRC16
        Description: A 16-bit checksum algorithm.
        Pros: Very fast, constant space complexity, very low-cost to implement.
        Cons: Not cryptographicly secure, not preimage resistant, not collision resistant.
        Implementation notes: This implementation uses a lookup table to speed up the algorithm.
    */

    typedef struct qc_crc16_t
    {
        /// @brief Algorithm state
        uint16_t s;
    } qc_crc16_t;

    /// @brief Initialize a CRC16 context
    /// @param ctx The context to initialize
    static inline void qc_crc16_init(qc_crc16_t *ctx, void *x)
    {
        (void)x;
        ctx->s = 0; // Initial value for CRC16 algorithm
    }

    /// @brief Update a CRC16 context with data
    /// @param ctx The context to update
    /// @param data The data to update the context with
    /// @param size The size of the data
    void qc_crc16_update(qc_crc16_t *ctx, const uint8_t *data, size_t size);

    /// @brief Finalize a CRC16 context
    /// @param ctx The context to finalize
    /// @return The CRC16 hash
    static inline void qc_crc16_final(qc_crc16_t *ctx, uint8_t *out)
    {
        // A nice property of CRC16 is that the nil digest is always 0x00000000
        ctx->s = QC_BE16(ctx->s);

        // Copy the digest to the output buffer
        out[0] = (uint8_t)(ctx->s >> 8);
        out[1] = (uint8_t)(ctx->s & 0xFF);
    }

    static inline uint16_t qc_crc16(const uint8_t *data, size_t size)
    {
        qc_crc16_t ctx;
        uint16_t out;
        qc_crc16_init(&ctx, NULL);
        qc_crc16_update(&ctx, data, size);
        qc_crc16_final(&ctx, (uint8_t *)&out);

        return out;
    }

#ifdef __cplusplus
}
#endif

#endif // __QCRYPTO_HASH_CRC16_H__
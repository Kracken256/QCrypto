/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#ifndef __QCRYPTO_HASH_CRC8_H__
#define __QCRYPTO_HASH_CRC8_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "../types.h"
#include "../macro.h"

    /*
        Algorithm: CRC8
        Description: A 8-bit checksum algorithm.
        Pros: Very fast, constant space complexity, very low-cost to implement.
        Cons: Not cryptographicly secure, not preimage resistant, not collision resistant.
        Implementation notes: This implementation uses a lookup table to speed up the algorithm.
    */

    typedef struct qc_crc8_t
    {
        /// @brief Algorithm state
        uint8_t s;
    } qc_crc8_t;

    /// @brief Initialize a CRC8 context
    /// @param ctx The context to initialize
    static inline void qc_crc8_init(qc_crc8_t *ctx, void *x)
    {
        (void)x;
        ctx->s = 0; // Initial value for CRC8 algorithm
    }

    /// @brief Update a CRC8 context with data
    /// @param ctx The context to update
    /// @param data The data to update the context with
    /// @param size The size of the data
    void qc_crc8_update(qc_crc8_t *ctx, const uint8_t *data, size_t size);

    /// @brief Finalize a CRC8 context
    /// @param ctx The context to finalize
    /// @return The CRC8 hash
    static inline void qc_crc8_final(qc_crc8_t *ctx, uint8_t *out)
    {
        // A nice property of CRC8 is that the nil digest is always 0x00000000
        ctx->s ^= 0;

        out[0] = ctx->s;
    }

    static inline uint8_t qc_crc8(const uint8_t *data, size_t size)
    {
        qc_crc8_t ctx;
        uint8_t out;
        qc_crc8_init(&ctx, NULL);
        qc_crc8_update(&ctx, data, size);
        qc_crc8_final(&ctx, (uint8_t *)&out);

        return out;
    }

#ifdef __cplusplus
}
#endif

#endif // __QCRYPTO_HASH_CRC8_H__
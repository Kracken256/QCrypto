/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#ifndef __QCRYPTO_HASH_CRC_H__
#define __QCRYPTO_HASH_CRC_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "../types.h"
#include "../macro.h"

    /*
        Algorithm: Cyclical Redundancy Check Generic
        Description: A N-bit checksum algorithm.
        Pros: Very fast, constant space complexity, very low-cost to implement.
        Cons: Not cryptographicly secure, not preimage resistant, not collision resistant.
        Implementation notes: This implementation uses a lookup table to speed up the algorithm.
    */

    typedef struct qc_crc_t
    {
        /// @brief Algorithm state
        uint64_t s;

        uint8_t num_bits;

        uint64_t mask;

        uint64_t poly;
        uint64_t init;
        uint64_t xor_out;

        uint64_t table[256];
    } qc_crc_t;

    /// @brief Initialize a CRC context
    /// @param ctx The context to initialize
    void qc_crc_init(qc_crc_t *ctx, void *x);

    /// @brief Update a CRC context with data
    /// @param ctx The context to update
    /// @param data The data to update the context with
    /// @param size The size of the data
    void qc_crc_update(qc_crc_t *ctx, const uint8_t *data, size_t size);

    /// @brief Finalize a CRC context
    /// @param ctx The context to finalize
    /// @return The CRC hash
    static inline void qc_crc_final(qc_crc_t *ctx, uint8_t *out)
    {
        ctx->s = QC_BE64(ctx->s ^ ctx->xor_out);

        out[0] = (uint8_t)(ctx->s >> 56);
        out[1] = (uint8_t)(ctx->s >> 48);
        out[2] = (uint8_t)(ctx->s >> 40);
        out[3] = (uint8_t)(ctx->s >> 32);
        out[4] = (uint8_t)(ctx->s >> 24);
        out[5] = (uint8_t)(ctx->s >> 16);
        out[6] = (uint8_t)(ctx->s >> 8);
        out[7] = (uint8_t)(ctx->s);
    }

    static inline void qc_crc_reset(qc_crc_t *ctx, void *x)
    {
        (void)x;
        ctx->s = ctx->init;
    }

#ifdef __cplusplus
}
#endif

#endif // __QCRYPTO_HASH_CRC_H__
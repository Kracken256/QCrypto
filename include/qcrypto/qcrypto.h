/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#ifndef __QCRYPTO_H__
#define __QCRYPTO_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "types.h"
#include "hash/all.h"

    typedef void (*QC_MD_INIT_FN_T)(void *, void *);
    typedef void (*QC_MD_UPDATE_FN_T)(void *, const uint8_t *, uint64_t);
    typedef void (*QC_MD_FINAL_FN_T)(void *, uint8_t *);

    typedef enum QC_ALGORITHMS
    {
        __QC_DIGEST__ = 1000,
        QC_CRC32,
        QC_CRC64ISO,
    } QC_ALGORITHMS;

    typedef struct QC_MD_CTX
    {
        QC_MD_INIT_FN_T init;
        QC_MD_UPDATE_FN_T update;
        QC_MD_FINAL_FN_T final;
        QC_ALGORITHMS algo;
        uint64_t dsgt_size;
        uint16_t ctx_size;
        void *ctx_ptr;
    } QC_MD_CTX;

    #define QC_OK 1

    /// @brief Create a new message digest context
    /// @param[in] ctx The context to create
    /// @param algo The algorithm to use
    /// @param ... Additional arguments
    /// @return returns 1 on success, negative on failure
    /// @note The ctx pointer does not need to be initialized
    /// @note The ctx pointer must be freed with QC_DigestFree to
    /// free the internal context
    int QC_DigestInit(QC_MD_CTX *ctx, QC_ALGORITHMS algo, ...);

    /// @brief Update a hash context
    /// @param ctx The hash context
    /// @param data The data to hash
    /// @param size The size of the data
    /// @return returns 1 on success, negative on failure
    int QC_DigestUpdate(QC_MD_CTX *ctx, const uint8_t *data, uint64_t size);

    /// @brief Finalize a hash context
    /// @param ctx The hash context
    /// @param out The output buffer
    /// @return returns 1 on success, negative on failure
    int QC_DigestFinal(QC_MD_CTX *ctx, uint8_t *out);

    /// @brief Reset a hash context
    /// @param ctx The hash context
    /// @param ... Additional arguments
    /// @return returns 1 on success, negative on failure
    /// @note This will avoid allocating a new context
    int QC_DigestReset(QC_MD_CTX *ctx, ...);

    /// @brief Free a hash context
    /// @param ctx The hash context
    void QC_DigestFree(QC_MD_CTX *ctx);

    /// @brief Calculate hash all in one
    /// @param algo The algorithm to use
    /// @param data The data to hash
    /// @param size The size of the data
    /// @param out The output buffer
    /// @param ... Additional arguments
    /// @return returns 1 on success, negative on failure
    int QC_Digest(QC_ALGORITHMS algo, const uint8_t *data, uint64_t size, uint8_t *out, ...);

#ifdef __cplusplus
}
#endif

#endif // __QCRYPTO_H__
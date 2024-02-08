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

    typedef void (*QC_MD_INIT_FN_T)(void *, void *);
    typedef void (*QC_MD_UPDATE_FN_T)(void *, const uint8_t *, uint64_t);
    typedef void (*QC_MD_FINAL_FN_T)(void *, uint8_t *);
    typedef void (*QC_MD_RESET_FN_T)(void *, void *);

    typedef enum QC_ALGORITHMS
    {
        __QC_DIGEST__ = 1000,

        /* Cyclic Redundancy Check family */
        QC_CRC,
        QC_CRC8,
        QC_CRC16,
        QC_CRC32,
        QC_CRC64ISO,

        /* Message Digest family */
        QC_MD2,
        QC_MD4,
        QC_MD5,
        QC_MD6,

        /* SHA */
        QC_SHA0,
        QC_SHA1,

        /* SHA2 family */
        QC_SHA224,
        QC_SHA256,
        QC_SHA384,
        QC_SHA512,
        QC_SHA512_224,
        QC_SHA512_256,

        /* SHA3 family */
        QC_SHA3_224,
        QC_SHA3_256,
        QC_SHA3_384,
        QC_SHA3_512,

        /* BLAKE family */
        QC_BLAKE256,
        QC_BLAKE512,
        QC_BLAKE2S,
        QC_BLAKE2B,
        QC_BLAKE2X,
        QC_BLAKE3,

        /* Whirlpool family */
        QC_WHIRLPOOL,

        /* Tiger family */
        QC_TIGER,

        /* RIPEMD family */
        QC_RIPEMD128,
        QC_RIPEMD160,
        QC_RIPEMD256,
        QC_RIPEMD320,

        /* Keccak family */
        QC_KECCAK224,
        QC_KECCAK256,
        QC_KECCAK384,
        QC_KECCAK512,

        /* Skein family */
        QC_SKEIN,

        /* Snefru family */
        QC_SNEFRU128,
        QC_SNEFRU256,

        /* Spectral Hash family */
        QC_SPECTRAL_HASH,

        /* Streebog family */
        QC_STREEBOG256,
        QC_STREEBOG512,

        /* SWIFFT family */
        QC_SWIFFT,

        /* SM3 family */
        QC_SM3,

        /* GOST family */
        QC_GOST,

        /* FSB family */
        QC_FSB_160,
        QC_FSB_512,

        __QC_CIPHER__ = 2000,

        /* AES family */
        QC_AES128,
        QC_AES192,
        QC_AES256,
        QC_AES384,
        QC_AES512,

        /* DES family */
        QC_DES,
        QC_3DES,

        /* RC family */
        QC_RC2,
        QC_RC3,
        QC_RC4,
        QC_RC5,
        QC_RC6,

        /* FISH family */
        QC_BLOWFISH,
        QC_TWOFISH,
        QC_THREEFISH,

        /* CAST family */
        QC_CAST128,
        QC_CAST256,

        /* IDEA family */
        QC_IDEA,

        /* SEED family */
        QC_SEED,

        /* CAMELLIA family */
        QC_CAMELLIA128,
        QC_CAMELLIA192,
        QC_CAMELLIA256,

        /* ARIA family */
        QC_ARIA128,
        QC_ARIA192,
        QC_ARIA256,
    } QC_ALGORITHMS;

    typedef struct QC_MD_CTX
    {
        QC_MD_INIT_FN_T init;
        QC_MD_UPDATE_FN_T update;
        QC_MD_FINAL_FN_T final;
        QC_MD_RESET_FN_T reset;
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
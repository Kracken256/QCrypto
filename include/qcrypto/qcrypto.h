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

        QC_CHACHA,
        QC_SALSA,
        QC_RABBIT,
        QC_HC128,
        QC_HC256,
        QC_ISAAC,

        QC_XOR,
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

    typedef int (*QC_CIPHER_INIT_FN_T)(void *, void *);
    typedef int (*QC_CIPHER_SETUP_FN_T)(void *, void *, void *);
    typedef int (*QC_CIPHER_ENCRYPT_FN_T)(void *, const uint8_t *, uint64_t, uint8_t *, uint64_t *);
    typedef int (*QC_CIPHER_DECRYPT_FN_T)(void *, const uint8_t *, uint64_t, uint8_t *, uint64_t *);
    typedef int (*QC_CIPHER_RESET_FN_T)(void *, void *);

    typedef enum QC_CIPHER_MODE
    {
        QC_ECB,
        QC_CBC,
        QC_CFB,
        QC_OFB,
        QC_CTR,
        QC_GCM,
        QC_CCM,
        QC_XTS,
        QC_OCB,
        QC_SIV,
        QC_EAX,
    } QC_CIPHER_MODE;

    typedef struct QC_CIPHER_CTX
    {
        QC_CIPHER_INIT_FN_T init;
        QC_CIPHER_SETUP_FN_T setup;
        QC_CIPHER_ENCRYPT_FN_T encrypt;
        QC_CIPHER_DECRYPT_FN_T decrypt;
        QC_CIPHER_RESET_FN_T reset;
        QC_ALGORITHMS algo;
        QC_CIPHER_MODE mode;
        uint32_t key_size;
        uint32_t iv_size;
        uint32_t block_size;
        uint64_t tag_size;
        uint16_t ctx_size;
        void *ctx_ptr;
    } QC_CIPHER_CTX;

    /// @brief Create a new cipher context
    /// @param[in] ctx The context to create
    /// @param algo The algorithm to use
    /// @param mode The mode to use
    /// @param ... Additional arguments
    /// @return returns 1 on success, negative on failure
    /// @note The ctx pointer does not need to be initialized
    /// @note The ctx pointer must be freed with QC_CipherFree to
    /// free the internal context
    int QC_CipherInit(QC_CIPHER_CTX *ctx, QC_ALGORITHMS algo, QC_CIPHER_MODE mode, ...);

    /// @brief Setup a cipher context
    /// @param ctx The cipher context
    /// @param key The key to use
    /// @param iv The initialization vector to use
    /// @return returns 1 on success, negative on failure
    int QC_CipherSetup(QC_CIPHER_CTX *ctx, const uint8_t *key, const uint8_t *iv);

    /// @brief Create and setup a cipher context
    /// @param ctx The cipher context
    /// @param algo The algorithm to use
    /// @param mode The mode to use
    /// @param key The key to use
    /// @param iv The initialization vector to use
    /// @param ... Additional arguments
    /// @return returns 1 on success, negative on failure
    /// @note This is a convenience function that calls QC_CipherInit and QC_CipherSetup
    /// @note The ctx pointer does not need to be initialized
    /// @note The ctx pointer must be freed with QC_CipherFree to
    /// free the internal context
    int QC_CipherCreate(QC_CIPHER_CTX *ctx, QC_ALGORITHMS algo, QC_CIPHER_MODE mode, const uint8_t *key, const uint8_t *iv, ...);

    /// @brief Encrypt data
    /// @param ctx The cipher context
    /// @param plaintext The plaintext to encrypt
    /// @param plaintext_size The size of the plaintext
    /// @param ciphertext The output buffer
    /// @param ciphertext_size The size of the ciphertext
    /// @return returns 1 on success, negative on failure
    int QC_CipherEncrypt(QC_CIPHER_CTX *ctx, const uint8_t *plaintext, uint64_t plaintext_size, uint8_t *ciphertext, uint64_t *ciphertext_size);

    /// @brief Decrypt data
    /// @param ctx The cipher context
    /// @param ciphertext The ciphertext to decrypt
    /// @param ciphertext_size The size of the ciphertext
    /// @param plaintext The output buffer
    /// @param plaintext_size The size of the plaintext
    /// @return returns 1 on success, negative on failure
    int QC_CipherDecrypt(QC_CIPHER_CTX *ctx, const uint8_t *ciphertext, uint64_t ciphertext_size, uint8_t *plaintext, uint64_t *plaintext_size);

    /// @brief Reset a cipher context
    /// @param ctx The cipher context
    /// @param ... Additional arguments
    /// @return returns 1 on success, negative on failure
    /// @note This will avoid allocating a new context
    int QC_CipherReset(QC_CIPHER_CTX *ctx, ...);

    /// @brief Free a cipher context
    /// @param ctx The cipher context
    void QC_CipherFree(QC_CIPHER_CTX *ctx);

    /// @brief Do encryption all in one
    /// @param algo The algorithm to use
    /// @param mode The mode to use
    /// @param key The key to use
    /// @param iv The initialization vector to use
    /// @param plaintext The plaintext to encrypt
    /// @param plaintext_size The size of the plaintext
    /// @param ciphertext The output buffer
    /// @param ciphertext_size The size of the ciphertext
    /// @param ... Additional arguments
    /// @return returns 1 on success, negative on failure
    int QC_Encrypt(QC_ALGORITHMS algo, QC_CIPHER_MODE mode, const uint8_t *key, const uint8_t *iv, const uint8_t *plaintext, uint64_t plaintext_size, uint8_t *ciphertext, uint64_t *ciphertext_size, ...);

    /// @brief Do decryption all in one
    /// @param algo The algorithm to use
    /// @param mode The mode to use
    /// @param key The key to use
    /// @param iv The initialization vector to use
    /// @param ciphertext The ciphertext to decrypt
    /// @param ciphertext_size The size of the ciphertext
    /// @param plaintext The output buffer
    /// @param plaintext_size The size of the plaintext
    /// @param ... Additional arguments
    /// @return returns 1 on success, negative on failure
    int QC_Decrypt(QC_ALGORITHMS algo, QC_CIPHER_MODE mode, const uint8_t *key, const uint8_t *iv, const uint8_t *ciphertext, uint64_t ciphertext_size, uint8_t *plaintext, uint64_t *plaintext_size, ...);

#ifdef __cplusplus
}
#endif

#endif // __QCRYPTO_H__
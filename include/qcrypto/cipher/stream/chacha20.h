/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#ifndef __QCRYPTO_HASH_CHACHA20_H__
#define __QCRYPTO_HASH_CHACHA20_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "../../types.h"
#include "../../macro.h"

    /*
        Algorithm: ChaCha20 stream cipher
        Description: Fast, secure, side-channel resistant stream cipher
        Pros: Fast, secure, side-channel resistant
        Cons: Lacking hardware acceleration
    */

    typedef struct qc_chacha20_t
    {
        uint32_t keystream32[16];
        uint64_t position;
        uint8_t key[32];
        uint8_t nonce[12];
        uint64_t counter;
        uint32_t state[16];
    } qc_chacha20_t;

    /// @brief Initialize the CHACHA20 context
    /// @param ctx The CHACHA20 context
    /// @warning va_list must inclide 64 bit counter
    int qc_chacha20_init(qc_chacha20_t *ctx, void *);

    /// @brief Setup the CHACHA20 context with a key and nonce
    /// @param ctx The CHACHA20 context
    /// @param key The key
    /// @param nonce The nonce
    int qc_chacha20_setup(qc_chacha20_t *ctx, const uint8_t *key, const uint8_t *nonce);

    /// @brief Encrypt or decrypt data with the CHACHA20 context
    /// @param ctx The CHACHA20 context
    /// @param data The data to encrypt or decrypt
    /// @param length The length of the data
    int qc_chacha20_crypt(qc_chacha20_t *ctx, const uint8_t *in, uint64_t in_size, uint8_t *out, uint64_t *out_size);

#ifdef __cplusplus
}
#endif

#endif // __QCRYPTO_HASH_CHACHA20_H__
/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#include <qcrypto/qcrypto.h>
#include <stdarg.h>

#include <qcrypto/cipher/all.h>
#include <qcrypto/macro.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

enum ALGO_TYPE_CTX_SIZE
{
    HEKS = 0
};

static void *safe_malloc(size_t size)
{
    void *ptr = malloc(size);
    if (ptr == NULL)
    {
        perror("QCRYPTO: malloc failed");
        exit(1);
    }
    return ptr;
}

static int QC_vCipherInit(QC_CIPHER_CTX *ctx, QC_ALGORITHMS algo, QC_CIPHER_MODE mode, va_list args)
{
    ctx->algo = algo;

    switch (algo)
    {
        // case QC_CRC:
        //     ctx->init = (QC_MD_INIT_FN_T)qc_crc_init;
        //     ctx->update = (QC_MD_UPDATE_FN_T)qc_crc_update;
        //     ctx->final = (QC_MD_FINAL_FN_T)qc_crc_final;
        //     ctx->reset = (QC_MD_RESET_FN_T)qc_crc_reset;
        //     ctx->dsgt_size = 8;
        //     ctx->ctx_size = QC_CRC_CTX_SIZE;
        //     ctx->ctx_ptr = safe_malloc(ctx->ctx_size);
        //     break;

    default:
        ctx->init = NULL;
        ctx->setup = NULL;
        ctx->encrypt = NULL;
        ctx->decrypt = NULL;
        ctx->reset = NULL;
        ctx->algo = algo;
        ctx->mode = mode;
        ctx->ctx_ptr = NULL;
        ctx->ctx_size = 0;
        ctx->key_size = 0;
        ctx->iv_size = 0;
        ctx->block_size = 0;
        ctx->tag_size = 0;
        return -1;
    }

    ctx->init(ctx->ctx_ptr, args);

    return 1;
}

QC_EXPORT int QC_CipherInit(QC_CIPHER_CTX *ctx, QC_ALGORITHMS algo, QC_CIPHER_MODE mode, ...)
{
    va_list args;

    va_start(args, mode);
    if (QC_vCipherInit(ctx, algo, mode, args) < 0)
    {
        va_end(args);
        return -1;
    }

    va_end(args);

    return 1;
}

QC_EXPORT int QC_CipherSetup(QC_CIPHER_CTX *ctx, const uint8_t *key, const uint8_t *iv)
{
    (void)ctx;
    (void)key;
    (void)iv;

    return 0;
}

QC_EXPORT int QC_CipherCreate(QC_CIPHER_CTX *ctx, QC_ALGORITHMS algo, QC_CIPHER_MODE mode, const uint8_t *key, const uint8_t *iv, ...)
{
    va_list args;

    va_start(args, iv);
    if (QC_vCipherInit(ctx, algo, mode, args) < 0)
    {
        va_end(args);
        return -1;
    }

    va_end(args);

    if (QC_CipherSetup(ctx, key, iv) < 0)
    {
        QC_CipherFree(ctx);
        return -1;
    }

    return 1;
}

QC_EXPORT int QC_CipherEncrypt(QC_CIPHER_CTX *ctx, const uint8_t *plaintext, uint64_t plaintext_size, uint8_t *ciphertext, uint64_t *ciphertext_size)
{
    if (ctx->encrypt == NULL)
    {
        return -1;
    }

    ctx->encrypt(ctx->ctx_ptr, plaintext, plaintext_size, ciphertext, ciphertext_size);

    return 1;
}

QC_EXPORT int QC_CipherDecrypt(QC_CIPHER_CTX *ctx, const uint8_t *ciphertext, uint64_t ciphertext_size, uint8_t *plaintext, uint64_t *plaintext_size)
{
    if (ctx->decrypt == NULL)
    {
        return -1;
    }

    ctx->decrypt(ctx->ctx_ptr, ciphertext, ciphertext_size, plaintext, plaintext_size);

    return 1;
}

QC_EXPORT int QC_CipherReset(QC_CIPHER_CTX *ctx, ...)
{
    va_list args;

    va_start(args, ctx);

    ctx->reset(ctx->ctx_ptr, args);

    va_end(args);

    return 1;
}

QC_EXPORT void QC_CipherFree(QC_CIPHER_CTX *ctx)
{
    if (!ctx)
        return;

    if (ctx->ctx_ptr != NULL)
    {
        memset(ctx->ctx_ptr, 0, ctx->ctx_size);
        free(ctx->ctx_ptr);

        ctx->ctx_ptr = NULL;
    }

    memset(ctx, 0, sizeof(QC_CIPHER_CTX)); // clear the context
}

int QC_Encrypt(QC_ALGORITHMS algo, QC_CIPHER_MODE mode, const uint8_t *key, const uint8_t *iv, const uint8_t *plaintext, uint64_t plaintext_size, uint8_t *ciphertext, uint64_t *ciphertext_size, ...)
{
    QC_CIPHER_CTX ctx;
    va_list args;

    va_start(args, ciphertext_size);
    if (QC_CipherCreate(&ctx, algo, mode, key, iv, args, args) < 0)
    {
        va_end(args);
        return -1;
    }
    va_end(args);

    if (QC_CipherEncrypt(&ctx, plaintext, plaintext_size, ciphertext, ciphertext_size) < 0)
    {
        QC_CipherFree(&ctx);
        return -1;
    }

    QC_CipherFree(&ctx);

    return 1;
}
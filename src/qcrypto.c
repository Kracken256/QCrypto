/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#include <qcrypto/qcrypto.h>
#include <stdarg.h>

#include <qcrypto/hash/all.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

enum ALGO_TYPE_CTX_SIZE
{
    QC_CRC32_CTX_SIZE = sizeof(qc_crc32_t),
    QC_CRC64ISO_CTX_SIZE = sizeof(qc_crc64_t),
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

static int QC_vDigestReset(QC_MD_CTX *ctx, va_list args)
{
    if (ctx->init == NULL)
    {
        return -1;
    }

    ctx->init(ctx->ctx_ptr, args);

    return 1;
}

static int QC_vDigestInit(QC_MD_CTX *ctx, QC_ALGORITHMS algo, va_list args)
{
    ctx->algo = algo;

    switch (algo)
    {
    case QC_CRC32:
        ctx->init = (QC_MD_INIT_FN_T)qc_crc32_init;
        ctx->update = (QC_MD_UPDATE_FN_T)qc_crc32_update;
        ctx->final = (QC_MD_FINAL_FN_T)qc_crc32_final;
        ctx->dsgt_size = 4;
        ctx->ctx_size = QC_CRC32_CTX_SIZE;
        ctx->ctx_ptr = safe_malloc(ctx->ctx_size);
        break;
    case QC_CRC64ISO:
        ctx->init = (QC_MD_INIT_FN_T)qc_crc64_goiso_init;
        ctx->update = (QC_MD_UPDATE_FN_T)qc_crc64_goiso_update;
        ctx->final = (QC_MD_FINAL_FN_T)qc_crc64_goiso_final;
        ctx->dsgt_size = 8;
        ctx->ctx_size = QC_CRC64ISO_CTX_SIZE;
        ctx->ctx_ptr = safe_malloc(ctx->ctx_size);
        break;
    default:
        ctx->init = NULL;
        ctx->update = NULL;
        ctx->final = NULL;
        ctx->algo = algo;
        ctx->ctx_ptr = NULL;
        ctx->ctx_size = 0;
        ctx->dsgt_size = 0;
        return -1;
    }

    return QC_vDigestReset(ctx, args);
}

QC_EXPORT int QC_DigestInit(QC_MD_CTX *ctx, QC_ALGORITHMS algo, ...)
{
    va_list args;

    va_start(args, algo);
    if (QC_vDigestInit(ctx, algo, args) < 0)
    {
        va_end(args);
        return -1;
    }

    va_end(args);

    return 1;
}

QC_EXPORT int QC_DigestUpdate(QC_MD_CTX *ctx, const uint8_t *data, uint64_t size)
{
    if (ctx->update == NULL)
    {
        return -1;
    }

    ctx->update(ctx->ctx_ptr, data, size);

    return 1;
}

QC_EXPORT int QC_DigestFinal(QC_MD_CTX *ctx, uint8_t *out)
{
    if (ctx->final == NULL)
    {
        return -1;
    }

    ctx->final(ctx->ctx_ptr, out);

    return 1;
}

QC_EXPORT int QC_DigestReset(QC_MD_CTX *ctx, ...)
{
    va_list args;

    va_start(args, ctx);
    if (QC_vDigestReset(ctx, args) < 0)
    {
        va_end(args);
        return -1;
    }

    va_end(args);

    return 1;
}

QC_EXPORT void QC_DigestFree(QC_MD_CTX *ctx)
{
    if (ctx->ctx_ptr != NULL)
    {
        memset(ctx->ctx_ptr, 0, ctx->ctx_size);
        free(ctx->ctx_ptr);

        ctx->ctx_ptr = NULL;
    }
}

QC_EXPORT int QC_Digest(QC_ALGORITHMS algo, const uint8_t *data, uint64_t size, uint8_t *out, ...)
{
    QC_MD_CTX ctx;
    va_list args;

    va_start(args, out);
    if (QC_vDigestInit(&ctx, algo, args) < 0)
    {
        va_end(args);
        return -1;
    }
    va_end(args);

    if (QC_DigestUpdate(&ctx, data, size) < 0)
    {
        QC_DigestFree(&ctx);
        return -1;
    }

    if (QC_DigestFinal(&ctx, out) < 0)
    {
        QC_DigestFree(&ctx);
        return -1;
    }

    QC_DigestFree(&ctx);

    return 1;
}
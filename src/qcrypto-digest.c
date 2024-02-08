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
    QC_CRC_CTX_SIZE = sizeof(qc_crc_t),
    QC_CRC8_CTX_SIZE = sizeof(qc_crc8_t),
    QC_CRC16_CTX_SIZE = sizeof(qc_crc16_t),
    QC_CRC32_CTX_SIZE = sizeof(qc_crc32_t),
    QC_CRC64ISO_CTX_SIZE = sizeof(qc_crc64_t),
    QC_MD2_CTX_SIZE = sizeof(qc_md2_t),
    QC_MD4_CTX_SIZE = sizeof(qc_md4_t),
    QC_MD5_CTX_SIZE = sizeof(qc_md5_t),
    QC_SHA1_CTX_SIZE = sizeof(qc_sha1_t),
    QC_SHA224_CTX_SIZE = sizeof(qc_sha224_t),
    QC_SHA256_CTX_SIZE = sizeof(qc_sha256_t),

    // Expiremental
    QC_CHACHA20_ROUNDROBIN256_CTX_SIZE = sizeof(qc_chacha20_roundrobin256_t),
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

static int QC_vDigestInit(QC_MD_CTX *ctx, QC_ALGORITHMS algo, va_list args)
{
    ctx->algo = algo;

    switch (algo)
    {
    case QC_CRC:
        ctx->init = (QC_MD_INIT_FN_T)qc_crc_init;
        ctx->update = (QC_MD_UPDATE_FN_T)qc_crc_update;
        ctx->final = (QC_MD_FINAL_FN_T)qc_crc_final;
        ctx->reset = (QC_MD_RESET_FN_T)qc_crc_reset;
        ctx->dsgt_size = 8;
        ctx->ctx_size = QC_CRC_CTX_SIZE;
        ctx->ctx_ptr = safe_malloc(ctx->ctx_size);
        break;
    case QC_CRC8:
        ctx->init = (QC_MD_INIT_FN_T)qc_crc8_init;
        ctx->update = (QC_MD_UPDATE_FN_T)qc_crc8_update;
        ctx->final = (QC_MD_FINAL_FN_T)qc_crc8_final;
        ctx->reset = (QC_MD_RESET_FN_T)qc_crc8_init;
        ctx->dsgt_size = 1;
        ctx->ctx_size = QC_CRC8_CTX_SIZE;
        ctx->ctx_ptr = safe_malloc(ctx->ctx_size);
        break;
    case QC_CRC16:
        ctx->init = (QC_MD_INIT_FN_T)qc_crc16_init;
        ctx->update = (QC_MD_UPDATE_FN_T)qc_crc16_update;
        ctx->final = (QC_MD_FINAL_FN_T)qc_crc16_final;
        ctx->reset = (QC_MD_RESET_FN_T)qc_crc16_init;
        ctx->dsgt_size = 2;
        ctx->ctx_size = QC_CRC16_CTX_SIZE;
        ctx->ctx_ptr = safe_malloc(ctx->ctx_size);
        break;
    case QC_CRC32:
        ctx->init = (QC_MD_INIT_FN_T)qc_crc32_init;
        ctx->update = (QC_MD_UPDATE_FN_T)qc_crc32_update;
        ctx->final = (QC_MD_FINAL_FN_T)qc_crc32_final;
        ctx->reset = (QC_MD_RESET_FN_T)qc_crc32_init;
        ctx->dsgt_size = 4;
        ctx->ctx_size = QC_CRC32_CTX_SIZE;
        ctx->ctx_ptr = safe_malloc(ctx->ctx_size);
        break;
    case QC_CRC64ISO:
        ctx->init = (QC_MD_INIT_FN_T)qc_crc64_goiso_init;
        ctx->update = (QC_MD_UPDATE_FN_T)qc_crc64_goiso_update;
        ctx->final = (QC_MD_FINAL_FN_T)qc_crc64_goiso_final;
        ctx->reset = (QC_MD_RESET_FN_T)qc_crc64_goiso_init;
        ctx->dsgt_size = 8;
        ctx->ctx_size = QC_CRC64ISO_CTX_SIZE;
        ctx->ctx_ptr = safe_malloc(ctx->ctx_size);
        break;
    case QC_MD2:
        ctx->init = (QC_MD_INIT_FN_T)qc_md2_init;
        ctx->update = (QC_MD_UPDATE_FN_T)qc_md2_update;
        ctx->final = (QC_MD_FINAL_FN_T)qc_md2_final;
        ctx->reset = (QC_MD_RESET_FN_T)qc_md2_init;
        ctx->dsgt_size = 16;
        ctx->ctx_size = QC_MD2_CTX_SIZE;
        ctx->ctx_ptr = safe_malloc(ctx->ctx_size);
        break;
    case QC_MD4:
        ctx->init = (QC_MD_INIT_FN_T)qc_md4_init;
        ctx->update = (QC_MD_UPDATE_FN_T)qc_md4_update;
        ctx->final = (QC_MD_FINAL_FN_T)qc_md4_final;
        ctx->reset = (QC_MD_RESET_FN_T)qc_md4_init;
        ctx->dsgt_size = 16;
        ctx->ctx_size = QC_MD4_CTX_SIZE;
        ctx->ctx_ptr = safe_malloc(ctx->ctx_size);
        break;
    case QC_MD5:
        ctx->init = (QC_MD_INIT_FN_T)qc_md5_init;
        ctx->update = (QC_MD_UPDATE_FN_T)qc_md5_update;
        ctx->final = (QC_MD_FINAL_FN_T)qc_md5_final;
        ctx->reset = (QC_MD_RESET_FN_T)qc_md5_init;
        ctx->dsgt_size = 16;
        ctx->ctx_size = QC_MD5_CTX_SIZE;
        ctx->ctx_ptr = safe_malloc(ctx->ctx_size);
        break;
    case QC_SHA1:
        ctx->init = (QC_MD_INIT_FN_T)qc_sha1_init;
        ctx->update = (QC_MD_UPDATE_FN_T)qc_sha1_update;
        ctx->final = (QC_MD_FINAL_FN_T)qc_sha1_final;
        ctx->reset = (QC_MD_RESET_FN_T)qc_sha1_init;
        ctx->dsgt_size = 20;
        ctx->ctx_size = QC_SHA1_CTX_SIZE;
        ctx->ctx_ptr = safe_malloc(ctx->ctx_size);
        break;
    case QC_SHA256:
        ctx->init = (QC_MD_INIT_FN_T)qc_sha256_init;
        ctx->update = (QC_MD_UPDATE_FN_T)qc_sha256_update;
        ctx->final = (QC_MD_FINAL_FN_T)qc_sha256_final;
        ctx->reset = (QC_MD_RESET_FN_T)qc_sha256_init;
        ctx->dsgt_size = 32;
        ctx->ctx_size = QC_SHA256_CTX_SIZE;
        ctx->ctx_ptr = safe_malloc(ctx->ctx_size);
        break;
    case QC_SHA224:
        ctx->init = (QC_MD_INIT_FN_T)qc_sha224_init;
        ctx->update = (QC_MD_UPDATE_FN_T)qc_sha224_update;
        ctx->final = (QC_MD_FINAL_FN_T)qc_sha224_final;
        ctx->reset = (QC_MD_RESET_FN_T)qc_sha224_init;
        ctx->dsgt_size = 28;
        ctx->ctx_size = QC_SHA224_CTX_SIZE;
        ctx->ctx_ptr = safe_malloc(ctx->ctx_size);
        break;

    // Expiremental
    case QC_CHACHA20_ROUNDROBIN256:
        ctx->init = (QC_MD_INIT_FN_T)qc_chacha20_roundrobin256_init;
        ctx->update = (QC_MD_UPDATE_FN_T)qc_chacha20_roundrobin256_update;
        ctx->final = (QC_MD_FINAL_FN_T)qc_chacha20_roundrobin256_final;
        ctx->reset = (QC_MD_RESET_FN_T)qc_chacha20_roundrobin256_init;
        ctx->dsgt_size = 32;
        ctx->ctx_size = QC_CHACHA20_ROUNDROBIN256_CTX_SIZE;
        ctx->ctx_ptr = safe_malloc(ctx->ctx_size);
        break;

    default:
        ctx->init = NULL;
        ctx->update = NULL;
        ctx->final = NULL;
        ctx->reset = NULL;
        ctx->algo = algo;
        ctx->ctx_ptr = NULL;
        ctx->ctx_size = 0;
        ctx->dsgt_size = 0;
        return -1;
    }

    ctx->init(ctx->ctx_ptr, args);

    return 1;
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

    ctx->reset(ctx->ctx_ptr, args);

    va_end(args);

    return 1;
}

QC_EXPORT void QC_DigestFree(QC_MD_CTX *ctx)
{
    if (!ctx)
        return;

    if (ctx->ctx_ptr != NULL)
    {
        memset(ctx->ctx_ptr, 0, ctx->ctx_size);
        free(ctx->ctx_ptr);

        ctx->ctx_ptr = NULL;
    }

    memset(ctx, 0, sizeof(QC_MD_CTX)); // clear the context
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
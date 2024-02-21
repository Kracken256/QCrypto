/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#include <qcrypto/qcrypto.h>
#include <stdarg.h>

#include <qcrypto/rand/all.h>
#include <qcrypto/macro.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

enum ALGO_TYPE_CTX_SIZE
{
    QC_XOR128_CTX_SIZE = sizeof(qc_xor128_t),
};

static void *safe_malloc(size_t size)
{
    void *ptr = malloc(size);
    if (ptr == NULL)
    {
        perror("QCRYPTO: malloc failed");
        exit(1);
    }
    memset(ptr, 0, size);
    return ptr;
}

QC_EXPORT int QC_RandInit(QC_RAND_CTX *ctx, QC_ALGORITHMS algo)
{
    ctx->algo = algo;

    switch (algo)
    {
    case QC_XOR128:
        ctx->ctx_ptr = safe_malloc(QC_XOR128_CTX_SIZE);
        ctx->ctx_size = QC_XOR128_CTX_SIZE;
        ctx->init = (QC_RAND_INIT_FN_T)qc_xor128_seed;
        ctx->reset = (QC_RAND_RESET_FN_T)qc_xor128_reset;
        ctx->next32 = (QC_RAND_NEXT32_FN_T)qc_xor128_next32;
        ctx->algo = algo;
        ctx->period.b2_exp = 0;
        ctx->period.mantissa = 0;
        break;
    default:
        ctx->init = NULL;
        ctx->reset = NULL;
        ctx->next32 = NULL;
        ctx->ctx_ptr = NULL;
        ctx->ctx_size = 0;
        ctx->period.b2_exp = 0;
        ctx->period.mantissa = 0;
        return -1;
    }

    return 1;
}

QC_EXPORT int QC_RandSeed(QC_RAND_CTX *ctx, const uint8_t *seed, uint64_t size)
{
    static const uint8_t default_seed[32] = "THIS IS THE SEED FOR QCRYPTO RNG";

    if (ctx->init == NULL)
        return -1;

    if (seed == NULL || size == 0)
    {
        seed = default_seed;
        size = sizeof(default_seed);
    }

    ctx->init(ctx->ctx_ptr, seed, size);

    return 1;
}

QC_EXPORT int QC_RandReset(QC_RAND_CTX *ctx)
{
    ctx->reset(ctx->ctx_ptr);

    return 1;
}

QC_EXPORT int QC_RandFill(QC_RAND_CTX *ctx, uint8_t *buf, uint64_t size)
{
    uint64_t chk, i;
    uint8_t leftover;

    chk = size / 4;
    leftover = size % 4;

    for (i = 0; i < chk; i++)
    {
        *(uint32_t *)buf = ctx->next32(ctx->ctx_ptr);
        buf += 4;
    }

    if (leftover)
    {
        uint32_t r = ctx->next32(ctx->ctx_ptr);
        memcpy(buf, &r, leftover);
    }

    return 1;
}

QC_EXPORT void QC_RandFree(QC_RAND_CTX *ctx)
{
    if (!ctx)
        return;

    if (ctx->ctx_ptr != NULL)
    {
        memset(ctx->ctx_ptr, 0, ctx->ctx_size);
        free(ctx->ctx_ptr);
    }

    memset(ctx, 0, sizeof(QC_RAND_CTX)); // clear the context
}

QC_EXPORT int QC_Rand(QC_ALGORITHMS algo, uint8_t *buf, uint64_t size, const uint8_t *seed, uint64_t seed_size)
{
    QC_RAND_CTX ctx;
    int ret;

    ret = QC_RandInit(&ctx, algo);
    if (ret != 1)
        return ret;

    ret = QC_RandSeed(&ctx, seed, seed_size);
    if (ret != 1)
        return ret;

    ret = QC_RandFill(&ctx, buf, size);
    if (ret != 1)
        return ret;

    QC_RandFree(&ctx);

    return 1;
}
/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
    From: https://www.rfc-editor.org/rfc/rfc3174.html
*/

#include <qcrypto/hash/sha1.h>
#include <qcrypto/macro.h>
#include <string.h>

#define INIT_A 0x67452301
#define INIT_B 0xEFCDAB89
#define INIT_C 0x98BADCFE
#define INIT_D 0x10325476
#define INIT_E 0xC3D2E1F0

#define ROTATE(bits,word) \
                (((word) << (bits)) | ((word) >> (32-(bits))))

QC_EXPORT void qc_sha1_init(qc_sha1_t *ctx, void *x)
{
    (void)x;

    ctx->Length_Low = 0;
    ctx->Length_High = 0;
    ctx->Message_Block_Index = 0;

    ctx->Intermediate_Hash[0] = INIT_A;
    ctx->Intermediate_Hash[1] = INIT_B;
    ctx->Intermediate_Hash[2] = INIT_C;
    ctx->Intermediate_Hash[3] = INIT_D;
    ctx->Intermediate_Hash[4] = INIT_E;
}

void SHA1ProcessMessageBlock(qc_sha1_t *ctx)
{
    const uint32_t K[] = {/* Constants defined in SHA-1   */
                          0x5A827999,
                          0x6ED9EBA1,
                          0x8F1BBCDC,
                          0xCA62C1D6};
    int t;                  /* Loop counter                */
    uint32_t temp;          /* Temporary word value        */
    uint32_t W[80];         /* Word sequence               */
    uint32_t A, B, C, D, E; /* Word buffers                */

    /*
     *  Initialize the first 16 words in the array W
     */
    for (t = 0; t < 16; t++)
    {
        W[t] = ctx->Message_Block[t * 4] << 24;
        W[t] |= ctx->Message_Block[t * 4 + 1] << 16;
        W[t] |= ctx->Message_Block[t * 4 + 2] << 8;
        W[t] |= ctx->Message_Block[t * 4 + 3];
    }

    for (t = 16; t < 80; t++)
    {
        W[t] = ROTATE(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
    }

    A = ctx->Intermediate_Hash[0];
    B = ctx->Intermediate_Hash[1];
    C = ctx->Intermediate_Hash[2];
    D = ctx->Intermediate_Hash[3];
    E = ctx->Intermediate_Hash[4];

    for (t = 0; t < 20; t++)
    {
        temp = ROTATE(5, A) +
               ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        E = D;
        D = C;
        C = ROTATE(30, B);
        B = A;
        A = temp;
    }

    for (t = 20; t < 40; t++)
    {
        temp = ROTATE(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = ROTATE(30, B);
        B = A;
        A = temp;
    }

    for (t = 40; t < 60; t++)
    {
        temp = ROTATE(5, A) +
               ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        E = D;
        D = C;
        C = ROTATE(30, B);
        B = A;
        A = temp;
    }

    for (t = 60; t < 80; t++)
    {
        temp = ROTATE(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = ROTATE(30, B);
        B = A;
        A = temp;
    }

    ctx->Intermediate_Hash[0] += A;
    ctx->Intermediate_Hash[1] += B;
    ctx->Intermediate_Hash[2] += C;
    ctx->Intermediate_Hash[3] += D;
    ctx->Intermediate_Hash[4] += E;

    ctx->Message_Block_Index = 0;
}

QC_EXPORT void qc_sha1_update(qc_sha1_t *ctx, const uint8_t *data, size_t size)
{
    while (size--)
    {
        ctx->Message_Block[ctx->Message_Block_Index++] =
            (*data & 0xFF);

        ctx->Length_Low += 8;
        if (ctx->Length_Low == 0)
        {
            ctx->Length_High++;
        }

        if (ctx->Message_Block_Index == 64)
            SHA1ProcessMessageBlock(ctx);

        data++;
    }
}

void SHA1PadMessage(qc_sha1_t *ctx)
{
    /*
     *  Check to see if the current message block is too small to hold
     *  the initial padding bits and length.  If so, we will pad the
     *  block, process it, and then continue padding into a second
     *  block.
     */
    if (ctx->Message_Block_Index > 55)
    {
        ctx->Message_Block[ctx->Message_Block_Index++] = 0x80;
        while (ctx->Message_Block_Index < 64)
        {
            ctx->Message_Block[ctx->Message_Block_Index++] = 0;
        }

        SHA1ProcessMessageBlock(ctx);

        while (ctx->Message_Block_Index < 56)
        {
            ctx->Message_Block[ctx->Message_Block_Index++] = 0;
        }
    }
    else
    {
        ctx->Message_Block[ctx->Message_Block_Index++] = 0x80;
        while (ctx->Message_Block_Index < 56)
        {
            ctx->Message_Block[ctx->Message_Block_Index++] = 0;
        }
    }

    /*
     *  Store the message length as the last 8 octets
     */
    ctx->Message_Block[56] = ctx->Length_High >> 24;
    ctx->Message_Block[57] = ctx->Length_High >> 16;
    ctx->Message_Block[58] = ctx->Length_High >> 8;
    ctx->Message_Block[59] = ctx->Length_High;
    ctx->Message_Block[60] = ctx->Length_Low >> 24;
    ctx->Message_Block[61] = ctx->Length_Low >> 16;
    ctx->Message_Block[62] = ctx->Length_Low >> 8;
    ctx->Message_Block[63] = ctx->Length_Low;

    SHA1ProcessMessageBlock(ctx);
}

QC_EXPORT void qc_sha1_final(qc_sha1_t *ctx, uint8_t *out)
{
    int i;

    SHA1PadMessage(ctx);

    ctx->Length_Low = 0;
    ctx->Length_High = 0;

    for (i = 0; i < 20; ++i)
        out[i] = ctx->Intermediate_Hash[i >> 2] >> 8 * (3 - (i & 0x03));
}
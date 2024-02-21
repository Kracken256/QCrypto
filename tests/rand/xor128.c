#include <stdio.h>
#include <qcrypto/qcrypto.h>

int main()
{
    QC_RAND_CTX ctx;

    if (QC_RandInit(&ctx, QC_XOR128) != 1)
    {
        printf("Failed to initialize the context\n");
        return 1;
    }

    if (QC_RandSeed(&ctx, (uint8_t *)"Hello, World!", 0) != 1)
    {
        printf("Failed to seed the context\n");
        return 1;
    }

    uint8_t buf[4096];

    while (1)
    {
        if (QC_RandFill(&ctx, buf, 4096) != 1)
        {
            printf("Failed to fill the buffer\n");
            return 1;
        }

        for (int i = 0; i < 4096; i++)
        {
            printf("%02x", buf[i]);
        }
    }

    QC_RandFree(&ctx);
}
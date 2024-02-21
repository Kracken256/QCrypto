/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#include <qcrypto/qcrypto.h>
#include <stdio.h>

int main()
{
    uint64_t digest;

    if (QC_Digest(QC_CRC, (const uint8_t*)"hello world", 11, (uint8_t *)&digest, 64, 0x0b8832cbf5b3c646, 0x0a532b523827d0e7ULL, 0xa5fe29cae22e6563ULL) != QC_OK)
    {
        printf("CRC init failed\n");
        return 1;
    }

    if (digest != 0xE6270167ECBABD5B)
    {
        printf("CRC failed: %016lx\n", digest);
        return 1;
    }

    printf("CRC passed\n");

    return 0;
}
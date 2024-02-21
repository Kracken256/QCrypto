/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

// This is a custom algorithm that I created. 

#include <qcrypto/qcrypto.h>
#include <stdio.h>
#include <string.h>

static int hashfile(const char *file)
{
    FILE *f = fopen(file, "rb");
    if (!f)
    {
        printf("Could not open file: %s\n", file);
        return 1;
    }

    QC_MD_CTX ctx;
    uint8_t hash[32];

    QC_DigestInit(&ctx, QC_CHACHA20_ROUNDROBIN256);

    uint8_t buf[1024];
    size_t len;

    while ((len = fread(buf, 1, sizeof(buf), f)) > 0)
    {
        QC_DigestUpdate(&ctx, buf, len);
    }

    QC_DigestFinal(&ctx, hash);

    for (size_t i = 0; i < sizeof(hash); i++)
    {
        printf("%02x", hash[i]);
    }

    fclose(f);
    return 0;
}

static int hashstdin()
{
    QC_MD_CTX ctx;
    uint8_t hash[32];

    QC_DigestInit(&ctx, QC_CHACHA20_ROUNDROBIN256);

    uint8_t buf[1024];
    size_t len;

    while ((len = fread(buf, 1, sizeof(buf), stdin)) > 0)
    {
        QC_DigestUpdate(&ctx, buf, len);
    }

    QC_DigestFinal(&ctx, hash);

    for (size_t i = 0; i < sizeof(hash); i++)
    {
        printf("%02x", hash[i]);
    }

    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2)
    {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)
        {
            printf("Usage: [stdin] | %s\n", argv[0]);
            printf("       %s [file]\n", argv[0]);
            return 0;
        }

        return hashfile(argv[1]);
    }

    return hashstdin();
}
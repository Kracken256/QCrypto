/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#include <qcrypto/qcrypto.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static uint64_t get_nanoseconds()
{
    struct timespec ts = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static int hashfile(const char *file)
{
    FILE *f = fopen(file, "rb");
    size_t total = 0;
    uint64_t start, end, diff;
    float rate;

    if (!f)
    {
        printf("Could not open file: %s\n", file);
        return 1;
    }

    start = get_nanoseconds();


    QC_MD_CTX ctx;
    unsigned char hash[32];

    QC_DigestInit(&ctx, QC_CHACHA20_ROUNDROBIN256);

    uint8_t buf[1024];
    size_t len;

    while ((len = fread(buf, 1, sizeof(buf), f)) > 0)
    {
        QC_DigestUpdate(&ctx, buf, len);
        total += len;
    }

    QC_DigestFinal(&ctx, hash);

    end = get_nanoseconds();

    for (size_t i = 0; i < sizeof(hash); i++)
    {
        printf("%02x", hash[i]);
    }

    fclose(f);

    diff = end - start;

    // GB/s
    rate = (float)total / diff;

    printf("\n\nTotal bytes: %lu\n", total);
    printf("Total time: %lu ns\n", diff);
    printf("Rate: %f GB/s\n", rate);

    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2)
    {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)
        {
            printf("Usage: %s\n", argv[0]);
            printf("       %s [file]\n", argv[0]);
            return 0;
        }

        return hashfile(argv[1]);
    }

    printf("Usage: %s\n", argv[0]);
    printf("       Use large file for benchmarking\n");
}
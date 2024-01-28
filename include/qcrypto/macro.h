/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#ifndef __QCRYPTO_MACRO_H__
#define __QCRYPTO_MACRO_H__

#ifdef __cplusplus
extern "C"
{
#endif

#if defined(_WIN32) || defined(_WIN64)
#define QC_EXPORT __declspec(dllexport)
#else
#define QC_EXPORT __attribute__((visibility("default")))
#endif

#if !defined(QC_ENDIANNESS)
#define QC_ENDIANNESS 0

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define QC_ENDIANNESS_BIG
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define QC_ENDIANNESS_LITTLE
#else
#error "Unable to determine endianness"
#endif

#ifdef QC_ENDIANNESS_BIG
#define QC_BE16(x) (x)
#define QC_BE32(x) (x)
#define QC_BE64(x) (x)
#define QC_LE16(x) __builtin_bswap16(x)
#define QC_LE32(x) __builtin_bswap32(x)
#define QC_LE64(x) __builtin_bswap64(x)
#else
#define QC_BE16(x) __builtin_bswap16(x)
#define QC_BE32(x) __builtin_bswap32(x)
#define QC_BE64(x) __builtin_bswap64(x)
#define QC_LE16(x) (x)
#define QC_LE32(x) (x)
#define QC_LE64(x) (x)

#endif

#endif

#ifdef __cplusplus
}
#endif

#endif // __QCRYPTO_MACRO_H__
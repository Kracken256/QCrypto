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
#define QX_EXPORT __declspec(dllexport)
#else
#define QX_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
}
#endif

#endif // __QCRYPTO_MACRO_H__
/*
    QCrypto - A simple cryptography library
    Author: Wesley C. Jones
    License: Unlicense (Public Domain)
*/

#ifndef __QCRYPTO_HASH_ALL_H__
#define __QCRYPTO_HASH_ALL_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "crc8.h"
#include "crc16.h"
#include "crc32.h"
#include "crc64.h"
#include "crc.h"

#include "md2.h"
#include "md4.h"
#include "md5.h"

#include "sha1.h"
#include "sha224.h"
#include "sha256.h"

// Expiremental
#include "chacha20-roundrobin256.h"

#ifdef __cplusplus
}
#endif

#endif // __QCRYPTO_HASH_ALL_H__
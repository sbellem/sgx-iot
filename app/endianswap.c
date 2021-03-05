/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <openssl/bn.h>

#include "app.h"

/**
 * Macros for little to big endian conversion.
 * One example for its use is for byte endianness conversion for an
 * OpenSSL-based application which uses big endian format, whereas,
 * Intel(r) SGX uses little endian format.
 */
#if !defined(SWAP_ENDIAN_DW)
#define SWAP_ENDIAN_DW(dw) ((((dw)&0x000000ff) << 24) | (((dw)&0x0000ff00) << 8) | (((dw)&0x00ff0000) >> 8) | (((dw)&0xff000000) >> 24))
#endif

#if !defined(SWAP_ENDIAN_32B)
#define SWAP_ENDIAN_8X32B(ptr)                                           \
    {                                                                    \
        uint32_t temp = 0;                                               \
        temp = SWAP_ENDIAN_DW(((uint32_t *)(ptr))[0]);                   \
        ((uint32_t *)(ptr))[0] = SWAP_ENDIAN_DW(((uint32_t *)(ptr))[7]); \
        ((uint32_t *)(ptr))[7] = temp;                                   \
        temp = SWAP_ENDIAN_DW(((uint32_t *)(ptr))[1]);                   \
        ((uint32_t *)(ptr))[1] = SWAP_ENDIAN_DW(((uint32_t *)(ptr))[6]); \
        ((uint32_t *)(ptr))[6] = temp;                                   \
        temp = SWAP_ENDIAN_DW(((uint32_t *)(ptr))[2]);                   \
        ((uint32_t *)(ptr))[2] = SWAP_ENDIAN_DW(((uint32_t *)(ptr))[5]); \
        ((uint32_t *)(ptr))[5] = temp;                                   \
        temp = SWAP_ENDIAN_DW(((uint32_t *)(ptr))[3]);                   \
        ((uint32_t *)(ptr))[3] = SWAP_ENDIAN_DW(((uint32_t *)(ptr))[4]); \
        ((uint32_t *)(ptr))[4] = temp;                                   \
    }
#endif

BIGNUM* bignum_from_little_endian_bytes_32(const uint8_t * const bytes)
{
    /* Create BIGNUM from raw (little endian) bytes
       without using memcpy (static scanner requirement) */
    uint8_t copied_bytes[32];
    for (size_t i = 0 ; i < sizeof(copied_bytes) ; ++i)
    {
        copied_bytes[i] = bytes[i];
    }

    SWAP_ENDIAN_8X32B(copied_bytes);
    BIGNUM * bn = BN_bin2bn(copied_bytes, sizeof(copied_bytes), NULL);
    return bn;
}

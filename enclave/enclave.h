/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>

#include <sgx_tcrypto.h>
#include <sgx_utils.h>
#include <sgx_tseal.h>

#if defined(__cplusplus)
extern "C" {
#endif

void print(const char*);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */

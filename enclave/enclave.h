/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <assert.h>
#include <stdlib.h>

#include <sgx_tcrypto.h>
//#include <sgx_tkey_exchange.h>
#include <sgx_quote.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

#if defined(__cplusplus)
extern "C" {
#endif

void print(const char*);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */

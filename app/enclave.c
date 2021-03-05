/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>

#include <sgx_urts.h>  /* For sgx_launch_token_t */

#include "app.h"

bool create_enclave(const char *const enclave_binary)
{
    printf("[GatewayApp]: Creating enclave\n");

    /* SGX_DEBUG_FLAG is a macro set in sgx_urts.h to enable debugging when
       building in debug and pre-release mode.  In common/common.mk
       this mode is controlled by SGX_DEBUG and SGX_PRERELEASE.
       Setting either to 1 will set SGX_DEBUG_FLAG to 1 (true).
    */
    sgx_lasterr = sgx_create_enclave(enclave_binary,
                                              SGX_DEBUG_FLAG,
                                              &launch_token,
                                              &launch_token_updated,
                                              &enclave_id,
                                              NULL);
    return (sgx_lasterr == SGX_SUCCESS);
}

void destroy_enclave()
{
    printf("[GatewayApp]: Destroying enclave\n");

    sgx_status_t err = sgx_destroy_enclave(enclave_id);
    if (err != SGX_SUCCESS)
    {
        fprintf(stderr, "[GatewayApp]: ERROR: %s\n", decode_sgx_status(err));
        return;
    }
    enclave_id = 0;
}

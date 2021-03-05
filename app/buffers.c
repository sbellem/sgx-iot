/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>

#include "app.h"

bool allocate_buffers()
{
    printf("[GatewayApp]: Allocating buffers\n");
    sealed_data_buffer = calloc(sealed_data_buffer_size, 1);
    public_key_buffer = calloc(public_key_buffer_size, 1);
    signature_buffer = calloc(signature_buffer_size, 1);

    if (sealed_data_buffer == NULL || public_key_buffer == NULL || signature_buffer == NULL)
    {
        fprintf(stderr, "[GatewayApp]: allocate_buffers() memory allocation failure\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
    }

    return (sgx_lasterr == SGX_SUCCESS);
}

void cleanup_buffers()
{
    printf("[GatewayApp]: Deallocating buffers\n");

    if (sealed_data_buffer != NULL)
    {
        free(sealed_data_buffer);
        sealed_data_buffer = NULL;
    }

    if (public_key_buffer != NULL)
    {
        free(public_key_buffer);
        public_key_buffer = NULL;
    }

    if (signature_buffer != NULL)
    {
        free(signature_buffer);
        signature_buffer = NULL;
    }

    if (input_buffer != NULL)
    {
        free(input_buffer);
        input_buffer = NULL;
    }
}


/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>

#include "app.h"


bool load_enclave_state(const char *const statefile)
{
    void* new_buffer;
    size_t new_buffer_size;

    printf("[GatewayApp]: Loading enclave state\n");

    bool ret_status = read_file_into_memory(statefile, &new_buffer, &new_buffer_size);

    /* If we previously allocated a buffer, free it before putting new one in its place */
    if (sealed_data_buffer != NULL)
    {
        free(sealed_data_buffer);
        sealed_data_buffer = NULL;
    }

    /* Put new buffer into context */
    sealed_data_buffer = new_buffer;
    sealed_data_buffer_size = new_buffer_size;

    return ret_status;
}

bool save_enclave_state(const char *const statefile)
{
    bool ret_status = true;

    printf("[GatewayApp]: Saving enclave state\n");

    FILE *file = open_file(statefile, "wb");

    if (file == NULL)
    {
        fprintf(stderr, "[GatewayApp]: save_enclave_state() fopen failed\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        return false;
    }

    if (fwrite(sealed_data_buffer, sealed_data_buffer_size, 1, file) != 1)
    {
        fprintf(stderr, "[GatewayApp]: Enclave state only partially written.\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        ret_status = false;
    }

    fclose(file);

    return ret_status;
}

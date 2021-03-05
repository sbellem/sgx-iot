/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "app.h"

/* Globals */

sgx_enclave_id_t enclave_id;
sgx_launch_token_t launch_token;
int launch_token_updated;
sgx_status_t sgx_lasterr;

void *public_key_buffer;
size_t public_key_buffer_size;
void *sealed_data_buffer;
size_t sealed_data_buffer_size;
void *signature_buffer;
size_t signature_buffer_size;
void *input_buffer;
size_t input_buffer_size;

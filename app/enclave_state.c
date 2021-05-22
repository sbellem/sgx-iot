/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>

#include "app.h"

bool load_enclave_state(const char *const statefile) {
    void *new_buffer;
    size_t new_buffer_size;

    printf("[GatewayApp]: Loading enclave state\n");

    bool ret_status =
        read_file_into_memory(statefile, &new_buffer, &new_buffer_size);

    /* If we previously allocated a buffer, free it before putting new one in
     * its place */
    if (sealed_privkey_buffer != NULL) {
        free(sealed_privkey_buffer);
        sealed_privkey_buffer = NULL;
    }

    /* Put new buffer into context */
    sealed_privkey_buffer = new_buffer;
    sealed_privkey_buffer_size = new_buffer_size;

    return ret_status;
}

bool load_sealed_data(const char *const sealed_data_file, void *buffer,
                      size_t buffer_size) {
    void *new_buffer;
    size_t new_buffer_size;

    bool ret_status =
        read_file_into_memory(sealed_data_file, &new_buffer, &new_buffer_size);

    /* If we previously allocated a buffer, free it before putting new one in
     * its place */
    if (buffer != NULL) {
        free(buffer);
        buffer = NULL;
    }

    /* Put new buffer into context */
    buffer = new_buffer;
    buffer_size = new_buffer_size;

    return ret_status;
}

bool load_sealedpubkey(const char *const sealedpubkey_file) {
    printf("[GatewayApp]: Loading sealed public key\n");
    // bool ret_status = load_sealed_data(sealedpubkey_file,
    // sealed_pubkey_buffer,
    //                                   sealed_pubkey_buffer_size);
    // return ret_status;
    void *new_buffer;
    size_t new_buffer_size;

    bool ret_status =
        read_file_into_memory(sealedpubkey_file, &new_buffer, &new_buffer_size);

    /* If we previously allocated a buffer, free it before putting new one in
     * its place */
    if (sealed_pubkey_buffer != NULL) {
        free(sealed_pubkey_buffer);
        sealed_pubkey_buffer = NULL;
    }

    /* Put new buffer into context */
    sealed_pubkey_buffer = new_buffer;
    sealed_pubkey_buffer_size = new_buffer_size;

    return ret_status;
}

bool save_enclave_state(const char *const sealedprivkey_file,
                        const char *const sealedpubkey_file) {
    // bool ret_status = true;
    // ret_status = save_state(sealedprivkey_file, sealed_privkey_buffer,
    //                        sealed_privkey_buffer_size);
    // ret_status = save_state(sealedpubkey_file, sealed_pubkey_buffer,
    //                        sealed_pubkey_buffer_size);
    // return ret_status;
    bool ret_status = true;

    printf("[GatewayApp]: Saving enclave state - sealed priv key\n");

    FILE *sk_file = open_file(sealedprivkey_file, "wb");

    if (sk_file == NULL) {
        fprintf(stderr, "[GatewayApp]: save_enclave_state() fopen failed\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        return false;
    }

    if (fwrite(sealed_privkey_buffer, sealed_privkey_buffer_size, 1, sk_file) !=
        1) {
        fprintf(stderr,
                "[GatewayApp]: Enclave state only partially written.\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        ret_status = false;
    }

    fclose(sk_file);

    printf("[GatewayApp]: Saving enclave state - sealed pub key\n");

    FILE *file = open_file(sealedpubkey_file, "wb");

    if (file == NULL) {
        fprintf(stderr, "[GatewayApp]: save_enclave_state() fopen failed\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        return false;
    }

    if (fwrite(sealed_pubkey_buffer, sealed_pubkey_buffer_size, 1, file) != 1) {
        fprintf(stderr,
                "[GatewayApp]: Enclave state only partially written.\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        ret_status = false;
    }

    fclose(file);

    return ret_status;
}

bool save_state(const char *const statefile, void *buffer, size_t buffer_size) {
    bool ret_status = true;

    printf("[GatewayApp]: Saving enclave state\n");

    FILE *file = open_file(statefile, "wb");

    if (file == NULL) {
        fprintf(stderr, "[GatewayApp]: save_enclave_state() fopen failed\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        return false;
    }

    if (fwrite(buffer, buffer_size, 1, file) != 1) {
        fprintf(stderr,
                "[GatewayApp]: Enclave state only partially written.\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        ret_status = false;
    }

    fclose(file);

    return ret_status;
}

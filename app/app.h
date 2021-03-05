/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _APP_H
#define _APP_H

#include <sys/types.h>
#include <stdbool.h>

#include <sgx_urts.h>
#include <openssl/bn.h>


/* Globals */

extern sgx_enclave_id_t enclave_id;
extern sgx_launch_token_t launch_token;
extern int launch_token_updated;
extern sgx_status_t sgx_lasterr;

extern void *public_key_buffer;       /* unused for signing */
extern size_t public_key_buffer_size; /* unused for signing */
extern void *sealed_data_buffer;
extern size_t sealed_data_buffer_size;
extern void *signature_buffer;
extern size_t signature_buffer_size;
extern void *input_buffer;
extern size_t input_buffer_size;


/* Function prototypes */

const char * decode_sgx_status(sgx_status_t status);

FILE* open_file(const char* const filename, const char* const mode);

bool create_enclave(const char *const enclave_binary);

bool enclave_get_buffer_sizes(void);

bool allocate_buffers(void);

bool read_file_into_memory(const char *const filename, void **buffer, size_t *buffer_size);

bool load_enclave_state(const char *const statefile);

bool load_input_file(const char *const input_file);

bool enclave_sign_data(void);

bool enclave_generate_key(void);

bool save_enclave_state(const char *const statefile);

BIGNUM* bignum_from_little_endian_bytes_32(const unsigned char * const bytes);

bool save_signature(const char *const signature_file);

bool save_public_key(const char *const public_key_file);

void destroy_enclave(void);

void cleanup_buffers(void);

#endif /* !_APP_H */

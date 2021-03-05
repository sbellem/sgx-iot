/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>

#include <enclave_u.h> /* For sgx_enclave_id_t */

#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

#include "app.h"

bool enclave_generate_key()
{
    sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

    printf("[GatewayApp]: Calling enclave to generate key material\n");

    /*
    * Invoke ECALL, 'ecall_key_gen_and_seal()', to generate a keypair and seal it to the enclave.
    */
    sgx_lasterr = ecall_key_gen_and_seal(enclave_id,
                                         &ecall_retval,
                                         (char *)public_key_buffer,
                                         public_key_buffer_size,
                                         (char *)sealed_data_buffer,
                                         sealed_data_buffer_size);
    if (sgx_lasterr == SGX_SUCCESS &&
        (ecall_retval != SGX_SUCCESS))
    {
        fprintf(stderr, "[GatewayApp]: ERROR: ecall_key_gen_and_seal returned %d\n", ecall_retval);
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
    }

    return (sgx_lasterr == SGX_SUCCESS);
}

static bool convert_sgx_key_to_openssl_key(EC_KEY *key, const uint8_t *key_buffer, size_t key_buffer_size)
{
    bool ret_status = true;

    if (key_buffer_size != 64)
    {
        fprintf(stderr, "[GatewayApp]: assertion failed: key_buffer_size == 64\n");
        return false;
    }

    BIGNUM *bn_x = bignum_from_little_endian_bytes_32(key_buffer);
    BIGNUM *bn_y = bignum_from_little_endian_bytes_32(key_buffer + 32);

    if (1 != EC_KEY_set_public_key_affine_coordinates(key, bn_x, bn_y))
    {
        fprintf(stderr, "[GatewayApp]: Failed to convert public key to OpenSSL format\n");
        ret_status = false;
    }

    BN_free(bn_x);
    BN_free(bn_y);

    return ret_status;
}

bool save_public_key(const char *const public_key_file)
{
    bool ret_status = true;

    printf("[GatewayApp]: Saving public key\n");

    FILE *file = open_file(public_key_file, "wt");

    if (file == NULL)
    {
        fprintf(stderr, "[GatewayApp]: save_public_key() fopen failed\n");
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
        return false;
    }

    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);

    if (convert_sgx_key_to_openssl_key(key, (uint8_t *)public_key_buffer, public_key_buffer_size))
    {
        PEM_write_EC_PUBKEY(file, key);
    }
    else
    {
        fprintf(stderr, "[GatewayApp]: Failed export public key\n");
        ret_status = false;
    }

    EC_KEY_free(key);
    key = NULL;

    fclose(file);

    return ret_status;
}

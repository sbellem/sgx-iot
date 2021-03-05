/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdarg.h>
#include <stdio.h>

#include <enclave_t.h>
#include "enclave.h"

#include <sgx_tcrypto.h>
#include <sgx_utils.h>
#include <sgx_tseal.h>

/**
 * This function generates a key pair and then seals the private key.
 *
 * @param pubkey                 Output parameter for public key.
 * @param pubkey_size            Input parameter for size of public key.
 * @param sealedprivkey          Output parameter for sealed private key.
 * @param sealedprivkey_size     Input parameter for size of sealed private key.
 *
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success, some
 *                               sgx_status_t value upon failure.
 */

sgx_status_t ecall_key_gen_and_seal(char *pubkey, size_t pubkey_size, char *sealedprivkey, size_t sealedprivkey_size)
{
  // Step 1: Open Context.
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle = NULL;

  if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS)
  {
    print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }

  // Step 2: Create Key Pair.
  sgx_ec256_private_t p_private;
  if ((ret = sgx_ecc256_create_key_pair(&p_private, (sgx_ec256_public_t *)pubkey, p_ecc_handle)) != SGX_SUCCESS)
  {
    print("\nTrustedApp: sgx_ecc256_create_key_pair() failed !\n");
    goto cleanup;
  }

  // Step 3: Calculate sealed data size.
  if (sealedprivkey_size >= sgx_calc_sealed_data_size(0U, sizeof(p_private)))
  {
    if ((ret = sgx_seal_data(0U, NULL, sizeof(p_private), (uint8_t *)&p_private, (uint32_t) sealedprivkey_size, (sgx_sealed_data_t *)sealedprivkey)) != SGX_SUCCESS)
    {
      print("\nTrustedApp: sgx_seal_data() failed !\n");
      goto cleanup;
    }
  }
  else
  {
    print("\nTrustedApp: Size allocated for sealedprivkey by untrusted app is less than the required size !\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  print("\nTrustedApp: Key pair generated and private key was sealed. Sent the public key and sealed private key back.\n");
  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  if (p_ecc_handle != NULL)
  {
    sgx_ecc256_close_context(p_ecc_handle);
  }

  return ret;
}

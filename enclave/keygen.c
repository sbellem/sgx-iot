/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdarg.h>
#include <stdio.h>

#include "enclave.h"
#include <enclave_t.h>

#include <sgx_quote.h>
#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

/**
 * This function generates a key pair and then seals the private key.
 *
 * @param pubkey                 Output parameter for public key.
 * @param pubkey_size            Input parameter for size of public key.
 * @param sealedprivkey          Output parameter for sealed private key.
 * @param sealedprivkey_size     Input parameter for size of sealed private key.
 *
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */

sgx_status_t ecall_key_gen_and_seal(char *pubkey, size_t pubkey_size,
                                    char *sealedprivkey,
                                    size_t sealedprivkey_size) {
  // Step 1: Open Context.
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle = NULL;

  if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS) {
    print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }

  // Step 2: Create Key Pair.
  sgx_ec256_private_t p_private;
  if ((ret =
           sgx_ecc256_create_key_pair(&p_private, (sgx_ec256_public_t *)pubkey,
                                      p_ecc_handle)) != SGX_SUCCESS) {
    print("\nTrustedApp: sgx_ecc256_create_key_pair() failed !\n");
    goto cleanup;
  }

  // Step 3: Calculate sealed data size.
  if (sealedprivkey_size >= sgx_calc_sealed_data_size(0U, sizeof(p_private))) {
    if ((ret = sgx_seal_data(0U, NULL, sizeof(p_private), (uint8_t *)&p_private,
                             (uint32_t)sealedprivkey_size,
                             (sgx_sealed_data_t *)sealedprivkey)) !=
        SGX_SUCCESS) {
      print("\nTrustedApp: sgx_seal_data() failed !\n");
      goto cleanup;
    }
  } else {
    print("\nTrustedApp: Size allocated for sealedprivkey by untrusted app "
          "is less than the required size !\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  print("\nTrustedApp: Key pair generated and private key was sealed. Sent the "
        "public key and sealed private key back.\n");
  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  if (p_ecc_handle != NULL) {
    sgx_ecc256_close_context(p_ecc_handle);
  }

  return ret;
}

sgx_status_t ecall_key_gen_and_seal_all(char *sealedpubkey,
                                        size_t sealedpubkey_size,
                                        char *sealedprivkey,
                                        size_t sealedprivkey_size) {
  // Step 1: Open Context.
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle = NULL;

  if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS) {
    print("\n[[TrustedApp]]: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }

  // Step 2: Create Key Pair.
  sgx_ec256_private_t p_private;
  sgx_ec256_public_t p_public;
  if ((ret = sgx_ecc256_create_key_pair(&p_private, &p_public, p_ecc_handle)) !=
      SGX_SUCCESS) {
    print("\n[[TrustedApp]]: sgx_ecc256_create_key_pair() failed !\n");
    goto cleanup;
  }

  // Step 3.1: Calculate sealed private key data size.
  if (sealedprivkey_size >= sgx_calc_sealed_data_size(0U, sizeof(p_private))) {
    if ((ret = sgx_seal_data(0U, NULL, sizeof(p_private), (uint8_t *)&p_private,
                             (uint32_t)sealedprivkey_size,
                             (sgx_sealed_data_t *)sealedprivkey)) !=
        SGX_SUCCESS) {
      print("\nTrustedApp: sgx_seal_data() failed !\n");
      goto cleanup;
    }
  } else {
    print("\n[[TrustedApp]]: Size allocated for sealedprivkey by untrusted "
          "app "
          "is less than the required size !\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  // Step 3.2: Calculate sealed public key data size.
  if (sealedpubkey_size >= sgx_calc_sealed_data_size(0U, sizeof(p_public))) {
    if ((ret = sgx_seal_data(0U, NULL, sizeof(p_public), (uint8_t *)&p_public,
                             (uint32_t)sealedpubkey_size,
                             (sgx_sealed_data_t *)sealedpubkey)) !=
        SGX_SUCCESS) {
      print("\n[[TrustedApp]]: sgx_seal_data() failed !\n");
      goto cleanup;
    }
  } else {
    print("\n[[TrustedApp]]: Size allocated for sealedpubkey by untrusted "
          "app "
          "is less than the required size !\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  print("\n[[TrustedApp]]: Key pair generated and private & public keys were "
        "sealed.\n");
  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  if (p_ecc_handle != NULL) {
    sgx_ecc256_close_context(p_ecc_handle);
  }

  return ret;
}

sgx_status_t ecall_report_gen(sgx_report_t *report,
                              sgx_target_info_t *target_info,
                              sgx_report_data_t report_data) {
  //#ifdef SGX_HW_SIM
  //  return sgx_create_report(NULL, NULL, report);
  //#else
  // sgx_report_data_t report_data = {{0}};

  // Hardcoded "Hello World!" string in hexadecimal format
  // const uint8_t x[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20,
  //                     0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21};
  // int iterations = 10;
  // sgx_status_t sha_ret;
  // sgx_sha256_hash_t tmp_hash;
  // sha_ret = sgx_sha256_msg(x, sizeof(x), (sgx_sha256_hash_t *)tmp_hash);

  // for (int i = 1; i < iterations - 1; i++) {
  //    sha_ret = sgx_sha256_msg((const uint8_t *)&tmp_hash, sizeof(tmp_hash),
  //                             (sgx_sha256_hash_t *)tmp_hash);
  //}

  // sha_ret = sgx_sha256_msg((const uint8_t *)&tmp_hash, sizeof(tmp_hash),
  //                         (sgx_sha256_hash_t *)&report_data);

  return sgx_create_report(target_info, &report_data, report);
  //#endif
}

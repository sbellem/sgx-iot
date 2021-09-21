/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>

#include <enclave_u.h> /* For sgx_enclave_id_t */

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>

#include "app.h"

bool load_input_file(const char *const input_file) {
  printf("[GatewayApp]: Loading input file\n");

  return read_file_into_memory(input_file, &input_buffer, &input_buffer_size);
}

bool enclave_sign_data() {
  sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

  printf("[GatewayApp]: Calling enclave to generate key material\n");

  /*
   * Invoke ECALL, 'ecall_unseal_and_sign()', to sign some data with the
   * sealed key
   */
  sgx_lasterr = ecall_unseal_and_sign(
      enclave_id, &ecall_retval, (uint8_t *)input_buffer,
      (uint32_t)input_buffer_size, (char *)sealed_privkey_buffer,
      sealed_privkey_buffer_size, (char *)signature_buffer,
      signature_buffer_size);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != 0)) {
    fprintf(stderr, "[GatewayApp]: ERROR: ecall_unseal_and_sign returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }

  return (sgx_lasterr == SGX_SUCCESS);
}

bool save_signature(const char *const signature_file) {
  bool ret_status = true;
  ECDSA_SIG *ecdsa_sig = NULL;
  BIGNUM *r = NULL, *s = NULL;
  FILE *file = NULL;
  unsigned char *sig_buffer = NULL;
  int sig_len = 0;
  int sig_len2 = 0;

  if (signature_buffer_size != 64) {
    fprintf(stderr,
            "[GatewayApp]: assertion failed: signature_buffer_size == 64\n");
    ret_status = false;
    goto cleanup;
  }

  ecdsa_sig = ECDSA_SIG_new();
  if (ecdsa_sig == NULL) {
    fprintf(stderr, "[GatewayApp]: memory alloction failure ecdsa_sig\n");
    ret_status = false;
    goto cleanup;
  }

  r = bignum_from_little_endian_bytes_32((unsigned char *)signature_buffer);
  s = bignum_from_little_endian_bytes_32((unsigned char *)signature_buffer +
                                         32);
  if (!ECDSA_SIG_set0(ecdsa_sig, r, s)) {
    ret_status = false;
    goto cleanup;
  }

  sig_len = i2d_ECDSA_SIG(ecdsa_sig, NULL);
  if (sig_len <= 0) {
    ret_status = false;
    goto cleanup;
  }

  sig_len2 = i2d_ECDSA_SIG(ecdsa_sig, &sig_buffer);
  if (sig_len != sig_len2) {
    ret_status = false;
    goto cleanup;
  }

  file = open_file(signature_file, "wb");
  if (file == NULL) {
    fprintf(stderr, "[GatewayApp]: save_signature() fopen failed\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    ret_status = false;
    goto cleanup;
  }

  if (fwrite(sig_buffer, (size_t)sig_len, 1, file) != 1) {
    fprintf(stderr, "GatewayApp]: ERROR: Could not write signature\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    ret_status = false;
    goto cleanup;
  }

cleanup:
  if (file != NULL) {
    fclose(file);
  }
  if (ecdsa_sig) {
    ECDSA_SIG_free(ecdsa_sig); /* Above will also free r and s */
  }
  if (sig_buffer) {
    free(sig_buffer);
  }

  return ret_status;
}

// quote.c
// bool enclave_gen_quote() {
//    sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;
//    sgx_spid_t spid;
//
//    printf("[GatewayApp]: Calling enclave to generate quote\n");
//    printf("[GatewayApp]: SPID: %s\n", getenv("SGX_SPID"));
//    from_hexstring((unsigned char *)&spid, (unsigned char
//    *)getenv("SGX_SPID"),
//                   16);
//
//    /*
//     * Invoke ECALL, 'ecall_unseal_and_quote()', to generate a quote including
//     * the sealed public key in the report data field.
//     */
//    sgx_lasterr = ecall_unseal_and_quote(enclave_id, &ecall_retval,
//                                         (char *)sealed_pubkey_buffer,
//                                         //(char *)sealed_privkey_buffer,
//                                         // sealed_privkey_buffer_size);
//                                         sealed_pubkey_buffer_size, spid);
//    if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != 0)) {
//        fprintf(stderr,
//                "[GatewayApp]: ERROR: ecall_unseal_and_quote returned %d\n",
//                ecall_retval);
//        sgx_lasterr = SGX_ERROR_UNEXPECTED;
//    }
//
//    return (sgx_lasterr == SGX_SUCCESS);
//}

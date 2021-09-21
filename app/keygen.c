/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdlib.h>

#include <enclave_u.h> /* For sgx_enclave_id_t */

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>

#include "app.h"

bool enclave_generate_key() {
  sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

  printf("[GatewayApp]: Calling enclave to generate key material\n");

  /*
   * Invoke ECALL, 'ecall_key_gen_and_seal()', to generate a keypair and seal
   * it to the enclave.
   */
  // sgx_lasterr = ecall_key_gen_and_seal(
  sgx_lasterr = ecall_key_gen_and_seal_all(
      enclave_id, &ecall_retval, (char *)sealed_pubkey_buffer,
      sealed_pubkey_buffer_size, (char *)sealed_privkey_buffer,
      sealed_privkey_buffer_size);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
    fprintf(stderr, "[GatewayApp]: ERROR: ecall_key_gen_and_seal returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }

  return (sgx_lasterr == SGX_SUCCESS);
}

static bool convert_sgx_key_to_openssl_key(EC_KEY *key,
                                           const uint8_t *key_buffer,
                                           size_t key_buffer_size) {
  bool ret_status = true;

  if (key_buffer_size != 64) {
    fprintf(stderr, "[GatewayApp]: assertion failed: key_buffer_size == 64\n");
    return false;
  }

  BIGNUM *bn_x = bignum_from_little_endian_bytes_32(key_buffer);
  BIGNUM *bn_y = bignum_from_little_endian_bytes_32(key_buffer + 32);

  if (1 != EC_KEY_set_public_key_affine_coordinates(key, bn_x, bn_y)) {
    fprintf(stderr,
            "[GatewayApp]: Failed to convert public key to OpenSSL format\n");
    ret_status = false;
  }

  BN_free(bn_x);
  BN_free(bn_y);

  return ret_status;
}

bool save_public_key(const char *const public_key_file) {
  bool ret_status = true;

  printf("[GatewayApp]: Saving public key\n");

  FILE *file = open_file(public_key_file, "wt");

  if (file == NULL) {
    fprintf(stderr, "[GatewayApp]: save_public_key() fopen failed\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    return false;
  }

  EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);

  if (convert_sgx_key_to_openssl_key(key, (uint8_t *)public_key_buffer,
                                     public_key_buffer_size)) {
    PEM_write_EC_PUBKEY(file, key);
  } else {
    fprintf(stderr, "[GatewayApp]: Failed export public key\n");
    ret_status = false;
  }

  EC_KEY_free(key);
  key = NULL;

  fclose(file);

  return ret_status;
}

// For REMOTE ATTESTATION
// TODO get report and generate quote, with public key in report data
bool enclave_generate_quote(sgx_report_data_t report_data) {
  sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;
  printf("[GatewayApp]: Calling enclave to generate attestation report\n");
  printf("[GatewayApp]: SPID: %s\n", getenv("SGX_SPID"));
  sgx_spid_t spid;
  from_hexstring((unsigned char *)&spid, (unsigned char *)getenv("SGX_SPID"),
                 16);
  // print_hexstring(stdout, &spid, 16);

  /*
   * Invoke ECALL, 'ecall_report_gen()', to generate an attestation
   * report with the public key in the report data.
   */
  sgx_status_t status;
  sgx_report_t report;
  sgx_target_info_t target_info;
  sgx_epid_group_id_t epid_gid;
  sgx_quote_t *quote;
  uint32_t sz = 0;
  sgx_quote_sign_type_t linkable = SGX_UNLINKABLE_SIGNATURE;

  // init quote
  printf("[GatewayApp]: Quote init phase ...\n");
  memset(&report, 0, sizeof(report));
  status = sgx_init_quote(&target_info, &epid_gid);
  if (status != SGX_SUCCESS) {
    fprintf(stderr, "[GatewayApp]: sgx_init_quote: %08x\n", status);
    return 1;
    // return (sgx_lasterr == SGX_SUCCESS);
  }

  // Invoke ECALL, 'ecall_report_gen()', to generate an attestation report
  printf("[GatewayApp]: ECALL - Report generation phase ...\n");
  sgx_lasterr = ecall_report_gen(enclave_id, &ecall_retval, &report,
                                 &target_info, report_data);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
    fprintf(stderr, "[GatewayApp]: ERROR: ecall_report_gen returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }

  // calculate quote size
  printf("[GatewayApp]: Call sgx_calc_quote_size() ...\n");
  status = sgx_calc_quote_size(NULL, 0, &sz);
  if (status != SGX_SUCCESS) {
    fprintf(stderr, "SGX error while getting quote size: %08x\n", status);
    return 1;
  }

  quote = (sgx_quote_t *)malloc(sz);
  if (quote == NULL) {
    fprintf(stderr, "out of memory\n");
    return 1;
  }
  memset(quote, 0, sz);

  // get quote
  printf("[GatewayApp]: Call sgx_get_quote() ...\n");
  status =
      sgx_get_quote(&report, linkable, &spid, NULL, NULL, 0, NULL, quote, sz);
  fprintf(stdout, "[GatewayApp]: status of sgx_get_quote(): %08x\n", status);
  printf("[GatewayApp]: status of sgx_get_quote(): %s\n",
         status == SGX_SUCCESS ? "success" : "error");
  if (status != SGX_SUCCESS) {
    fprintf(stderr, "[GatewayApp]: sgx_get_quote: %08x\n", status);
    return 1;
  }

  printf("\n[GatewayApp]: MRENCLAVE: \t");
  print_hexstring(stdout, &quote->report_body.mr_enclave,
                  sizeof(sgx_measurement_t));
  printf("\n[GatewayApp]: MRSIGNER: \t");
  print_hexstring(stdout, &quote->report_body.mr_signer,
                  sizeof(sgx_measurement_t));
  printf("\n[GatewayApp]: Report Data: \t");
  print_hexstring(stdout, &quote->report_body.report_data,
                  sizeof(sgx_report_data_t));
  printf("\n\n");

  char *b64quote = NULL;
  b64quote = base64_encode((char *)quote, sz);
  if (b64quote == NULL) {
    printf("Could not base64 encode quote\n");
    return 1;
  }

  printf("Quote, ready to be sent to IAS (POST /attestation/v4/report):\n");
  printf("{\n");
  printf("\t\"isvEnclaveQuote\":\"%s\"", b64quote);
  // if (OPT_ISSET(flags, OPT_NONCE)) {
  //    printf(",\n\t\"nonce\":\"");
  //    print_hexstring(stdout, &config->nonce, 16);
  //    printf("\"");
  //}

  printf("\n}\n\n");
  printf("See "
         "https://api.trustedservices.intel.com/documents/"
         "sgx-attestation-api-spec.pdf\n");

  return (sgx_lasterr == SGX_SUCCESS);
}

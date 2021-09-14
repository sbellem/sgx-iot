#include "app.h"
#include <enclave_u.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * @brief verify the signature on sensor data using ecall, verification result
 * is printed to terminal output where 0 means success
 *
 * @return (sgx_lasterr == SGX_SUCCESS)
 */
bool enclave_verify_signature(void) {
  sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;
  printf("[GatewayApp]: Calling enclave to verify signature\n");
  uint8_t result = 255;
  sgx_lasterr = ecall_unseal_and_verify(
      enclave_id, &ecall_retval, (uint8_t *)input_buffer,
      (uint32_t)input_buffer_size, (char *)sealed_pubkey_buffer,
      sealed_pubkey_buffer_size, (char *)sealed_signature_buffer,
      sealed_signature_buffer_size, &result);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != 0)) {
    fprintf(stderr,
            "[GatewayApp]: ERROR: ecall_unseal_and_verify returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }

  printf("[GatewayApp]: verification result: %d\n", result);
  return (sgx_lasterr == SGX_SUCCESS);
}
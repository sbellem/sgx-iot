#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "enclave.h"
#include <enclave_t.h>

#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

/**
 * @brief This function unseals the public key and signture from app and then
 * performs ECDSA verification on the data
 *
 * @param msg Input parameter for message whose signature is to be verified
 * @param msg_size Input parameter for size of msg
 * @param pubkey Input parameter for sealed public key
 * @param pubkey_size Input parameter for size of pubkey
 * @param signature Input parameter for sealed signature
 * @param signature_size Input parameter for size of signature
 * @param result The verification result: 0 means success
 * @return sgx_status_t SGX_SUCCESS (Error code = 0x0000) on success, some other
 * appropriate sgx_status_t value upon failure.
 */
sgx_status_t ecall_unseal_and_verify(uint8_t *msg, uint32_t msg_size,
                                     char *pubkey, size_t pubkey_size,
                                     char *signature, size_t signature_size,
                                     uint8_t *result) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_ecc_state_handle_t p_ecc_handle = NULL;

    print("\nTrustedApp: Received sensor data, sealed public key, and "
          "signature.\n");
    uint8_t *unsealed_signature;
    uint32_t unsealed_signature_size;
    // Step 1: Calculate sealed/encrypted data length.
    uint32_t unsealed_pubkey_size =
        sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)pubkey);
    uint8_t *const unsealed_pubkey =
        (uint8_t *)malloc(unsealed_pubkey_size); // Check malloc return;
    if (unsealed_pubkey == NULL) {
        print("\nTrustedApp: malloc(unsealed_pubkey_size) failed !\n");
        goto cleanup;
    }

    // Step 2: Unseal pubkey.
    if ((ret = sgx_unseal_data((sgx_sealed_data_t *)pubkey, NULL, NULL,
                               unsealed_pubkey, &unsealed_pubkey_size)) !=
        SGX_SUCCESS) {
        print("\nTrustedApp: sgx_unseal_data() (pubkey) failed !\n");
        goto cleanup;
    }

    // Step 3: Calculate sealed signature size
    unsealed_signature_size =
        sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)signature);

    unsealed_signature = malloc(unsealed_signature_size);
    if (unsealed_signature == NULL) {
        print("\nTrustedApp: malloc(unsealed_signature_size) failed !\n");
        goto cleanup;
    }

    // Step 4: Unseal signature
    if ((ret = sgx_unseal_data((sgx_sealed_data_t *)signature, NULL, NULL,
                               unsealed_signature, &unsealed_signature_size)) !=
        SGX_SUCCESS) {
        print("\nTrustedApp: sgx_unseal_data() (signature) failed !\n");
        goto cleanup;
    }

    // Step 5: Open Context.
    if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS) {
        print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
        goto cleanup;
    }

    // Step 6: Perform ECDSA verification.
    if ((ret = sgx_ecdsa_verify(msg, msg_size,
                                (sgx_ec256_public_t *)unsealed_pubkey,
                                (sgx_ec256_signature_t *)unsealed_signature,
                                result, p_ecc_handle)) != SGX_SUCCESS) {
        print("\nTrustedApp: sgx_ecdsa_verify() failed !\n");
        goto cleanup;
    }
    print("\nTrustedApp: Unsealed the sealed public key, verified sensor data "
          "signature with this public key and then, sent the result back.\n");
    ret = SGX_SUCCESS;

cleanup:
    // Step 5: Close Context, release memory
    if (p_ecc_handle != NULL) {
        sgx_ecc256_close_context(p_ecc_handle);
    }

    if (unsealed_pubkey != NULL) {
        memset_s(unsealed_pubkey, unsealed_pubkey_size, 0,
                 unsealed_pubkey_size);
        free(unsealed_pubkey);
    }

    if (unsealed_signature != NULL) {
        memset_s(unsealed_signature, unsealed_signature_size, 0,
                 unsealed_signature_size);
        free(unsealed_signature);
    }

    return ret;
}
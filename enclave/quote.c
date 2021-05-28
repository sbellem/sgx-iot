#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <enclave_t.h>
#include "enclave.h"

#include <sgx_quote.h>
#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_uae_epid.h>
#include <sgx_utils.h>

/**
 * This function unseals the sealed public key from app and then generates a
 * quote with the public key (x & y coordinates, uncompressed) in the report
 * data field.
 *
 * @param sealed             Input parameter for sealed public key.
 * @param sealed_size        Input parameter for size of sealed public key.
 * @param quote              Output parameter for quote.
 * @param quote_size         Input parameter for size of quote.
 *
 * @return                   SGX_SUCCESS (Error code = 0x0000) on success, some
 *                           other appropriate sgx_status_t value upon failure.
 */
sgx_status_t ecall_unseal_and_quote(sgx_report_t *report,
                                    sgx_target_info_t *target_info,
                                    char *sealed, size_t sealed_size) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    print("\nTrustedApp: Received the sealed public key.\n");

    // Step 1: Calculate sealed/encrypted data length.
    uint32_t unsealed_data_size =
        sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed);
    uint8_t *const unsealed_data =
        (uint8_t *)malloc(unsealed_data_size);  // Check malloc return;
    if (unsealed_data == NULL) {
        print("\nTrustedApp: malloc(unsealed_data_size) failed !\n");
        goto cleanup;
    }

    // Step 2: Unseal public key, and copy into report data
    if ((ret = sgx_unseal_data((sgx_sealed_data_t *)sealed, NULL, NULL,
                               unsealed_data, &unsealed_data_size)) !=
        SGX_SUCCESS) {
        print("\nTrustedApp: sgx_unseal_data() failed !\n");
        goto cleanup;
    }

    sgx_report_data_t report_data = {{0}};
    // memcpy((uint8_t *const) & report_data, unsealed_data,
    //       sizeof(unsealed_data_size));
    memcpy(&report_data, unsealed_data, sizeof(unsealed_data_size));

    // BEGIN WIP --------------------------------------------
    print("[[TrustedApp]]: Calling enclave to generate attestation report\n");
    ret = sgx_create_report(target_info, &report_data, report);
    // --------------------------------------------- END WIP

    print(
        "\nTrustedApp: Unsealed the sealed public key, generated a quote with "
        "with this public key in the report data, and sent quote back\n");

    // ret = SGX_SUCCESS;

cleanup:
    // Step 5: Release memory
    if (unsealed_data != NULL) {
        memset_s(unsealed_data, unsealed_data_size, 0, unsealed_data_size);
        free(unsealed_data);
    }

    return ret;
}

/**
 * This function unseals the sealed public key from app and then generates a
 * quote with the public key (x & y coordinates, uncompressed) in the report
 * data field.
 *
 * @param sealed             Input parameter for sealed public key.
 * @param sealed_size        Input parameter for size of sealed public key.
 * @param quote              Output parameter for quote.
 * @param quote_size         Input parameter for size of quote.
 *
 * @return                   SGX_SUCCESS (Error code = 0x0000) on success, some
 *                           other appropriate sgx_status_t value upon failure.
 */
/*
sgx_status_t ecall_unseal_and_quote(char *sealed, size_t sealed_size,
                                    char *quote, size_t quote_size) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_ecc_state_handle_t p_ecc_handle = NULL;

    print("\nTrustedApp: Received the sealed public key.\n");

    // Step 1: Calculate sealed/encrypted data length.
    uint32_t unsealed_data_size =
        sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed);
    uint8_t *const unsealed_data =
        (uint8_t *)malloc(unsealed_data_size);  // Check malloc return;
    if (unsealed_data == NULL) {
        print("\nTrustedApp: malloc(unsealed_data_size) failed !\n");
        goto cleanup;
    }

    // Step 2: Unseal data.
    if ((ret = sgx_unseal_data((sgx_sealed_data_t *)sealed, NULL, NULL,
                               unsealed_data, &unsealed_data_size)) !=
        SGX_SUCCESS) {
        print("\nTrustedApp: sgx_unseal_data() failed !\n");
        goto cleanup;
    }

    // Step 3: Open Context.
    if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS) {
        print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
        goto cleanup;
    }

    // Step 4: Perform ECDSA Signing.
    if ((ret =
             sgx_ecdsa_sign(msg, msg_size, (sgx_ec256_private_t *)unsealed_data,
                            (sgx_ec256_signature_t *)signature,
                            p_ecc_handle)) != SGX_SUCCESS) {
        print("\nTrustedApp: sgx_ecdsa_sign() failed !\n");
        goto cleanup;
    }

    print(
        "\nTrustedApp: Unsealed the sealed private key, signed sensor data "
        "with this private key and then, sent the signature back.\n");

    ret = SGX_SUCCESS;

cleanup:
    // Step 5: Close Context, release memory
    if (p_ecc_handle != NULL) {
        sgx_ecc256_close_context(p_ecc_handle);
    }
    if (unsealed_data != NULL) {
        memset_s(unsealed_data, unsealed_data_size, 0, unsealed_data_size);
        free(unsealed_data);
    }

    return ret;
}
*/

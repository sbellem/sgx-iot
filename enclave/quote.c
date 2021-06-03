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
 * @param report             Input parameter for report.
 * @param target_info        Input parameter for target info.
 * @param sealed             Input parameter for sealed public key.
 * @param sealed_size        Input parameter for size of sealed public key.
 *
 * @return                   SGX_SUCCESS (Error code = 0x0000) on success, some
 *                           other appropriate sgx_status_t value upon failure.
 */
sgx_status_t ecall_unseal_and_quote(sgx_report_t *report,
                                    sgx_target_info_t *target_info,
                                    char *sealed, size_t sealed_size,
                                    char *public_key, size_t public_key_size) {
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

    // DEBUG - copy unsealed public key to public_key_buffer to print to stdout
    // memcpy_s((uint8_t *)public_key, sizeof(public_key_size), &unsealed_data,
    // unsealed_data_size);
    memcpy((uint8_t *)public_key, unsealed_data, unsealed_data_size);

    sgx_report_data_t report_data = {{0}};
    memcpy((uint8_t *const) & report_data, unsealed_data, unsealed_data_size);
    // memcpy(&report_data, unsealed_data, unsealed_data_size);

    // BEGIN WIP --------------------------------------------
    print("[[TrustedApp]]: Calling enclave to generate attestation report\n");
    ret = sgx_create_report(target_info, &report_data, report);
    // --------------------------------------------- END WIP

    print(
        "\n[[TrustedApp]]: Unsealed the sealed public key and created a report "
        "containing the public key in the report data.\n");

    // ret = SGX_SUCCESS;

cleanup:
    // Step 5: Release memory
    if (unsealed_data != NULL) {
        memset_s(unsealed_data, unsealed_data_size, 0, unsealed_data_size);
        free(unsealed_data);
    }

    return ret;
}

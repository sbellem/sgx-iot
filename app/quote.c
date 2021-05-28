#include <stdio.h>
#include <stdlib.h>

#include <enclave_u.h> /* For sgx_enclave_id_t */

#include <sgx_quote.h>

#include "app.h"

bool enclave_gen_quote() {
    printf("[GatewayApp]: Calling enclave to generate report\n");

    sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;
    sgx_report_t report;
    sgx_spid_t spid;
    sgx_target_info_t target_info;
    sgx_epid_group_id_t epid_gid;
    sgx_status_t status;

    /* Init Quote */
    status = sgx_init_quote(&target_info, &epid_gid);

    /*
     * Invoke ECALL, 'ecall_unseal_and_quote()', to generate a quote including
     * the sealed public key in the report data field.
     */
    memset(&report, 0, sizeof(report));
    sgx_lasterr = ecall_unseal_and_quote(
        enclave_id, &ecall_retval, &report, &target_info,
        (char *)sealed_pubkey_buffer, sealed_pubkey_buffer_size,
        (char *)public_key_buffer, public_key_buffer_size);

    if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != 0)) {
        fprintf(stderr,
                "[GatewayApp]: ERROR: ecall_unseal_and_quote returned %d\n",
                ecall_retval);
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
    }

    // DEBUG Print pub key big endian form
    /* ----- ----- ----- ----- experiment ----- ----- ----- ----- */
    if (public_key_buffer_size != 64) {
        fprintf(stderr,
                "[GatewayApp]: assertion failed: key_buffer_size == 64\n");
        return false;
    }
    BIGNUM *bn_x =
        bignum_from_little_endian_bytes_32((uint8_t *)public_key_buffer);
    BIGNUM *bn_y =
        bignum_from_little_endian_bytes_32((uint8_t *)public_key_buffer + 32);

    FILE *fpx = open_file("bn_x", "wt");
    BN_print_fp(fpx, bn_x);
    FILE *fpy = open_file("bn_y", "wt");
    BN_print_fp(fpy, bn_y);

    printf("\nbn_x: %s\n", BN_bn2dec(bn_x));
    printf("bn_y: %s\n\n", BN_bn2dec(bn_y));
    printf("\nbn_x: %s\n", BN_bn2hex(bn_x));
    printf("bn_y: %s\n\n", BN_bn2hex(bn_y));
    /* ----- ----- ----- ----- experiment ----- ----- ----- ----- */

    // calculate quote size
    sgx_quote_t *quote;
    uint32_t sz = 0;

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
    sgx_quote_sign_type_t linkable = SGX_UNLINKABLE_SIGNATURE;

    printf("[GatewayApp]: SPID: %s\n", getenv("SGX_SPID"));
    from_hexstring((unsigned char *)&spid, (unsigned char *)getenv("SGX_SPID"),
                   16);
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
    printf(
        "See "
        "https://api.trustedservices.intel.com/documents/"
        "sgx-attestation-api-spec.pdf\n");

    return (sgx_lasterr == SGX_SUCCESS);
}

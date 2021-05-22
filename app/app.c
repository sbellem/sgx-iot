/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <getopt.h>
#include <stdio.h>

#include <openssl/evp.h>

#include "app.h"

static struct option long_options[] = {
    {"keygen", no_argument, 0, 0},
    {"sign", no_argument, 0, 0},
    {"enclave-path", required_argument, 0, 0},
    {"sealedprivkey", required_argument, 0, 0},
    {"sealedpubkey", required_argument, 0, 0},
    {"signature", required_argument, 0, 0},
    {"public-key", required_argument, 0, 0},
    {0, 0, 0, 0}};

/**
 * main()
 */
int main(int argc, char **argv) {
    bool opt_keygen = false;
    bool opt_sign = false;
    const char *opt_enclave_path = NULL;
    const char *opt_sealedprivkey_file = NULL;
    const char *opt_sealedpubkey_file = NULL;
    const char *opt_signature_file = NULL;
    const char *opt_input_file = NULL;
    const char *opt_public_key_file = NULL;

    int option_index = 0;

    while (getopt_long_only(argc, argv, "", long_options, &option_index) !=
           -1) {
        switch (option_index) {
            case 0:
                opt_keygen = true;
                break;
            case 1:
                opt_sign = true;
                break;
            case 2:
                opt_enclave_path = optarg;
                break;
            case 3:
                opt_sealedprivkey_file = optarg;
                break;
            case 4:
                opt_sealedpubkey_file = optarg;
                break;
            case 5:
                opt_signature_file = optarg;
                break;
            case 6:
                opt_public_key_file = optarg;
                break;
        }
    }

    if (optind < argc) {
        opt_input_file = argv[optind++];
    }

    if (!opt_keygen && !opt_sign) {
        fprintf(stderr, "Error: Must specifiy either --keygen or --sign\n");
        return EXIT_FAILURE;
    }

    if (opt_keygen && (!opt_enclave_path || !opt_sealedprivkey_file ||
                       !opt_sealedprivkey_file || !opt_public_key_file)) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr,
                "  %s --keygen --enclave-path /path/to/enclave.signed.so "
                "--sealedprivkey sealedprivkey.bin "
                "--sealedpubkey_file sealedpubkey.bin "
                "--public-key mykey.pem\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    if (opt_sign && (!opt_enclave_path || !opt_sealedprivkey_file ||
                     !opt_signature_file || !opt_input_file)) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr,
                "  %s --sign --enclave-path /path/to/enclave.signed.so "
                "--sealedprivkey "
                "sealeddata.bin --signature inputfile.signature inputfile\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    OpenSSL_add_all_algorithms(); /* Init OpenSSL lib */

    bool success_status =
        create_enclave(opt_enclave_path) && enclave_get_buffer_sizes() &&
        allocate_buffers() &&
        (opt_sign ? load_enclave_state(opt_sealedprivkey_file) : true) &&
        (opt_keygen ? enclave_generate_key() : true) &&
        (opt_sign ? load_input_file(opt_input_file) : true) &&
        (opt_sign ? enclave_sign_data() : true) &&
        // save_enclave_state(opt_sealedprivkey_file) &&
        save_enclave_state(opt_sealedprivkey_file, opt_sealedpubkey_file) &&
        (opt_sign ? save_signature(opt_signature_file) : true);
    //(opt_keygen ? save_public_key(opt_public_key_file) : true);
    // TODO call function to generate report with public key in it
    //(opt_keygen ? enclave_generate_quote() : true);
    //(opt_keygen ? save_public_key(opt_public_key_file) : true);

    if (sgx_lasterr != SGX_SUCCESS) {
        fprintf(stderr, "[GatewayApp]: ERROR: %s\n",
                decode_sgx_status(sgx_lasterr));
    }

    destroy_enclave();
    cleanup_buffers();

    return success_status ? EXIT_SUCCESS : EXIT_FAILURE;
}

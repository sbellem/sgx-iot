/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <sys/types.h>
#include <sgx_error.h>

#include "app.h"

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char * msg;
} sgx_errlist_t;

static sgx_errlist_t sgx_errlist[] = {
    {SGX_ERROR_UNEXPECTED,               "Unexpected error occurred."},
    {SGX_ERROR_INVALID_PARAMETER,        "Invalid parameter."},
    {SGX_ERROR_OUT_OF_MEMORY,            "Out of memory."},
    {SGX_ERROR_ENCLAVE_LOST,             "Power transition occurred."},
    {SGX_ERROR_INVALID_ENCLAVE,          "Invalid enclave image."},
    {SGX_ERROR_INVALID_ENCLAVE_ID,       "Invalid enclave identification."},
    {SGX_ERROR_INVALID_SIGNATURE,        "Invalid enclave signature."},
    {SGX_ERROR_OUT_OF_EPC,               "Out of EPC memory."},
    {SGX_ERROR_NO_DEVICE,                "Invalid SGX device."},
    {SGX_ERROR_MEMORY_MAP_CONFLICT,      "Memory map conflicted."},
    {SGX_ERROR_INVALID_METADATA,         "Invalid encalve metadata."},
    {SGX_ERROR_DEVICE_BUSY,              "SGX device is busy."},
    {SGX_ERROR_INVALID_VERSION,          "Enclave metadata version is invalid."},
    {SGX_ERROR_ENCLAVE_FILE_ACCESS,      "Can't open enclave file."},

    {SGX_ERROR_INVALID_FUNCTION,         "Invalid function name."},
    {SGX_ERROR_OUT_OF_TCS,               "Out of TCS."},
    {SGX_ERROR_ENCLAVE_CRASHED,          "The enclave is crashed."},

    {SGX_ERROR_MAC_MISMATCH,             "Report varification error occurred."},
    {SGX_ERROR_INVALID_ATTRIBUTE,        "The enclave is not authorized."},
    {SGX_ERROR_INVALID_CPUSVN,           "Invalid CPUSVN."},
    {SGX_ERROR_INVALID_ISVSVN,           "Invalid ISVSVN."},
    {SGX_ERROR_INVALID_KEYNAME,          "The requested key name is invalid."},

    {SGX_ERROR_SERVICE_UNAVAILABLE,          "AESM service is not responsive."},
    {SGX_ERROR_SERVICE_TIMEOUT,              "Request to AESM is time out."},
    {SGX_ERROR_SERVICE_INVALID_PRIVILEGE,    "Error occurred while getting launch token."},

    /* NRI Added: */
    {SGX_ERROR_AE_INVALID_EPIDBLOB,    "Indicates an Intel(R) EPID blob verification error."}
};


const char* decode_sgx_status(sgx_status_t status)
{
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (size_t idx = 0; idx < ttl; idx++) {
        if(status == sgx_errlist[idx].err) {
            return sgx_errlist[idx].msg;
        }
    }
    return "Unexpected error parsing SGX return status";
}

/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>

/* Ensure that ocall_print_string has extern C linkage */
#include <enclave_u.h>

void ocall_print_string(const char *str) {
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

// void ocall_print_int(const int num) {
//    /* Proxy/Bridge will check the length and null-terminate
//     * the input string to prevent buffer overflow.
//     */
//    printf("%d", num);
//}

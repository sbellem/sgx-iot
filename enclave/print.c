/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "enclave.h"
#include <enclave_t.h>

void print(const char *const str) { ocall_print_string(str); }

// void printint(const int num) { ocall_print_int(num); }

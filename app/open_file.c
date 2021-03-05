/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>

#include "app.h"

FILE* open_file(const char* const filename, const char* const mode)
{
    return fopen(filename, mode);
}
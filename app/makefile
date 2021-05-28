#
# Copyright (C) 2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

include ../common/common.mk
include ../common/rules.mk

SGX_EDGER8R_FLAGS += --untrusted-dir ../interface
CFLAGS += $(SGX_HOST_CFLAGS) -std=c99
CXXFLAGS += $(SGX_HOST_CXXFLAGS)
CPPFLAGS += $(SGX_HOST_CPPFLAGS) -I../interface
LDFLAGS += $(SGX_HOST_LDFLAGS)
# Add to LDFLAGS if enclave_stub_u is a shared library: -Wl,-rpath,../interface -Wl,-rpath,interface
LDLIBS += -L ../interface -lenclave_stub_u $(SGX_HOST_LDLIBS) -lcrypto -ldl

.PHONY: all clean

all: ../interface/libenclave_stub_u.a app

../interface/libenclave_stub_u.a: ../interface/enclave.edl

app: app.o globals.o ocall_print_string.o decode_sgx_status.o enclave.o buffers.o enclave_state.o endianswap.o readfile.o ecall_buffer.o keygen.o sign.o open_file.o hexutil.o base64.o quote.o
#ocall_print_int.o

clean:
	rm -f ../interface/*_u.* app *.o

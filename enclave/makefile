#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

include ../common/common.mk
include ../common/rules.mk

SGX_EDGER8R_FLAGS += --trusted-dir ../interface
CFLAGS += $(SGX_ENCLAVE_CFLAGS) -std=c99 -Wno-unused-parameter
CXXFLAGS += $(SGX_ENCLAVE_CXXFLAGS)
CPPFLAGS += $(SGX_ENCLAVE_CPPFLAGS) -I../interface
LDFLAGS += $(SGX_ENCLAVE_LDFLAGS)
LDLIBS += -L ../interface -lenclave_stub_t $(SGX_ENCLAVE_LDLIBS)

.PHONY: all clean

all: ../interface/libenclave_stub_t.a enclave.signed.so

../interface/libenclave_stub_t.a: ../interface/enclave.edl

enclave.unsigned.so: calcbuffsize.o keygen.o print.o sign.o quote.o

enclave.signed.so: enclave.key.pem

enclave.key.pem:
	openssl genrsa -3 -out $@ 3072

clean:
	rm -f ../interface/*_t.* enclave.key.pem enclave.unsigned.so enclave.signed.so *.o


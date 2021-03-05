#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

.SUFFIXES: .edl _u.h _u.c _u.o _stub_u.a _stub_u.so _t.h _t.c _t.o _stub_t.a .unsigned.so .signed.so

# Implicit rules to generate untrusted (host) stubs

lib%_stub_u.a: %.edl
	$(SGX_EDGER8R) $(SGX_EDGER8R_FLAGS) --untrusted $< --search-path $(SGX_SDK)/include
	$(CC) $(SGX_HOST_CFLAGS) $(SGX_HOST_CPPFLAGS) $(TARGET_ARCH) -c $*_u.c -o $*_u.o
	$(AR) $(ARFLAGS) $@ $*_u.o
	ranlib -Dt $@

lib%_stub_u.so: %.edl
	$(SGX_EDGER8R) $(SGX_EDGER8R_FLAGS) --untrusted $< --search-path $(SGX_SDK)/include
	$(CC) $(SGX_HOST_CFLAGS) $(SGX_HOST_CPPFLAGS) $(TARGET_ARCH) -c $*_u.c -o $*_u.o
	$(CC) $(LDFLAGS) $(TARGET_ARCH) -shared $*_u.o $(LOADLIBES) $(SGX_HOST_LDLIBS) -o $@

# Implicit rules to generate trusted (enclave) stubs

lib%_stub_t.a: %.edl
	$(SGX_EDGER8R) $(SGX_EDGER8R_FLAGS) --trusted $< --search-path $(SGX_SDK)/include
	$(CC) $(SGX_ENCLAVE_CFLAGS) $(SGX_ENCLAVE_CPPFLAGS) $(TARGET_ARCH) -c $*_t.c -o $*_t.o
	$(AR) $(ARFLAGS) $@ $*_t.o
	ranlib -Dt $@

# Implicit rules to generate enclave binaries

%.unsigned.so:
	$(CC) $(LDFLAGS) $(TARGET_ARCH) $^ $(LOADLIBES) $(LDLIBS) -o $@

%.signed.so: %.unsigned.so %.key.pem
	$(SGX_ENCLAVE_SIGNER) sign -key $*.key.pem -enclave $< -out $@ -config $*.config.xml


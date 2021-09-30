#!/bin/sh -e
#                                               -*- Makefile -*-
#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#


test -d demo_sgx || mkdir demo_sgx

# Clean up from previous runs
rm -f demo_sgx/*
cd demo_sgx


echo "Provisioning private elliptic curve key:"
# Generate the keypair (both private & public keys are sealed to enclave)
#../app/app --keygen --enclave-path `pwd`/../enclave/enclave.signed.so --statefile sealeddata.bin --public-key secp256r1.pem
../app/app --keygen \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --sealedprivkey sealedprivkey.bin \
    --sealedpubkey sealedpubkey.bin \
    --public-key secp256r1.pem
echo "Key provisoning completed.\n"

echo "\nGenerating quote for remote attestation:"
# Generate the quote
../app/app --quote \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --sealedpubkey sealedpubkey.bin \
    --quotefile quote.bin
echo "Quote generation completed.\n"

echo "\nSigning sensor data:"
../app/app --sign \
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --sealedprivkey sealedprivkey.bin \
    --signature Sensor_Data.signature \
    --sealedsignature sealedsignature.bin ../Sensor_Data
echo "Sensor data signed.\n"

echo "\nVerifying sensor data from enclave:"
../app/app --verify\
    --enclave-path `pwd`/../enclave/enclave.signed.so \
    --sealedsignature sealedsignature.bin \
    --sealedpubkey sealedpubkey.bin \
    ../Sensor_Data 
echo "Sensor data verified inside enclave.\n"

echo "\nVerifying quote and signature:"
cd ..
python verify.py

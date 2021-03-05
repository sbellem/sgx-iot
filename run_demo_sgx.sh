#!/bin/sh -e
#                                               -*- Makefile -*-
#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

test -d demo_sgx || mkdir demo_sgx
cd demo_sgx

# Clean up from previous runs
rm -f sealeddata.bin secp256r1.pem Sensor_Data.signature

echo "Provisioning private elliptic curve key:"
# Generate the keypair (private key is sealed to enclave)
../app/app --keygen --enclave-path `pwd`/../enclave/enclave.signed.so --statefile sealeddata.bin --public-key secp256r1.pem
echo "Key provisoning completed."

echo "Generated public key:"
cat secp256r1.pem
echo -n "Registering publc key with server.."
# This step is left as an excercise for the reader
sleep 1
echo ".done"

echo "Signing sensor data:"
../app/app --sign --enclave-path `pwd`/../enclave/enclave.signed.so --statefile sealeddata.bin --signature Sensor_Data.signature ../Sensor_Data
echo "Sensor data signed."

echo -n "Transmitting signature to server.."
# This step is left as an exercise for the reader
sleep 1
echo ".done"

echo "Verifying signature:"
# Secure elave is not required for signature verification; just use OpenSSL
openssl dgst -verify secp256r1.pem -signature Sensor_Data.signature ../Sensor_Data

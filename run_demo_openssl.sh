#!/bin/sh -e
#                                               -*- Makefile -*-
#
# Copyright (C) 2011-2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

test -d demo_openssl || mkdir demo_openssl
cd demo_openssl

# Clean up from previous runs
rm -f secp256r1-key.pem secp256r1.pem Sensor_Data.signature

echo -n "Provisioning private elliptic curve key.."
# First generate the private key
openssl ecparam -name prime256v1 -genkey -out secp256r1-key.pem 2> /dev/null
# Then extract the public key (needed for signature verification later)
openssl ec -in secp256r1-key.pem -pubout -out secp256r1.pem 2> /dev/null
echo ".done"

echo "Generated public key:"
cat secp256r1.pem
echo -n "Registering publc key with server.."
# This step is left as an excercise for the reader
sleep 1
echo ".done"

echo -n "Signing sensor data.."
openssl dgst -sign secp256r1-key.pem -out Sensor_Data.signature ../Sensor_Data
echo ".done"

echo -n "Transmitting signature to server.."
# This step is left as an exercise for the reader
sleep 1
echo ".done"

echo "Verifying signature:"
openssl dgst -verify secp256r1.pem -signature Sensor_Data.signature ../Sensor_Data

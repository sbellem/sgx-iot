import base64
import json
import os
import pprint

import requests

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


def little2big_endian(b):
    return swap_endians(b)


def swap_endians(b, *, length=32, from_byteorder="little", to_byteorder="big"):
    return int.from_bytes(b, from_byteorder).to_bytes(length, "big")


##############################################################################
#                                                                            #
#                          Verify quote with IAS                             #
#                                                                            #
##############################################################################
print("Reading quote from file ...")
with open("demo_sgx/quote.bin", "rb") as f:
    quote_bytes = f.read()

quote_b64 = base64.b64encode(quote_bytes)
quote_dict = {"isvEnclaveQuote": quote_b64.decode()}

# send the quote for verification
# To send the quote over to Intel, you need your API primary subscription key,
# which you should have set as an environment variable before starting the
# container. (See the prerequisite section if needed.)
url = "https://api.trustedservices.intel.com/sgx/dev/attestation/v4/report"

headers = {
    "Content-Type": "application/json",
    "Ocp-Apim-Subscription-Key": os.environ["IAS_PRIMARY_KEY"],
}

print("Sending quote to Intel's Attestation Service for verification ...")
res = requests.post(url, json=quote_dict, headers=headers)

if res.ok:
    print("Attestation verification succeeded!\n")
else:
    print(f"Attestatin failed, with status {res.status_code} and reason {res.reason}\n")
    exit(1)

print("IAS response is: ")
pprint.pprint(res.json())

ias_report = {"body": res.json(), "headers": dict(res.headers)}

with open("demo_sgx/ias_report.json", "w") as f:
    json.dump(ias_report, f)

import auditee  # noqa

auditee.verify_mrenclave(
    "/usr/src/sgxiot/",
    "/usr/src/sgxiot/enclave/enclave.signed.so",
    ias_report="/usr/src/sgxiot/demo_sgx/ias_report.json",
)


##############################################################################
#                                                                            #
#                 Extract Pulic Key from attestation report                  #
#                                                                            #
##############################################################################
print("\nExtracting public key from IAS report ...")
quote_body = res.json()["isvEnclaveQuoteBody"]
report_data = base64.b64decode(quote_body)[368:432]
x_little = report_data[:32]
y_little = report_data[32:]
x = little2big_endian(x_little)
y = little2big_endian(y_little)
point = b"\x04" + x + y
pubkey = ec.EllipticCurvePublicKey.from_encoded_point(curve=ec.SECP256R1(), data=point)


##############################################################################
#                                                                            #
#                          Verify Signature                                  #
#                                                                            #
##############################################################################
with open("demo_sgx/Sensor_Data.signature", "rb") as f:
    signature = f.read()

with open("Sensor_Data") as f:
    sensor_data = f.read()

print(f"\nVerifying signature {signature.hex()} for sensor data:\n{sensor_data}\n")
pubkey.verify(
    signature, sensor_data.encode(), signature_algorithm=ec.ECDSA(hashes.SHA256()),
)

print("Signature verification successful!")

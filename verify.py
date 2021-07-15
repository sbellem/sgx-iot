import base64
import json
import os
import pathlib
import sys
import time

import auditee
import requests

from blessings import Terminal
from colorama import init as init_colorama  # , Fore, Back, Style
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

init_colorama()
term = Terminal()

SOURCE_CODE = pathlib.Path("/home/photon/sgxiot")
SIGNED_ENCLAVE = SOURCE_CODE.joinpath("enclave", "enclave.signed.so")
DEMO_DIR = SOURCE_CODE.joinpath("demo_sgx")
IAS_REPORT = SOURCE_CODE.joinpath("demo_sgx/ias_report.json")


def little2big_endian(b):
    return swap_endians(b)


def swap_endians(b, *, length=32, from_byteorder="little", to_byteorder="big"):
    return int.from_bytes(b, from_byteorder).to_bytes(length, "big")


##############################################################################
#                                                                            #
#                          Verify quote with IAS                             #
#                                                                            #
##############################################################################
print(f"{term.bold}Reading quote from file ...{term.normal}")
time.sleep(4)
with open(DEMO_DIR.joinpath("quote.bin"), "rb") as f:
    quote_bytes = f.read()

quote_b64 = base64.b64encode(quote_bytes)
quote_dict = {"isvEnclaveQuote": quote_b64.decode()}
print(f"{term.blue}{quote_b64.decode()}{term.normal}\n")

# send the quote for verification
# To send the quote over to Intel, you need your API primary subscription key,
# which you should have set as an environment variable before starting the
# container. (See the prerequisite section if needed.)
url = "https://api.trustedservices.intel.com/sgx/dev/attestation/v4/report"

headers = {
    "Content-Type": "application/json",
    "Ocp-Apim-Subscription-Key": os.environ["IAS_PRIMARY_KEY"],
}

print(
    f"{term.bold}Sending quote to Intel's Attestation Service for verification ...{term.normal}"
)
time.sleep(4)
res = requests.post(url, json=quote_dict, headers=headers)

if res.ok:
    print(f"{term.green}Attestation report verification succeeded!\n{term.normal}")
else:

    sys.exit(
        f"{term.red}Attestatin verification failed, with status: "
        f"{res.status_code} and reason: {res.reason}\n"
        f"Did you set SGX_SPID and IAS_PRIMARY_KEY?\n"
        "See https://github.com/sbellem/sgx-iot#set-environment-variables{term.normal}"
    )

print(f"{term.bold}IAS response is: {term.normal}")
print(f"{term.blue}{json.dumps(res.json(), indent=4)}")
time.sleep(5)

ias_report = {"body": res.json(), "headers": dict(res.headers)}

with open(DEMO_DIR.joinpath("ias_report.json"), "w") as f:
    json.dump(ias_report, f)

##############################################################################
#                                                                            #
#                          Verify reported MRENCLAVE                         #
#                                                                            #
##############################################################################
print(
    f"{term.bold}Verify reported MRENCLAVE against trusted source code ...{term.normal}"
)
time.sleep(4)

match = auditee.verify_mrenclave(SOURCE_CODE, SIGNED_ENCLAVE, ias_report=IAS_REPORT,)

if not match:
    sys.exit(
        f"{term.red}MRENCLAVE of remote attestation report does not match trusted source code.{term.normal}"
    )
time.sleep(5)


##############################################################################
#                                                                            #
#                 Extract Pulic Key from attestation report                  #
#                                                                            #
##############################################################################
print(f"{term.bold}\nExtracting public key from IAS report ...{term.normal}")
quote_body = res.json()["isvEnclaveQuoteBody"]
report_data = base64.b64decode(quote_body)[368:432]
x_little = report_data[:32]
y_little = report_data[32:]
x = little2big_endian(x_little)
y = little2big_endian(y_little)
point = b"\x04" + x + y
pubkey = ec.EllipticCurvePublicKey.from_encoded_point(curve=ec.SECP256R1(), data=point)

pubkey_pem = pubkey.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
print(f"{term.blue}{pubkey_pem.decode()}{term.normal}")

time.sleep(4)


##############################################################################
#                                                                            #
#                          Verify Signature                                  #
#                                                                            #
##############################################################################
with open(DEMO_DIR.joinpath("Sensor_Data.signature"), "rb") as f:
    signature = f.read()

with open(SOURCE_CODE.joinpath("Sensor_Data")) as f:
    sensor_data = f.read()

print(
    f"{term.bold}\nVerifying signature:{term.normal}\n"
    f"{term.blue}{signature.hex()}{term.normal}\n"
    f"{term.bold}for sensor data:{term.normal}\n"
    f"{sensor_data}\n"
)
pubkey.verify(
    signature, sensor_data.encode(), signature_algorithm=ec.ECDSA(hashes.SHA256()),
)

print(f"{term.green}Signature verification successful!{term.normal}")

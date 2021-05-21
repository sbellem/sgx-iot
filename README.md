# Gateway Key Provisioning and Secure Signing using Intel® Software Guard Extensions
This is an adaptation of the original code sample found at
https://software.intel.com/content/www/us/en/develop/articles/code-sample-gateway-key-provisioning-and-secure-signing-using-intel-software-guard.html. For convenience, the original code is also under the branch
[`download`](https://github.com/sbellem/sgx-iot/tree/download).

The focus of this adaptation is on combining the key generation with remote
attestation such that the public key is included in the report data of a remote
attestation report.

## Prerequisites
* You need [docker](https://docs.docker.com/engine/install/) and
  [docker-compose](https://docs.docker.com/compose/install/).

* The docker-based development environment assumes it is running on an SGX-enabled
  processor. If you are not sure whether your computer supports SGX, and/or how to
  enable it, see https://github.com/ayeks/SGX-hardware#test-sgx.

* Obtain an **Unlinkable** subscription key for the
  [Intel SGX Attestation Service Utilizing Enhanced Privacy ID (EPID)](https://api.portal.trustedservices.intel.com/).


## Quickstart
### Set Environment Variables
Before starting a container, set the two following environment variables:

* `SGX_SPID` - used to create a quote
* `IAS_PRIMARY_KEY` - used to access Intel's Attestation Service (IAS)

```shell
export SGX_SPID=<your-SPID>
export IAS_PRIMARY_KEY=<your-ias-primary-key>
```

### Spin up a container

```shell
docker-compose run --rm sgxiot bash
```

### Run the demo
The demo creates an asymmetric elliptic curve keypair. It seals the private key,
and writes the public key to a file, under `demo_sgx/secp256r1.pem`.

The demo also generates a quote that can be sent to Intel for verification. The
quote contains the public key in its `report_data` field.

```shell
./run_demo_sgx.sh
```

```shell
Provisioning private elliptic curve key:
[GatewayApp]: Creating enclave
[GatewayApp]: Querying enclave for buffer sizes

TrustedApp: Sizes for public key, sealed private key and signature calculated successfully.
[GatewayApp]: Allocating buffers
[GatewayApp]: Calling enclave to generate key material

TrustedApp: Key pair generated and private key was sealed. Sent the public key and sealed private key back.
[GatewayApp]: Saving enclave state
[GatewayApp]: Saving public key

bn_x: 81642911444757341234100352166297173983820050325410340992371942041376895891620
bn_y: 30097397527010383176635710518216378788557068565976601776099243912358222513896

bn_x: B4804014E8C2E7383428289970E5F673EEC509623E59EAAC7BF1AAFB078578A4
bn_y: 428A85F844CA5FE4AE33A23E52339E8E6135EA2BAF78CE127B943ACEA5DA46E8

[GatewayApp]: Calling enclave to generate attestation report
[GatewayApp]: SPID: 53ab75e49cc02fe564fd515917881be8
[GatewayApp]: Quote init phase ...
[GatewayApp]: ECALL - Report generation phase ...
[GatewayApp]: Call sgx_calc_quote_size() ...
[GatewayApp]: Call sgx_get_quote() ...
[GatewayApp]: status of sgx_get_quote(): 00000000
[GatewayApp]: status of sgx_get_quote(): success

[GatewayApp]: MRENCLAVE:        a8a3094d76217c5dd0a1126ac142b36dd34f88514a99bf8dfc8ea852f1fa6238
[GatewayApp]: MRSIGNER:         6704e3afefb2c93c6ab9ad6e4fd97a93a5d056a41c2a99c701cca1f5f01f7c4b
[GatewayApp]: Report Data:      b4804014e8c2e7383428289970e5f673eec509623e59eaac7bf1aafb078578a4428a85f844ca5fe4ae33a23e52339e8e6135ea2baf78ce127b943acea5da46e8

Quote, ready to be sent to IAS (POST /attestation/v4/report):
{
        "isvEnclaveQuote":"AgAAAFsLAAALAAoAAAAAAFOrdeScwC/lZP1RWReIG+iRaFn0HiQK7vu+7g8BckAuCRH//wECAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAKijCU12IXxd0KESasFCs23TT4hRSpm/jfyOqFLx+mI4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABnBOOv77LJPGq5rW5P2XqTpdBWpBwqmccBzKH18B98SwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0gQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC0gEAU6MLnODQoKJlw5fZz7sUJYj5Z6qx78ar7B4V4pEKKhfhEyl/krjOiPlIzno5hNeorr3jOEnuUOs6l2kboqAIAAHmlFCVS6cp4FM7WhB3jpxWVDukXLMRgBvaHshb1qfuRqR6twO+shb5XQkLd/bNftWeTtZC+IVyUWjqSFJhuMyt8lXiNureQxoTxHvTa2//lL0tMKGjgZBt01ucRhIeyIb9LnAvgLw7EXuRmit4RjRKfVpSgMjnYtu1ZDsO+qoSCGlfY2WDy4oHCBQvz/ErTGA4cX20luT3G+4V9rvbUFL1XcdrRzEIBeOYv1o3w3ZhmhLNrqBxlB8JJrndMTvRb+idI5CYK7AGGIMvO6XPzgzDKvm2T+4hpqwQrUoQQilvcIkAJ7els/y53psv/m/T6R07ygBGkSF0kHFgnP1o7gs510cI7E7s714smfwnf7+fQMmDIIqBuOUCcAwmVMTbkpYETLGZwfMaaCI2tvWgBAADt2TDVlkTLaf/Hi5xnk8NaA/PcdbEVNf1LGnuorB4qY5dvM83rF6ABEV7N6uF5pH73b/oZwY+F4AxJW1cb8zjSrGJVb+LlO2zOrtDs0mb1RfckXChrGEgZtj0Tx584YSDRhPuQp2mvQjQyVYrOGCfzhyIDyiuqbhbvjPXWVVVKIjBWh+QZxZ3b/YJBPm38/XQfWV/JotJUMB6rUUzGSZi91a/Eb/7hrNjRyKXAYboog4IHrKJWgLRwPSdNcjZAeZAjZKJK5OCEk25341G6FoG34H9k6LeXidTBk/VRXrzlBbbbBbLg8mMqGDLv0WVXZnaYgDf/Jidu8vp08vknfi28PtxcIWmqwXOazO00yHU7OvUfjynnOxh0t+REa2YYxdehPAfO0nsgVmUruuj3s2vwtbgiQ6il03O/Sw4CabOya3C8Evce6tTHoPBtYGVs24Tgn5mXM+NSRs+ad+eDKsSqHymzd/sVrYaJlmL87zlcvtC8y33FVEIJ"
}

See https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf
[GatewayApp]: Destroying enclave
[GatewayApp]: Deallocating buffers
Key provisoning completed.

Generated public key:
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtIBAFOjC5zg0KCiZcOX2c+7FCWI+
Weqse/Gq+weFeKRCioX4RMpf5K4zoj5SM56OYTXqK694zhJ7lDrOpdpG6A==
-----END PUBLIC KEY-----

Registering publc key with server...done

Signing sensor data:
[GatewayApp]: Creating enclave
[GatewayApp]: Querying enclave for buffer sizes

TrustedApp: Sizes for public key, sealed private key and signature calculated successfully.
[GatewayApp]: Allocating buffers
[GatewayApp]: Loading enclave state
[GatewayApp]: Loading input file
[GatewayApp]: Calling enclave to generate key material

TrustedApp: Received sensor data and the sealed private key.

TrustedApp: Unsealed the sealed private key, signed sensor data with this private key and then, sent the signature back.
[GatewayApp]: Saving enclave state
[GatewayApp]: Destroying enclave
[GatewayApp]: Deallocating buffers
Sensor data signed.
Transmitting signature to server...done
Verifying signature:
Verified OK
```

### Send the quote to Intel
Go into an ipython shell:

```shell
ipython
```

Copy the quote from the output, and assign it to a variable:

```python
quote = {
    "isvEnclaveQuote":"AgAAAFsLAAALAAoAAAAAAFOrdeScwC/lZP1RWReIG+iRaFn0HiQK7vu+7g8BckAuCRH//wECAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAKijCU12IXxd0KESasFCs23TT4hRSpm/jfyOqFLx+mI4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABnBOOv77LJPGq5rW5P2XqTpdBWpBwqmccBzKH18B98SwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0gQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC0gEAU6MLnODQoKJlw5fZz7sUJYj5Z6qx78ar7B4V4pEKKhfhEyl/krjOiPlIzno5hNeorr3jOEnuUOs6l2kboqAIAAHmlFCVS6cp4FM7WhB3jpxWVDukXLMRgBvaHshb1qfuRqR6twO+shb5XQkLd/bNftWeTtZC+IVyUWjqSFJhuMyt8lXiNureQxoTxHvTa2//lL0tMKGjgZBt01ucRhIeyIb9LnAvgLw7EXuRmit4RjRKfVpSgMjnYtu1ZDsO+qoSCGlfY2WDy4oHCBQvz/ErTGA4cX20luT3G+4V9rvbUFL1XcdrRzEIBeOYv1o3w3ZhmhLNrqBxlB8JJrndMTvRb+idI5CYK7AGGIMvO6XPzgzDKvm2T+4hpqwQrUoQQilvcIkAJ7els/y53psv/m/T6R07ygBGkSF0kHFgnP1o7gs510cI7E7s714smfwnf7+fQMmDIIqBuOUCcAwmVMTbkpYETLGZwfMaaCI2tvWgBAADt2TDVlkTLaf/Hi5xnk8NaA/PcdbEVNf1LGnuorB4qY5dvM83rF6ABEV7N6uF5pH73b/oZwY+F4AxJW1cb8zjSrGJVb+LlO2zOrtDs0mb1RfckXChrGEgZtj0Tx584YSDRhPuQp2mvQjQyVYrOGCfzhyIDyiuqbhbvjPXWVVVKIjBWh+QZxZ3b/YJBPm38/XQfWV/JotJUMB6rUUzGSZi91a/Eb/7hrNjRyKXAYboog4IHrKJWgLRwPSdNcjZAeZAjZKJK5OCEk25341G6FoG34H9k6LeXidTBk/VRXrzlBbbbBbLg8mMqGDLv0WVXZnaYgDf/Jidu8vp08vknfi28PtxcIWmqwXOazO00yHU7OvUfjynnOxh0t+REa2YYxdehPAfO0nsgVmUruuj3s2vwtbgiQ6il03O/Sw4CabOya3C8Evce6tTHoPBtYGVs24Tgn5mXM+NSRs+ad+eDKsSqHymzd/sVrYaJlmL87zlcvtC8y33FVEIJ"
}
```

To send the quote over to Intel, you need your API primary subscription key,
which you should have set as an environment variable before starting the
container. (See the prerequisite section if needed.)

```python
import os

headers = {
    'Content-Type': 'application/json',
    'Ocp-Apim-Subscription-Key': os.environ["IAS_PRIMARY_KEY"],
}
```

send the quote for verification:

```python
import requests

url = 'https://api.trustedservices.intel.com/sgx/dev/attestation/v4/report'

res = requests.post(url, json=quote, headers=headers)
```

If everything went well the `res.status_code` should be 200, or
`res.ok` `True`. You can look at `res.reason` for more information if you
got an error.

```python
In [6]: res.json()
Out[6]: 
{'id': '241352371682676293259277452268094264738',
 'timestamp': '2021-05-20T04:51:10.638041',
 'version': 4,
 'advisoryURL': 'https://security-center.intel.com',
 'advisoryIDs': ['INTEL-SA-00161',
  'INTEL-SA-00381',
  'INTEL-SA-00389',
  'INTEL-SA-00320',
  'INTEL-SA-00329',
  'INTEL-SA-00220',
  'INTEL-SA-00270',
  'INTEL-SA-00293'],
 'isvEnclaveQuoteStatus': 'GROUP_OUT_OF_DATE',
 'platformInfoBlob': '150200650400090000111102040101070000000000000000000B00000B000000020000000000000B5B6DB2D012D7BBA9067D6818A3CCBDEDC2EA2250EF57A18F3F85B03FAA9A09E606FE0414651A88C4F5335A733BC0C521083D62358CD310BD088C9C62A07B29E9F5',
 'isvEnclaveQuoteBody': 'AgAAAFsLAAALAAoAAAAAAFOrdeScwC/lZP1RWReIG+iRaFn0HiQK7vu+7g8BckAuCRH//wECAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAKijCU12IXxd0KESasFCs23TT4hRSpm/jfyOqFLx+mI4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABnBOOv77LJPGq5rW5P2XqTpdBWpBwqmccBzKH18B98SwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0gQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC0gEAU6MLnODQoKJlw5fZz7sUJYj5Z6qx78ar7B4V4pEKKhfhEyl/krjOiPlIzno5hNeorr3jOEnuUOs6l2kbo'}
```

With the above output, it's possible to check the MRENCLAVE, etc, and to
extract the public key out of the report data.

**NOTE:** The `res.headers` are important to check signature and certificates
to make sure the report is authentic, meaning that it was signed by Intel's
key.


### Extract the Public Key
From the json of the response, we get the quote body, encoded in base 64.

```python
quote_body = res.json()['isvEnclaveQuoteBody']
```

In order to extract the report data out of the quote, it's necessary to be
aware of the structure of a quote (`sgx_quote_t`) and of a report
(`sgx_report_body_t`).

```C
typedef struct _quote_t
{
    uint16_t            version;        /* 0   */
    uint16_t            sign_type;      /* 2   */
    sgx_epid_group_id_t epid_group_id;  /* 4   */
    sgx_isv_svn_t       qe_svn;         /* 8   */
    sgx_isv_svn_t       pce_svn;        /* 10  */
    uint32_t            xeid;           /* 12  */
    sgx_basename_t      basename;       /* 16  */
    sgx_report_body_t   report_body;    /* 48  */
    uint32_t            signature_len;  /* 432 */
    uint8_t             signature[];    /* 436 */
} sgx_quote_t;
```

The repport data is at the end of the `report_body`, at offset 320:

```C
typedef struct _report_body_t
{
    sgx_cpu_svn_t           cpu_svn;        /* (  0) Security Version of the CPU */
    sgx_misc_select_t       misc_select;    /* ( 16) Which fields defined in SSA.MISC */
    uint8_t                 reserved1[SGX_REPORT_BODY_RESERVED1_BYTES];  /* ( 20) */
    sgx_isvext_prod_id_t    isv_ext_prod_id;/* ( 32) ISV assigned Extended Product ID */
    sgx_attributes_t        attributes;     /* ( 48) Any special Capabilities the Enclave possess */
    sgx_measurement_t       mr_enclave;     /* ( 64) The value of the enclave's ENCLAVE measurement */
    uint8_t                 reserved2[SGX_REPORT_BODY_RESERVED2_BYTES];  /* ( 96) */
    sgx_measurement_t       mr_signer;      /* (128) The value of the enclave's SIGNER measurement */
    uint8_t                 reserved3[SGX_REPORT_BODY_RESERVED3_BYTES];  /* (160) */
    sgx_config_id_t         config_id;      /* (192) CONFIGID */
    sgx_prod_id_t           isv_prod_id;    /* (256) Product ID of the Enclave */
    sgx_isv_svn_t           isv_svn;        /* (258) Security Version of the Enclave */
    sgx_config_svn_t        config_svn;     /* (260) CONFIGSVN */
    uint8_t                 reserved4[SGX_REPORT_BODY_RESERVED4_BYTES];  /* (262) */
    sgx_isvfamily_id_t      isv_family_id;  /* (304) ISV assigned Family ID */
    sgx_report_data_t       report_data;    /* (320) Data provided by the user */
} sgx_report_body_t;
```

With the above information, we can decode the base 64 encoded quote, and
access the report data in it.

```python
import base64

report_data = base64.b64decode(quote_body)[368:432]
```

The original demo wrote the public key in PEM format under the file
`demo_sgx/secp256r1.pem`. The public key we have in the report data should
match the one in the `.pem` file. We'll use Python's `cryptography` library to
verify this.

With Python's `cryptography` library, the public point can be used to
instantiate a public key object, `EllipticCurvePublicKey`, from which it's
possible to obtain other formats such as PEM and DER.

It's important to note that Python's cryptography library expects the point to
be encoded as per Section 2.3.3 in https://www.secg.org/sec1-v2.pdf. The
report data contains both x and y coordinates, in uncompressed form, and
without the octet prefix `04`. It's therefore necessary to add the octet
prefix to the report data.

```python
from cryptography.hazmat.primitives.asymmetric import ec

point = b"\x04" + report_data
pubkey = ec.EllipticCurvePublicKey.from_encoded_point(curve=ec.SECP256R1(), data=point)
```

Check that it matches the PEM data file:

```python
from cryptography.hazmat.primitives import serialization

pem_from_report_data = pubkey.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

with open('demo_sgx/secp256r1.pem') as f:
    pem_file_data = f.read()

pem_from_report_data == pem_file_data.encode()
# True
```



---

# Original Documentation
This is the original documentation as it can still be found under the download branch,
or from the download on the code sample website at https://software.intel.com/content/www/us/en/develop/articles/code-sample-gateway-key-provisioning-and-secure-signing-using-intel-software-guard.html.

## Prerequisites
### 1) Install the SGX software stack
Make sure you've installed the SGX software stack (driver, PSW and SDK)
and tested the installation by running sample apps.

Following command will check whether the SGX driver was loaded:

```shell
$ sudo lsmod | grep isgx
```

The above command should display `isgx`.

Following command will check whether the AESM background service
is loaded and running:

```shell
$ sudo service aemsd status
```

If it's not running, please run it with:

```shell
$ sudo service aesmd start
```

or

```shell
$ sudo service aemsd restart
```

NOTE: If AESM service fails to run even after the above, then it means the
SGX driver was not loaded. Please re-check whether SGX driver was loaded.

### 2) Source environment for using SGX tools

```shell
$ source <path of sgxsdk installation>/environment
```

For example, if you installed SGX SDK in your home directory, then the command would be:

```shell
$ source ~/sgxsdk/environment
```

### 3) Install OpenSSL
The sample uses OpenSSL libraries to encode the output files. Install `libssl-dev`:

```shell
$ sudo apt install libssl-dev
```

### 4) Compile the demo

If you have hardware support for Intel(R) SGX:

```shell
make
```

If you would rather use the simulator:

```shell
make SGX_MODE=sim
```

### 5) Run it in simulation mode
Run the pure-software simulation of the sample (after making it executable):

```shell
$ chmod +x run_demo_*.sh
$ ./run_demo_openssl.sh
```

### 6) Run it with an SGX Enclave
Run the same flow, using an SGX enclave:

```shell
./run_demo_sgx.sh
```

# Gateway Key Provisioning and Secure Signing using Intel® Software Guard Extensions

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

## Using Docker
If you wish to run in hardware mode then you stil need SGX enabled ...

TODO: give pointers to check if SGX is enabled.

To generate a quote to send to Intel, the hardware mode is also needed.

### Prerequisites
* You need [docker](https://docs.docker.com/engine/install/) and
  [docker-compose](https://docs.docker.com/compose/install/).

* The docker-based development environment assumes it is running on an SGX-enabled
  processor. If you are not sure whether your computer supports SGX, and/or how to
  enable it, see https://github.com/ayeks/SGX-hardware#test-sgx.

* Obtain an **Unlinkable** subscription key for the
  [Intel SGX Attestation Service Utilizing Enhanced Privacy ID (EPID)](https://api.portal.trustedservices.intel.com/).

Set the `SGX_SPID` environment variable:

```shell
export SGX_SPID=<your-SPID>
```

To interact with IAS, set your primary key:

```shell
export IAS_PRIMARY_KEY=<your-ias-primary-key>
```

start a container:

```shell
docker-compose run --rm sgxiot bash
```

run the demo:

```shell
./run_demo_sgx.sh
```

```console
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

len_bn_x: 32
len_bn_y: 32
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

go into an ipython shell:

```shell
ipython
```

Copy the quote from the output, and assign it to a variable:

```python
quote = {
    "isvEnclaveQuote":"AgAAAFsLAAALAAoAAAAAAFOrdeScwC/lZP1RWReIG+iRaFn0HiQK7vu+7g8BckAuCRH//wECAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAKijCU12IXxd0KESasFCs23TT4hRSpm/jfyOqFLx+mI4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABnBOOv77LJPGq5rW5P2XqTpdBWpBwqmccBzKH18B98SwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0gQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC0gEAU6MLnODQoKJlw5fZz7sUJYj5Z6qx78ar7B4V4pEKKhfhEyl/krjOiPlIzno5hNeorr3jOEnuUOs6l2kboqAIAAHmlFCVS6cp4FM7WhB3jpxWVDukXLMRgBvaHshb1qfuRqR6twO+shb5XQkLd/bNftWeTtZC+IVyUWjqSFJhuMyt8lXiNureQxoTxHvTa2//lL0tMKGjgZBt01ucRhIeyIb9LnAvgLw7EXuRmit4RjRKfVpSgMjnYtu1ZDsO+qoSCGlfY2WDy4oHCBQvz/ErTGA4cX20luT3G+4V9rvbUFL1XcdrRzEIBeOYv1o3w3ZhmhLNrqBxlB8JJrndMTvRb+idI5CYK7AGGIMvO6XPzgzDKvm2T+4hpqwQrUoQQilvcIkAJ7els/y53psv/m/T6R07ygBGkSF0kHFgnP1o7gs510cI7E7s714smfwnf7+fQMmDIIqBuOUCcAwmVMTbkpYETLGZwfMaaCI2tvWgBAADt2TDVlkTLaf/Hi5xnk8NaA/PcdbEVNf1LGnuorB4qY5dvM83rF6ABEV7N6uF5pH73b/oZwY+F4AxJW1cb8zjSrGJVb+LlO2zOrtDs0mb1RfckXChrGEgZtj0Tx584YSDRhPuQp2mvQjQyVYrOGCfzhyIDyiuqbhbvjPXWVVVKIjBWh+QZxZ3b/YJBPm38/XQfWV/JotJUMB6rUUzGSZi91a/Eb/7hrNjRyKXAYboog4IHrKJWgLRwPSdNcjZAeZAjZKJK5OCEk25341G6FoG34H9k6LeXidTBk/VRXrzlBbbbBbLg8mMqGDLv0WVXZnaYgDf/Jidu8vp08vknfi28PtxcIWmqwXOazO00yHU7OvUfjynnOxh0t+REa2YYxdehPAfO0nsgVmUruuj3s2vwtbgiQ6il03O/Sw4CabOya3C8Evce6tTHoPBtYGVs24Tgn5mXM+NSRs+ad+eDKsSqHymzd/sVrYaJlmL87zlcvtC8y33FVEIJ"
}
```

To send the quote over to Intel, you need your API primary subscription key:

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

If everything went well the `res.status_code` should be 200, or `res.ok` `True`.

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

With the above output, it's possible to check the MRENCLAVE, etc, and to extract the
public key out of the report data.

The res.headers are important to check signature and certificates to make sure the
report is authentic, meaning that it was signed by Intel's key.



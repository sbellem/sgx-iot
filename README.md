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

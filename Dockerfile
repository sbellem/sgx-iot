##############################################################################
#                                                                            #
#                            Demo base                                       #
#                                                                            #
##############################################################################
FROM ubuntu:20.04 AS demo-base

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED 1

# Python 3.9
RUN apt-get update && apt-get install -y \
                python3.9 \
                python3.9-dev \
                python3-pip \
                git \
                wget \
        && rm -rf /var/lib/apt/lists/*

# symlink python3.9 to python
RUN cd /usr/bin \
    && ln -s pydoc3.9 pydoc \
    && ln -s python3.9 python \
    && ln -s python3.9-config python-config

# pip
# taken from:
# https://github.com/docker-library/python/blob/4bff010c9735707699dd72524c7d1a827f6f5933/3.10-rc/buster/Dockerfile#L71-L95
ENV PYTHON_PIP_VERSION 21.0.1
ENV PYTHON_GET_PIP_URL https://github.com/pypa/get-pip/raw/29f37dbe6b3842ccd52d61816a3044173962ebeb/public/get-pip.py
ENV PYTHON_GET_PIP_SHA256 e03eb8a33d3b441ff484c56a436ff10680479d4bd14e59268e67977ed40904de

RUN set -ex; \
	\
    apt-get update; \
	wget -O get-pip.py "$PYTHON_GET_PIP_URL"; \
	echo "$PYTHON_GET_PIP_SHA256 *get-pip.py" | sha256sum --check --strict -; \
	\
	python get-pip.py \
		--disable-pip-version-check \
		--no-cache-dir \
		"pip==$PYTHON_PIP_VERSION" \
	; \
	pip --version; \
	\
	find /usr/local -depth \
		\( \
			\( -type d -a \( -name test -o -name tests -o -name idle_test \) \) \
			-o \
			\( -type f -a \( -name '*.pyc' -o -name '*.pyo' \) \) \
		\) -exec rm -rf '{}' +; \
	rm -f get-pip.py

# docker cli
RUN set -ex; \
    \
    apt-get update; \
    apt-get install -y \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg \
        lsb-release;
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
        gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

RUN echo \
    "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

RUN apt-get update && apt-get install -y docker-ce-cli

# SGX PSW
ENV INTEL_SGX_URL "https://download.01.org/intel-sgx"
RUN set -eux; \
    url="$INTEL_SGX_URL/sgx_repo/ubuntu"; \
    echo "deb [arch=amd64] $url focal main" \
                | tee /etc/apt/sources.list.d/intel-sgx.list; \
    wget -qO - "$url/intel-sgx-deb.key" | apt-key add -; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
                libsgx-headers \
                libsgx-ae-epid \
                libsgx-ae-le \
                libsgx-ae-pce \
                libsgx-enclave-common \
                libsgx-enclave-common-dev \
                libsgx-epid \
                libsgx-epid-dev \
                libsgx-uae-service \
                libsgx-urts; \
    rm -rf /var/lib/apt/lists/*;

# install nix
ARG UID=1000
ARG GID=1000

RUN apt-get update && apt-get install --yes git curl wget sudo xz-utils
RUN groupadd --gid $GID --non-unique photon \
    && useradd --create-home --uid $UID --gid $GID --non-unique --shell /bin/bash photon \
    && usermod --append --groups sudo photon \
    && echo "photon ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/photon \
    && mkdir -p /etc/nix \
    && echo 'sandbox = false' > /etc/nix/nix.conf

ENV USER photon
USER photon

WORKDIR /home/photon

#COPY --chown=photon:photon ./nix.conf /home/photon/.config/nix/nix.conf

RUN curl -L https://nixos.org/nix/install | sh

RUN . /home/photon/.nix-profile/etc/profile.d/nix.sh && \
  nix-channel --add https://nixos.org/channels/nixos-21.11 nixpkgs && \
  nix-channel --update

ENV NIX_PROFILES "/nix/var/nix/profiles/default /home/photon/.nix-profile"
ENV NIX_PATH /home/photon/.nix-defexpr/channels
ENV NIX_SSL_CERT_FILE /etc/ssl/certs/ca-certificates.crt
ENV PATH /home/photon/.nix-profile/bin:$PATH

RUN pip install --user cryptography ipython requests pyyaml ipdb blessings colorama
RUN set -ex; \
    \
    cd /tmp; \
    git clone --recurse-submodules https://github.com/sbellem/auditee.git; \
    pip install --user auditee/

ENV PATH="/home/photon/.local/bin:${PATH}"

##############################################################################
#                                                                            #
#                            Build enclave (trusted)                         #
#                                                                            #
##############################################################################
FROM  nixpkgs/nix AS build-enclave

WORKDIR /usr/src

COPY common /usr/src/common
COPY enclave /usr/src/enclave
COPY interface /usr/src/interface
COPY makefile /usr/src/makefile

COPY nix /usr/src/nix
COPY default.nix /usr/src/default.nix

RUN nix-build

##############################################################################
#                                                                            #
#                            Build app (untrusted)                           #
#                                                                            #
##############################################################################
FROM initc3/linux-sgx:2.14-ubuntu20.04 AS build-app

RUN apt-get update && apt-get install -y \
                autotools-dev \
                automake \
                xxd \
                iputils-ping \
                libssl-dev \
                vim \
                git \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/sgxiot

ENV SGX_SDK /opt/sgxsdk
ENV PATH $PATH:$SGX_SDK/bin:$SGX_SDK/bin/x64
ENV PKG_CONFIG_PATH $SGX_SDK/pkgconfig
ENV LD_LIBRARY_PATH $SGX_SDK/sdk_libs

COPY . .

ARG SGX_MODE=HW
ENV SGX_MODE $SGX_MODE

ARG SGX_DEBUG=1
ENV SGX_DEBUG $SGX_DEBUG

RUN make untrusted

##############################################################################
#                                                                            #
#                            Demo runtime                                    #
#                                                                            #
##############################################################################
FROM demo-base

RUN mkdir /home/photon/sgxiot
WORKDIR /home/photon/sgxiot

COPY --chown=photon:photon common common
COPY --chown=photon:photon enclave enclave
COPY --chown=photon:photon interface interface
COPY --chown=photon:photon nix nix
COPY --chown=photon:photon .auditee.yml \
                           default.nix \
                           makefile \
                           nix.Dockerfile \
                           run_demo_sgxra.sh \
                           Sensor_Data \
                           verify.py \
                           ./

COPY --from=build-enclave --chown=photon:photon /usr/src/result/bin/enclave.signed.so enclave/enclave.signed.so
COPY --from=build-app --chown=photon:photon /usr/src/sgxiot/app app
COPY --from=initc3/linux-sgx:2.14-ubuntu20.04 --chown=photon:photon /opt/sgxsdk /opt/sgxsdk

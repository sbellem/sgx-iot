FROM initc3/nix-sgx-sdk@sha256:509e4c8e5ab7aeea4d78d2f61df45caa388279036a0c8e984630321d783ea2d3 AS build-enclave

WORKDIR /usr/src

COPY common /usr/src/common
COPY enclave /usr/src/enclave
COPY interface /usr/src/interface
COPY makefile /usr/src/makefile

COPY nix /usr/src/nix
COPY enclave.nix /usr/src/enclave.nix

RUN nix-build enclave.nix


FROM initc3/linux-sgx:2.13-ubuntu20.04

RUN apt-get update && apt-get install -y \
                autotools-dev \
                automake \
                xxd \
                iputils-ping \
                libssl-dev \
                python3.9 \
                python3.9-dev \
                python3-pip \
                vim \
                git \
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

RUN pip install cryptography ipython requests pyyaml ipdb
RUN set -ex; \
    \
    cd /tmp; \
    git clone --recurse-submodules https://github.com/sbellem/auditee.git; \
    pip install auditee/

WORKDIR /usr/src/sgxiot

ENV SGX_SDK /opt/sgxsdk
ENV PATH $PATH:$SGX_SDK/bin:$SGX_SDK/bin/x64
ENV PKG_CONFIG_PATH $SGX_SDK/pkgconfig
ENV LD_LIBRARY_PATH $SGX_SDK/sdk_libs

COPY . .

COPY --from=build-enclave /usr/src/result/bin/enclave.signed.so enclave/enclave.signed.so

ARG SGX_MODE=HW
ENV SGX_MODE $SGX_MODE

ARG SGX_DEBUG=1
ENV SGX_DEBUG $SGX_DEBUG

RUN make just-app

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

# docker buildx
#RUN set -ex; \
#    \
#    apt-get update && apt-get install -y curl; \
#    mkdir -p ~/.docker/cli-plugins; \
#    cd ~/.docker/cli-plugins; \
#    curl -L https://github.com/docker/buildx/releases/download/v0.5.1/buildx-v0.5.1.darwin-amd64 -o docker-buildx; \
#    chmod a+x ~/.docker/cli-plugins/docker-buildx;

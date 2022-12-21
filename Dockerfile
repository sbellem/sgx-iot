##############################################################################
#                                                                            #
#                            Demo base                                       #
#                                                                            #
##############################################################################
FROM initc3/linux-sgx:2.16-ubuntu20.04 AS demo-base

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED 1

RUN apt-get update && apt-get install -y \
                curl \ 
                git \
                python3.9 \
                python3.9-dev \
                python3-pip \
                python-is-python3 \
                sudo \
                xz-utils \
        && rm -rf /var/lib/apt/lists/*

# install nix
ARG UID=1000
ARG GID=1000

RUN groupadd --gid $GID --non-unique photon \
    && useradd --create-home --uid $UID --gid $GID --non-unique --shell /bin/bash photon \
    && usermod --append --groups sudo photon \
    && echo "photon ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/photon \
    && mkdir -p /etc/nix \
    && echo 'sandbox = false' > /etc/nix/nix.conf

ENV USER photon
USER photon

WORKDIR /home/photon

RUN curl -L https://nixos.org/nix/install | sh

RUN . /home/photon/.nix-profile/etc/profile.d/nix.sh && \
  nix-channel --add https://nixos.org/channels/nixos-22.11 nixpkgs && \
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
FROM initc3/linux-sgx:2.16-ubuntu20.04 AS build-app

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

COPY --from=build-enclave --chown=photon:photon \
                /usr/src/result/bin/enclave.signed.so enclave/enclave.signed.so
COPY --from=build-app --chown=photon:photon /usr/src/sgxiot/app app

FROM  nixpkgs/nix AS build-stage

RUN set -ex \
        \
        && mkdir /etc/nix \
        && echo "sandbox = true" >> /etc/nix/nix.conf \
        && nix-channel --add https://nixos.org/channels/nixos-21.05 nixpkgs \
        && nix-channel --update

WORKDIR /usr/src
COPY common /usr/src/common
COPY enclave /usr/src/enclave
COPY interface /usr/src/interface
COPY nix /usr/src/nix
COPY default.nix /usr/src/default.nix
COPY makefile /usr/src/makefile

# cachix & sgxsdk from cache
RUN nix-env -iA cachix -f https://cachix.org/api/v1/install
RUN /nix/store/*cachix*/bin/cachix use initc3

RUN nix-build

FROM scratch AS export-stage
COPY --from=build-stage /usr/src/result/bin /

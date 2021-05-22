let
  sources = import ./nix/sources.nix;
  pkgs = import sources.nixpkgs { };
  sgxsdk = /nix/store/znr7dg5bkv2kspcmqrak59hb88hcqv4k-sgxsdk;
in
pkgs.stdenv.mkDerivation {
  inherit sgxsdk;
  name = "sgx-iot";
  # FIXME not sure why but the build is non-deterministic if using src = ./.;
  # Possibly some untracked file(s) causing the problem ...?
  src = ./.;
  # NOTE The commit (rev) cannot include this file, and therefore will at the very
  # best one commit behind the commit including this file.
  #src = pkgs.fetchFromGitHub {
  #  owner = "sbellem";
  #  repo = "sgx-iot";
  #  rev = "d357650fad44c646e30b9049cbc1d4ddbbf47313";
  #  # Command to get the sha256 hash (note the --fetch-submodules arg):
  #  # nix run -f '<nixpkgs>' nix-prefetch-github -c nix-prefetch-github --rev d357650fad44c646e30b9049cbc1d4ddbbf47313 sbellem sgx-iot
  #  sha256 = "1mpvr6g1dly2bkph57lwk2kn36yddfp614pq2l6w9ap94dp0siiw";
  #};
  preConfigure = ''
    export SGX_SDK=$sgxsdk/sgxsdk
    export PATH=$PATH:$SGX_SDK/bin:$SGX_SDK/bin/x64
    export PKG_CONFIG_PATH=$SGX_SDK/pkgconfig
    export LD_LIBRARY_PATH=$SGX_SDK/sdk_libs
    export SGX_MODE=HW
    export SGX_DEBUG=1
    '';
  #configureFlags = ["--with-sgxsdk=$SGX_SDK"];
  buildInputs = with pkgs; [
    sgxsdk
    unixtools.xxd
    bashInteractive
    autoconf
    automake
    libtool
    file
    openssl
    which
  ];
  buildFlags = ["enclave.signed.so"];
  installPhase = ''
    runHook preInstall

    mkdir -p $out/bin
    cp enclave/enclave.unsigned.so $out/bin/
    cp enclave/enclave.signed.so $out/bin/

    runHook postInstall
  '';
  #postInstall = ''
  #  $sgxsdk/sgxsdk/bin/x64/sgx_sign dump -cssfile enclave_sigstruct_raw -dumpfile /dev/null -enclave $out/bin/Enclave.signed.so
  #  cp enclave_sigstruct_raw $out/bin/
  #  '';
  dontFixup = true;
}

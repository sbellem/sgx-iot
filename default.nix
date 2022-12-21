let
  sources = import ./nix/sources.nix;
  pkgs = import sources.nixpkgs { };
in
pkgs.stdenv.mkDerivation {
  name = "sgx-iot";
  # FIXME not sure why but the build is non-deterministic if using src = ./.;
  # Possibly some untracked file(s) causing the problem ...?
  #src = ./.;
  # NOTE The commit (rev) cannot include this file, and therefore will, at the very
  # best, be one commit behind the commit including this file.
  src = pkgs.fetchFromGitHub {
    owner = "sbellem";
    repo = "sgx-iot";
    rev = "5e68ce4442b68870a51fb5d435259ea6d6a29d1c";
    #sha256 = pkgs.lib.fakesha256; # ( to get the hash )
    sha256 = "sha256-fskdLUeM3lYoQnqrs4yfewKhMIVrbN33mfiyEpKwFoU=";
  };
  preConfigure = ''
    export SGX_SDK=${pkgs.sgx-sdk}/sgxsdk
    export PATH=$PATH:$SGX_SDK/bin:$SGX_SDK/bin/x64
    export PKG_CONFIG_PATH=$SGX_SDK/pkgconfig
    export LD_LIBRARY_PATH=$SGX_SDK/sdk_libs
    export SGX_MODE=HW
    export SGX_DEBUG=1
    '';
  #configureFlags = ["--with-sgxsdk=$SGX_SDK"];
  buildInputs = with pkgs; [
    sgx-sdk
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

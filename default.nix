let
  sources = import ./nix/sources.nix;
  pkgs = import sources.nixpkgs { };
  sgx = import sources.sgxarcz { };
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
    rev = "78ff964ec2aed99162b172df4df2a794362312dd";
    # Command to get the sha256 hash (note the --fetch-submodules arg):
    # nix run -f '<nixpkgs>' nix-prefetch-github -c nix-prefetch-github --rev 78ff964ec2aed99162b172df4df2a794362312dd sbellem sgx-iot
    sha256 = "06v3x6w62hv1v9b2ygm4p71nayj40h0lvc4xi561p6iw21az423z";
  };
  preConfigure = ''
    export SGX_SDK=${sgx.sgx-sdk}/sgxsdk
    export PATH=$PATH:$SGX_SDK/bin:$SGX_SDK/bin/x64
    export PKG_CONFIG_PATH=$SGX_SDK/pkgconfig
    export LD_LIBRARY_PATH=$SGX_SDK/sdk_libs
    export SGX_MODE=HW
    export SGX_DEBUG=1
    '';
  #configureFlags = ["--with-sgxsdk=$SGX_SDK"];
  buildInputs = with pkgs; [
    sgx.sgx-sdk
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

{
  description = "virtual environments";

  inputs.devshell.url = "github:numtide/devshell";
  inputs.flake-utils.url = "github:numtide/flake-utils";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/master";

  outputs = { self, flake-utils, devshell, nixpkgs }:

    flake-utils.lib.eachDefaultSystem (system: {
      devShells.default =
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ devshell.overlays.default ];
          };
        in
          pkgs.mkShell {
            NIX_CFLAGS_COMPILE = pkgs.lib.optionals pkgs.stdenv.isDarwin [
              "-I${pkgs.lib.getDev pkgs.libcxx}/include/c++/v1"
            ];
            buildInputs = [
              pkgs.python310
              pkgs.poetry
              pkgs.rocksdb
              pkgs.snappy
              pkgs.openssl
              pkgs.readline
              pkgs.zlib
              pkgs.xz
              pkgs.bzip2
              pkgs.lz4
              pkgs.cmake
            ];

            shellHook = ''
              export CFLAGS="-I${pkgs.rocksdb}/include"
              export LDFLAGS="-L${pkgs.rocksdb}/lib"
              poetry env use python3.10
            '';
          };
    });
}

{
  description = "Hathor Network full-node";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/master";
    flake-utils.url = "github:numtide/flake-utils";
    devshell.url = "github:numtide/devshell";
    poetry2nix = {
      url = "github:nix-community/poetry2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, flake-utils, devshell, nixpkgs, poetry2nix }:
    let
      # The HM module is system-independent
      hmOutput = {
        homeManagerModules.default = import ./nix/hm-module.nix;
      };

      # Per-system outputs (packages + devShells)
      perSystemOutput = flake-utils.lib.eachDefaultSystem (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [
              devshell.overlays.default
              poetry2nix.overlays.default
            ];
          };
        in
        {
          packages = {
            hathor-core = pkgs.callPackage ./nix/package.nix { };
            default = self.packages.${system}.hathor-core;
          };

          devShells.default = pkgs.mkShell {
            buildInputs = [
              pkgs.python312
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
              poetry env use python3.12
            '';
          };
        });

    in
    hmOutput // perSystemOutput;
}

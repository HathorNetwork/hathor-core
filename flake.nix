{
  description = "virtual environments";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    devshell.url = "github:numtide/devshell";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, flake-utils, devshell, nixpkgs, ... }:
    let
      overlays.default = final: prev: {
        nodejs = final.nodejs_24;
        nodePackages = prev.nodePackages;
      };
    in
    flake-utils.lib.eachDefaultSystem (system: {
      devShell =
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [
              devshell.overlays.default
              overlays.default
            ];
            # Always allow unfree here
            config = {
              allowUnfree = true;
            };
          };
        in
        pkgs.devshell.mkShell {
          packages = with pkgs; [
            nixpkgs-fmt
            nodejs_24
            yarn-berry
            claude-code
            python312
            poetry
            rocksdb
            snappy
            openssl
            readline
            zlib
            xz
            bzip2
            lz4
            cmake
          ];

          devshell.startup.shell-hook.text = ''
            export CFLAGS="-I${pkgs.rocksdb}/include"
            export LDFLAGS="-L${pkgs.rocksdb}/lib"
            poetry env use python3.12
          '';
        };
    });
}

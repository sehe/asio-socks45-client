{
  description = "A basic flake with a shell";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.05";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = {
    nixpkgs,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      devShells.default = pkgs.stdenvNoCC.mkDerivation {
        name = "asio-socks-dev";

        nativeBuildInputs = with pkgs; [
          boost170
          ccache
          cmake
          gdb
          gcc13
          kcachegrind
          libbacktrace
          massif-visualizer
          openssl.dev
          pkg-config
          valgrind
        ];

        env = {
          ASAN_OPTIONS = "color=always";
        };
      };
    });
}

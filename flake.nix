# This is an example flake.nix for a Switch project based on devkitA64.
# It will work on any devkitPro example with a Makefile out of the box.
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
  };

  outputs = {
    nixpkgs,
    flake-utils,
    rust-overlay,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      overlays = [(import rust-overlay)];
      pkgs = import nixpkgs {
        inherit system overlays;
      };
      rustToolchain = pkgs.rust-bin.stable.latest;
      buildInputs = with pkgs; [
        rustToolchain.default
        cargo-limit
      ];
    in {
      devShells.default = pkgs.mkShell {
        name = "async-debugger-dev";
        inherit buildInputs;

        # Each package provides a shell hook that sets all necessary
        # environmental variables. This part is necessary, otherwise your build
        # system won't know where to find devkitPro. By setting these
        # variables we allow devkitPro's example Makefiles to work out of the box.
      };
    });
}

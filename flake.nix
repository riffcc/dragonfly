{
  description = "Dragonfly development flake";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url  = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
          targets = [ "x86_64-unknown-linux-musl" ];
        };
      in
      with pkgs;
      {
        devShells.default = mkShell {
          SQLITE3_STATIC = "1";
          LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
          buildInputs = [
            rustToolchain
            openssl
            pkg-config
            pkgsStatic.stdenv.cc
            pkgsStatic.openssl
            pkgsStatic.sqlite
            pkgsStatic.aws-lc
            pkgsStatic.libssh2
            pkgsStatic.zlib
            nodejs
            cargo-make
          ];
          
          # For target compilation
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${pkgs.pkgsStatic.stdenv.cc}/bin/musl-gcc";
          
          # Force host builds to use gcc instead of lld
          RUSTFLAGS = "-C linker=gcc";
          # OpenSSL configuration for musl
          OPENSSL_STATIC = "true";
          OPENSSL_DIR = "${pkgs.pkgsStatic.openssl.dev}";
          OPENSSL_LIB_DIR = "${pkgs.pkgsStatic.openssl.out}/lib";
          OPENSSL_INCLUDE_DIR = "${pkgs.pkgsStatic.openssl.dev}/include";
          
          # pkg-config for cross-compilation
          PKG_CONFIG_ALLOW_CROSS = "1";
          PKG_CONFIG_ALL_STATIC = "1";
          
          shellHook = ''
            echo "Setting up Node.js environment..."
            export PATH="${pkgs.nodejs}/bin:$PATH"

            # Only install Tailwind if node_modules doesn't exist
            if [ ! -d "node_modules" ]; then
              echo "Installing Tailwind CSS..."
              npm install -D tailwindcss postcss autoprefixer
              npx tailwindcss init
            fi
            echo "Rust musl target added"
            echo "Target linker: $CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER"
          '';
        };
      }
    );
}

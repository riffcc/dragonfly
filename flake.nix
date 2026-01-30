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
      in
      with pkgs;
      {
        devShells.default = mkShell {
          buildInputs = [
            rust-bin.stable.latest.default
            openssl
            pkg-config
            sccache
            nodejs
          ];

          RUSTC_WRAPPER = "${pkgs.sccache}/bin/sccache";
          shellHook = ''
            echo "Setting up Node.js environment..."
            export PATH="${pkgs.nodejs}/bin:$PATH"

            # Only install Tailwind if node_modules doesn't exist
            if [ ! -d "node_modules" ]; then
              echo "Installing Tailwind CSS..."
              npm install -D tailwindcss postcss autoprefixer
              npx tailwindcss init
            fi
            echo "in rust dev shell"
          '';
        };
      }
    );
}


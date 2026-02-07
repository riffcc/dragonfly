### Nix development and build environment (WIP)
 
use nix package manager and `cargo-make` to develop and build with distribution in mind.

```
sudo apt install nix
nix develop
# build distribution binaries
cargo make build-dist
# build everyithing, + distribution binaries
cargo make build-all [--release]
# run cargo check on the distribution build
cargo make check-dist
```

> See `Makefile.toml` for `cargo make` commands

using `nix develop` should JustWork^tm for setting up an ephemeral development and build environment, this includes:

- rust, and assosciated tooling such as rustup, toolchains, etc.
- installation of system libraries such as muslibc
- installation of static package libraries such as openssl
- setting of environment variables to use said tools

This process is defined in `flake.nix`. The changes made for this set-up only persist in the shell where `nix develop` was executed

To automate the entry/exit of the dev environment:

- install `direnv`
- `echo "use flake" > .envrc` (in the root of the dir-tree)
- `direnv allow`

> The plan is to field-test this approach, and if received well, extend it to more aspects, such as testing, CI/CD, distribution, tooling setup, etc.

# 🐉 Dragonfly

NOTE: Dragonfly is still in development and not ready for production use.

This README reflects the goals of the project for an initial release, ***and is not yet reality***.

> 🧠 The **Bare Metal Infrastructure Management System** that makes metal effortless —
> built in Rust, styled in Tailwind, designed for efficiency and reliability.

Dragonfly is a **fast**, **flexible**, and ***satisfying*** platform
for managing and deploying bare-metal infrastructure at any scale.

Whether you’ve got 5 test VMs or 5,000 enterprise grade machines in a datacenter...

Dragonfly will help.

![Dragonfly UI](media/screenshots/light-mode-machinelist.png)

---

## What does it do?
Dragonfly is a virtual and bare-metal provisioning and orchestration system.
It answers the question:

> “I just racked a machine—what happens next?”

When a machine boots via PXE, it loads a minimal Alpine-based agent that registers itself with the Dragonfly server.
From there, Dragonfly can:

* Grab details about the machine

* Automatically or manually assign an operating system and optional role

* Install the operating system

Dragonfly turns unconfigured hardware into usable infrastructure —
automatically, securely, and *quickly*.

## ✨ Features
The main highlights:
- 🌍 Web interface for managing, deploying
  and monitoring your machines and infrastructure.
- 📡 Automatic machine registration via PXE + Dragonfly Agent
- 🔄 Automated OS installation with support for ISOs, PXE, and chainloading.
- 🧚 Powered by Tinkerbell under the hood
  for wide compatibility and support for just about any hardware.
- 🏎️ Deployment as fast as four minutes.
- 🛰️ (WIP) Distributed storage and IPFS deployment
  for integrated data management.

More features:
- 🌍 (WIP) Uses DNS to find machine hostnames automatically
- 🔒 (WIP) Login system with admin/user roles and permissions
- 🔧 (WIP) Reimage any machine in two clicks
- 🧸 (WIP) **Safety Mode (Molly Guard)** — avoid accidentally nuking a machine
- 🚀 (WIP) Built-in IPMI/BMC/Redfish power control
  and SSH control support for flexible node power operations.
- 🧠 (WIP) Effortless grouping and tagging for your machines,
  and emoji/font-awesome icon support for easy visual identification.
- 💈 (WIP) Real-time deployment tracking with progress bars and status indicators.
- 🖼️ (WIP) Ready for Retina, ultrawide and kiosk displays
- 🏷️ (WIP) "Just Type" experience — with bulk editing, drag-fill, and autocomplete  
- 🎨 (WIP) Tailwind-powered theming — pick your aesthetic or import your own.
- 🩻 (WIP) Introspection - view details of your machines,
  including hardware, OS, and network configuration.
- 🔍 (WIP) Search - find any machine by name, tag, or ID.
- 📊 (WIP) Granular reporting and monitoring of your machines.
- 📦 (WIP) Built in image management for OS and drivers.
- 🎮 (WIP) Gamepad and touchscreeen support for easy navigation of the UI.

## 🛣️ Roadmap

See [ROADMAP.md](ROADMAP.md) for upcoming features and planned work.

## 🚀 Installation

Dragonfly provides an automated installer that sets up the complete stack:

```bash
# Build the project
cargo build --release

# Run the installer (automatically installs k3s, Helm, Dragonfly, and Tinkerbell)
./target/release/dragonfly install
```

The installer will:
1. Detect your network configuration and bootstrap IP
2. Install k3s (lightweight Kubernetes)
3. Install Helm (Kubernetes package manager)
4. Deploy Dragonfly to Kubernetes
5. Deploy Tinkerbell in the background

Once installation completes, you'll see:
```
🚀 Ready at http://<your-ip>:3000
```

### Remote Management

Dragonfly can manage remote Kubernetes clusters via KUBECONFIG:

```bash
# Point to a remote cluster with Tinkerbell already deployed
export KUBECONFIG=/path/to/kubeconfig
./target/release/dragonfly server
```

This enables:
- Managing bare metal from your laptop
- One Dragonfly instance controlling multiple clusters
- Geographic distribution of management interfaces

See [ARCHITECTURE.md](ARCHITECTURE.md) for more details on deployment patterns.

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

### Development Mode

For local development without installation:

```bash
# Run in demo mode (no hardware touched)
cargo run -- server
```

Access the web interface at [http://localhost:3000](http://localhost:3000).

## 🗄️ Database Integration

Dragonfly uses the SQLx crate for database integration.

## 📚 Credits

Dragonfly is inspired by and intended as a GUI for the Tinkerbell project. It would not be possible without their work, and we're grateful for their efforts.

We also thank other projects that Dragonfly builds on, such as:
* [MooseFS](https://moosefs.org/)
* [CubeFS](https://cubefs.io/)
* [Tinkerbell](https://tinkerbell.org/)
* [Alpine Linux](https://alpinelinux.org/)
* [k0s](https://k0s.sh/)
* [Proxmox](https://proxmox.com/)
* [OpenJBOD](https://github.com/OpenJBOD)

Thanks to [Taylor Vick](https://unsplash.com/photos/cable-network-M5tzZtFCOfs) for the login page background image ("racks.jpg")

Thanks to [DJARTMUSIC](https://pixabay.com/sound-effects/short-fire-whoosh-1-317280/) for the rocket ignition sound effect.

## 📝 License

Dragonfly is licensed under the AGPLv3 license.

See the [LICENSE](LICENSE) for more details.

# 🐉 Dragonfly

> metal, managed

Dragonfly is a **fast**, **flexible**, and ***satisfying*** platform
for managing and deploying bare-metal infrastructure at any scale.

Whether you’ve got 5 test VMs or 5,000 enterprise grade machines in a datacenter...

Dragonfly will help.

![Dragonfly UI](media/screenshots/machine-list-selected-4.png)

---

## What does it do?
Dragonfly is a virtual and bare-metal provisioning and orchestration system.
It answers the question:

> “I just racked a machine - what happens next?”

When a machine boots via PXE, it loads a minimal agent that registers itself with the Dragonfly server.

From there, Dragonfly can:

* Grab details about the machine
* Install an operating system
* Boot any ISO via the Dragonfly server
* Run memtest or drop to a root shell

Dragonfly turns unconfigured hardware into usable infrastructure —
automatically, securely, and *quickly*.

## Features
The main highlights:
- 🌍 Web interface for managing, deploying
  and monitoring your machines and infrastructure.
- 📡 Automatic machine registration via PXE + Spark (Dragonfly Agent)
- 🔄 Automated OS installation with support for ISOs, PXE, and chainloading.
- 🏎️ Deploy Linux in under 60 seconds.
- 🔧 Perform maintenance tasks such as memtest, rescue mode boot and remote reimaging.
More features:
- 🔒 Login system with admin/user roles and permissions
- 🔧 Reimage any machine in two clicks
- 🧠 Effortless grouping and tagging for your machines,
  and emoji/font-awesome icon support for easy visual identification.
- 💈 Real-time deployment tracking with progress bars and status indicators.
- 🏷️ "Just Type" experience — with bulk editing, drag-fill, and autocomplete.
- 🩻 Introspection - view details of your machines,
  including hardware, OS, and network configuration.
- 🔍 Search - find any machine by name, tag, or ID.

## 🛣️ Roadmap

See [ROADMAP.md](ROADMAP.md) for upcoming features and planned work.

## 🚀 Installation

See [dragonfly.computer](https://dragonfly.computer/docs/installation/) for installation instructions.

## 📚 Credits

Dragonfly is inspired by and intended as a GUI for the Tinkerbell project. It would not be possible without their work, and we're grateful for their efforts.

We also thank other projects that Dragonfly builds on, such as:
* [MooseFS](https://moosefs.org/)
* [Alpine Linux](https://alpinelinux.org/)
* [Proxmox](https://proxmox.com/)
* [OpenJBOD](https://github.com/OpenJBOD)

Thanks to [Taylor Vick](https://unsplash.com/photos/cable-network-M5tzZtFCOfs) for the login page background image ("racks.jpg")

## 📝 License

Dragonfly is licensed under the AGPLv3 license.

See the [LICENSE](LICENSE) for more details.

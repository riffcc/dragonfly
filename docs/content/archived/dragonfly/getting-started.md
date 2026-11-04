---
title: Getting Started
weight: 1
---

# Getting Started with Dragonfly

Dragonfly simplifies bare metal provisioning by automating the entire lifecycle from power-on to ready-to-use.

## Prerequisites

- A Linux machine to run Dragonfly (can be a VM, container, or bare metal)
- Network access to your target machines
- Target machines with PXE-capable network interfaces
- (Optional) IPMI/Redfish/BMC access for power control

## Installation

### Quick Install

```bash
# Download Dragonfly
curl -LO https://github.com/riffcc/dragonfly/releases/latest/download/dragonfly

# Make executable
chmod +x dragonfly

# Run the installer
./dragonfly install
```

The installer will:
1. Detect your network configuration
2. Configure DHCP (reservation or proxy mode)
3. Set up TFTP for PXE boot files
4. Initialize ReDB database
5. Start Dragonfly server

### What Gets Installed

| Component | Purpose |
|-----------|------------|
| **Dragonfly Server** | Web UI and orchestration |
| **DHCP Server** | PXE boot support (can run alongside existing DHCP) |
| **TFTP Server** | Serves iPXE boot files |
| **ReDB Database** | Embedded state storage |

No Kubernetes required for Simple or Flight mode.

## First Boot

After installation, open the web UI:

```
http://<your-ip>:3000
```

You'll see the welcome screen. Choose your deployment mode:

- **Simple** — Basic provisioning, single server
- **Flight** — Full datacenter management
- **Swarm** — Multi-region with Citadel

## Discovering Your First Machine

1. **Configure your machine to PXE boot** (usually in BIOS settings)
2. **Power on the machine**
3. **Watch Dragonfly discover it** — The machine will appear in the UI within seconds

The machine will boot into the **Mage agent**, which:
- Detects CPU, RAM, and disk information
- Reports hardware specs back to Dragonfly
- Receives a memorable name (like `CensusAbleQualityParent`)
- Awaits OS assignment

## Assigning an Operating System

1. Click on the discovered machine in the UI
2. Select an OS template (Debian, Ubuntu, etc.)
3. Optionally set hostname and SSH keys
4. Click **Install**

Dragonfly will:
1. Create a Workflow linking the machine to the template
2. Reboot the machine into imaging mode (via BMC or manual)
3. Execute native actions: partition, image2disk, writefile, kexec
4. Boot directly into the installed OS

Typical install time: **~4 minutes**.

## Demo Mode

Want to explore without touching real hardware?

```bash
./dragonfly server --demo
```

This runs Dragonfly with simulated machines, perfect for:
- Learning the UI
- Testing workflows
- Development and demos

## Operating Modes

Dragonfly supports three deployment modes:

| Mode | Use Case |
|------|----------|
| **Simple** | Single server, standalone ReDB, no external dependencies |
| **Flight** | Full automated provisioning with grouping, tagging, bulk ops |
| **Swarm** | Multi-region clusters with Citadel coordination |

## Storage Options

### Default: ReDB (Embedded)
```bash
# Data stored in:
/var/lib/dragonfly/dragonfly.redb
```

Zero dependencies. Just works.

### Optional: Kubernetes
```bash
# Enable Kubernetes backend
export DRAGONFLY_BACKEND=kubernetes
export KUBECONFIG=/path/to/kubeconfig
./dragonfly server
```

Data stored as CRDs in etcd. Enables multiple Dragonfly instances sharing state.

## Power Control

For full automation, configure BMC credentials per machine:

- **IPMI**: Traditional BMC protocol
- **Redfish**: Modern REST-based BMC
- **Wake-on-LAN**: Power-on only

With BMC configured, Dragonfly can:
- Reboot machines into PXE automatically
- Set boot device to network
- Power cycle on failure

## Next Steps

- [Understand the core concepts](concepts)
- [Learn about the architecture](architecture)
- [Configure Dragonfly for your environment](configuration)

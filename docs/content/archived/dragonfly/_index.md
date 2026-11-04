---
title: Dragonfly
cascade:
  type: docs
---

**Dragonfly** is a bare-metal infrastructure management system that turns unconfigured hardware into usable infrastructure — automatically, securely, and *quickly*.

When you rack a new machine, Dragonfly answers: "What happens next?"

## The Vision

```
Power on → Auto-discovered → OS assigned → Installed in 4 minutes → Ready
```

No manual intervention. No USB drives. No sitting at consoles typing IP addresses.

## Key Features

- **Automatic Discovery**: Machines PXE boot and register themselves via the Mage agent
- **Web UI**: Beautiful interface for managing your metal
- **Native Provisioning**: Rust-based actions, no Docker overhead
- **Fast Provisioning**: ~4 minute OS installations
- **Decoupled Architecture**: Run Dragonfly anywhere — your laptop, a VM, or in-cluster
- **Flexible Storage**: Embedded ReDB (default) or Kubernetes etcd
- **Multiple Power Control**: IPMI, Redfish, Wake-on-LAN
- **Proxmox Integration**: Manage VMs alongside bare metal

## How It Works

Dragonfly orchestrates the complete machine lifecycle:

1. **Discovery** — Machine PXE boots, Mage agent detects hardware and registers
2. **Assignment** — Operator chooses OS and role via web UI
3. **Provisioning** — Native actions execute: partition, image, configure, kexec
4. **Ready** — Machine boots into assigned OS, ready for use

## Architecture

Dragonfly follows a decoupled, stateless design:

- **ReDB or Kubernetes** stores all state (Hardware, Workflows, Templates)
- **Native Actions** handle OS installation (no Docker containers)
- **Dragonfly Server** provides the web UI and orchestration logic
- **Boot Services** (DHCP, TFTP, iPXE) handle PXE infrastructure

This means Dragonfly can run on your laptop managing a remote datacenter, or inside Kubernetes managing bare metal in the same rack.

## Deployment Modes

| Mode | Use Case |
|------|----------|
| **Simple** | Single server, standalone ReDB, no Kubernetes required |
| **Flight** | Full datacenter management, multi-machine orchestration |
| **Swarm** | Multi-region with Citadel coordination, shared etcd |

{{< cards >}}
  {{< card link="getting-started" title="Getting Started" icon="play" >}}
  {{< card link="concepts" title="Concepts" icon="book-open" >}}
  {{< card link="architecture" title="Architecture" icon="template" >}}
  {{< card link="configuration" title="Configuration" icon="adjustments" >}}
  {{< card link="https://github.com/riffcc/dragonfly" title="GitHub" icon="github" >}}
{{< /cards >}}

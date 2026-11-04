---
title: Architecture
weight: 3
---

# Architecture

Dragonfly is designed as a modular, decoupled system where each component has a focused responsibility.

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Operator's Browser                        │
│                     (Web UI @ :3000)                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   Dragonfly Server                          │
│   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│   │   API    │ │    UI    │ │   Auth   │ │Provisioner│      │
│   └──────────┘ └──────────┘ └──────────┘ └──────────┘      │
│   ┌──────────┐ ┌──────────┐ ┌──────────┐                   │
│   │  ReDB /  │ │  Proxmox │ │   BMC    │                   │
│   │   K8s    │ │  Client  │ │  Control │                   │
│   └──────────┘ └──────────┘ └──────────┘                   │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│   DHCP Server   │ │   TFTP Server   │ │  iPXE Scripts   │
│   (Reservation/ │ │   (Boot Files)  │ │  (Boot Fate)    │
│   Proxy Mode)   │ │                 │ │                 │
└─────────────────┘ └─────────────────┘ └─────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Bare Metal Machines                       │
│        ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐        │
│        │ Mage │ │ Mage │ │ Mage │ │ Mage │ │ Mage │        │
│        │Agent │ │Agent │ │Agent │ │Agent │ │Agent │        │
│        └──────┘ └──────┘ └──────┘ └──────┘ └──────┘        │
└─────────────────────────────────────────────────────────────┘
```

## Component Crates

Dragonfly is a Rust workspace with 11 focused crates:

### Foundation

| Crate | Purpose |
|-------|---------|
| **dragonfly-common** | Shared types: Machine, DiskInfo, BmcCredentials, RegisterRequest |
| **dragonfly-crd** | Kubernetes-compatible CRDs: Hardware, Template, Workflow (dragonfly.computer/v1) |

### Boot Infrastructure

| Crate | Purpose |
|-------|---------|
| **dragonfly-dhcp** | DHCP server with PXE support (reservation/proxy/autoproxy modes) |
| **dragonfly-tftp** | RFC 1350 TFTP server with extensions, serves iPXE binaries |
| **dragonfly-ipxe** | iPXE script generation based on machine state (server controls fate) |
| **dragonfly-metadata** | Cloud-init metadata service for instance configuration |

### Hardware Control

| Crate | Purpose |
|-------|---------|
| **dragonfly-bmc** | IPMI, Redfish, and Wake-on-LAN power control |

### Provisioning Execution

| Crate | Purpose |
|-------|---------|
| **dragonfly-actions** | Native Rust action engine (partition, image2disk, writefile, kexec) |
| **dragonfly-workflow** | Workflow orchestration with pluggable storage (ReDB, Memory, K8s) |

### Core

| Crate | Purpose |
|-------|---------|
| **dragonfly-agent** | Mage — lightweight Alpine agent for discovery and imaging |
| **dragonfly-server** | Web UI, API, orchestration logic, authentication |

## Decoupled Design

### The Bootstrap Problem

How do you provision the cluster that provisions other machines? Dragonfly solves this cleanly:

1. **Dragonfly runs anywhere** — Your laptop, a VM, an existing server
2. **ReDB is embedded** — Single file, zero external dependencies
3. **State is portable** — Copy the redb file or share via K8s
4. **Multiple instances can coexist** — All point to the same storage backend

This means you can:
- Install Dragonfly on your laptop to bootstrap a datacenter
- Move Dragonfly into the cluster it just provisioned
- Run multiple Dragonfly instances for HA (with K8s backend)

### Source of Truth

```
                    ┌──────────────────┐
                    │   ReDB / etcd    │
                    │ (Source of Truth)│
                    └──────────────────┘
                           ▲
                    ┌──────┴──────┐
            ┌───────┴───┐   ┌─────┴─────┐
            │ Dragonfly │   │ Dragonfly │
            │ Instance 1│   │ Instance 2│
            │ (Laptop)  │   │(In-cluster)│
            └───────────┘   └───────────┘
```

Both instances see the same machines, same state, same workflows. No conflicts.

## Data Flow

### Boot Request Flow

```
1. Machine powers on, BIOS requests PXE boot
2. DHCP server provides IP + next-server (Dragonfly TFTP)
3. Machine downloads iPXE binary (undionly.kpxe or ipxe.efi)
4. iPXE executes, fetches script from HTTP /boot/${mac}
5. Server looks up MAC, decides boot fate:
   - Unknown → Discovery script (boot Mage)
   - Assigned → Imaging script (execute workflow)
   - Complete → Local boot (boot from disk)
```

### Discovery Flow

```
1. iPXE loads discovery script
2. Mage agent boots (Alpine-based)
3. Agent detects hardware via sysinfo:
   - CPU model, cores, threads
   - RAM amount
   - Disk devices and sizes
   - Network interfaces and MACs
   - BMC presence
4. Agent POST /api/machines/register
5. Server creates Hardware CRD
6. Machine appears in Web UI with memorable name
```

### Provisioning Flow

```
1. Operator selects OS template in Web UI
2. Server creates Workflow (Hardware → Template link)
3. Machine reboots via BMC or manual
4. iPXE now returns imaging script
5. Mage boots in imaging mode
6. Agent fetches Workflow from server
7. ActionEngine executes actions sequentially:
   - partition: Create GPT/MBR partitions
   - image2disk: Stream OS image to disk
   - writefile: Configure hostname, network, SSH
   - kexec: Jump to installed kernel
8. Progress reported via /api/workflows/{id}/progress
9. Machine boots into installed OS
10. Status updated to "Ready"
```

## Storage Backends

Dragonfly supports pluggable storage via the `DragonflyStore` trait:

### ReDB (Default)
- Embedded Rust database
- Location: `/var/lib/dragonfly/dragonfly.redb`
- Zero external dependencies
- Perfect for standalone/small deployments
- Backup: copy single file

### Kubernetes
- Data stored as Custom Resources in etcd
- API group: `dragonfly.computer/v1`
- Enable: `DRAGONFLY_BACKEND=kubernetes`
- Requires KUBECONFIG access
- Multiple Dragonfly instances share state

### Memory (Testing)
- In-memory store for tests
- No persistence
- Deterministic behavior

## Technology Stack

| Layer | Technology |
|-------|------------|
| **Language** | Rust (Edition 2024) |
| **Web Framework** | Axum |
| **Async Runtime** | Tokio |
| **Database** | ReDB (embedded) or K8s etcd |
| **Templates** | MiniJinja (auto-reload) |
| **Styling** | Tailwind CSS |
| **Kubernetes** | kube-rs client |
| **Authentication** | Argon2, JWT, Sessions |

## Security Model

- **Authentication**: Password-based with Argon2 hashing
- **Sessions**: Server-side with secure cookies
- **API**: JWT tokens for programmatic access
- **Network**: HTTPS recommended for production
- **BMC Credentials**: Stored per-machine in database

## Deployment Patterns

### Single Node (Simple/Flight Mode)

```
┌─────────────────────────────┐
│        Single Server        │
│  ┌───────────────────────┐  │
│  │    Dragonfly Server   │  │
│  │  + DHCP + TFTP + ReDB │  │
│  └───────────────────────┘  │
└─────────────────────────────┘
```

### High Availability (Swarm Mode)

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│   Node 1    │  │   Node 2    │  │   Node 3    │
│  Dragonfly  │  │  Dragonfly  │  │  Dragonfly  │
│             │  │             │  │             │
└─────────────┘  └─────────────┘  └─────────────┘
       ▲               ▲               ▲
       └───────────────┼───────────────┘
                       │
              ┌────────┴────────┐
              │   Kubernetes    │
              │  (Shared etcd)  │
              └─────────────────┘
```

### Remote Management

```
┌─────────────────┐              ┌─────────────────┐
│  Datacenter A   │              │  Your Laptop    │
│  (Bare Metal)   │◄────────────►│  (Dragonfly)    │
│                 │    Network   │                 │
└─────────────────┘              └─────────────────┘
```

Manage Datacenter A from your laptop over the network. Dragonfly doesn't need to run in the same location as the hardware it manages.

## Native vs Tinkerbell

Dragonfly's `native-provisioning` branch differs from traditional Tinkerbell:

| Feature | Dragonfly | Tinkerbell |
|---------|-----------|------------|
| **Actions** | Native Rust | Docker containers |
| **Container Runtime** | Not required | Required on workers |
| **Execution Speed** | Faster | Container overhead |
| **Dependencies** | Self-contained | Docker + images |
| **Storage** | ReDB or K8s | K8s only |
| **GUI** | Included | None |
| **Boot Decision** | Server-side | Menu-driven |

The native approach means smaller agents, faster provisioning, and fewer moving parts.

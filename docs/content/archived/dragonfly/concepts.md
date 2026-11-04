---
title: Concepts
weight: 2
---

# Core Concepts

Understanding the fundamentals of Dragonfly's architecture and how it manages bare metal infrastructure.

## The Machine Lifecycle

Every machine in Dragonfly follows a lifecycle:

```
Discovery → Registration → OS Assignment → Provisioning → Ready
                                              ↓
                                           Error → Retry/Manual
```

| Phase | Description |
|-------|-------------|
| **Discovery** | Machine PXE boots, Mage agent detects hardware |
| **Registration** | Agent reports to server, Hardware CRD created |
| **OS Assignment** | Operator selects template via web UI |
| **Provisioning** | Native actions execute (partition, image, configure) |
| **Ready** | Machine boots into installed OS |
| **Error** | Installation failed, needs intervention |

## PXE Boot

**Preboot Execution Environment (PXE)** allows machines to boot from the network before any operating system is installed.

When a machine PXE boots:
1. BIOS/UEFI requests an IP address via DHCP
2. DHCP response includes "next-server" pointing to Dragonfly
3. Machine downloads iPXE binary via TFTP
4. iPXE fetches boot script from Dragonfly HTTP endpoint
5. **Server decides the machine's fate** — not the client

## Server Controls Boot Fate

A key design principle: **the server decides what happens, not the client**.

When a machine requests a boot script, Dragonfly looks up its MAC address and returns:

| State | Boot Script |
|-------|-------------|
| **Unknown MAC** | Discovery mode — boot Mage agent |
| **Registered, no OS** | Discovery mode — await assignment |
| **OS assigned** | Imaging mode — execute workflow |
| **Provisioned** | Local boot — boot from disk |

This prevents accidental reimaging and ensures consistent behavior.

## The Mage Agent

**Mage** is a lightweight Alpine-based agent that runs during discovery and provisioning:

- **Hardware Detection**: CPU model, core count, RAM, disk sizes, NICs
- **Network Discovery**: MAC addresses, IP assignments
- **Registration**: Reports hardware specs to Dragonfly server
- **Workflow Execution**: Runs native actions during imaging mode

Mage is ephemeral — it runs only during discovery and installation, then the target OS takes over.

## Custom Resource Definitions

Dragonfly uses Kubernetes-compatible CRDs (even without Kubernetes):

### Hardware
Represents a physical or virtual machine:
- MAC addresses, disk info, BMC credentials
- Current state, assigned template
- Memorable name (BIP39 wordlist)

### Template
Defines a provisioning workflow:
- Ordered list of actions to execute
- OS image location, partition layout
- Post-install configuration

### Workflow
Links Hardware to Template:
- Execution state (pending, running, completed, failed)
- Progress tracking per action
- Created when operator assigns OS

## Native Actions

Unlike Tinkerbell's Docker-based approach, Dragonfly executes actions **natively in Rust**:

| Action | Purpose |
|--------|---------|
| **partition** | Create disk partitions (GPT/MBR) |
| **image2disk** | Stream OS image to disk |
| **writefile** | Write configuration files |
| **kexec** | Jump directly to installed kernel |

Benefits:
- No container runtime required on target
- Faster execution (no Docker overhead)
- Smaller agent footprint
- Deterministic behavior

## Decoupled Architecture

A key principle: **Dragonfly is completely decoupled from the infrastructure it manages**.

This means:
- Dragonfly can run on your laptop managing a datacenter
- Multiple Dragonfly instances can share state
- If Dragonfly goes down, provisioned machines keep running
- Move Dragonfly into the cluster it just provisioned

As long as Dragonfly has access to its storage backend, it doesn't matter where it runs.

## Storage Backends

### ReDB (Default)
- Embedded Rust database, zero dependencies
- Single file: `/var/lib/dragonfly/dragonfly.redb`
- Perfect for standalone deployments
- Fast, reliable, no external services

### Kubernetes (Optional)
- Data stored as Custom Resources in etcd
- API group: `dragonfly.computer/v1`
- Enable with `DRAGONFLY_BACKEND=kubernetes`
- Allows multiple Dragonfly instances with shared state

## Memorable Names

Instead of tracking machines by MAC address or UUID, Dragonfly generates **memorable names** using BIP39 word lists:

```
CensusAbleQualityParent
NurtureQuickSilverDawn
```

These names are:
- Human-readable and pronounceable
- Easy to remember during conversations
- Deterministic (same MAC always generates same name)

## Power Control

Dragonfly supports multiple methods for controlling machine power:

| Method | Capabilities | Use Case |
|--------|--------------|----------|
| **IPMI** | Full control (on/off/cycle/boot device) | Enterprise servers |
| **Redfish** | Full control, REST-based | Modern servers |
| **Wake-on-LAN** | Power on only | Consumer hardware |

Configure BMC credentials per-machine for full power management.

## Operating Modes

Dragonfly adapts to different environments:

### Simple Mode
- Single Dragonfly server
- ReDB storage (embedded)
- Basic provisioning workflows
- **No Kubernetes required**

### Flight Mode
- Full datacenter management
- Multi-machine orchestration
- Advanced features: grouping, tagging, bulk operations
- Still no Kubernetes required

### Swarm Mode
- Multi-region/multi-cluster deployment
- Requires **Citadel** coordination layer
- Multiple Dragonfly instances with shared etcd
- Distributed orchestration

## Proxmox Integration

Dragonfly treats Proxmox VMs as "machines" alongside bare metal:

- Auto-discover VMs on Proxmox clusters
- Manage VMs through the same interface
- Track VMID, node, and cluster membership
- Power control via Proxmox API

This unifies management of VMs and physical servers in one place.

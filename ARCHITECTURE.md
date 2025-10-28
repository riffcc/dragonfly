# Dragonfly Architecture

## Core Design Principle: Decoupled Infrastructure Management

Dragonfly is designed to be **decoupled from the infrastructure it manages**. As long as Dragonfly has a KUBECONFIG pointing at a Kubernetes cluster with Tinkerbell, it doesn't matter WHERE Dragonfly runs.

### Deployment Flexibility

Dragonfly can run:
- **On your laptop** managing a remote datacenter
- **On a VM** managing bare metal clusters
- **On one cluster** managing multiple other clusters
- **Anywhere** with network access to the Kubernetes API

### Solving the Bootstrapping Problem

Instead of a circular dependency:
- ❌ Need k8s to run Dragonfly to deploy k8s

We have a clean bootstrap path:
- ✅ `dragonfly install` deploys minimal k3s + Tinkerbell
- ✅ Dragonfly pod runs inside that cluster
- ✅ But can be moved outside later if needed
- ✅ One Dragonfly instance can manage multiple clusters

## Multi-Instance High Availability

Since Dragonfly primarily injects data into Kubernetes resources (Tinkerbell workflows, hardware specs, deployment configs) and **k8s is the source of truth**, multiple instances can coexist:

```
[Dragonfly 1] ─┐
[Dragonfly 2] ─┼─→ [k8s API] → [Tinkerbell] → [Bare Metal]
[Dragonfly 3] ─┘
```

All instances are stateless and equivalent. Kubernetes handles consistency.

### Use Cases for Multi-Instance

- **HA by default** - One instance dies, others keep working
- **Geographic distribution** - UI endpoint near each team
- **Development workflow** - Work locally, deploy globally
- **"Swarm" mode** - Multiple control points for large deployments

## Installation Detection

Dragonfly detects "installed" mode in three ways:

1. **`DRAGONFLY_INSTALLED` environment variable** - Set in Kubernetes pod deployments
2. **Local `/var/lib/dragonfly` directory** - Indicates local installation (k3s on same host)
3. **Remote Kubernetes with `tink-system` namespace** - Detected via KUBECONFIG

This enables:
- **Local mode**: `dragonfly install` creates k3s locally, Dragonfly runs on same host
- **Remote mode**: `KUBECONFIG=/path/to/config dragonfly server` manages remote cluster
- **Pod mode**: Dragonfly runs inside Kubernetes with `DRAGONFLY_INSTALLED=true`

### Current State

**Today:** SQLite database with persistent volume
```
Dragonfly pod → SQLite volume → k8s API → etcd
```

**Future Vision: etcd Mode** (like Rancher)
```
[Dragonfly 1] ─┐
[Dragonfly 2] ─┼─→ [etcd] ← [k8s control plane]
[Dragonfly 3] ─┘              ↓
                         [Tinkerbell]
```

## Future: Native etcd Integration

### Benefits of etcd Mode

- **Zero persistent storage** - Dragonfly becomes completely stateless
- **Native HA** - etcd handles consistency across all instances
- **Watch semantics** - Instant updates via etcd watch API
- **Simpler deployment** - No volume management, no SQLite corruption risks
- **True operator pattern** - Same design as Kubernetes controllers

### Rancher Precedent

Rancher uses exactly this pattern - multiple Rancher instances all talking to the same etcd cluster that backs Kubernetes.

### Production-Grade Deployment

With etcd mode, `dragonfly install` could deploy:
- k3s (with embedded etcd)
- Dragonfly deployment (3 replicas by default)
- LoadBalancer pointing at all three instances

**Result:** Instant HA, zero configuration, production-grade by default.

## Operator-Pattern Architecture

Dragonfly follows the Kubernetes operator pattern:
- **Watches** Kubernetes resources
- **Kubernetes manages** Tinkerbell
- **Tinkerbell deploys** bare metal

Clean separation of concerns, cloud-native by design.

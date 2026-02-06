# Guidelines for Claude Code

## Project Overview
Dragonfly is a bare metal management tool,
for everything from building machines to
reinstalling an entire datacentre.

## Architecture - READ THIS FIRST

### Storage Backends (CRITICAL)
**USE REDB OR K8S/ETCD. REMOVE SQLITE.**

Dragonfly supports TWO storage backends via `DragonflyStore` trait:

1. **ReDB (DEFAULT)** - Embedded Rust database at `/var/lib/dragonfly/dragonfly.redb`
   - Used by default when no env var is set
   - No external dependencies required
   - Perfect for single-server or small deployments

2. **Kubernetes/etcd (OPTIONAL)** - Store everything in etcd via K8s CRDs
   - Enabled via env var (e.g., `DRAGONFLY_BACKEND=kubernetes`)
   - Uses whatever KUBECONFIG points to
   - For running inside K8s where you want data in etcd

**SQLite (`db.rs`) is DEPRECATED and being removed - DO NOT USE IT.**

**DO NOT USE MemoryStore IN PRODUCTION.** MemoryStore is for tests ONLY. Never cache settings or state in memory - always read from ReDB. In-memory caches lead to split-brain bugs where the UI writes to one place and other code reads from another.

**K8s IS NOT REQUIRED. EVER.** The storage backend choice is independent of features.

### Deployment Modes
These control WHAT Dragonfly does, not WHERE it stores data:

- **Simple** - Single server, basic provisioning
- **Flight** - Single server, full datacenter management (does NOT require K8s!)
- **Swarm** - Multi-region, multi-cluster coordination (requires Citadel, does NOT require K8s!)

Flight and Swarm are equally capable for datacenter management. Swarm adds multi-region/multi-cluster coordination via Citadel. Simple and Flight run entirely on ReDB.

### Authentication
- `require_login` defaults to `true` (internal tool)
- Fresh install: login page → welcome/mode selection → dashboard
- All settings stored in the configured storage backend (ReDB or K8s)

### Components
- **Spark** - The PXE agent. Boots on bare metal, detects hardware/disks/OS, reports to server, chainloads existing OS. This is a no_std bare metal Multiboot2 binary. Spark is the AGENT.
- **Mage** - The imaging environment. Alpine-based netboot OS used ONLY for writing images to disk. Mage is the WRITER. It does NOT do discovery or detection - that's Spark's job.
- **Server** - The Dragonfly server. Web UI, API, provisioning logic, workflow engine.

### Key Files
- `crates/dragonfly-spark/` - Spark agent (no_std bare metal)
- `crates/dragonfly-server/src/store/` - Storage abstraction (DragonflyStore trait)
- `crates/dragonfly-server/src/store/redb_store.rs` - ReDB implementation
- `crates/dragonfly-server/src/store/memory.rs` - In-memory fallback
- `crates/dragonfly-server/src/lib.rs` - Server initialization, backend selection

## Rules
- **Consult README.md** for context whenever needed
- **Keep README.md Updated** - When adding new commands, features, or changing functionality, ALWAYS update the README.md Usage section. Palace uses the README to understand what exists, so outdated docs lead to duplicate suggestions!
- **Test Driven Development** - Write tests before implementing ANY code or feature, no matter how small. We aim for high code coverage from the beginning.
- **Zero Placeholders** - Do not put in references to commands or functionality that are not implemented yet or do not exist
- **Modularity** - Break down components into small, focused files (typically <200 LoC per file)
- **Test Modularity** - Tests should be modular and organized for easy understanding and maintenance
- **"DO NOT SIMPLIFY - EVER"** - When thinking of simplifying something, think through the change deeply and ask the user what they want to do
- **Commit Regularly** - Test after every change and commit very regularly with tiny atomic chunks
- **Follow Language Style Guides** - Adhere to the style guide of your primary language
- **Use Palace Tools** - Use `pal test`, `pal build`, `pal run` for development workflows
- **NEVER REVERT FILES** - Do NOT use `git checkout` or `git restore` to revert files unless explicitly asked
- **PREFER NATIVE CRATES** - Strongly prefer native Rust crates over shelling out to external binaries. Do NOT shell out for data parsing (no lsblk, fdisk, tar for reading data). Shelling out is acceptable ONLY for system actions with no native alternative (e.g., `mdev -s` for device node refresh, `kexec` for kernel loading).

## Quality Standards
- Write comprehensive tests for all new features
- Keep functions small and focused
- Use meaningful variable and function names
- Document complex logic with clear comments
- Handle errors gracefully with proper error messages

## Development Workflow
1. **Understand Requirements** - Read README.md and existing code
2. **Write Tests First** - Create failing tests that define expected behavior
3. **Implement Features** - Write minimal code to make tests pass
4. **Refactor** - Clean up code while keeping tests green
5. **Commit** - Small, atomic commits with clear messages

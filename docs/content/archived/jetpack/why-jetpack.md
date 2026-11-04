---
title: Why Jetpack?
weight: 2
---

# Why Jetpack?

Ansible changed infrastructure automation. Jetpack takes it further.

## Lessons from Ansible

Ansible proved that agentless, push-based automation works. It showed that YAML playbooks are approachable. But after years of production use, patterns emerged:

- **Performance**: Serial execution becomes a bottleneck at scale
- **State**: Lack of state tracking leads to drift
- **Typing**: YAML's flexibility becomes a source of errors
- **Dependencies**: Python dependency management is painful

## The Jetpack Approach

Jetpack addresses these challenges:

| Challenge | Jetpack Solution |
|-----------|------------------|
| Performance | Parallel execution by default |
| State | Built-in state tracking and drift detection |
| Typing | Schema validation for playbooks |
| Dependencies | Single binary, no runtime dependencies |

## Familiar Syntax

If you know Ansible, you'll feel at home with Jetpack. We kept the good parts.

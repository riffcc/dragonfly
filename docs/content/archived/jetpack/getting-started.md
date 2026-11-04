---
title: Getting Started
weight: 1
---

# Getting Started with Jetpack

Jetpack makes infrastructure automation simple, fast, and reliable.

## Installation

Documentation coming soon.

## Your First Playbook

```yaml
# hello.yaml
- name: Hello World
  hosts: all
  tasks:
    - name: Print greeting
      debug:
        msg: "Hello from Jetpack!"
```

## Running Jetpack

```bash
jetpack run hello.yaml
```

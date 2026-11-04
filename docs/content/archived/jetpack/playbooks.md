---
title: Playbooks
weight: 3
---

# Playbooks

Playbooks are the core of Jetpack automation.

## Structure

A playbook is a YAML file containing one or more plays:

```yaml
- name: Configure web servers
  hosts: webservers
  tasks:
    - name: Install nginx
      package:
        name: nginx
        state: present

    - name: Start nginx
      service:
        name: nginx
        state: started
        enabled: true
```

## Plays

Each play targets a group of hosts and defines tasks to execute.

## Tasks

Tasks are the individual units of work. Each task uses a module to perform an action.

## Modules

Jetpack includes modules for common operations:

- `package` - Install and manage packages
- `service` - Manage system services
- `file` - Create and manage files
- `template` - Render templates
- `command` - Run shell commands
- `copy` - Copy files to remote hosts

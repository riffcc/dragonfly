---
title: Configuration
weight: 3
---

# Configuration

Configure Dragonfly for your environment.

## Configuration File

Dragonfly uses a YAML configuration file for its settings.

```yaml
# Example configuration
server:
  address: 0.0.0.0
  port: 8080

tftp:
  enabled: true
  root: /var/lib/dragonfly/tftp

dhcp:
  proxy_enabled: true
```

## Environment Variables

Configuration can also be provided via environment variables.

| Variable | Description | Default |
|----------|-------------|---------|
| `DRAGONFLY_PORT` | HTTP server port | `8080` |
| `DRAGONFLY_TFTP_ROOT` | TFTP root directory | `/var/lib/dragonfly/tftp` |

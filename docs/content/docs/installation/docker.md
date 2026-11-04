---
title: Docker
cascade:
  type: docs
weight: 3
sidebar:
    open: true
next: /docs/installation/production-setup/
---

You can run Dragonfly using Docker Compose.

Save this file as `docker-compose.yml`:

```yaml
services:
  dragonfly:
    image: ghcr.io/riffcc/dragonfly:latest
    restart: unless-stopped
    network_mode: host
    volumes:
      - dragonfly-data:/var/lib/dragonfly
    environment:
      - RUST_LOG=info

volumes:
  dragonfly-data:
```

Then run:

```bash
docker compose up -d
```

Visit the web interface at `http://your-hostname:3000`.

Host networking is required because Dragonfly's DHCP and TFTP services need direct access to the network for PXE boot functionality.

### Data persistence

All Dragonfly data (database, templates, boot images) is stored in the `dragonfly-data` volume. This persists across container restarts and upgrades.

To back up your data:

```bash
docker run --rm -v dragonfly-data:/data -v $(pwd):/backup debian:trixie-slim tar czf /backup/dragonfly-backup.tar.gz /data
```

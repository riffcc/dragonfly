---
title: Quick Start
cascade:
  type: docs
weight: 1
sidebar:
    open: true
---
You can install Dragonfly on any macOS or Linux system.

For Linux installations, we suggest using Debian or Ubuntu or running the Docker image, although you may have luck with other distributions.

### Docker
You can run Dragonfly using Docker Compose:

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

Visit the web interface at `http://localhost:3000`
(or `http://your-hostname:3000` if you're not running it locally)

For more details on running Dragonfly with Docker, see the [Docker guide](/docs/installation/docker).

### Native Installation
Download the latest binary from the [releases page](https://github.com/riffcc/dragonfly/releases).

You'll want the version for your computer.

{{< tabs items="Linux,macOS,Windows" defaultIndex="0" >}}
  <!-- Linux -->
  {{< tab >}}
  Download Dragonfly from the [releases page](https://github.com/riffcc/dragonfly/releases).
  ```
  wget -O dragonfly https://github.com/riffcc/dragonfly/releases/latest/download/dragonfly-linux-amd64
  ```

  Copy the binary to /usr/local/bin/dragonfly and make it executable:
  ```
  sudo cp dragonfly /usr/local/bin/dragonfly
  sudo chmod +x /usr/local/bin/dragonfly
  ```

  Install Dragonfly:
  ```
  sudo dragonfly install
  ```

  You can now visit the web interface on port 3000 `http://<machine-ip-address>:3000`

  {{< /tab >}}
  <!-- macOS -->
  {{< tab >}}
  macOS installation relies on installing Dragonfly as a native binary.
  Future releases will include Homebrew support.

  Download Dragonfly from the [releases page](https://github.com/riffcc/dragonfly/releases).
  ```
  wget -O dragonfly https://github.com/riffcc/dragonfly/releases/latest/download/dragonfly-macos-arm64
  ```

  Copy the binary to /usr/local/bin/dragonfly and make it executable:
  ```
  sudo cp dragonfly /usr/local/bin/dragonfly
  sudo chmod +x /usr/local/bin/dragonfly
  ```

  Install Dragonfly:
  ```
  sudo dragonfly install
  ```

  You can now visit the web interface on port 3000 `http://<machine-ip-address>:3000`

  {{< /tab >}}

  <!--Windows -->
  {{< tab >}}
  Installation on Windows is not currently supported, and support is not planned at this time.

  However, you may be able to get Dragonfly running via WSL2 (Windows Subsystem for Linux).

  If this is a strong need, please contact us at support@dragonflycomputer.com!
  {{< /tab >}}

{{< /tabs >}}

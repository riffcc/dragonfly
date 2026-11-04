---
title: Native installation
cascade:
  type: docs
weight: 2
sidebar:
    open: true
next: /docs/installation/production-setup/
---
Download the latest binary from the [releases page](https://github.com/riffcc/dragonfly/releases).

You'll want the version for your computer.

{{< tabs items="Linux,macOS,Windows" defaultIndex="0" >}}
  <!-- Linux -->
  {{< tab >}}
  Download Dragonfly from the [releases page](https://github.com/riffcc/dragonfly/releases).
  ```
  wget -O dragonfly https://github.com/riffcc/dragonfly/releases/download/v0.1.0-alpha1/dragonfly-linux-amd64
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
  Download Dragonfly from the [releases page](https://github.com/riffcc/dragonfly/releases).
  ```
  wget -O dragonfly https://github.com/riffcc/dragonfly/releases/download/v0.1.0-alpha1/dragonfly-darwin-amd64
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
  
  If this is a strong need, please contact us at support@dragonfly.computer
  {{< /tab >}}

{{< /tabs >}}

---
title: Installation
cascade:
  type: docs
weight: 2
sidebar:
    open: true
next: /docs/installation/native/
---
Ready to try Dragonfly?

You can run Dragonfly as a binary directly or using Docker, Podman or Kubernetes.
{{< cards >}}
  {{< card link="/docs/installation/binary" title="Binary installation" icon="binary" >}}
  {{< card link="/docs/installation/docker" title="Docker setup" icon="docker" >}}
  {{< card link="/docs/installation/production" title="Production deployment" icon="globe" >}}
  <!--
  {{< card link="multi region deployment" title="Multi-region deployment" icon="earth" >}}
  -->
  {{< card link="/docs/installation/kubernetes" title="Kubernetes deployment" icon="kubernetes" >}}
{{< /cards >}}

{{% steps %}}

### Install Dragonfly

Get Dragonfly running, whether it's on Docker, Kubernetes or **directly on your laptop**.

### Configure Dragonfly

Login to Dragonfly using your web browser and configure your settings.

### (Optional) Enable Spark on your computers

As soon as Dragonfly is up and running, you can use it to manage your computers.

The Spark agent allows you to perform basic maintenance tasks remotely or locally.

Enable PXE/Network booting on each computer you want to manage with Spark.

{{% /steps %}}

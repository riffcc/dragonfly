---
title: Managing ISO images
cascade:
  type: docs
weight: 2
sidebar:
    open: true
---
Dragonfly allows you to boot ISO images over the network. This is useful for deploying operating systems that are not available in Dragonfly's included templates.

{{% steps %}}

### Open Dragonfly
Navigate to your Dragonfly dashboard and go to the Settings page, then select the "ISO Images" option.

<img src="/images/screenshots/iso-manage.png" alt="Manage ISO images in the settings panel" style="width: 75%;" />

### Upload ISO Image
Upload your ISO image file to Dragonfly by clicking the "Upload ISO" button and selecting the file from your local machine.

<img src="/images/screenshots/iso-upload.png" alt="Manage ISO images in the settings panel" style="width: 75%;" />

### Select Network Boot
Temporarily or permanently configure your machine to boot from the network.

This may also be referred to as "PXE boot", "iPXE boot", or "network boot".

<img src="/images/screenshots/select-network-boot.png" alt="Configure your machine to boot from the network" style="width: 75%;" />

### Start Spark
Turn on your machine and Spark will appear.

<img src="/images/screenshots/spark-boot-menu.png" alt="Manage ISO images in the settings panel" style="width: 75%;" />

Select Boot from ISO by pressing "3".

### Select your ISO
Use the arrow keys to navigate the list of available ISO images,
or press the number key for the desired ISO image.

To boot Arch Linux here, we press "2".

<img src="/images/screenshots/spark-boot-from-iso-arch.png" alt="Select an ISO from the list" style="width: 75%;" />
<img src="/images/screenshots/spark-boot-from-iso-reboot.png" alt="Select an ISO from the list" style="width: 75%;" />

### Enjoy
Your ISO image will boot. Here's what booting Arch Linux looks like:
<img src="/images/screenshots/arch-linux-boots.webp" alt="Arch Linux rises from the depths!" style="width: 75%;" />

{{% /steps %}}

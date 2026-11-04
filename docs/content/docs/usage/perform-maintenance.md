---
title: Performing maintenance
cascade:
  type: docs
weight: 2
sidebar:
    open: true
---
Spark makes it easy to maintain machines remotely or locally.

{{% steps %}}

  ### Select Network Boot
  Temporarily or permanently configure your machine to boot from the network.
  
  This may also be referred to as "PXE boot", "iPXE boot", or "network boot".
  
  <img src="/images/screenshots/select-network-boot.png" alt="Configure your machine to boot from the network" style="width: 75%;" />
  
  ### Start Spark
  Turn on your machine and Spark will appear.
  
  <img src="/images/screenshots/spark-boot-menu.png" alt="Manage ISO images in the settings panel" style="width: 75%;" />

  Press 2 to enter the Advanced menu.

  ### Choose an action
  Select an action to perform on the machine.
  
  <img src="/images/screenshots/spark-advanced.png" alt="Manage ISO images in the settings panel" style="width: 75%;" />
  
  The following options are available at this time:
  * Install OS - Install an operating system from an available template
  * Memory Test - Launch memtest86+ to test your machine's memory
  * Boot Rescue Environment (Alpine) - Reboot into an Alpine Linux root shell/rescue environment
  * Remove from Dragonfly - Prevents a machine from being managed by Dragonfly

  ### 

{{% /steps %}}

Future improvements to Dragonfly will allow you to trigger these actions remotely.

---
title: Deploying with Dragonfly
cascade:
  type: docs
weight: 1
sidebar:
    open: true
---
Dragonfly makes it easy to deploy an operating system of your choice.

{{% steps %}}

### Navigate to the Machines page
Navigate to your Dragonfly dashboard and go to the Machines page.

<img src="/images/screenshots/machine-list-installed.png" alt="Dragonfly Machines Dashboard" style="width: 75%;" />

### Select machines to deploy to

Select the machine or machines you want to deploy an operating system to.

<img src="/images/screenshots/machine-list-selected.png" alt="Dragonfly Machine Selection" style="width: 75%;" />

### Choose an operating system

Choose the operating system you want to deploy from the list of available options.

<img src="/images/screenshots/machine-list-selected-2-pickos.png" alt="Dragonfly OS Selection" style="width: 75%;" />

### Select Reimage to trigger deployment

Select "Reimage" from the actions in the top left. 
<img src="/images/screenshots/machine-list-selected-3-reimage.png" alt="Dragonfly OS Deployment" style="width: 75%;" />

This will trigger the deployment process for the selected machine(s), replacing the current operating system with the one you selected.

<img src="/images/screenshots/machine-list-selected-3.png" alt="Dragonfly OS Deployment" style="width: 75%;" />

You will see the target operating system appear underneath the current operating system, and an icon indicating the pending change.

### Reboot into Mage to apply changes

Reboot each of the machines to complete the deployment process and install your new Debian 13 (or other chosen) operating system.

<img src="/images/screenshots/machine-list-installing.png" alt="Dragonfly OS Deployment" style="width: 75%;" />

Mage will run on each of the machines to automatically apply the requested operating system to the disk.
{{% /steps %}}

You can also deploy operating systems to a single machine by following the same steps but only selecting one machine.

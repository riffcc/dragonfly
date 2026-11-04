---
title: Dragonfly
layout: hextra-home
---

<div style="display: flex; flex-direction: row; gap: 3rem; align-items: center; flex-wrap: wrap; max-width: 1200px; margin: 0 auto;">
  <div style="flex: 1; min-width: 400px; max-width: 600px;">

{{< hextra/hero-headline >}}
metal, managed.
{{< /hextra/hero-headline >}}

{{< hextra/hero-subtitle >}}
Automatic discovery and installation for all your servers.
{{< /hextra/hero-subtitle >}}

<div class="hx:mt-8 hx:mb-8 hx:flex hx:flex-col hx:sm:flex-row hx:gap-4">
  <a href="/docs/installation/" class="dragonfly-btn dragonfly-btn-primary">Try Dragonfly</a>
  <a href="/docs/introduction/dragonfly/" class="dragonfly-btn dragonfly-btn-secondary">Learn More</a>
</div>

  </div>
  <div style="flex: 1; min-width: 300px; max-width: 450px; margin: 2rem;">
    <img src="/images/machines-light.png" alt="Dragonfly Machines Dashboard" style="width: 100%; border-radius: 0.5rem; box-shadow: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1);" class="hx:dark:hidden" />
    <img src="/images/machines.png" alt="Dragonfly Machines Dashboard" style="width: 100%; border-radius: 0.5rem; box-shadow: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1);" class="hx:hidden hx:dark:block" />
  </div>
</div>

{{< hextra/feature-grid >}}
  {{< hextra/feature-card
    title="Deploy Linux in under 60 seconds"
    subtitle="Bring up a machine all the way to SSH in 60 seconds or less. No USB drives, no console access needed."
    link="/docs/usage/deploying-with-dragonfly"
    icon="hard-drive-download"
  >}}
  {{< hextra/feature-card
    title="Network boot a machine"
    subtitle="Power on a machine and Dragonfly finds it. PXE boot, hardware detection, and registration happen automatically."
    link="/docs/introduction/dragonfly"
    icon="lightning-bolt"
  >}}
  {{< hextra/feature-card
    title="Remote maintenance"
    subtitle="Reinstall, wipe, diagnose, and repair remotely, even on machines without IPMI or BMC devices."
    link="/docs/usage/perform-maintenance/"
    icon="hammer"
  >}}
  {{< hextra/feature-card
    title="Proxmox integration"
    subtitle="Manage Proxmox VMs alongside bare metal. IPMI, Redfish, and Wake-on-LAN support coming soon."
    link="/docs/introduction/dragonfly"
    icon="power"
  >}}
  {{< hextra/feature-card
    title="Coexists with your infrastructure"
    subtitle="Works alongside existing DHCP servers. No need to rip and replace, just plug Dragonfly in."
    link="/docs/introduction/dragonfly"
    icon="handshake"
  >}}
  {{< hextra/feature-card
    title="Open source"
    subtitle="Built in the open under AGPLv3. Free to use, free to modify, designed for transparency and community."
    link="https://github.com/riffcc/dragonfly"
    icon="code"
  >}}
{{< /hextra/feature-grid >}}

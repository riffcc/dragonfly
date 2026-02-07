# Roadmap
Here's things we would like to work on and add to Dragonfly next.

This is speculative and subject to change.

## Upcoming planned features

- 📊 (WIP) Granular reporting and monitoring of your machines.
- 📦 (WIP) Built in image management for OS and drivers.
- 🎮 (WIP) Gamepad and touchscreeen support for easy navigation of the UI.
- 🧸 (WIP) **Safety Mode (Molly Guard)** — avoid accidentally nuking a machine
- 🚀 (WIP) Built-in IPMI/BMC/Redfish power control
  and SSH control support for flexible node power operations.
- 🌍 (WIP) Uses DNS to find machine hostnames automatically
- 🖼️ (WIP) Ready for Retina, ultrawide and kiosk displays 
- 🎨 (WIP) Tailwind-powered theming — pick your aesthetic or import your own.
* First run wizard:

* Wild looking electric green bar on the front page that shows the status of the last 100 deployments
* Lock individual nodes to prevent them from being reimaged or deleted
* Authentication system
  * Admin login for managing and adopting machines
  * Normal user login - can see machines and adopt new ones, but not reimage or delete any machines
* Configurable front page security
    * Allows open, logged in only, or admin only
    * Allowlist for IP addresses that can access the panel
* Safety mode - "molly guard" - disables power control and reimage controls
* IPMI/BMC/Redfish support
    * Allows for remote power control and monitoring of machines
    * Can be used to power on and adopt a new machine (given a known IPMI address)
    * Can be used to reimage machines by setting PXE mode
    * Power off, reset, power on, power cycle
    * Get power state, machine status, and power draw
* Multi-Factor Authentication

## Low priority planned features
* OpenJBOD support
  * Open source JBOD with a web interface that lets you power cycle disk chassis
* VLAN support
* Bonding/LACP support
* Gamepad support
* Retina/HiDPI display support
* Touchscreen support
* Automatic provisioning of Proxmox clusters
* A timer that measures how long it takes to deploy each kind of OS Template and even rough heuristics based on hardware (CPU, RAM, etc)
  and uses it to estimate remaining time for longer deployments.
  * This will have a "barber pole/candy spinner" animated progress bar for each deploying node.
  * This will also have a "deployed" status that shows the total number of nodes deployed and the average deployment time.
  * This will be displayed on the main page right after the status counts.
  * Timer exports to Prometheus/Grafana
    * Show all deployment times and stages
    * Show average deployment time by OS template
    * Show average deployment time by hardware type
    * Failed/succeeded counts by OS template, date, and time of day

Simple mode.
Tinkerbell mode.
Distributed mode.

Simple mode will use *direct PXE imaging completely agentlessly*, simply using MAC-to-hostname mapping (with the same reverse DNS lookup trick where a machine that attempts to PXE boot from it will be looked up in reverse DNS, so if it has a static DHCP lease and a DNS name, it can not just be assigned a real hostname *but also tags and roles* automatically. It'll literally just Kickstart/preseed/whatever VMs instead of using our deployment system, and it'll be slower but the tradeoff is that it will directly install machines without any intermediate steps.

Distributed mode will stretch and loadbalance the IPXE distribution/image distribution system, as well as make the entire system effortlessly HA. And there will be a "Convert to Dragonfly" button on newly deployed machines that turns a machine into a Dragonfly node automatically and joins it to the existing cluster.

If the user runs:
`dragonfly`

And no install, no run, no flags:
You launch the Dragonfly Demo Experience™

What This Demo Mode Should Do:
✅ Run in-memory only
No filesystem writes

No k3s startup

No agent listening

PXE disabled

Temporary port binding (e.g., localhost:3000)

Just enough to render the full Web UI with mock data

🧑‍🏫 Show the Real UI
Simulated machine list

Realtime-looking status

Tag editing

Tinkerbell workflows “in progress”

But everything is ephemeral and safe to explore

🧭 Show a banner:
Demo Mode: Dragonfly is not installed yet.
This is a preview — none of your hardware is touched.
[🚀 Install Now] [📖 Docs] [🛠 Advanced Setup]

🧠 Why This Is Brilliant
🪶 Zero commitment

⚡ Immediate UX payoff

🧠 Helps people decide without docs or flags

📦 Makes dragonfly self-explanatory — the binary is the experience

🧩 Bonus
Let users type:

dragonfly --demo

to re-enter it later — great for testing or CI screenshots.

# Memtest mode
Action -> Run utility -> Run memtest and report results

# Disk test mode
Actions -> Run utility -> Run disk test and report results

# Network test mode
Actions -> Run utility -> Run network test and report results

# Stress test mode
Actions -> Run utility -> Run stress test and report results


###############
# Tag editing #
###############
🧱 Rack Editor (Physical Layout)
🧠 Vibe:

Like placing LEGO bricks into a digital rack, with:

    Horizontal or vertical rack views

    Dragable VM and machine cards

    Snap-to-slot and auto-align on release

🎮 Gamepad UX:

    Left stick: Move focus

    Left trigger: Activate box select

    RB: Add to selection

    Right trigger: Assign to rack / move

    A: Toggle detailed view

    Start: Open rack config panel

    Right stick: Lassoo select machines

✨ Visual Flavor:

    Subtle glows per slot as you hover/select

    Slot info in a sidebar: uptime, last deploy, heat/temp if available

    Drag animation leaves behind a slight ghost trail of the card — just like moving icons on macOS or Win11

🧲 Drag-and-Drop Categoriser (Tagging UI)
🧠 Vibe:

Like sorting trading cards into piles — Trello meets VS Code workspaces.
🧩 Left Panel:

    Cards for every ungrouped VM or node

    Or open the "all nodes" view to categorise existing nodes

    Open a group (select it and fire at it with no node selected) to show all nodes in that group
    in a new modal, and then drag nodes out of it to unassign them from that group

🧱 Right Panel:

    Tag buckets or “category piles” (e.g. web, gpu, dev, decommission)

✋ Mouse UX:

    Click + drag to move one

    Box select for bulk

    Drag group → tag, release to assign

    Hover over a tag = preview what’s inside

🎮 Gamepad UX:

    LS: Move focus across grid

    LT: Box select

    RB: Additive select

    RT: Fire into target tag

    RT+RB: Select multiple targets (tag aliases or “Apply all”)

    X: Toggle preview mode for a tag (see contents in place)

    Y: Filter node list (show only gpu, mismatched, reimaging, etc.)

🧠 Extra Touches:

    Rumble feedback when snapping into slots or valid tag zones

    Toasts for actions:

        “4 nodes assigned to ‘gpu’”

    Undo button (press B once after a drag)

🧨 Future Layer: “Hot Zone” smart regions

    Drag onto a smart tag zone like “Needs OS” or “Needs Cleanup”

    System takes action (reimage, delete, flag for attention)

# Labs mode
Special tweaks that users might like
* Enable draining and rebooting of machines in safe mode

# Molly guard
Let's add a molly guard button.

It'll be a teddy bear emoji in the top right of the interface, which says "🧸 Safe" and changes to "⚡ Power" when clicked

In Safe mode, which will be a button like this (see image) modifications to machines, deletion of machines and power off, shutdown and reboot operations are locked behind a second modal which requires a click and hold to get past. So when you remove a machine, it pops up a window to confirm, then in mollyguard mode (safe mode) it opens a *second* modal and says "Safe mode is enabled. Are you sure you wish to proceed? This is a potentially dangerous action."

See @base.html for molly guard, see @machine_list.html for reimage.

# Speculative
* CheckMK agent support, so we can get monitoring straight from machines

//! Network stack integration using smoltcp
//!
//! Provides TCP/IP networking over VirtIO-net

use crate::serial;
use crate::virtio_net::VirtioNet;
use smoltcp::iface::{Config, Interface, SocketSet, SocketHandle};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{dhcpv4, tcp};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr, IpEndpoint, Ipv4Address};

/// Wrapper around VirtioNet that implements smoltcp's Device trait
pub struct NetDevice {
    inner: VirtioNet,
    rx_buffer: [u8; 1514],
    rx_len: usize,
}

impl NetDevice {
    pub fn new(device: VirtioNet) -> Self {
        NetDevice {
            inner: device,
            rx_buffer: [0; 1514],
            rx_len: 0,
        }
    }

    pub fn mac_address(&self) -> [u8; 6] {
        self.inner.mac_address()
    }
}

impl Device for NetDevice {
    type RxToken<'a> = RxTokenImpl<'a> where Self: 'a;
    type TxToken<'a> = TxTokenImpl<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Try to receive a packet
        self.rx_len = self.inner.recv(&mut self.rx_buffer);
        if self.rx_len > 0 {
            Some((
                RxTokenImpl { buffer: &self.rx_buffer[..self.rx_len] },
                TxTokenImpl { device: &mut self.inner },
            ))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxTokenImpl { device: &mut self.inner })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1514;
        caps.max_burst_size = Some(1);
        caps
    }
}

pub struct RxTokenImpl<'a> {
    buffer: &'a [u8],
}

impl<'a> RxToken for RxTokenImpl<'a> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        serial::print("RX: ");
        serial::print_dec(self.buffer.len() as u32);
        serial::println(" bytes");
        // smoltcp wants mutable access but we only have immutable
        // This is safe because smoltcp only reads the data
        let mut buf = [0u8; 1514];
        let len = self.buffer.len().min(1514);
        buf[..len].copy_from_slice(&self.buffer[..len]);
        f(&mut buf[..len])
    }
}

pub struct TxTokenImpl<'a> {
    device: &'a mut VirtioNet,
}

impl<'a> TxToken for TxTokenImpl<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = [0u8; 1514];
        let result = f(&mut buffer[..len]);
        serial::print("TX: ");
        serial::print_dec(len as u32);
        serial::println(" bytes");
        self.device.send(&buffer[..len]);
        result
    }
}

/// Read CPU timestamp counter for actual time measurement
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack)
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Starting timestamp (set on first call)
static mut START_TSC: u64 = 0;

/// Estimated CPU frequency in MHz (conservative estimate for VMs)
const CPU_MHZ: u64 = 2000; // 2 GHz - adjust if needed

pub fn now() -> Instant {
    let tsc = rdtsc();

    // Initialize start time on first call
    let start = unsafe {
        if START_TSC == 0 {
            START_TSC = tsc;
        }
        START_TSC
    };

    // Convert cycles to milliseconds: (cycles / MHz) / 1000
    // = cycles / (MHz * 1000) = cycles / (CPU_MHZ * 1000)
    let elapsed_cycles = tsc.saturating_sub(start);
    let elapsed_ms = elapsed_cycles / (CPU_MHZ * 1000);

    Instant::from_millis(elapsed_ms as i64)
}

/// Maximum DNS servers we store from DHCP
pub const MAX_DNS_SERVERS: usize = 3;

/// Network stack state
pub struct NetworkStack<'a> {
    pub device: NetDevice,
    pub iface: Interface,
    pub sockets: SocketSet<'a>,
    pub dhcp_handle: Option<smoltcp::iface::SocketHandle>,
    pub ip_addr: Option<Ipv4Address>,
    pub gateway: Option<Ipv4Address>,
    /// Boot server IP (siaddr from DHCP - this is the Dragonfly server)
    pub boot_server: Option<Ipv4Address>,
    /// DNS servers from DHCP option 6
    pub dns_servers: [Option<Ipv4Address>; MAX_DNS_SERVERS],
    pub dns_server_count: usize,
}

impl<'a> NetworkStack<'a> {
    /// Initialize the network stack with DHCP
    pub fn new(
        mut device: NetDevice,
        socket_storage: &'a mut [smoltcp::iface::SocketStorage<'a>],
    ) -> Option<Self> {
        let mac = device.mac_address();
        let hw_addr = HardwareAddress::Ethernet(EthernetAddress(mac));
        let config = Config::new(hw_addr);
        let timestamp = now();
        let mut iface = Interface::new(config, &mut device, timestamp);

        // Set a random IP address initially (will be replaced by DHCP)
        iface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(Ipv4Address::UNSPECIFIED.into(), 0)).ok();
        });

        let mut sockets = SocketSet::new(socket_storage);

        // Create DHCP socket
        let dhcp_socket = dhcpv4::Socket::new();
        let dhcp_handle = sockets.add(dhcp_socket);

        serial::println("Network: Starting DHCP...");

        Some(NetworkStack {
            device,
            iface,
            sockets,
            dhcp_handle: Some(dhcp_handle),
            ip_addr: None,
            gateway: None,
            boot_server: None,
            dns_servers: [None; MAX_DNS_SERVERS],
            dns_server_count: 0,
        })
    }

    /// Poll the network stack - call this regularly
    pub fn poll(&mut self) {
        let timestamp = now();
        self.iface.poll(timestamp, &mut self.device, &mut self.sockets);

        // Check DHCP status
        if let Some(handle) = self.dhcp_handle {
            let socket = self.sockets.get_mut::<dhcpv4::Socket>(handle);
            if let Some(event) = socket.poll() {
                match event {
                    dhcpv4::Event::Configured(config) => {
                        let ip = config.address.address();
                        serial::print("DHCP: Got IP ");
                        serial::print_dec(ip.0[0] as u32);
                        serial::print(".");
                        serial::print_dec(ip.0[1] as u32);
                        serial::print(".");
                        serial::print_dec(ip.0[2] as u32);
                        serial::print(".");
                        serial::print_dec(ip.0[3] as u32);
                        serial::println("");

                        self.ip_addr = Some(ip);

                        // Extract boot server (siaddr) from DHCP packet
                        if let Some(ref packet) = config.packet {
                            let siaddr = packet.server_ip();
                            if !siaddr.is_unspecified() {
                                serial::print("DHCP: Boot server (siaddr) ");
                                serial::print_dec(siaddr.0[0] as u32);
                                serial::print(".");
                                serial::print_dec(siaddr.0[1] as u32);
                                serial::print(".");
                                serial::print_dec(siaddr.0[2] as u32);
                                serial::print(".");
                                serial::print_dec(siaddr.0[3] as u32);
                                serial::println("");
                                self.boot_server = Some(siaddr);
                            }
                        }

                        // Fallback: use DHCP server address if siaddr not set
                        if self.boot_server.is_none() {
                            let server = config.server.address;
                            if !server.is_unspecified() {
                                serial::print("DHCP: Using DHCP server ");
                                serial::print_dec(server.0[0] as u32);
                                serial::print(".");
                                serial::print_dec(server.0[1] as u32);
                                serial::print(".");
                                serial::print_dec(server.0[2] as u32);
                                serial::print(".");
                                serial::print_dec(server.0[3] as u32);
                                serial::println("");
                                self.boot_server = Some(server);
                            }
                        }

                        // Update interface with DHCP-assigned address
                        // IMPORTANT: Don't clear+re-add if address unchanged —
                        // clearing kills active TCP connections via smoltcp
                        let new_cidr: IpCidr = config.address.into();
                        let needs_update = self.iface.ip_addrs().iter().next() != Some(&new_cidr);
                        if needs_update {
                            self.iface.update_ip_addrs(|addrs| {
                                addrs.clear();
                                addrs.push(new_cidr).ok();
                            });
                        }

                        // Capture DNS servers from DHCP option 6
                        self.dns_server_count = 0;
                        for dns in config.dns_servers.iter() {
                            if self.dns_server_count < MAX_DNS_SERVERS {
                                serial::print("DHCP: DNS server ");
                                serial::print_dec(dns.0[0] as u32);
                                serial::print(".");
                                serial::print_dec(dns.0[1] as u32);
                                serial::print(".");
                                serial::print_dec(dns.0[2] as u32);
                                serial::print(".");
                                serial::print_dec(dns.0[3] as u32);
                                serial::println("");
                                self.dns_servers[self.dns_server_count] = Some(*dns);
                                self.dns_server_count += 1;
                            }
                        }

                        // Set gateway
                        if let Some(router) = config.router {
                            serial::print("DHCP: Gateway ");
                            serial::print_dec(router.0[0] as u32);
                            serial::print(".");
                            serial::print_dec(router.0[1] as u32);
                            serial::print(".");
                            serial::print_dec(router.0[2] as u32);
                            serial::print(".");
                            serial::print_dec(router.0[3] as u32);
                            serial::println("");

                            self.gateway = Some(router);
                            self.iface.routes_mut().add_default_ipv4_route(router).ok();
                        }
                    }
                    dhcpv4::Event::Deconfigured => {
                        serial::println("DHCP: Lost configuration");
                        self.ip_addr = None;
                        self.gateway = None;
                    }
                }
            }
        }
    }

    /// Check if we have an IP address
    pub fn has_ip(&self) -> bool {
        self.ip_addr.is_some()
    }

    /// Get our IP address
    pub fn get_ip(&self) -> Option<Ipv4Address> {
        self.ip_addr
    }

    /// Freeze DHCP — remove the DHCP socket from the set.
    ///
    /// Once we have an IP, DHCP has served its purpose. Keeping it active
    /// causes ARP rate-limit interference with TCP connections (smoltcp's
    /// global neighbor cache `silent_until` gets reset by DHCP ARP activity,
    /// preventing TCP sockets from resolving the server's MAC address).
    ///
    /// A boot manager doesn't need lease renewal.
    pub fn freeze_dhcp(&mut self) {
        if let Some(handle) = self.dhcp_handle.take() {
            self.sockets.remove(handle);
            serial::println("DHCP: Frozen (socket removed, IP retained)");
        }
    }

    /// Create a TCP socket and return its handle
    pub fn create_tcp_socket(&mut self, rx_buffer: &'a mut [u8], tx_buffer: &'a mut [u8]) -> SocketHandle {
        let rx_buf = tcp::SocketBuffer::new(rx_buffer);
        let tx_buf = tcp::SocketBuffer::new(tx_buffer);
        let socket = tcp::Socket::new(rx_buf, tx_buf);
        self.sockets.add(socket)
    }

    /// Connect a TCP socket to a remote endpoint
    pub fn tcp_connect(&mut self, handle: SocketHandle, remote: IpEndpoint) -> bool {
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        let local_port = 49152 + (now().total_millis() as u16 % 16384); // Ephemeral port
        match socket.connect(self.iface.context(), remote, local_port) {
            Ok(()) => {
                serial::print("TCP: Connecting to ");
                let ip = match remote.addr {
                    smoltcp::wire::IpAddress::Ipv4(addr) => addr,
                    _ => Ipv4Address::UNSPECIFIED,
                };
                serial::print_dec(ip.0[0] as u32);
                serial::print(".");
                serial::print_dec(ip.0[1] as u32);
                serial::print(".");
                serial::print_dec(ip.0[2] as u32);
                serial::print(".");
                serial::print_dec(ip.0[3] as u32);
                serial::print(":");
                serial::print_dec(remote.port as u32);
                serial::println("");
                true
            }
            Err(_) => {
                serial::println("TCP: Connect failed");
                false
            }
        }
    }

    /// Check if TCP socket is connected
    pub fn tcp_is_connected(&mut self, handle: SocketHandle) -> bool {
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        socket.is_active() && socket.may_send()
    }

    /// Check if TCP socket can send
    pub fn tcp_can_send(&mut self, handle: SocketHandle) -> bool {
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        socket.can_send()
    }

    /// Check if TCP socket can receive
    pub fn tcp_can_recv(&mut self, handle: SocketHandle) -> bool {
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        socket.can_recv()
    }

    /// Send data on TCP socket
    pub fn tcp_send(&mut self, handle: SocketHandle, data: &[u8]) -> usize {
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        match socket.send_slice(data) {
            Ok(n) => n,
            Err(_) => 0,
        }
    }

    /// Receive data from TCP socket
    pub fn tcp_recv(&mut self, handle: SocketHandle, buffer: &mut [u8]) -> usize {
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        match socket.recv_slice(buffer) {
            Ok(n) => n,
            Err(_) => 0,
        }
    }

    /// Get TCP socket state as a debug string
    pub fn tcp_state_str(&mut self, handle: SocketHandle) -> &'static str {
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        match socket.state() {
            tcp::State::Closed => "Closed",
            tcp::State::Listen => "Listen",
            tcp::State::SynSent => "SynSent",
            tcp::State::SynReceived => "SynReceived",
            tcp::State::Established => "Established",
            tcp::State::FinWait1 => "FinWait1",
            tcp::State::FinWait2 => "FinWait2",
            tcp::State::CloseWait => "CloseWait",
            tcp::State::Closing => "Closing",
            tcp::State::LastAck => "LastAck",
            tcp::State::TimeWait => "TimeWait",
        }
    }

    /// Close and remove TCP socket, freeing the SocketSet slot
    pub fn tcp_close(&mut self, handle: SocketHandle) {
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        socket.abort(); // RST — immediate close, no TIME_WAIT
        self.sockets.remove(handle); // Free the slot
    }
}

/// Format MAC address as colon-separated hex string
pub fn format_mac(mac: &[u8; 6], buf: &mut [u8]) -> usize {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut pos = 0;
    for (i, &byte) in mac.iter().enumerate() {
        if i > 0 && pos < buf.len() {
            buf[pos] = b':';
            pos += 1;
        }
        if pos < buf.len() {
            buf[pos] = HEX[(byte >> 4) as usize];
            pos += 1;
        }
        if pos < buf.len() {
            buf[pos] = HEX[(byte & 0xf) as usize];
            pos += 1;
        }
    }
    pos
}

/// Format IPv4 address as dotted decimal string
pub fn format_ip(ip: &Ipv4Address, buf: &mut [u8]) -> usize {
    let mut pos = 0;
    for (i, &byte) in ip.0.iter().enumerate() {
        if i > 0 && pos < buf.len() {
            buf[pos] = b'.';
            pos += 1;
        }
        // Write decimal digits
        if byte >= 100 {
            buf[pos] = b'0' + byte / 100;
            pos += 1;
            buf[pos] = b'0' + (byte / 10) % 10;
            pos += 1;
        } else if byte >= 10 {
            buf[pos] = b'0' + byte / 10;
            pos += 1;
        }
        buf[pos] = b'0' + byte % 10;
        pos += 1;
    }
    pos
}

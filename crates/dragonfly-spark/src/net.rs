//! Network stack integration using smoltcp
//!
//! Provides TCP/IP networking over VirtIO-net

use crate::serial;
use crate::virtio_net::VirtioNet;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::dhcpv4;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr, Ipv4Address};

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
        self.device.send(&buffer[..len]);
        result
    }
}

/// Simple monotonic clock based on CPU cycles (approximate)
static mut TICK_COUNT: u64 = 0;

pub fn now() -> Instant {
    // Increment tick counter (very approximate timing)
    unsafe {
        TICK_COUNT += 1;
    }
    Instant::from_millis(unsafe { TICK_COUNT } as i64)
}

/// Network stack state
pub struct NetworkStack<'a> {
    pub device: NetDevice,
    pub iface: Interface,
    pub sockets: SocketSet<'a>,
    pub dhcp_handle: Option<smoltcp::iface::SocketHandle>,
    pub ip_addr: Option<Ipv4Address>,
    pub gateway: Option<Ipv4Address>,
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
        let mut iface = Interface::new(config, &mut device, now());

        // Set a random IP address initially (will be replaced by DHCP)
        iface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(Ipv4Address::UNSPECIFIED.into(), 0)).ok();
        });

        let mut sockets = SocketSet::new(socket_storage);

        // Create DHCP socket (smoltcp 0.11 - no buffer arguments)
        let dhcp_socket = dhcpv4::Socket::new();
        let dhcp_handle = sockets.add(dhcp_socket);

        serial::println("Network: Stack initialized, starting DHCP...");

        Some(NetworkStack {
            device,
            iface,
            sockets,
            dhcp_handle: Some(dhcp_handle),
            ip_addr: None,
            gateway: None,
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

                        // Update interface with DHCP-assigned address
                        self.iface.update_ip_addrs(|addrs| {
                            addrs.clear();
                            addrs.push(config.address.into()).ok();
                        });

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
}

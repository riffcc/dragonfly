//! HTTP client for Dragonfly server communication
//!
//! Minimal HTTP/1.1 client for check-in with Dragonfly server.
//! Uses the existing TCP socket primitives from smoltcp.

use crate::disk::OsInfo;
use crate::hw;
use crate::net::{self, format_ip, format_mac, NetworkStack};
use crate::serial;
use smoltcp::wire::{IpEndpoint, Ipv4Address};

/// Agent action returned by server
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AgentAction {
    /// Wait for user to assign a workflow (show menu)
    Wait,
    /// Execute the assigned workflow (chainload Mage)
    Execute,
    /// Reboot the machine
    Reboot,
    /// Boot the existing local OS
    LocalBoot,
}

/// Response from server check-in
#[derive(Debug)]
pub struct CheckInResponse {
    /// Machine ID assigned by server
    pub machine_id: [u8; 64],
    pub machine_id_len: usize,
    /// Whether this is a new registration
    pub is_new: bool,
    /// What action to take
    pub action: AgentAction,
    /// Workflow ID if action is Execute
    pub workflow_id: Option<[u8; 64]>,
    pub workflow_id_len: usize,
}

impl Default for CheckInResponse {
    fn default() -> Self {
        Self {
            machine_id: [0; 64],
            machine_id_len: 0,
            is_new: false,
            action: AgentAction::Wait,
            workflow_id: None,
            workflow_id_len: 0,
        }
    }
}

/// Static TCP buffers for check-in (only one check-in at a time)
static mut TCP_RX_BUFFER: [u8; 2048] = [0u8; 2048];
static mut TCP_TX_BUFFER: [u8; 2048] = [0u8; 2048];

/// Perform check-in with Dragonfly server
///
/// Returns the action the agent should take, or None if check-in failed.
///
/// # Safety
/// Uses static buffers - only one check-in can be in progress at a time.
pub fn checkin(
    stack: &mut NetworkStack<'_>,
    server_ip: Ipv4Address,
    server_port: u16,
    mac: &[u8; 6],
    detected_os: Option<&OsInfo>,
) -> Option<CheckInResponse> {
    serial::println("HTTP: Starting check-in with server");

    // Build JSON payload
    let mut json_buf = [0u8; 512];
    let json_len = build_checkin_json(mac, stack.get_ip()?, detected_os, &mut json_buf);

    serial::print("HTTP: JSON payload (");
    serial::print_dec(json_len as u32);
    serial::println(" bytes):");
    if let Ok(s) = core::str::from_utf8(&json_buf[..json_len]) {
        serial::println(s);
    }

    // Build HTTP request
    let mut http_buf = [0u8; 1024];
    let http_len = build_http_request(&json_buf[..json_len], &server_ip, server_port, &mut http_buf);

    // Create TCP socket using static buffers
    // SAFETY: Only one check-in can be in progress at a time (single-threaded bare metal)
    #[allow(static_mut_refs)]
    let tcp_handle = unsafe {
        stack.create_tcp_socket(&mut TCP_RX_BUFFER, &mut TCP_TX_BUFFER)
    };

    // Connect to server
    let endpoint = IpEndpoint::new(server_ip.into(), server_port);
    if !stack.tcp_connect(tcp_handle, endpoint) {
        serial::println("HTTP: Failed to initiate connection");
        return None;
    }

    // Wait for connection (2 second timeout)
    let mut connected = false;
    let start = net::now().total_millis();
    while (net::now().total_millis() - start) < 2000 {
        stack.poll();
        if stack.tcp_is_connected(tcp_handle) {
            connected = true;
            serial::println("HTTP: Connected!");
            break;
        }
    }

    if !connected {
        serial::print("HTTP: Connection timeout, state=");
        serial::println(stack.tcp_state_str(tcp_handle));
        stack.tcp_close(tcp_handle);
        return None;
    }

    // Send request (fast timeout - 200ms max)
    let mut sent = 0;
    let send_start = net::now().total_millis();
    while sent < http_len && (net::now().total_millis() - send_start) < 200 {
        stack.poll();
        if stack.tcp_can_send(tcp_handle) {
            let n = stack.tcp_send(tcp_handle, &http_buf[sent..http_len]);
            sent += n;
        }
    }

    serial::print("HTTP: Sent ");
    serial::print_dec(sent as u32);
    serial::println(" bytes");

    if sent < http_len {
        serial::println("HTTP: Failed to send complete request");
        stack.tcp_close(tcp_handle);
        return None;
    }

    // Wait for response (fast timeout - 500ms max)
    let mut response_buf = [0u8; 2048];
    let mut response_len = 0;
    let recv_start = net::now().total_millis();

    while (net::now().total_millis() - recv_start) < 500 {
        stack.poll();
        if stack.tcp_can_recv(tcp_handle) {
            let n = stack.tcp_recv(tcp_handle, &mut response_buf[response_len..]);
            response_len += n;
            if n == 0 {
                break; // Connection closed
            }
            // Check if we have complete response (ends with \r\n\r\n followed by body)
            if response_len > 4 {
                // Simple heuristic: look for double CRLF and assume body follows
                for i in 0..response_len.saturating_sub(3) {
                    if &response_buf[i..i+4] == b"\r\n\r\n" {
                        // Found headers end, give a bit more time for body
                        let body_start = i + 4;
                        if response_len > body_start + 10 {
                            // We have some body, break
                            break;
                        }
                    }
                }
            }
        }
    }

    serial::print("HTTP: Received ");
    serial::print_dec(response_len as u32);
    serial::println(" bytes");

    // Close and remove socket
    stack.tcp_close(tcp_handle);

    if response_len == 0 {
        serial::println("HTTP: No response from server");
        return None;
    }

    // Parse response
    parse_checkin_response(&response_buf[..response_len])
}

/// Build JSON check-in payload
fn build_checkin_json(
    mac: &[u8; 6],
    ip: Ipv4Address,
    detected_os: Option<&OsInfo>,
    buf: &mut [u8],
) -> usize {
    let mut pos = 0;

    // Helper to safely write bytes
    fn write_bytes(buf: &mut [u8], pos: &mut usize, data: &[u8]) {
        let end = *pos + data.len();
        if end <= buf.len() {
            buf[*pos..end].copy_from_slice(data);
            *pos = end;
        }
    }

    // Start object with MAC
    write_bytes(buf, &mut pos, b"{\"mac\":\"");
    pos += format_mac(mac, &mut buf[pos..]);
    write_bytes(buf, &mut pos, b"\"");

    // IP address
    write_bytes(buf, &mut pos, b",\"ip_address\":\"");
    pos += format_ip(&ip, &mut buf[pos..]);
    write_bytes(buf, &mut pos, b"\"");

    // Is virtual (always true for now in QEMU testing)
    write_bytes(buf, &mut pos, b",\"is_virtual\":true");

    // CPU model
    let (brand, brand_len) = hw::cpu_brand();
    if brand_len > 0 {
        write_bytes(buf, &mut pos, b",\"cpu_model\":\"");
        let copy_len = brand_len.min(buf.len().saturating_sub(pos + 20));
        if copy_len > 0 && pos + copy_len <= buf.len() {
            buf[pos..pos + copy_len].copy_from_slice(&brand[..copy_len]);
            pos += copy_len;
        }
        write_bytes(buf, &mut pos, b"\"");
    }

    // CPU cores
    let cores = hw::cpu_cores();
    write_bytes(buf, &mut pos, b",\"cpu_cores\":");
    pos += write_u32_decimal(&mut buf[pos..], cores);

    // Existing OS info if detected
    if let Some(os) = detected_os {
        write_bytes(buf, &mut pos, b",\"existing_os\":{\"name\":\"");

        let name = os.display_name();
        let name_bytes = name.as_bytes();
        let name_len = name_bytes.len().min(buf.len().saturating_sub(pos + 50));
        if name_len > 0 && pos + name_len <= buf.len() {
            buf[pos..pos+name_len].copy_from_slice(&name_bytes[..name_len]);
            pos += name_len;
        }

        write_bytes(buf, &mut pos, b"\",\"device\":\"/dev/sda\"}");
    }

    // Close main object
    write_bytes(buf, &mut pos, b"}");

    pos
}

/// Build HTTP POST request
fn build_http_request(body: &[u8], server_ip: &Ipv4Address, port: u16, buf: &mut [u8]) -> usize {
    let mut pos = 0;

    // Helper to safely write bytes
    fn write(buf: &mut [u8], pos: &mut usize, data: &[u8]) {
        let end = *pos + data.len();
        if end <= buf.len() {
            buf[*pos..end].copy_from_slice(data);
            *pos = end;
        }
    }

    // Request line
    write(buf, &mut pos, b"POST /api/agent/checkin HTTP/1.1\r\n");

    // Host header
    write(buf, &mut pos, b"Host: ");
    pos += format_ip(server_ip, &mut buf[pos..]);
    write(buf, &mut pos, b":");

    // Write port as decimal
    if port >= 10000 {
        buf[pos] = b'0' + (port / 10000) as u8;
        pos += 1;
    }
    if port >= 1000 {
        buf[pos] = b'0' + ((port / 1000) % 10) as u8;
        pos += 1;
    }
    if port >= 100 {
        buf[pos] = b'0' + ((port / 100) % 10) as u8;
        pos += 1;
    }
    if port >= 10 {
        buf[pos] = b'0' + ((port / 10) % 10) as u8;
        pos += 1;
    }
    buf[pos] = b'0' + (port % 10) as u8;
    pos += 1;
    write(buf, &mut pos, b"\r\n");

    // Content-Type header (32 bytes)
    write(buf, &mut pos, b"Content-Type: application/json\r\n");

    // Content-Length header
    write(buf, &mut pos, b"Content-Length: ");
    let body_len = body.len();
    if body_len >= 100 {
        buf[pos] = b'0' + (body_len / 100) as u8;
        pos += 1;
    }
    if body_len >= 10 {
        buf[pos] = b'0' + ((body_len / 10) % 10) as u8;
        pos += 1;
    }
    buf[pos] = b'0' + (body_len % 10) as u8;
    pos += 1;
    write(buf, &mut pos, b"\r\n");

    // Connection header (19 bytes)
    write(buf, &mut pos, b"Connection: close\r\n");

    // End of headers
    write(buf, &mut pos, b"\r\n");

    // Body
    let body_end = pos + body.len();
    if body_end <= buf.len() {
        buf[pos..body_end].copy_from_slice(body);
        pos = body_end;
    }

    pos
}

/// Parse check-in response JSON
fn parse_checkin_response(response: &[u8]) -> Option<CheckInResponse> {
    // Find HTTP status
    if !response.starts_with(b"HTTP/1.1 ") && !response.starts_with(b"HTTP/1.0 ") {
        serial::println("HTTP: Invalid response - not HTTP");
        return None;
    }

    // Check status code (bytes 9-11)
    let status = &response[9..12];
    if status != b"200" && status != b"201" {
        serial::print("HTTP: Server returned status ");
        if let Ok(s) = core::str::from_utf8(status) {
            serial::println(s);
        }
        return None;
    }

    serial::println("HTTP: Got 200/201 response");

    // Find body (after \r\n\r\n)
    let body_start = find_subsequence(response, b"\r\n\r\n")? + 4;
    let body = &response[body_start..];

    serial::print("HTTP: Response body: ");
    if let Ok(s) = core::str::from_utf8(body) {
        serial::println(s);
    }

    // Parse JSON response
    let mut result = CheckInResponse::default();

    // Find "action" field
    if let Some(action_pos) = find_subsequence(body, b"\"action\":\"") {
        let value_start = action_pos + 10;
        if let Some(value_end) = find_byte(&body[value_start..], b'"') {
            let action_str = &body[value_start..value_start + value_end];
            result.action = match action_str {
                b"wait" => AgentAction::Wait,
                b"execute" => AgentAction::Execute,
                b"reboot" => AgentAction::Reboot,
                b"localboot" => AgentAction::LocalBoot,
                _ => {
                    serial::print("HTTP: Unknown action: ");
                    if let Ok(s) = core::str::from_utf8(action_str) {
                        serial::println(s);
                    }
                    AgentAction::Wait
                }
            };
            serial::print("HTTP: Action = ");
            serial::println(match result.action {
                AgentAction::Wait => "wait",
                AgentAction::Execute => "execute",
                AgentAction::Reboot => "reboot",
                AgentAction::LocalBoot => "localboot",
            });
        }
    }

    // Find "is_new" field
    if find_subsequence(body, b"\"is_new\":true").is_some() {
        result.is_new = true;
        serial::println("HTTP: is_new = true");
    }

    // Find "machine_id" field
    if let Some(id_pos) = find_subsequence(body, b"\"machine_id\":\"") {
        let value_start = id_pos + 14;
        if let Some(value_end) = find_byte(&body[value_start..], b'"') {
            let id_len = value_end.min(result.machine_id.len());
            result.machine_id[..id_len].copy_from_slice(&body[value_start..value_start + id_len]);
            result.machine_id_len = id_len;
        }
    }

    // Find "workflow_id" field
    if let Some(wf_pos) = find_subsequence(body, b"\"workflow_id\":\"") {
        let value_start = wf_pos + 15;
        if let Some(value_end) = find_byte(&body[value_start..], b'"') {
            let mut wf_buf = [0u8; 64];
            let id_len = value_end.min(wf_buf.len());
            wf_buf[..id_len].copy_from_slice(&body[value_start..value_start + id_len]);
            result.workflow_id = Some(wf_buf);
            result.workflow_id_len = id_len;
        }
    }

    Some(result)
}

/// Write a u32 as decimal into a buffer, return bytes written
fn write_u32_decimal(buf: &mut [u8], mut n: u32) -> usize {
    if n == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
        }
        return 1;
    }
    // Write digits in reverse, then reverse
    let mut tmp = [0u8; 10];
    let mut len = 0;
    while n > 0 {
        tmp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    let copy_len = len.min(buf.len());
    for i in 0..copy_len {
        buf[i] = tmp[len - 1 - i];
    }
    copy_len
}

/// Template entry parsed from server response
#[derive(Debug)]
pub struct TemplateEntry {
    pub name: [u8; 64],
    pub name_len: usize,
    pub display_name: [u8; 64],
    pub display_name_len: usize,
}

/// Template list from server
pub struct TemplateList {
    pub entries: [TemplateEntry; 16],
    pub count: usize,
}

impl Default for TemplateEntry {
    fn default() -> Self {
        Self {
            name: [0; 64],
            name_len: 0,
            display_name: [0; 64],
            display_name_len: 0,
        }
    }
}

/// ISO entry parsed from server response
#[derive(Debug)]
pub struct IsoEntry {
    pub name: [u8; 64],
    pub name_len: usize,
}

/// ISO list from server
pub struct IsoList {
    pub entries: [IsoEntry; 16],
    pub count: usize,
}

impl Default for IsoEntry {
    fn default() -> Self {
        Self {
            name: [0; 64],
            name_len: 0,
        }
    }
}

/// Static TCP buffers for agent API calls (reused, single-threaded)
static mut AGENT_TCP_RX: [u8; 4096] = [0u8; 4096];
static mut AGENT_TCP_TX: [u8; 4096] = [0u8; 4096];

/// Helper: perform HTTP GET and return response body
fn http_get(
    stack: &mut NetworkStack<'_>,
    server_ip: Ipv4Address,
    server_port: u16,
    path: &[u8],
) -> Option<([u8; 4096], usize)> {
    // Build GET request
    let mut req_buf = [0u8; 512];
    let mut pos = 0;

    fn wr(buf: &mut [u8], pos: &mut usize, data: &[u8]) {
        let end = *pos + data.len();
        if end <= buf.len() {
            buf[*pos..end].copy_from_slice(data);
            *pos = end;
        }
    }

    wr(&mut req_buf, &mut pos, b"GET ");
    wr(&mut req_buf, &mut pos, path);
    wr(&mut req_buf, &mut pos, b" HTTP/1.1\r\nHost: ");
    pos += format_ip(&server_ip, &mut req_buf[pos..]);
    wr(&mut req_buf, &mut pos, b"\r\nConnection: close\r\n\r\n");

    // Create socket
    #[allow(static_mut_refs)]
    let tcp_handle = unsafe {
        stack.create_tcp_socket(&mut AGENT_TCP_RX, &mut AGENT_TCP_TX)
    };

    let endpoint = IpEndpoint::new(server_ip.into(), server_port);
    if !stack.tcp_connect(tcp_handle, endpoint) {
        return None;
    }

    // Wait for connection (2s)
    let start = net::now().total_millis();
    let mut connected = false;
    while (net::now().total_millis() - start) < 2000 {
        stack.poll();
        if stack.tcp_is_connected(tcp_handle) {
            connected = true;
            break;
        }
    }
    if !connected {
        serial::print("HTTP GET: Connection timeout, state=");
        serial::println(stack.tcp_state_str(tcp_handle));
        stack.tcp_close(tcp_handle);
        return None;
    }

    // Send request
    let mut sent = 0;
    let send_start = net::now().total_millis();
    while sent < pos && (net::now().total_millis() - send_start) < 200 {
        stack.poll();
        if stack.tcp_can_send(tcp_handle) {
            let n = stack.tcp_send(tcp_handle, &req_buf[sent..pos]);
            sent += n;
        }
    }

    // Receive response
    let mut resp_buf = [0u8; 4096];
    let mut resp_len = 0;
    let recv_start = net::now().total_millis();
    while (net::now().total_millis() - recv_start) < 500 {
        stack.poll();
        if stack.tcp_can_recv(tcp_handle) {
            let n = stack.tcp_recv(tcp_handle, &mut resp_buf[resp_len..]);
            resp_len += n;
            if n == 0 { break; }
        }
    }

    stack.tcp_close(tcp_handle);

    if resp_len == 0 { return None; }

    // Check for 200 OK
    if !resp_buf.starts_with(b"HTTP/1.1 200") && !resp_buf.starts_with(b"HTTP/1.0 200") {
        return None;
    }

    // Find body
    if let Some(body_start) = find_subsequence(&resp_buf[..resp_len], b"\r\n\r\n") {
        let start = body_start + 4;
        let body_len = resp_len - start;
        let mut body = [0u8; 4096];
        body[..body_len].copy_from_slice(&resp_buf[start..resp_len]);
        Some((body, body_len))
    } else {
        None
    }
}

/// Helper: perform HTTP POST with JSON body and return success
fn http_post_json(
    stack: &mut NetworkStack<'_>,
    server_ip: Ipv4Address,
    server_port: u16,
    path: &[u8],
    body: &[u8],
) -> bool {
    let mut req_buf = [0u8; 1024];
    let mut pos = 0;

    fn wr(buf: &mut [u8], pos: &mut usize, data: &[u8]) {
        let end = *pos + data.len();
        if end <= buf.len() {
            buf[*pos..end].copy_from_slice(data);
            *pos = end;
        }
    }

    wr(&mut req_buf, &mut pos, b"POST ");
    wr(&mut req_buf, &mut pos, path);
    wr(&mut req_buf, &mut pos, b" HTTP/1.1\r\nHost: ");
    pos += format_ip(&server_ip, &mut req_buf[pos..]);
    wr(&mut req_buf, &mut pos, b"\r\nContent-Type: application/json\r\nContent-Length: ");
    pos += write_u32_decimal(&mut req_buf[pos..], body.len() as u32);
    wr(&mut req_buf, &mut pos, b"\r\nConnection: close\r\n\r\n");
    // Append body
    let body_end = pos + body.len();
    if body_end <= req_buf.len() {
        req_buf[pos..body_end].copy_from_slice(body);
        pos = body_end;
    }

    // Create socket
    #[allow(static_mut_refs)]
    let tcp_handle = unsafe {
        stack.create_tcp_socket(&mut AGENT_TCP_RX, &mut AGENT_TCP_TX)
    };

    let endpoint = IpEndpoint::new(server_ip.into(), server_port);
    if !stack.tcp_connect(tcp_handle, endpoint) {
        return false;
    }

    let start = net::now().total_millis();
    let mut connected = false;
    while (net::now().total_millis() - start) < 2000 {
        stack.poll();
        if stack.tcp_is_connected(tcp_handle) {
            connected = true;
            break;
        }
    }
    if !connected {
        serial::print("HTTP POST: Connection timeout, state=");
        serial::println(stack.tcp_state_str(tcp_handle));
        stack.tcp_close(tcp_handle);
        return false;
    }

    let mut sent = 0;
    let send_start = net::now().total_millis();
    while sent < pos && (net::now().total_millis() - send_start) < 200 {
        stack.poll();
        if stack.tcp_can_send(tcp_handle) {
            let n = stack.tcp_send(tcp_handle, &req_buf[sent..pos]);
            sent += n;
        }
    }

    // Read response status
    let mut resp_buf = [0u8; 512];
    let mut resp_len = 0;
    let recv_start = net::now().total_millis();
    while (net::now().total_millis() - recv_start) < 500 {
        stack.poll();
        if stack.tcp_can_recv(tcp_handle) {
            let n = stack.tcp_recv(tcp_handle, &mut resp_buf[resp_len..]);
            resp_len += n;
            if n == 0 { break; }
            if resp_len > 20 { break; } // Just need status line
        }
    }

    stack.tcp_close(tcp_handle);

    resp_buf[..resp_len].starts_with(b"HTTP/1.1 200") || resp_buf[..resp_len].starts_with(b"HTTP/1.0 200")
}

/// Request OS installation from server
///
/// Tells the server to assign the given template and flag for reimage.
/// On success, Spark should reboot into imaging (Mage).
pub fn request_install(
    stack: &mut NetworkStack<'_>,
    server_ip: Ipv4Address,
    server_port: u16,
    machine_id: &[u8],
    machine_id_len: usize,
    mac: &[u8; 6],
    template_name: &[u8],
    template_name_len: usize,
) -> bool {
    serial::println("HTTP: Requesting OS install");

    let mut body = [0u8; 256];
    let mut pos = 0;

    fn wr(buf: &mut [u8], pos: &mut usize, data: &[u8]) {
        let end = *pos + data.len();
        if end <= buf.len() { buf[*pos..end].copy_from_slice(data); *pos = end; }
    }

    wr(&mut body, &mut pos, b"{\"machine_id\":\"");
    let id_len = machine_id_len.min(body.len().saturating_sub(pos + 50));
    body[pos..pos + id_len].copy_from_slice(&machine_id[..id_len]);
    pos += id_len;
    wr(&mut body, &mut pos, b"\",\"mac\":\"");
    pos += format_mac(mac, &mut body[pos..]);
    wr(&mut body, &mut pos, b"\",\"template_name\":\"");
    let tpl_len = template_name_len.min(body.len().saturating_sub(pos + 10));
    body[pos..pos + tpl_len].copy_from_slice(&template_name[..tpl_len]);
    pos += tpl_len;
    wr(&mut body, &mut pos, b"\"}");

    http_post_json(stack, server_ip, server_port, b"/api/agent/request-install", &body[..pos])
}

/// Remove this machine from Dragonfly server
pub fn remove_machine(
    stack: &mut NetworkStack<'_>,
    server_ip: Ipv4Address,
    server_port: u16,
    machine_id: &[u8],
    machine_id_len: usize,
    mac: &[u8; 6],
) -> bool {
    serial::println("HTTP: Requesting machine removal");

    let mut body = [0u8; 256];
    let mut pos = 0;

    fn wr(buf: &mut [u8], pos: &mut usize, data: &[u8]) {
        let end = *pos + data.len();
        if end <= buf.len() { buf[*pos..end].copy_from_slice(data); *pos = end; }
    }

    wr(&mut body, &mut pos, b"{\"machine_id\":\"");
    let id_len = machine_id_len.min(body.len().saturating_sub(pos + 30));
    body[pos..pos + id_len].copy_from_slice(&machine_id[..id_len]);
    pos += id_len;
    wr(&mut body, &mut pos, b"\",\"mac\":\"");
    pos += format_mac(mac, &mut body[pos..]);
    wr(&mut body, &mut pos, b"\"}");

    http_post_json(stack, server_ip, server_port, b"/api/agent/remove", &body[..pos])
}

/// Request a boot mode from server (memtest, rescue, or iso)
///
/// Sets a one-shot boot-mode tag on the machine. After rebooting,
/// iPXE fetches the boot script from the server, which sees the tag
/// and generates the appropriate script (memtest86+, rescue env, or sanboot).
pub fn request_boot_mode(
    stack: &mut NetworkStack<'_>,
    server_ip: Ipv4Address,
    server_port: u16,
    machine_id: &[u8],
    machine_id_len: usize,
    mac: &[u8; 6],
    mode: &[u8],
    mode_len: usize,
    iso_name: Option<(&[u8], usize)>,
) -> bool {
    serial::print("HTTP: Requesting boot mode: ");
    if let Ok(s) = core::str::from_utf8(&mode[..mode_len]) {
        serial::println(s);
    }

    let mut body = [0u8; 512];
    let mut pos = 0;

    fn wr(buf: &mut [u8], pos: &mut usize, data: &[u8]) {
        let end = *pos + data.len();
        if end <= buf.len() { buf[*pos..end].copy_from_slice(data); *pos = end; }
    }

    wr(&mut body, &mut pos, b"{\"machine_id\":\"");
    let id_len = machine_id_len.min(body.len().saturating_sub(pos + 100));
    body[pos..pos + id_len].copy_from_slice(&machine_id[..id_len]);
    pos += id_len;
    wr(&mut body, &mut pos, b"\",\"mac\":\"");
    pos += format_mac(mac, &mut body[pos..]);
    wr(&mut body, &mut pos, b"\",\"mode\":\"");
    let m_len = mode_len.min(body.len().saturating_sub(pos + 50));
    body[pos..pos + m_len].copy_from_slice(&mode[..m_len]);
    pos += m_len;
    wr(&mut body, &mut pos, b"\"");

    // Include iso_name if provided
    if let Some((name, name_len)) = iso_name {
        wr(&mut body, &mut pos, b",\"iso_name\":\"");
        let n_len = name_len.min(body.len().saturating_sub(pos + 10));
        body[pos..pos + n_len].copy_from_slice(&name[..n_len]);
        pos += n_len;
        wr(&mut body, &mut pos, b"\"");
    }

    wr(&mut body, &mut pos, b"}");

    http_post_json(stack, server_ip, server_port, b"/api/agent/boot-mode", &body[..pos])
}

/// Get list of available ISO images from server
pub fn get_isos(
    stack: &mut NetworkStack<'_>,
    server_ip: Ipv4Address,
    server_port: u16,
) -> Option<IsoList> {
    let (body, body_len) = http_get(stack, server_ip, server_port, b"/api/agent/isos")?;

    let mut list = IsoList {
        entries: core::array::from_fn(|_| IsoEntry::default()),
        count: 0,
    };

    // Parse JSON array of strings: ["debian-13.iso", "ubuntu-24.04.iso", ...]
    let body_slice = &body[..body_len];
    let mut search_start = 0;

    // Look for quoted strings inside the array
    while list.count < 16 && search_start < body_len {
        // Find next opening quote
        if let Some(quote_pos) = find_byte(&body_slice[search_start..], b'"') {
            let abs_start = search_start + quote_pos + 1;
            if abs_start >= body_len { break; }
            // Find closing quote
            if let Some(end_pos) = find_byte(&body_slice[abs_start..], b'"') {
                let entry = &mut list.entries[list.count];
                let len = end_pos.min(entry.name.len());
                entry.name[..len].copy_from_slice(&body_slice[abs_start..abs_start + len]);
                entry.name_len = len;
                list.count += 1;
                search_start = abs_start + end_pos + 1;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    if list.count > 0 { Some(list) } else { None }
}

/// Get list of OS templates from server
pub fn get_templates(
    stack: &mut NetworkStack<'_>,
    server_ip: Ipv4Address,
    server_port: u16,
) -> Option<TemplateList> {
    let (body, body_len) = http_get(stack, server_ip, server_port, b"/api/templates")?;

    let mut list = TemplateList {
        entries: core::array::from_fn(|_| TemplateEntry::default()),
        count: 0,
    };

    // Parse JSON array of template objects.
    // Each object has: "name", "display_name", "enabled" fields.
    // We skip disabled templates (enabled:false).
    //
    // Strategy: find each object boundary { ... }, then extract fields within it.
    let body_slice = &body[..body_len];
    let mut search_start = 0;

    while list.count < 16 {
        // Find next object start
        let remaining = &body_slice[search_start..];
        let obj_start = match find_byte(remaining, b'{') {
            Some(p) => search_start + p,
            None => break,
        };
        // Find object end (no nested objects in TemplateInfo)
        let obj_remaining = &body_slice[obj_start..];
        let obj_end = match find_byte(obj_remaining, b'}') {
            Some(p) => obj_start + p + 1,
            None => break,
        };
        let obj = &body_slice[obj_start..obj_end];

        // Check enabled field — skip disabled templates
        if find_subsequence(obj, b"\"enabled\":false").is_some() {
            search_start = obj_end;
            continue;
        }

        // Extract "name" field
        let (name_bytes, name_len) = extract_json_string(obj, b"\"name\":\"");

        if name_len > 0 {
            let entry = &mut list.entries[list.count];

            // Copy name
            let len = name_len.min(entry.name.len());
            entry.name[..len].copy_from_slice(&name_bytes[..len]);
            entry.name_len = len;

            // Try to extract display_name; fall back to name
            let (dn_bytes, dn_len) = extract_json_string(obj, b"\"display_name\":\"");
            if dn_len > 0 {
                let dl = dn_len.min(entry.display_name.len());
                entry.display_name[..dl].copy_from_slice(&dn_bytes[..dl]);
                entry.display_name_len = dl;
            } else {
                entry.display_name[..len].copy_from_slice(&name_bytes[..len]);
                entry.display_name_len = len;
            }

            list.count += 1;
        }

        search_start = obj_end;
    }

    if list.count > 0 { Some(list) } else { None }
}

/// Extract a JSON string value given a key prefix like `"name":"`.
/// Returns (buffer, length). Length is 0 if not found.
fn extract_json_string(obj: &[u8], key_prefix: &[u8]) -> ([u8; 64], usize) {
    let mut buf = [0u8; 64];
    if let Some(kp) = find_subsequence(obj, key_prefix) {
        let val_start = kp + key_prefix.len();
        if let Some(val_end) = find_byte(&obj[val_start..], b'"') {
            let len = val_end.min(buf.len());
            buf[..len].copy_from_slice(&obj[val_start..val_start + len]);
            return (buf, len);
        }
    }
    (buf, 0)
}

/// Find subsequence in byte slice
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// Find single byte in slice
fn find_byte(haystack: &[u8], needle: u8) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

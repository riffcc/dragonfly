//! HTTP client for Dragonfly server communication
//!
//! Minimal HTTP/1.1 client for check-in with Dragonfly server.
//! Uses the existing TCP socket primitives from smoltcp.

use crate::disk::OsInfo;
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

    // Wait for connection (fast timeout - 300ms max)
    let mut connected = false;
    let start = net::now().total_millis();
    while (net::now().total_millis() - start) < 300 {
        stack.poll();
        if stack.tcp_is_connected(tcp_handle) {
            connected = true;
            serial::println("HTTP: Connected!");
            break;
        }
    }

    if !connected {
        serial::println("HTTP: Connection timeout (300ms)");
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

    // Close connection
    stack.tcp_close(tcp_handle);

    // Poll to process close
    for _ in 0..1000 {
        stack.poll();
    }

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

    // Request line (30 bytes)
    write(buf, &mut pos, b"POST /agent/checkin HTTP/1.1\r\n");

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

/// Find subsequence in byte slice
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// Find single byte in slice
fn find_byte(haystack: &[u8], needle: u8) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

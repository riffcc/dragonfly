//! TFTP server implementation
//!
//! This module provides the main TFTP server that serves files for PXE boot,
//! primarily iPXE binaries and boot scripts.

use crate::error::{Result, TftpError};
use crate::packet::{ErrorCode, TftpOptions, TftpPacket};
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// Default block size (RFC 1350)
pub const DEFAULT_BLOCK_SIZE: u16 = 512;

/// Maximum block size (RFC 2348)
pub const MAX_BLOCK_SIZE: u16 = 65464;

/// Default timeout in seconds
pub const DEFAULT_TIMEOUT: u8 = 5;

/// Maximum retries
pub const MAX_RETRIES: u32 = 5;

/// Default window size (RFC 1350 single-block lockstep)
pub const DEFAULT_WINDOW_SIZE: u16 = 1;

/// Maximum window size we accept (RFC 7440 allows up to 65535)
pub const MAX_WINDOW_SIZE: u16 = 64;

/// Trait for providing files to the TFTP server
#[async_trait]
pub trait FileProvider: Send + Sync {
    /// Get file contents by path
    async fn get_file(&self, path: &str) -> Option<Bytes>;

    /// Get file size (for tsize option)
    async fn get_file_size(&self, path: &str) -> Option<u64>;
}

/// Event emitted by the TFTP server
#[derive(Debug, Clone)]
pub enum TftpEvent {
    /// Server started
    Started { bind_addr: SocketAddr },
    /// Transfer started
    TransferStarted {
        client: SocketAddr,
        filename: String,
        size: Option<u64>,
    },
    /// Transfer progress
    TransferProgress {
        client: SocketAddr,
        filename: String,
        bytes_sent: u64,
        total_bytes: Option<u64>,
    },
    /// Transfer completed
    TransferCompleted {
        client: SocketAddr,
        filename: String,
        bytes_sent: u64,
    },
    /// Transfer failed
    TransferFailed {
        client: SocketAddr,
        filename: String,
        error: String,
    },
    /// Server stopped
    Stopped,
}

/// TFTP server
pub struct TftpServer {
    bind_ip: Ipv4Addr,
    file_provider: Arc<dyn FileProvider>,
    event_sender: broadcast::Sender<TftpEvent>,
}

impl TftpServer {
    /// Create a new TFTP server
    pub fn new(bind_ip: Ipv4Addr, file_provider: Arc<dyn FileProvider>) -> Self {
        let (event_sender, _) = broadcast::channel(1024);
        Self {
            bind_ip,
            file_provider,
            event_sender,
        }
    }

    /// Subscribe to server events
    pub fn subscribe(&self) -> broadcast::Receiver<TftpEvent> {
        self.event_sender.subscribe()
    }

    /// Run the TFTP server
    pub async fn run(&self, shutdown: tokio::sync::watch::Receiver<bool>) -> Result<()> {
        let bind_addr = SocketAddrV4::new(self.bind_ip, 69);

        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| TftpError::BindFailed {
                addr: bind_addr.into(),
                source: e,
            })?;

        info!(addr = %bind_addr, "TFTP server started");
        let _ = self.event_sender.send(TftpEvent::Started {
            bind_addr: bind_addr.into(),
        });

        let mut buf = [0u8; 65535];
        let mut shutdown = shutdown;

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src)) => {
                            let data = buf[..len].to_vec();
                            let file_provider = self.file_provider.clone();
                            let event_sender = self.event_sender.clone();

                            // Handle each request in a new task
                            tokio::spawn(async move {
                                if let Err(e) = handle_request(data, src, file_provider, event_sender).await {
                                    error!(error = %e, client = %src, "Error handling TFTP request");
                                }
                            });
                        }
                        Err(e) => {
                            error!(error = %e, "Error receiving packet");
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("TFTP server shutting down");
                        let _ = self.event_sender.send(TftpEvent::Stopped);
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

/// Handle a single TFTP request
async fn handle_request(
    data: Vec<u8>,
    client: SocketAddr,
    file_provider: Arc<dyn FileProvider>,
    event_sender: broadcast::Sender<TftpEvent>,
) -> Result<()> {
    let packet = TftpPacket::parse(&data)?;

    match packet {
        TftpPacket::ReadRequest {
            filename,
            mode: _,
            options,
        } => handle_read_request(client, &filename, options, file_provider, event_sender).await,
        TftpPacket::WriteRequest { .. } => {
            // We don't accept writes
            send_error(client, ErrorCode::AccessViolation, "Write not supported").await
        }
        _ => {
            // Unexpected packet type
            send_error(client, ErrorCode::IllegalOperation, "Unexpected packet").await
        }
    }
}

/// Handle a read request
async fn handle_read_request(
    client: SocketAddr,
    filename: &str,
    options: TftpOptions,
    file_provider: Arc<dyn FileProvider>,
    event_sender: broadcast::Sender<TftpEvent>,
) -> Result<()> {
    debug!(client = %client, filename = %filename, "Read request");

    // Normalize filename (remove leading slashes)
    let filename = filename.trim_start_matches('/');

    // Get file contents
    let file_data = match file_provider.get_file(filename).await {
        Some(data) => data,
        None => {
            warn!(client = %client, filename = %filename, "File not found");
            let _ = event_sender.send(TftpEvent::TransferFailed {
                client,
                filename: filename.to_string(),
                error: "File not found".to_string(),
            });
            return send_error(client, ErrorCode::FileNotFound, "File not found").await;
        }
    };

    let file_size = file_data.len() as u64;

    // Create a new socket for this transfer (using ephemeral port)
    let transfer_socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(TftpError::IoError)?;

    // Negotiate options
    let block_size = options
        .blksize
        .map(|b| b.min(MAX_BLOCK_SIZE).max(8))
        .unwrap_or(DEFAULT_BLOCK_SIZE);

    let timeout_secs = options.timeout.unwrap_or(DEFAULT_TIMEOUT);

    let window_size = options
        .windowsize
        .map(|w| w.min(MAX_WINDOW_SIZE).max(1))
        .unwrap_or(DEFAULT_WINDOW_SIZE);

    // Send OACK if client requested options — RFC 2347: only echo back
    // options the client actually asked for AND that we support.
    // RFC 7440: acknowledge windowsize for windowed transfers.
    // If the client rejects our OACK, fall back to plain 512-byte transfers.
    let mut block_size = block_size;
    let mut window_size = window_size;
    if !options.is_empty() {
        let oack_options = TftpOptions {
            blksize: options.blksize.map(|_| block_size),
            tsize: options.tsize.map(|_| file_size),
            timeout: options.timeout,
            windowsize: options.windowsize.map(|_| window_size),
        };

        let oack = TftpPacket::oack(oack_options);
        transfer_socket
            .send_to(&oack.encode(), client)
            .await
            .map_err(TftpError::IoError)?;

        // Wait for ACK 0
        let mut ack_buf = [0u8; 512];
        let ack_timeout = Duration::from_secs(timeout_secs as u64);

        match timeout(ack_timeout, transfer_socket.recv_from(&mut ack_buf)).await {
            Ok(Ok((len, _))) => {
                let ack = TftpPacket::parse(&ack_buf[..len])?;
                match ack {
                    TftpPacket::Ack { block: 0 } => {}
                    TftpPacket::Error { code, message } => {
                        // Client rejected OACK — fall back to plain transfer
                        // with default 512-byte blocks (RFC 1350 baseline).
                        // Some firmware (Proxmox UEFI) won't retry, so we
                        // must degrade gracefully instead of giving up.
                        warn!(
                            client = %client,
                            code = ?code,
                            message = %message,
                            "Client rejected OACK, falling back to defaults"
                        );
                        block_size = DEFAULT_BLOCK_SIZE;
                        window_size = DEFAULT_WINDOW_SIZE;
                    }
                    _ => {
                        return send_error_on(
                            &transfer_socket,
                            client,
                            ErrorCode::IllegalOperation,
                            "Expected ACK",
                        )
                        .await;
                    }
                }
            }
            Ok(Err(e)) => return Err(TftpError::IoError(e)),
            Err(_) => {
                let _ = event_sender.send(TftpEvent::TransferFailed {
                    client,
                    filename: filename.to_string(),
                    error: "Timeout waiting for OACK acknowledgment".to_string(),
                });
                return Err(TftpError::Timeout {
                    filename: filename.to_string(),
                });
            }
        }
    }

    let _ = event_sender.send(TftpEvent::TransferStarted {
        client,
        filename: filename.to_string(),
        size: Some(file_size),
    });

    // Send file using windowed transfer (RFC 7440)
    //
    // With windowsize=1 this is identical to classic RFC 1350 lockstep.
    // With windowsize>1, we send N DATA blocks before waiting for an ACK
    // of the last block in the window. On partial ACK (client missed a
    // block), we retransmit from the block after the ACKed one. On timeout,
    // we retransmit the entire window.
    let block_size_usize = block_size as usize;
    let window_size_usize = window_size as usize;
    let mut block_num: u16 = 1;
    let mut offset: usize = 0;
    let timeout_duration = Duration::from_secs(timeout_secs as u64);

    if window_size > 1 {
        debug!(
            client = %client,
            window_size = window_size,
            block_size = block_size,
            "Windowed transfer (RFC 7440)"
        );
    }

    'transfer: loop {
        let window_start_block = block_num;
        let window_start_offset = offset;
        let mut sent_count: u16 = 0;
        let mut is_final_window = false;

        // Phase 1: Send a window of DATA blocks
        for _ in 0..window_size_usize {
            let end = (offset + block_size_usize).min(file_data.len());
            let block_data = file_data.slice(offset..end);
            let is_last_block = block_data.len() < block_size_usize;

            let current_block = window_start_block.wrapping_add(sent_count);
            let data_packet = TftpPacket::data(current_block, block_data);
            transfer_socket
                .send_to(&data_packet.encode(), client)
                .await
                .map_err(TftpError::IoError)?;

            sent_count += 1;
            offset = end;

            if is_last_block {
                // Short block (or zero-length when file is exact multiple of block_size)
                // signals end of transfer per RFC 1350
                is_final_window = true;
                break;
            }
        }

        let window_last_block = window_start_block.wrapping_add(sent_count - 1);

        // Phase 2: Wait for ACK of last block in window
        let mut retries = 0;
        'ack: loop {
            let mut ack_buf = [0u8; 512];
            match timeout(timeout_duration, transfer_socket.recv_from(&mut ack_buf)).await {
                Ok(Ok((len, _))) => {
                    let ack = TftpPacket::parse(&ack_buf[..len])?;
                    match ack {
                        TftpPacket::Ack { block } if block == window_last_block => {
                            // Full window acknowledged
                            block_num = window_last_block.wrapping_add(1);
                            break 'ack;
                        }
                        TftpPacket::Ack { block } => {
                            // Check if partial ACK within our window
                            let acked_blocks =
                                block.wrapping_sub(window_start_block).wrapping_add(1);
                            if acked_blocks > 0 && acked_blocks < sent_count {
                                // Partial ACK — client got some blocks, retransmit the rest
                                let acked_usize = acked_blocks as usize;
                                offset =
                                    window_start_offset + (acked_usize * block_size_usize);
                                block_num = block.wrapping_add(1);
                                debug!(
                                    client = %client,
                                    acked = block,
                                    expected = window_last_block,
                                    "Partial window ACK, retransmitting from block {}",
                                    block_num
                                );
                                break 'ack;
                            }
                            // Stale ACK from before this window — ignore
                            continue 'ack;
                        }
                        TftpPacket::Error { code, message } => {
                            warn!(client = %client, code = ?code, message = %message, "Client error");
                            let _ = event_sender.send(TftpEvent::TransferFailed {
                                client,
                                filename: filename.to_string(),
                                error: message,
                            });
                            return Ok(());
                        }
                        _ => {
                            retries += 1;
                            if retries >= MAX_RETRIES {
                                let _ = event_sender.send(TftpEvent::TransferFailed {
                                    client,
                                    filename: filename.to_string(),
                                    error: "Too many retries".to_string(),
                                });
                                return Err(TftpError::Timeout {
                                    filename: filename.to_string(),
                                });
                            }
                        }
                    }
                }
                Ok(Err(e)) => return Err(TftpError::IoError(e)),
                Err(_) => {
                    retries += 1;
                    if retries >= MAX_RETRIES {
                        let _ = event_sender.send(TftpEvent::TransferFailed {
                            client,
                            filename: filename.to_string(),
                            error: "Timeout".to_string(),
                        });
                        return Err(TftpError::Timeout {
                            filename: filename.to_string(),
                        });
                    }
                    // Retransmit entire window
                    offset = window_start_offset;
                    block_num = window_start_block;
                    debug!(
                        client = %client,
                        window_start = window_start_block,
                        retry = retries,
                        "Window timeout, retransmitting"
                    );
                    break 'ack;
                }
            }
        }

        // Report progress
        let bytes_sent = offset as u64;
        let _ = event_sender.send(TftpEvent::TransferProgress {
            client,
            filename: filename.to_string(),
            bytes_sent,
            total_bytes: Some(file_size),
        });

        if is_final_window {
            break 'transfer;
        }
    }

    info!(client = %client, filename = %filename, bytes = file_size, "Transfer completed");
    let _ = event_sender.send(TftpEvent::TransferCompleted {
        client,
        filename: filename.to_string(),
        bytes_sent: file_size,
    });

    Ok(())
}

/// Send an error packet to client (using new socket)
async fn send_error(client: SocketAddr, code: ErrorCode, message: &str) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(TftpError::IoError)?;

    send_error_on(&socket, client, code, message).await
}

/// Send an error packet on existing socket
async fn send_error_on(
    socket: &UdpSocket,
    client: SocketAddr,
    code: ErrorCode,
    message: &str,
) -> Result<()> {
    let error = TftpPacket::error(code, message);
    socket
        .send_to(&error.encode(), client)
        .await
        .map_err(TftpError::IoError)?;
    Ok(())
}

impl std::fmt::Debug for TftpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TftpServer")
            .field("bind_ip", &self.bind_ip)
            .finish_non_exhaustive()
    }
}

/// In-memory file provider for testing and static files
pub struct MemoryFileProvider {
    files: HashMap<String, Bytes>,
}

impl MemoryFileProvider {
    /// Create a new memory file provider
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
        }
    }

    /// Add a file
    pub fn add_file(&mut self, path: impl Into<String>, data: impl Into<Bytes>) {
        self.files.insert(path.into(), data.into());
    }
}

impl Default for MemoryFileProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FileProvider for MemoryFileProvider {
    async fn get_file(&self, path: &str) -> Option<Bytes> {
        self.files.get(path).cloned()
    }

    async fn get_file_size(&self, path: &str) -> Option<u64> {
        self.files.get(path).map(|b| b.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_file_provider() {
        let mut provider = MemoryFileProvider::new();
        provider.add_file("test.txt", Bytes::from_static(b"hello"));

        // Can't easily test async in sync test, but we can test the structure
        assert!(provider.files.contains_key("test.txt"));
    }

    #[tokio::test]
    async fn test_memory_file_provider_get() {
        let mut provider = MemoryFileProvider::new();
        provider.add_file("ipxe.efi", Bytes::from_static(b"fake ipxe binary"));

        let file = provider.get_file("ipxe.efi").await;
        assert!(file.is_some());
        assert_eq!(&file.unwrap()[..], b"fake ipxe binary");

        let missing = provider.get_file("nonexistent.txt").await;
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_memory_file_provider_size() {
        let mut provider = MemoryFileProvider::new();
        provider.add_file("kernel", vec![0u8; 1024]);

        let size = provider.get_file_size("kernel").await;
        assert_eq!(size, Some(1024));

        let missing_size = provider.get_file_size("missing").await;
        assert!(missing_size.is_none());
    }

    #[test]
    fn test_tftp_server_new() {
        let provider = Arc::new(MemoryFileProvider::new());
        let server = TftpServer::new(Ipv4Addr::new(0, 0, 0, 0), provider);
        assert_eq!(server.bind_ip, Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn test_tftp_server_subscribe() {
        let provider = Arc::new(MemoryFileProvider::new());
        let server = TftpServer::new(Ipv4Addr::new(0, 0, 0, 0), provider);
        let _receiver = server.subscribe();
    }
}

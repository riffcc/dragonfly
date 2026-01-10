//! TFTP packet handling
//!
//! This module provides utilities for parsing and building TFTP packets
//! according to RFC 1350.

use crate::error::{Result, TftpError};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// TFTP opcodes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Opcode {
    /// Read request
    Rrq = 1,
    /// Write request
    Wrq = 2,
    /// Data packet
    Data = 3,
    /// Acknowledgment
    Ack = 4,
    /// Error
    Error = 5,
    /// Option acknowledgment (RFC 2347)
    Oack = 6,
}

impl TryFrom<u16> for Opcode {
    type Error = TftpError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Opcode::Rrq),
            2 => Ok(Opcode::Wrq),
            3 => Ok(Opcode::Data),
            4 => Ok(Opcode::Ack),
            5 => Ok(Opcode::Error),
            6 => Ok(Opcode::Oack),
            _ => Err(TftpError::InvalidPacket(format!("unknown opcode: {}", value))),
        }
    }
}

/// TFTP error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    /// Not defined
    NotDefined = 0,
    /// File not found
    FileNotFound = 1,
    /// Access violation
    AccessViolation = 2,
    /// Disk full
    DiskFull = 3,
    /// Illegal operation
    IllegalOperation = 4,
    /// Unknown transfer ID
    UnknownTransferId = 5,
    /// File already exists
    FileAlreadyExists = 6,
    /// No such user
    NoSuchUser = 7,
    /// Option negotiation failed (RFC 2347)
    OptionNegotiationFailed = 8,
}

/// TFTP transfer mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferMode {
    /// Binary (octet) mode
    Octet,
    /// ASCII (netascii) mode
    NetAscii,
}

impl TransferMode {
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "octet" => Ok(TransferMode::Octet),
            "netascii" => Ok(TransferMode::NetAscii),
            _ => Err(TftpError::InvalidPacket(format!("unknown mode: {}", s))),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            TransferMode::Octet => "octet",
            TransferMode::NetAscii => "netascii",
        }
    }
}

/// TFTP options (RFC 2347, 2348, 2349)
#[derive(Debug, Clone, Default)]
pub struct TftpOptions {
    /// Block size (RFC 2348)
    pub blksize: Option<u16>,
    /// Transfer size (RFC 2349)
    pub tsize: Option<u64>,
    /// Timeout (RFC 2349)
    pub timeout: Option<u8>,
    /// Window size (RFC 7440)
    pub windowsize: Option<u16>,
}

impl TftpOptions {
    /// Check if any options are set
    pub fn is_empty(&self) -> bool {
        self.blksize.is_none()
            && self.tsize.is_none()
            && self.timeout.is_none()
            && self.windowsize.is_none()
    }
}

/// TFTP packet types
#[derive(Debug, Clone)]
pub enum TftpPacket {
    /// Read request
    ReadRequest {
        filename: String,
        mode: TransferMode,
        options: TftpOptions,
    },
    /// Write request
    WriteRequest {
        filename: String,
        mode: TransferMode,
        options: TftpOptions,
    },
    /// Data packet
    Data { block: u16, data: Bytes },
    /// Acknowledgment
    Ack { block: u16 },
    /// Error
    Error { code: ErrorCode, message: String },
    /// Option acknowledgment
    Oack { options: TftpOptions },
}

impl TftpPacket {
    /// Parse a TFTP packet from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(TftpError::InvalidPacket("packet too short".to_string()));
        }

        let mut buf = data;
        let opcode = Opcode::try_from(buf.get_u16())?;

        match opcode {
            Opcode::Rrq => Self::parse_request(buf, false),
            Opcode::Wrq => Self::parse_request(buf, true),
            Opcode::Data => Self::parse_data(buf),
            Opcode::Ack => Self::parse_ack(buf),
            Opcode::Error => Self::parse_error(buf),
            Opcode::Oack => Self::parse_oack(buf),
        }
    }

    fn parse_request(data: &[u8], is_write: bool) -> Result<Self> {
        let mut parts = data.split(|&b| b == 0);

        let filename = parts
            .next()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .ok_or_else(|| TftpError::InvalidPacket("missing filename".to_string()))?;

        let mode_str = parts
            .next()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .ok_or_else(|| TftpError::InvalidPacket("missing mode".to_string()))?;

        let mode = TransferMode::from_str(&mode_str)?;

        // Parse options (key-value pairs)
        let mut options = TftpOptions::default();
        loop {
            let key = match parts.next() {
                Some(k) if !k.is_empty() => String::from_utf8_lossy(k).to_lowercase(),
                _ => break,
            };
            let value = match parts.next() {
                Some(v) => String::from_utf8_lossy(v).to_string(),
                _ => break,
            };

            match key.as_str() {
                "blksize" => options.blksize = value.parse().ok(),
                "tsize" => options.tsize = value.parse().ok(),
                "timeout" => options.timeout = value.parse().ok(),
                "windowsize" => options.windowsize = value.parse().ok(),
                _ => {} // Ignore unknown options
            }
        }

        if is_write {
            Ok(TftpPacket::WriteRequest {
                filename,
                mode,
                options,
            })
        } else {
            Ok(TftpPacket::ReadRequest {
                filename,
                mode,
                options,
            })
        }
    }

    fn parse_data(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(TftpError::InvalidPacket("data packet too short".to_string()));
        }

        let mut buf = data;
        let block = buf.get_u16();
        let data = Bytes::copy_from_slice(buf);

        Ok(TftpPacket::Data { block, data })
    }

    fn parse_ack(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(TftpError::InvalidPacket("ack packet too short".to_string()));
        }

        let mut buf = data;
        let block = buf.get_u16();

        Ok(TftpPacket::Ack { block })
    }

    fn parse_error(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(TftpError::InvalidPacket("error packet too short".to_string()));
        }

        let mut buf = data;
        let code_num = buf.get_u16();
        let code = match code_num {
            0 => ErrorCode::NotDefined,
            1 => ErrorCode::FileNotFound,
            2 => ErrorCode::AccessViolation,
            3 => ErrorCode::DiskFull,
            4 => ErrorCode::IllegalOperation,
            5 => ErrorCode::UnknownTransferId,
            6 => ErrorCode::FileAlreadyExists,
            7 => ErrorCode::NoSuchUser,
            8 => ErrorCode::OptionNegotiationFailed,
            _ => ErrorCode::NotDefined,
        };

        let message = buf
            .split(|&b| b == 0)
            .next()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .unwrap_or_default();

        Ok(TftpPacket::Error { code, message })
    }

    fn parse_oack(data: &[u8]) -> Result<Self> {
        let mut parts = data.split(|&b| b == 0);
        let mut options = TftpOptions::default();

        loop {
            let key = match parts.next() {
                Some(k) if !k.is_empty() => String::from_utf8_lossy(k).to_lowercase(),
                _ => break,
            };
            let value = match parts.next() {
                Some(v) => String::from_utf8_lossy(v).to_string(),
                _ => break,
            };

            match key.as_str() {
                "blksize" => options.blksize = value.parse().ok(),
                "tsize" => options.tsize = value.parse().ok(),
                "timeout" => options.timeout = value.parse().ok(),
                "windowsize" => options.windowsize = value.parse().ok(),
                _ => {}
            }
        }

        Ok(TftpPacket::Oack { options })
    }

    /// Encode the packet to bytes
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();

        match self {
            TftpPacket::ReadRequest {
                filename,
                mode,
                options,
            } => {
                buf.put_u16(Opcode::Rrq as u16);
                buf.put_slice(filename.as_bytes());
                buf.put_u8(0);
                buf.put_slice(mode.as_str().as_bytes());
                buf.put_u8(0);
                Self::encode_options(&mut buf, options);
            }
            TftpPacket::WriteRequest {
                filename,
                mode,
                options,
            } => {
                buf.put_u16(Opcode::Wrq as u16);
                buf.put_slice(filename.as_bytes());
                buf.put_u8(0);
                buf.put_slice(mode.as_str().as_bytes());
                buf.put_u8(0);
                Self::encode_options(&mut buf, options);
            }
            TftpPacket::Data { block, data } => {
                buf.put_u16(Opcode::Data as u16);
                buf.put_u16(*block);
                buf.put_slice(data);
            }
            TftpPacket::Ack { block } => {
                buf.put_u16(Opcode::Ack as u16);
                buf.put_u16(*block);
            }
            TftpPacket::Error { code, message } => {
                buf.put_u16(Opcode::Error as u16);
                buf.put_u16(*code as u16);
                buf.put_slice(message.as_bytes());
                buf.put_u8(0);
            }
            TftpPacket::Oack { options } => {
                buf.put_u16(Opcode::Oack as u16);
                Self::encode_options(&mut buf, options);
            }
        }

        buf.freeze()
    }

    fn encode_options(buf: &mut BytesMut, options: &TftpOptions) {
        if let Some(blksize) = options.blksize {
            buf.put_slice(b"blksize");
            buf.put_u8(0);
            buf.put_slice(blksize.to_string().as_bytes());
            buf.put_u8(0);
        }
        if let Some(tsize) = options.tsize {
            buf.put_slice(b"tsize");
            buf.put_u8(0);
            buf.put_slice(tsize.to_string().as_bytes());
            buf.put_u8(0);
        }
        if let Some(timeout) = options.timeout {
            buf.put_slice(b"timeout");
            buf.put_u8(0);
            buf.put_slice(timeout.to_string().as_bytes());
            buf.put_u8(0);
        }
        if let Some(windowsize) = options.windowsize {
            buf.put_slice(b"windowsize");
            buf.put_u8(0);
            buf.put_slice(windowsize.to_string().as_bytes());
            buf.put_u8(0);
        }
    }

    /// Create an error packet
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        TftpPacket::Error {
            code,
            message: message.into(),
        }
    }

    /// Create a data packet
    pub fn data(block: u16, data: impl Into<Bytes>) -> Self {
        TftpPacket::Data {
            block,
            data: data.into(),
        }
    }

    /// Create an ACK packet
    pub fn ack(block: u16) -> Self {
        TftpPacket::Ack { block }
    }

    /// Create an OACK packet
    pub fn oack(options: TftpOptions) -> Self {
        TftpPacket::Oack { options }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_try_from() {
        assert_eq!(Opcode::try_from(1).unwrap(), Opcode::Rrq);
        assert_eq!(Opcode::try_from(2).unwrap(), Opcode::Wrq);
        assert_eq!(Opcode::try_from(3).unwrap(), Opcode::Data);
        assert_eq!(Opcode::try_from(4).unwrap(), Opcode::Ack);
        assert_eq!(Opcode::try_from(5).unwrap(), Opcode::Error);
        assert_eq!(Opcode::try_from(6).unwrap(), Opcode::Oack);
        assert!(Opcode::try_from(99).is_err());
    }

    #[test]
    fn test_transfer_mode() {
        assert_eq!(TransferMode::from_str("octet").unwrap(), TransferMode::Octet);
        assert_eq!(TransferMode::from_str("OCTET").unwrap(), TransferMode::Octet);
        assert_eq!(
            TransferMode::from_str("netascii").unwrap(),
            TransferMode::NetAscii
        );
        assert!(TransferMode::from_str("invalid").is_err());
    }

    #[test]
    fn test_parse_rrq() {
        // RRQ packet: opcode(2) + filename + 0 + mode + 0
        let mut packet = vec![0x00, 0x01]; // RRQ opcode
        packet.extend_from_slice(b"ipxe.efi");
        packet.push(0);
        packet.extend_from_slice(b"octet");
        packet.push(0);

        let parsed = TftpPacket::parse(&packet).unwrap();
        match parsed {
            TftpPacket::ReadRequest {
                filename, mode, ..
            } => {
                assert_eq!(filename, "ipxe.efi");
                assert_eq!(mode, TransferMode::Octet);
            }
            _ => panic!("expected ReadRequest"),
        }
    }

    #[test]
    fn test_parse_rrq_with_options() {
        let mut packet = vec![0x00, 0x01]; // RRQ opcode
        packet.extend_from_slice(b"kernel");
        packet.push(0);
        packet.extend_from_slice(b"octet");
        packet.push(0);
        packet.extend_from_slice(b"blksize");
        packet.push(0);
        packet.extend_from_slice(b"1428");
        packet.push(0);
        packet.extend_from_slice(b"tsize");
        packet.push(0);
        packet.extend_from_slice(b"0");
        packet.push(0);

        let parsed = TftpPacket::parse(&packet).unwrap();
        match parsed {
            TftpPacket::ReadRequest { options, .. } => {
                assert_eq!(options.blksize, Some(1428));
                assert_eq!(options.tsize, Some(0));
            }
            _ => panic!("expected ReadRequest"),
        }
    }

    #[test]
    fn test_parse_data() {
        let mut packet = vec![0x00, 0x03]; // DATA opcode
        packet.extend_from_slice(&[0x00, 0x01]); // block 1
        packet.extend_from_slice(b"Hello, world!");

        let parsed = TftpPacket::parse(&packet).unwrap();
        match parsed {
            TftpPacket::Data { block, data } => {
                assert_eq!(block, 1);
                assert_eq!(&data[..], b"Hello, world!");
            }
            _ => panic!("expected Data"),
        }
    }

    #[test]
    fn test_parse_ack() {
        let packet = vec![0x00, 0x04, 0x00, 0x05]; // ACK block 5
        let parsed = TftpPacket::parse(&packet).unwrap();
        match parsed {
            TftpPacket::Ack { block } => {
                assert_eq!(block, 5);
            }
            _ => panic!("expected Ack"),
        }
    }

    #[test]
    fn test_parse_error() {
        let mut packet = vec![0x00, 0x05]; // ERROR opcode
        packet.extend_from_slice(&[0x00, 0x01]); // File not found
        packet.extend_from_slice(b"File not found");
        packet.push(0);

        let parsed = TftpPacket::parse(&packet).unwrap();
        match parsed {
            TftpPacket::Error { code, message } => {
                assert_eq!(code, ErrorCode::FileNotFound);
                assert_eq!(message, "File not found");
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn test_encode_ack() {
        let packet = TftpPacket::ack(42);
        let encoded = packet.encode();
        assert_eq!(&encoded[..], &[0x00, 0x04, 0x00, 42]);
    }

    #[test]
    fn test_encode_data() {
        let packet = TftpPacket::data(1, Bytes::from_static(b"test data"));
        let encoded = packet.encode();
        assert_eq!(&encoded[0..4], &[0x00, 0x03, 0x00, 0x01]);
        assert_eq!(&encoded[4..], b"test data");
    }

    #[test]
    fn test_encode_error() {
        let packet = TftpPacket::error(ErrorCode::FileNotFound, "not found");
        let encoded = packet.encode();
        assert_eq!(&encoded[0..4], &[0x00, 0x05, 0x00, 0x01]);
        assert_eq!(&encoded[4..encoded.len() - 1], b"not found");
        assert_eq!(encoded[encoded.len() - 1], 0); // null terminator
    }

    #[test]
    fn test_encode_oack() {
        let options = TftpOptions {
            blksize: Some(1024),
            tsize: Some(12345),
            timeout: None,
            windowsize: None,
        };
        let packet = TftpPacket::oack(options);
        let encoded = packet.encode();

        // Parse back to verify
        let parsed = TftpPacket::parse(&encoded).unwrap();
        match parsed {
            TftpPacket::Oack { options } => {
                assert_eq!(options.blksize, Some(1024));
                assert_eq!(options.tsize, Some(12345));
            }
            _ => panic!("expected Oack"),
        }
    }

    #[test]
    fn test_roundtrip_rrq() {
        let original = TftpPacket::ReadRequest {
            filename: "test.bin".to_string(),
            mode: TransferMode::Octet,
            options: TftpOptions {
                blksize: Some(512),
                tsize: Some(1024),
                timeout: Some(5),
                windowsize: Some(1),
            },
        };

        let encoded = original.encode();
        let parsed = TftpPacket::parse(&encoded).unwrap();

        match parsed {
            TftpPacket::ReadRequest {
                filename,
                mode,
                options,
            } => {
                assert_eq!(filename, "test.bin");
                assert_eq!(mode, TransferMode::Octet);
                assert_eq!(options.blksize, Some(512));
                assert_eq!(options.tsize, Some(1024));
                assert_eq!(options.timeout, Some(5));
                assert_eq!(options.windowsize, Some(1));
            }
            _ => panic!("expected ReadRequest"),
        }
    }
}

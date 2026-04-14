//! VLESS protocol client implementation (RFC draft).
//!
//! Encodes/decodes VLESS headers and manages the multiplexed connection
//! to the NodeShift proxy server.

use bytes::{BufMut, BytesMut, Bytes};
use crate::{config::ServerConfig, CoreError, Result};
use crate::crypto::parse_uuid;

pub const VLESS_VERSION:   u8 = 0x00;
pub const CMD_TCP:         u8 = 0x01;
pub const CMD_UDP:         u8 = 0x02;
pub const ADDR_IPV4:       u8 = 0x01;
pub const ADDR_DOMAIN:     u8 = 0x02;
pub const ADDR_IPV6:       u8 = 0x03;
pub const OPT_CHUNK_STREAM: u8 = 0x01;

/// Parsed VLESS response header.
#[derive(Debug)]
pub struct VlessResponse {
    pub version:      u8,
    pub addons_len:   u8,
    pub addons:       Bytes,
}

/// VLESS protocol client.
pub struct VlessClient {
    config: ServerConfig,
    uuid:   [u8; 16],
}

impl VlessClient {
    pub fn new(config: ServerConfig) -> Result<Self> {
        let uuid = parse_uuid(&config.uuid)?;
        Ok(Self { config, uuid })
    }

    /// Build a VLESS TCP request header targeting `dst_host:dst_port`.
    pub fn build_request_header(&self, dst_host: &str, dst_port: u16) -> Bytes {
        let mut buf = BytesMut::with_capacity(64);

        // Version
        buf.put_u8(VLESS_VERSION);

        // UUID (16 bytes)
        buf.put_slice(&self.uuid);

        // Addons (1 byte length + data): chunk-stream flow = 0x01 len + empty
        buf.put_u8(0x01);  // addons_length = 1

        // Command
        buf.put_u8(CMD_TCP);

        // Target port (big-endian)
        buf.put_u16(dst_port);

        // Address type + address
        if dst_host.parse::<std::net::Ipv4Addr>().is_ok() {
            let ip: std::net::Ipv4Addr = dst_host.parse().unwrap();
            buf.put_u8(ADDR_IPV4);
            buf.put_slice(&ip.octets());
        } else if dst_host.parse::<std::net::Ipv6Addr>().is_ok() {
            let ip: std::net::Ipv6Addr = dst_host.parse().unwrap();
            buf.put_u8(ADDR_IPV6);
            buf.put_slice(&ip.octets());
        } else {
            // Domain name
            let domain = dst_host.as_bytes();
            buf.put_u8(ADDR_DOMAIN);
            buf.put_u8(domain.len() as u8);
            buf.put_slice(domain);
        }

        buf.freeze()
    }

    /// Parse a VLESS response header from a byte slice.
    pub fn parse_response(data: &[u8]) -> Result<VlessResponse> {
        if data.len() < 2 {
            return Err(CoreError::Protocol("response too short".into()));
        }
        let version    = data[0];
        let addons_len = data[1];

        if version != VLESS_VERSION {
            return Err(CoreError::Protocol(
                format!("unexpected VLESS version: {}", version)));
        }

        let addons_end = 2 + addons_len as usize;
        if data.len() < addons_end {
            return Err(CoreError::Protocol("response truncated".into()));
        }

        Ok(VlessResponse {
            version,
            addons_len,
            addons: Bytes::copy_from_slice(&data[2..addons_end]),
        })
    }

    /// Encode a data chunk with length prefix (VLESS chunk format).
    pub fn encode_chunk(data: &[u8]) -> Bytes {
        let mut buf = BytesMut::with_capacity(2 + data.len());
        buf.put_u16(data.len() as u16);
        buf.put_slice(data);
        buf.freeze()
    }

    /// Decode a chunk header, returning (data_length, header_consumed_bytes).
    pub fn decode_chunk_header(data: &[u8]) -> Result<(usize, usize)> {
        if data.len() < 2 {
            return Err(CoreError::Protocol("chunk header incomplete".into()));
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        Ok((len, 2))
    }

    pub fn server_address(&self) -> (&str, u16) {
        (&self.config.host, self.config.port)
    }
}

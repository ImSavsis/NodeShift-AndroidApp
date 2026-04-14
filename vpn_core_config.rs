//! Tunnel configuration types for NodeShift VPN.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host:        String,
    pub port:        u16,
    pub uuid:        String,
    pub public_key:  String,      // X25519 public key (base64url)
    pub short_id:    String,      // Reality short ID (hex)
    pub sni:         String,
    pub protocol:    Protocol,
    pub fingerprint: TlsFingerprint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub server:          ServerConfig,
    pub local_address:   String,
    pub local_prefix:    u8,
    pub dns_primary:     String,
    pub dns_secondary:   String,
    pub mtu:             u32,
    pub udp_enabled:     bool,
    pub split_tunnel:    bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    VlessReality,
    VlessTls,
    Vmess,
    Trojan,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TlsFingerprint {
    #[default]
    Chrome,
    Firefox,
    Safari,
    Ios,
    Android,
    Edge,
    Random,
}

impl TunnelConfig {
    pub fn validate(&self) -> crate::Result<()> {
        if self.server.host.is_empty() {
            return Err(crate::CoreError::Config("host is empty".into()));
        }
        if self.server.uuid.len() != 36 {
            return Err(crate::CoreError::Config(
                format!("invalid UUID length: {}", self.server.uuid.len())));
        }
        if self.server.port == 0 {
            return Err(crate::CoreError::Config("port is 0".into()));
        }
        Ok(())
    }
}

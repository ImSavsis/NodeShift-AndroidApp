//! Cryptographic primitives for NodeShift VPN.

use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crate::{CoreError, Result};

pub struct KeyPair {
    pub private: [u8; 32],
    pub public:  [u8; 32],
}

/// Generate a new X25519 key pair for Reality handshake.
pub fn generate_x25519_keypair() -> KeyPair {
    let secret  = StaticSecret::random_from_rng(OsRng);
    let public  = PublicKey::from(&secret);
    KeyPair {
        private: secret.to_bytes(),
        public:  public.to_bytes(),
    }
}

/// Compute X25519 Diffie-Hellman shared secret.
pub fn x25519_dh(private_key: &[u8; 32], public_key: &[u8; 32]) -> Result<[u8; 32]> {
    let secret = StaticSecret::from(*private_key);
    let their_public = PublicKey::from(*public_key);
    Ok(secret.diffie_hellman(&their_public).to_bytes())
}

/// Parse a base64url-encoded X25519 public key.
pub fn decode_public_key(b64: &str) -> Result<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD.decode(b64)
        .map_err(|e| CoreError::Crypto(format!("base64 decode: {}", e)))?;
    if bytes.len() != 32 {
        return Err(CoreError::Crypto(format!("expected 32 bytes, got {}", bytes.len())));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// HKDF-SHA256 key derivation.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; output_len];
    hk.expand(info, &mut okm)
        .map_err(|e| CoreError::Crypto(format!("HKDF expand: {}", e)))?;
    Ok(okm)
}

/// SHA-256 hash.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Constant-time byte slice comparison.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) { diff |= x ^ y; }
    diff == 0
}

/// Parse UUID string (with dashes) into 16-byte array.
pub fn parse_uuid(uuid_str: &str) -> Result<[u8; 16]> {
    let hex: String = uuid_str.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 32 {
        return Err(CoreError::Crypto(format!("Invalid UUID: {}", uuid_str)));
    }
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = u8::from_str_radix(&hex[i*2..i*2+2], 16)
            .map_err(|e| CoreError::Crypto(e.to_string()))?;
    }
    Ok(bytes)
}

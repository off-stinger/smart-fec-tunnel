//! Channel-bound device authentication shared by the SFT QUIC transports.

use anyhow::{bail, Result};
use std::{
    collections::{HashMap, VecDeque},
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;

const MAGIC: &[u8; 4] = b"SFTA";
const VERSION: u8 = 1;
const PREFIX_LEN: usize = 4 + 1 + 8 + 8 + 16;
pub const ENVELOPE_LEN: usize = PREFIX_LEN + 32;
pub const DEFAULT_AUTH_WINDOW_SECS: u64 = 30;
pub const DEFAULT_REPLAY_CAPACITY: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthClaims {
    pub device_id: u64,
    pub timestamp: u64,
    pub nonce: [u8; 16],
}

/// Bounded process-wide replay protection. A cache local to one connection
/// cannot prevent replaying a valid proof on a second connection.
#[derive(Debug)]
pub struct ReplayCache {
    capacity: usize,
    entries: HashMap<[u8; 16], u64>,
    order: VecDeque<([u8; 16], u64)>,
}

impl ReplayCache {
    pub fn new(capacity: usize) -> Result<Self> {
        if capacity == 0 {
            bail!("replay cache capacity must be non-zero")
        }
        Ok(Self {
            capacity,
            entries: HashMap::new(),
            order: VecDeque::new(),
        })
    }

    pub fn check_and_insert(&mut self, nonce: [u8; 16], now: u64, window_secs: u64) -> bool {
        while let Some((old_nonce, expires_at)) = self.order.front().copied() {
            if expires_at > now {
                break;
            }
            self.order.pop_front();
            if self.entries.get(&old_nonce) == Some(&expires_at) {
                self.entries.remove(&old_nonce);
            }
        }
        if self.entries.contains_key(&nonce) {
            return false;
        }
        while self.entries.len() >= self.capacity {
            if let Some((old_nonce, expires_at)) = self.order.pop_front() {
                if self.entries.get(&old_nonce) == Some(&expires_at) {
                    self.entries.remove(&old_nonce);
                }
            } else {
                break;
            }
        }
        let expires_at = now.saturating_add(window_secs).saturating_add(1);
        self.entries.insert(nonce, expires_at);
        self.order.push_back((nonce, expires_at));
        true
    }
}

pub fn unix_time() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn device_key(secret: &str) -> [u8; 32] {
    *blake3::hash(secret.as_bytes()).as_bytes()
}

pub fn make_envelope(
    secret: &str,
    device_id: u64,
    timestamp: u64,
    nonce: [u8; 16],
    tls_exporter: &[u8; 32],
) -> [u8; ENVELOPE_LEN] {
    let mut out = [0u8; ENVELOPE_LEN];
    out[..4].copy_from_slice(MAGIC);
    out[4] = VERSION;
    out[5..13].copy_from_slice(&device_id.to_be_bytes());
    out[13..21].copy_from_slice(&timestamp.to_be_bytes());
    out[21..37].copy_from_slice(&nonce);
    let mut mac = blake3::Hasher::new_keyed(&device_key(secret));
    mac.update(&out[..PREFIX_LEN]);
    mac.update(tls_exporter);
    out[PREFIX_LEN..].copy_from_slice(mac.finalize().as_bytes());
    out
}

pub fn envelope_device_id(envelope: &[u8]) -> Result<u64> {
    if envelope.len() != ENVELOPE_LEN || &envelope[..4] != MAGIC || envelope[4] != VERSION {
        bail!("invalid authentication envelope")
    }
    let device_id = u64::from_be_bytes(envelope[5..13].try_into().unwrap());
    if device_id == 0 {
        bail!("device id must be non-zero")
    }
    Ok(device_id)
}

pub fn verify_envelope(
    envelope: &[u8],
    secret: &str,
    tls_exporter: &[u8; 32],
    now: u64,
    window_secs: u64,
    replay_cache: &mut ReplayCache,
) -> Result<AuthClaims> {
    if envelope.len() != ENVELOPE_LEN || &envelope[..4] != MAGIC || envelope[4] != VERSION {
        bail!("invalid authentication envelope")
    }
    let device_id = envelope_device_id(envelope)?;
    let timestamp = u64::from_be_bytes(envelope[13..21].try_into().unwrap());
    if now.abs_diff(timestamp) > window_secs {
        bail!("expired authentication envelope")
    }
    let nonce: [u8; 16] = envelope[21..37].try_into().unwrap();
    let expected = make_envelope(secret, device_id, timestamp, nonce, tls_exporter);
    if !bool::from(expected[PREFIX_LEN..].ct_eq(&envelope[PREFIX_LEN..])) {
        bail!("invalid device proof")
    }
    // Authenticate first: unauthenticated packets must not poison the cache.
    if !replay_cache.check_and_insert(nonce, now, window_secs) {
        bail!("replayed authentication envelope")
    }
    Ok(AuthClaims {
        device_id,
        timestamp,
        nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-device-secret";
    const BINDING: [u8; 32] = [7; 32];

    #[test]
    fn accepts_valid_channel_bound_envelope_once() {
        let mut cache = ReplayCache::new(8).unwrap();
        let envelope = make_envelope(SECRET, 7, 1_000, [1; 16], &BINDING);
        let claims = verify_envelope(&envelope, SECRET, &BINDING, 1_005, 30, &mut cache).unwrap();
        assert_eq!(claims.device_id, 7);
        assert!(verify_envelope(&envelope, SECRET, &BINDING, 1_005, 30, &mut cache).is_err());
    }

    #[test]
    fn rejects_wrong_secret_binding_expiry_and_zero_device() {
        let valid = make_envelope(SECRET, 7, 1_000, [2; 16], &BINDING);
        for (secret, binding, now) in [
            ("wrong", BINDING, 1_000),
            (SECRET, [8; 32], 1_000),
            (SECRET, BINDING, 1_031),
        ] {
            let mut cache = ReplayCache::new(8).unwrap();
            assert!(verify_envelope(&valid, secret, &binding, now, 30, &mut cache).is_err());
        }
        let zero = make_envelope(SECRET, 0, 1_000, [3; 16], &BINDING);
        let mut cache = ReplayCache::new(8).unwrap();
        assert!(verify_envelope(&zero, SECRET, &BINDING, 1_000, 30, &mut cache).is_err());
    }

    #[test]
    fn invalid_mac_does_not_poison_nonce_and_cache_is_bounded() {
        let mut cache = ReplayCache::new(2).unwrap();
        let mut invalid = make_envelope(SECRET, 7, 1_000, [4; 16], &BINDING);
        invalid[ENVELOPE_LEN - 1] ^= 1;
        assert!(verify_envelope(&invalid, SECRET, &BINDING, 1_000, 30, &mut cache).is_err());
        let valid = make_envelope(SECRET, 7, 1_000, [4; 16], &BINDING);
        assert!(verify_envelope(&valid, SECRET, &BINDING, 1_000, 30, &mut cache).is_ok());
        assert!(cache.check_and_insert([5; 16], 1_000, 30));
        assert!(cache.check_and_insert([6; 16], 1_000, 30));
        assert_eq!(cache.entries.len(), 2);
    }

    #[test]
    fn expired_entries_can_be_reused_after_window() {
        let mut cache = ReplayCache::new(2).unwrap();
        assert!(cache.check_and_insert([9; 16], 100, 30));
        assert!(!cache.check_and_insert([9; 16], 130, 30));
        assert!(cache.check_and_insert([9; 16], 131, 30));
    }
}

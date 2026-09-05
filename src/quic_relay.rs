//! QUIC DATAGRAM carrier for the existing authenticated SFT/FEC wire protocol.
//!
//! The client relays the already encoded SFT datagrams into QUIC. The server
//! unwraps them to a loopback legacy server. This deliberately keeps one FEC
//! implementation and provides a rollback boundary between transports.

use crate::quic_auth::{
    envelope_device_id, make_envelope, unix_time, verify_envelope, ReplayCache,
    DEFAULT_AUTH_WINDOW_SECS, DEFAULT_REPLAY_CAPACITY, ENVELOPE_LEN,
};
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use quinn::{
    congestion::{Controller, ControllerFactory},
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    rustls::{self, pki_types::CertificateDer, pki_types::PrivateKeyDer},
    ClientConfig, Connection, Endpoint, ServerConfig, TransportConfig,
};
use rand::RngCore;
use std::{
    collections::HashMap,
    fs::File,
    io::BufReader,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, sync::Mutex, time};
use tracing::{info, warn};

const ALPN: &[u8] = b"sft-quic/1";
const EXPORTER_LABEL: &[u8] = b"EXPORTER-SFT-AUTH-v1";
const MAX_DATAGRAM: usize = 65_535;
const CARRIER_HEADER: usize = 12;
const MAX_CARRIER_FRAGMENTS: usize = 128;
const MAX_CARRIER_GROUPS: usize = 2048;
const CARRIER_TTL: Duration = Duration::from_secs(3);
const CARRIER_PING: &[u8] = b"SFT-Q-PING-1";
const CARRIER_PONG: &[u8] = b"SFT-Q-PONG-1";
const CARRIER_HEARTBEAT: Duration = Duration::from_secs(2);
// QUIC DATAGRAM is intentionally unreliable. A missing PONG alone is not proof
// that the path is dead, so count any authenticated server datagram as evidence
// that the carrier is alive while retaining fast failure detection.
const CARRIER_DEAD_TIMEOUT: Duration = Duration::from_secs(6);
const CARRIER_WINDOW: u64 = 1024 * 1024;

#[derive(Clone, Debug)]
struct CarrierController {
    window: u64,
}

impl Controller for CarrierController {
    fn on_congestion_event(
        &mut self,
        _now: std::time::Instant,
        _sent: std::time::Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
        // The encapsulated TUIC connection and SFT pacer already respond to
        // congestion. Reducing this outer carrier window would punish the same
        // loss twice and collapse throughput.
    }

    fn on_mtu_update(&mut self, _new_mtu: u16) {}

    fn window(&self) -> u64 {
        self.window
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.window
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

#[derive(Debug)]
struct CarrierControllerFactory;

impl ControllerFactory for CarrierControllerFactory {
    fn build(self: Arc<Self>, _now: std::time::Instant, _current_mtu: u16) -> Box<dyn Controller> {
        Box::new(CarrierController {
            window: CARRIER_WINDOW,
        })
    }
}

#[derive(Debug)]
struct CarrierGroup {
    created: Instant,
    parts: Vec<Option<Vec<u8>>>,
}

#[derive(Debug, Default)]
struct CarrierReassembly {
    groups: HashMap<u64, CarrierGroup>,
}

impl CarrierReassembly {
    fn push(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>> {
        if frame.len() < CARRIER_HEADER {
            bail!("short QUIC carrier fragment")
        }
        let message = u64::from_be_bytes(frame[..8].try_into().unwrap());
        let index = u16::from_be_bytes(frame[8..10].try_into().unwrap()) as usize;
        let count = u16::from_be_bytes(frame[10..12].try_into().unwrap()) as usize;
        if count == 0 || count > MAX_CARRIER_FRAGMENTS || index >= count {
            bail!("invalid QUIC carrier dimensions")
        }
        let now = Instant::now();
        self.groups
            .retain(|_, group| now.duration_since(group.created) <= CARRIER_TTL);
        if !self.groups.contains_key(&message) && self.groups.len() >= MAX_CARRIER_GROUPS {
            bail!("QUIC carrier reassembly limit reached")
        }
        let group = self.groups.entry(message).or_insert_with(|| CarrierGroup {
            created: now,
            parts: vec![None; count],
        });
        if group.parts.len() != count {
            bail!("inconsistent QUIC carrier fragment count")
        }
        group.parts[index].get_or_insert_with(|| frame[CARRIER_HEADER..].to_vec());
        if group.parts.iter().any(Option::is_none) {
            return Ok(None);
        }
        let group = self.groups.remove(&message).unwrap();
        let total: usize = group
            .parts
            .iter()
            .map(|part| part.as_ref().unwrap().len())
            .sum();
        if total > MAX_DATAGRAM {
            bail!("reassembled QUIC carrier datagram too large")
        }
        let mut payload = Vec::with_capacity(total);
        for part in group.parts {
            payload.extend_from_slice(&part.unwrap());
        }
        Ok(Some(payload))
    }
}

async fn send_carrier(connection: &Connection, payload: &[u8], message: &mut u64) -> Result<()> {
    let maximum = connection
        .max_datagram_size()
        .context("peer did not negotiate QUIC DATAGRAM")?;
    if maximum <= CARRIER_HEADER {
        bail!("negotiated QUIC DATAGRAM size is too small")
    }
    let chunk = maximum - CARRIER_HEADER;
    let count = payload.len().max(1).div_ceil(chunk);
    if count > MAX_CARRIER_FRAGMENTS {
        bail!("QUIC carrier requires too many fragments")
    }
    *message = message.wrapping_add(1);
    for (index, part) in payload.chunks(chunk).enumerate() {
        let mut frame = Vec::with_capacity(CARRIER_HEADER + part.len());
        frame.extend_from_slice(&message.to_be_bytes());
        frame.extend_from_slice(&(index as u16).to_be_bytes());
        frame.extend_from_slice(&(count as u16).to_be_bytes());
        frame.extend_from_slice(part);
        connection.send_datagram_wait(Bytes::from(frame)).await?;
    }
    if payload.is_empty() {
        let mut frame = Vec::with_capacity(CARRIER_HEADER);
        frame.extend_from_slice(&message.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&1u16.to_be_bytes());
        connection.send_datagram_wait(Bytes::from(frame)).await?;
    }
    Ok(())
}

fn transport_config() -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport.max_concurrent_bidi_streams(1_u8.into());
    transport.max_idle_timeout(Some(Duration::from_secs(20).try_into().unwrap()));
    transport.keep_alive_interval(Some(Duration::from_secs(2)));
    // 1472 bytes plus the IPv4 header is a standard 1500-byte packet. Quinn's
    // PMTU discovery and black-hole detection remain enabled and can lower it;
    // the carrier fragmentation layer handles the resulting smaller DATAGRAM.
    transport.initial_mtu(1472);
    transport.congestion_controller_factory(Arc::new(CarrierControllerFactory));
    transport.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
    transport.datagram_send_buffer_size(4 * 1024 * 1024);
    Arc::new(transport)
}

fn exporter(connection: &Connection, nonce: &[u8; 16]) -> Result<[u8; 32]> {
    let mut binding = [0u8; 32];
    connection
        .export_keying_material(&mut binding, EXPORTER_LABEL, nonce)
        .map_err(|_| anyhow::anyhow!("TLS exporter failed"))?;
    Ok(binding)
}

fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(
        File::open(path).with_context(|| format!("open certificate {}", path.display()))?,
    );
    let certificates: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<_, _>>()
        .context("parse certificate PEM")?;
    if certificates.is_empty() {
        bail!("certificate file is empty")
    }
    Ok(certificates)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(
        File::open(path).with_context(|| format!("open private key {}", path.display()))?,
    );
    rustls_pemfile::private_key(&mut reader)
        .context("parse private key PEM")?
        .context("private key file is empty")
}

fn server_endpoint(listen: SocketAddr, cert: &Path, private_key: &Path) -> Result<Endpoint> {
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(load_certificates(cert)?, load_private_key(private_key)?)?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let mut config = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    config.transport_config(transport_config());
    Endpoint::server(config, listen).context("bind QUIC server")
}

fn client_endpoint(bind: SocketAddr, ca_cert: &Path) -> Result<Endpoint> {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in load_certificates(ca_cert)? {
        roots.add(certificate).context("add trusted certificate")?;
    }
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let mut config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
    config.transport_config(transport_config());
    let mut endpoint = Endpoint::client(bind).context("bind QUIC client")?;
    endpoint.set_default_client_config(config);
    Ok(endpoint)
}

fn parse_keyring(path: &Path) -> Result<HashMap<u64, String>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read keyring {}", path.display()))?;
    let mut keys = HashMap::new();
    for (line_index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let id: u64 = fields
            .next()
            .context("missing device id")?
            .parse()
            .with_context(|| format!("invalid device id on line {}", line_index + 1))?;
        let secret = fields.next().context("missing device secret")?;
        if id == 0 || secret.len() < 16 || fields.next().is_some() || keys.contains_key(&id) {
            bail!("invalid keyring entry on line {}", line_index + 1)
        }
        keys.insert(id, secret.to_owned());
    }
    if keys.is_empty() {
        bail!("keyring contains no devices")
    }
    Ok(keys)
}

async fn authenticate_client(connection: &Connection, device_id: u64, secret: &str) -> Result<()> {
    if device_id == 0 {
        bail!("device id must be non-zero")
    }
    let (mut send, mut receive) = connection.open_bi().await?;
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let proof = make_envelope(
        secret,
        device_id,
        unix_time()?,
        nonce,
        &exporter(connection, &nonce)?,
    );
    send.write_all(&proof).await?;
    send.finish()?;
    if receive.read_to_end(16).await? != b"OK" {
        bail!("QUIC device authentication rejected")
    }
    Ok(())
}

async fn authenticate_server(
    connection: &Connection,
    keys: &HashMap<u64, String>,
    replays: &Mutex<ReplayCache>,
) -> Result<u64> {
    let (mut send, mut receive) = time::timeout(Duration::from_secs(5), connection.accept_bi())
        .await
        .context("authentication stream timeout")??;
    let proof = receive.read_to_end(ENVELOPE_LEN).await?;
    let device_id = envelope_device_id(&proof)?;
    let secret = keys.get(&device_id).context("unknown device")?;
    let nonce: [u8; 16] = proof[21..37].try_into().unwrap();
    let mut replay_cache = replays.lock().await;
    verify_envelope(
        &proof,
        secret,
        &exporter(connection, &nonce)?,
        unix_time()?,
        DEFAULT_AUTH_WINDOW_SECS,
        &mut replay_cache,
    )?;
    send.write_all(b"OK").await?;
    send.finish()?;
    Ok(device_id)
}

async fn relay_connection(connection: Connection, upstream: SocketAddr) -> Result<()> {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await?;
    socket.connect(upstream).await?;
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    let mut received = CarrierReassembly::default();
    let mut message = 0u64;
    loop {
        tokio::select! {
            incoming = connection.read_datagram() => {
                let incoming = incoming?;
                if incoming.as_ref() == CARRIER_PING {
                    connection.send_datagram_wait(Bytes::from_static(CARRIER_PONG)).await?;
                } else if let Some(payload) = received.push(&incoming)? {
                    socket.send(&payload).await?;
                }
            }
            incoming = socket.recv(&mut buffer) => {
                let size = incoming?;
                send_carrier(&connection, &buffer[..size], &mut message).await?;
            }
        }
    }
}

pub async fn run_server(
    listen: SocketAddr,
    upstream: SocketAddr,
    cert: &Path,
    private_key: &Path,
    keyring: &Path,
) -> Result<()> {
    let endpoint = server_endpoint(listen, cert, private_key)?;
    let keys = Arc::new(parse_keyring(keyring)?);
    let replays = Arc::new(Mutex::new(ReplayCache::new(DEFAULT_REPLAY_CAPACITY)?));
    info!(%listen, %upstream, "SFT QUIC relay server started");
    while let Some(connecting) = endpoint.accept().await {
        let keys = keys.clone();
        let replays = replays.clone();
        tokio::spawn(async move {
            let result = async {
                let connection = connecting.await?;
                let device_id = authenticate_server(&connection, &keys, &replays).await?;
                info!(device_id, remote = %connection.remote_address(), "QUIC device authenticated");
                relay_connection(connection, upstream).await
            }.await;
            if let Err(error) = result {
                warn!(%error, "QUIC connection closed");
            }
        });
    }
    Ok(())
}

async fn relay_client_session(socket: &UdpSocket, connection: &Connection) -> Result<()> {
    let (peer_tx, peer_rx) = tokio::sync::watch::channel(None);
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    let mut received = CarrierReassembly::default();
    let mut message = 0u64;
    let mut heartbeat = time::interval(CARRIER_HEARTBEAT);
    heartbeat.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    let mut last_server_activity = Instant::now();
    // Poll both directions independently: QUIC send backpressure must never
    // stop draining return traffic or prevent the liveness timer from running.
    let send = async {
        loop {
            let (size, peer) = socket.recv_from(&mut buffer).await?;
            peer_tx.send_replace(Some(peer));
            send_carrier(connection, &buffer[..size], &mut message).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let receive = async {
        loop {
            tokio::select! {
                _ = heartbeat.tick() => {
                    if last_server_activity.elapsed() > CARRIER_DEAD_TIMEOUT {
                        bail!("QUIC carrier heartbeat timeout")
                    }
                    connection.send_datagram(Bytes::from_static(CARRIER_PING))?;
                }
                incoming = connection.read_datagram() => {
                    let incoming = incoming?;
                    // Both PONG and ordinary relay traffic prove that the
                    // authenticated peer and return path are still usable.
                    last_server_activity = Instant::now();
                    if incoming.as_ref() != CARRIER_PONG {
                        let local_peer = *peer_rx.borrow();
                        if let (Some(peer), Some(payload)) = (local_peer, received.push(&incoming)?) {
                            socket.send_to(&payload, peer).await?;
                        }
                    }
                }
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        result = receive => result,
        result = send => result,
    }
}

pub async fn run_client(
    listen: SocketAddr,
    server: SocketAddr,
    server_name: &str,
    ca_cert: &Path,
    device_id: u64,
    secret: &str,
) -> Result<()> {
    let endpoint = client_endpoint(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)), ca_cert)?;
    let socket = UdpSocket::bind(listen)
        .await
        .context("bind local QUIC relay")?;
    info!(%listen, %server, "SFT QUIC relay client started");
    let mut delay = Duration::from_secs(1);
    loop {
        let result = async {
            let connection = endpoint.connect(server, server_name)?.await?;
            authenticate_client(&connection, device_id, secret).await?;
            info!(%server, max_datagram = ?connection.max_datagram_size(), "QUIC relay connected and authenticated");
            delay = Duration::from_secs(1);
            relay_client_session(&socket, &connection).await
        }
        .await;
        warn!(error = %result.as_ref().unwrap_err(), "QUIC relay reconnecting");
        time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(30));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn keyring_rejects_weak_duplicate_and_reserved_entries() {
        let path = std::env::temp_dir().join(format!("sft-quic-keyring-{}", std::process::id()));
        for invalid in [
            "",
            "0 abcdefghijklmnop",
            "1 short",
            "1 abcdefghijklmnop\n1 different-secret-value",
        ] {
            File::create(&path)
                .unwrap()
                .write_all(invalid.as_bytes())
                .unwrap();
            assert!(parse_keyring(&path).is_err());
        }
        File::create(&path)
            .unwrap()
            .write_all(b"7 abcdefghijklmnop\n8 different-secret-value\n")
            .unwrap();
        assert_eq!(parse_keyring(&path).unwrap().len(), 2);
        std::fs::remove_file(path).unwrap();
    }

    fn carrier_fragment(message: u64, index: u16, count: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&message.to_be_bytes());
        frame.extend_from_slice(&index.to_be_bytes());
        frame.extend_from_slice(&count.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn carrier_reassembles_out_of_order_and_ignores_duplicates() {
        let mut received = CarrierReassembly::default();
        assert!(received
            .push(&carrier_fragment(4, 1, 3, b"bravo"))
            .unwrap()
            .is_none());
        assert!(received
            .push(&carrier_fragment(4, 1, 3, b"wrong"))
            .unwrap()
            .is_none());
        assert!(received
            .push(&carrier_fragment(4, 2, 3, b"charlie"))
            .unwrap()
            .is_none());
        assert_eq!(
            received.push(&carrier_fragment(4, 0, 3, b"alpha")).unwrap(),
            Some(b"alphabravocharlie".to_vec())
        );
    }

    #[test]
    fn carrier_rejects_invalid_dimensions() {
        let mut received = CarrierReassembly::default();
        for frame in [
            vec![0; CARRIER_HEADER - 1],
            carrier_fragment(1, 0, 0, b""),
            carrier_fragment(1, 2, 2, b""),
            carrier_fragment(1, 0, (MAX_CARRIER_FRAGMENTS + 1) as u16, b""),
        ] {
            assert!(received.push(&frame).is_err());
        }
    }
}

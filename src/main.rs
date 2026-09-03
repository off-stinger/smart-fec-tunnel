use anyhow::{bail, Context, Result};
use blake3::Hasher;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use clap::{Parser, Subcommand};
use rand::{Rng, RngCore};
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, Mutex},
    time,
};
use tracing::{info, warn};

const MAGIC: u32 = 0x5346_4543; // SFEC
const VERSION_V1: u8 = 1;
const VERSION_V2: u8 = 2;
const VERSION_V3: u8 = 3;
const KIND_DATA: u8 = 1;
const KIND_PARITY: u8 = 2;
const KIND_REPORT: u8 = 3;
const HEADER: usize = 36;
const HEADER_V2: usize = 44;
const V3_SELECTOR: usize = 8;
const V3_NONCE: usize = 24;
const V3_INNER_HEADER: usize = 31;
const TAG: usize = 16;
// V3 adds 79 bytes around a shard. 1380 therefore produces a 1459-byte UDP
// payload, below the IPv4/Ethernet 1472-byte no-fragment ceiling while allowing
// a typical 1200-1350-byte QUIC datagram to remain in one FEC shard.
const SHARD: usize = 1380;
const FRAGMENT_HEADER: usize = 14;
const CHUNK: usize = SHARD - FRAGMENT_HEADER;
const DATA_SHARDS: usize = 10;
const GROUP_TTL: Duration = Duration::from_secs(2);
const REASSEMBLY_TTL: Duration = Duration::from_secs(3);
const REORDER_WINDOW: u64 = 64;
const MAX_GROUPS: usize = 2048;
const MAX_REASSEMBLIES: usize = 4096;
const MAX_PARITY: usize = 3;
const MAX_V2_SESSIONS_PER_DEVICE: usize = 16;
const MAX_V1_MIGRATION_SESSIONS: usize = 64;
const MAX_DEVICE_KEYS: usize = 65_536;

#[derive(Parser, Debug)]
#[command(version, about = "Adaptive authenticated FEC tunnel for TUIC/UDP")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Client {
        #[arg(long, default_value = "127.0.0.1:3333")]
        listen: SocketAddr,
        #[arg(long)]
        server: SocketAddr,
        #[arg(long, env = "SMART_FEC_KEY")]
        key: String,
        /// Non-zero device key identifier. Omit to use the legacy V1 wire format.
        #[arg(long, env = "SMART_FEC_KEY_ID")]
        key_id: Option<u64>,
        #[arg(long, default_value_t = 10.0)]
        rate_mbps: f64,
    },
    Server {
        #[arg(long, default_value = "0.0.0.0:4096")]
        listen: SocketAddr,
        #[arg(long, default_value = "127.0.0.1:443")]
        upstream: SocketAddr,
        /// Optional legacy V1 shared key during migration.
        #[arg(long, env = "SMART_FEC_KEY")]
        key: Option<String>,
        /// V2 keyring: one `key_id secret` entry per line (root-readable only).
        #[arg(long, env = "SMART_FEC_KEYRING")]
        keyring: Option<PathBuf>,
        #[arg(long, default_value_t = 1024)]
        max_sessions: usize,
        #[arg(long, default_value_t = 120)]
        session_idle_secs: u64,
        #[arg(long, default_value_t = 10.0)]
        rate_mbps: f64,
    },
    Balance {
        #[arg(long, default_value = "127.0.0.1:18080")]
        listen: SocketAddr,
        #[arg(long, required = true, num_args = 1..)]
        upstream: Vec<SocketAddr>,
    },
}

#[derive(Clone, Debug)]
struct Frame {
    version: u8,
    key_id: u64,
    kind: u8,
    session: u64,
    sequence: u64,
    group: u64,
    index: u16,
    data: u8,
    parity: u8,
    payload: Vec<u8>,
}

impl Frame {
    fn encode(&self, key: &[u8; 32]) -> Vec<u8> {
        let header = if self.version == VERSION_V2 {
            HEADER_V2
        } else {
            HEADER
        };
        let mut out = Vec::with_capacity(header + self.payload.len() + TAG);
        out.extend_from_slice(&MAGIC.to_be_bytes());
        out.push(self.version);
        out.push(self.kind);
        if self.version == VERSION_V2 {
            out.extend_from_slice(&self.key_id.to_be_bytes());
        }
        out.extend_from_slice(&self.session.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.group.to_be_bytes());
        out.extend_from_slice(&self.index.to_be_bytes());
        out.push(self.data);
        out.push(self.parity);
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.payload);
        let mut h = Hasher::new_keyed(key);
        h.update(&out);
        out.extend_from_slice(&h.finalize().as_bytes()[..TAG]);
        out
    }

    fn decode(buf: &[u8], key: &[u8; 32]) -> Result<Self> {
        if buf.len() < 6 + TAG {
            bail!("short frame")
        }
        let version = buf[4];
        let (header, key_id, offset) = match version {
            VERSION_V1 => (HEADER, 0, 6),
            VERSION_V2 => {
                if buf.len() < HEADER_V2 + TAG {
                    bail!("short v2 frame")
                }
                (
                    HEADER_V2,
                    u64::from_be_bytes(buf[6..14].try_into().unwrap()),
                    14,
                )
            }
            _ => bail!("bad protocol version"),
        };
        if buf.len() < header + TAG {
            bail!("short frame")
        }
        let body_len = buf.len() - TAG;
        let mut h = Hasher::new_keyed(key);
        h.update(&buf[..body_len]);
        if h.finalize().as_bytes()[..TAG] != buf[body_len..] {
            bail!("bad auth")
        }
        if u32::from_be_bytes(buf[0..4].try_into().unwrap()) != MAGIC {
            bail!("bad protocol")
        }
        let payload_len =
            u16::from_be_bytes(buf[offset + 28..offset + 30].try_into().unwrap()) as usize;
        if header + payload_len + TAG != buf.len() {
            bail!("bad length")
        }
        Ok(Self {
            version,
            key_id,
            kind: buf[5],
            session: u64::from_be_bytes(buf[offset..offset + 8].try_into().unwrap()),
            sequence: u64::from_be_bytes(buf[offset + 8..offset + 16].try_into().unwrap()),
            group: u64::from_be_bytes(buf[offset + 16..offset + 24].try_into().unwrap()),
            index: u16::from_be_bytes(buf[offset + 24..offset + 26].try_into().unwrap()),
            data: buf[offset + 26],
            parity: buf[offset + 27],
            payload: buf[header..header + payload_len].to_vec(),
        })
    }

    fn encode_wire(&self, key: &[u8; 32]) -> Result<Vec<u8>> {
        if self.version != VERSION_V3 {
            return Ok(self.encode(key));
        }
        let mut inner = Vec::with_capacity(V3_INNER_HEADER + self.payload.len());
        inner.push(self.kind);
        inner.extend_from_slice(&self.session.to_be_bytes());
        inner.extend_from_slice(&self.sequence.to_be_bytes());
        inner.extend_from_slice(&self.group.to_be_bytes());
        inner.extend_from_slice(&self.index.to_be_bytes());
        inner.push(self.data);
        inner.push(self.parity);
        inner.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        inner.extend_from_slice(&self.payload);

        let mut nonce = [0u8; V3_NONCE];
        rand::thread_rng().fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new(key.into());
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), inner.as_ref())
            .map_err(|_| anyhow::anyhow!("v3 encryption failed"))?;
        let mut out = Vec::with_capacity(V3_SELECTOR + V3_NONCE + ciphertext.len());
        out.extend_from_slice(&v3_selector(key));
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn decode_v3(buf: &[u8], key_id: u64, key: &[u8; 32]) -> Result<Self> {
        if buf.len() < V3_SELECTOR + V3_NONCE + V3_INNER_HEADER + TAG
            || buf[..V3_SELECTOR] != v3_selector(key)
        {
            bail!("invalid v3 envelope")
        }
        let nonce = XNonce::from_slice(&buf[V3_SELECTOR..V3_SELECTOR + V3_NONCE]);
        let cipher = XChaCha20Poly1305::new(key.into());
        let inner = cipher
            .decrypt(nonce, &buf[V3_SELECTOR + V3_NONCE..])
            .map_err(|_| anyhow::anyhow!("v3 authentication failed"))?;
        if inner.len() < V3_INNER_HEADER {
            bail!("short v3 payload")
        }
        let payload_len = u16::from_be_bytes(inner[29..31].try_into().unwrap()) as usize;
        if V3_INNER_HEADER + payload_len != inner.len() {
            bail!("bad v3 length")
        }
        Ok(Self {
            version: VERSION_V3,
            key_id,
            kind: inner[0],
            session: u64::from_be_bytes(inner[1..9].try_into().unwrap()),
            sequence: u64::from_be_bytes(inner[9..17].try_into().unwrap()),
            group: u64::from_be_bytes(inner[17..25].try_into().unwrap()),
            index: u16::from_be_bytes(inner[25..27].try_into().unwrap()),
            data: inner[27],
            parity: inner[28],
            payload: inner[V3_INNER_HEADER..].to_vec(),
        })
    }
}

fn v3_selector(key: &[u8; 32]) -> [u8; V3_SELECTOR] {
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(b"smart-fec-v3-routing-selector");
    hasher.finalize().as_bytes()[..V3_SELECTOR]
        .try_into()
        .unwrap()
}

fn decode_client_frame(buf: &[u8], key_id: u64, key: &[u8; 32]) -> Result<Frame> {
    if buf.starts_with(&MAGIC.to_be_bytes()) {
        Frame::decode(buf, key)
    } else {
        Frame::decode_v3(buf, key_id, key)
    }
}

#[derive(Debug)]
struct Adaptive {
    parity: usize,
    bad: u8,
    good: u16,
    last_loss_ppm: u32,
    smoothed_loss_ppm: u32,
}

impl Default for Adaptive {
    fn default() -> Self {
        Self {
            parity: 2,
            bad: 0,
            good: 0,
            last_loss_ppm: 0,
            smoothed_loss_ppm: 0,
        }
    }
}

impl Adaptive {
    fn target(loss: u32) -> usize {
        match loss {
            0..=9_999 => 0,
            10_000..=49_999 => 1,
            50_000..=99_999 => 2,
            _ => 3,
        }
    }
    fn report(&mut self, loss: u32) {
        self.last_loss_ppm = loss;
        self.smoothed_loss_ppm = ((self.smoothed_loss_ppm as u64 * 3 + loss as u64) / 4) as u32;
        let target = Self::target(self.smoothed_loss_ppm);
        if target > self.parity {
            self.bad += 1;
            self.good = 0;
            if self.bad >= 2 {
                self.parity = (self.parity + 1).min(MAX_PARITY);
                self.bad = 0;
            }
        } else if target < self.parity {
            self.good += 1;
            self.bad = self.bad.saturating_sub(1);
            if self.good >= 15 {
                self.parity -= 1;
                self.good = 0;
            }
        } else {
            self.bad = self.bad.saturating_sub(1);
            self.good = 0;
        }
    }
}

#[derive(Debug)]
struct Encoder {
    version: u8,
    key_id: u64,
    session: u64,
    sequence: u64,
    packet: u64,
    group: u64,
    shards: Vec<Vec<u8>>,
    adaptive: Adaptive,
}

impl Encoder {
    #[cfg(test)]
    fn new(session: u64) -> Self {
        Self::with_identity(session, VERSION_V1, 0)
    }
    fn with_identity(session: u64, version: u8, key_id: u64) -> Self {
        Self {
            version,
            key_id,
            session,
            sequence: 1,
            packet: 1,
            group: 1,
            shards: Vec::new(),
            adaptive: Adaptive::default(),
        }
    }
    fn report_frame(&mut self, loss_ppm: u32) -> Frame {
        let f = Frame {
            version: self.version,
            key_id: self.key_id,
            kind: KIND_REPORT,
            session: self.session,
            sequence: self.sequence,
            group: 0,
            index: 0,
            data: 0,
            parity: 0,
            payload: loss_ppm.to_be_bytes().to_vec(),
        };
        self.sequence += 1;
        f
    }
    fn encode_datagram(&mut self, payload: &[u8]) -> Result<Vec<Frame>> {
        let packet_id = self.packet;
        self.packet += 1;
        let count = payload.len().max(1).div_ceil(CHUNK);
        if count > u16::MAX as usize {
            bail!("datagram too large")
        }
        let mut frames = Vec::new();
        let chunks: Vec<&[u8]> = if payload.is_empty() {
            vec![&[]]
        } else {
            payload.chunks(CHUNK).collect()
        };
        for (idx, chunk) in chunks.into_iter().enumerate() {
            let mut shard = vec![0u8; FRAGMENT_HEADER + chunk.len()];
            shard[0..8].copy_from_slice(&packet_id.to_be_bytes());
            shard[8..10].copy_from_slice(&(idx as u16).to_be_bytes());
            shard[10..12].copy_from_slice(&(count as u16).to_be_bytes());
            shard[12..14].copy_from_slice(&(chunk.len() as u16).to_be_bytes());
            shard[14..14 + chunk.len()].copy_from_slice(chunk);
            self.shards.push(shard);
            if self.shards.len() == DATA_SHARDS {
                frames.extend(self.flush()?);
            }
        }
        Ok(frames)
    }
    fn flush(&mut self) -> Result<Vec<Frame>> {
        if self.shards.is_empty() {
            return Ok(Vec::new());
        }
        let data = self.shards.len();
        let parity = if self.adaptive.parity == 0 {
            0
        } else if data < DATA_SHARDS {
            self.adaptive.parity.min(data + 1)
        } else {
            (data * self.adaptive.parity).div_ceil(DATA_SHARDS)
        }
        .min(MAX_PARITY);
        let shard_len = self
            .shards
            .iter()
            .map(Vec::len)
            .max()
            .unwrap_or(FRAGMENT_HEADER);
        for shard in &mut self.shards {
            shard.resize(shard_len, 0);
        }
        let mut frames = Vec::with_capacity(data + parity);
        for (index, shard) in self.shards.iter().enumerate() {
            frames.push(Frame {
                version: self.version,
                key_id: self.key_id,
                kind: KIND_DATA,
                session: self.session,
                sequence: self.sequence,
                group: self.group,
                index: index as u16,
                data: data as u8,
                parity: parity as u8,
                payload: shard.clone(),
            });
            self.sequence += 1;
        }
        if parity > 0 {
            let rs = ReedSolomon::new(data, parity)?;
            let mut all = self.shards.clone();
            all.extend((0..parity).map(|_| vec![0u8; SHARD]));
            rs.encode(&mut all)?;
            for p in 0..parity {
                frames.push(Frame {
                    version: self.version,
                    key_id: self.key_id,
                    kind: KIND_PARITY,
                    session: self.session,
                    sequence: self.sequence,
                    group: self.group,
                    index: (data + p) as u16,
                    data: data as u8,
                    parity: parity as u8,
                    payload: all[data + p].clone(),
                });
                self.sequence += 1;
            }
        }
        self.shards.clear();
        self.group += 1;
        Ok(frames)
    }
}

#[derive(Debug)]
struct Group {
    created: Instant,
    data: usize,
    parity: usize,
    shards: Vec<Option<Vec<u8>>>,
    delivered: Vec<bool>,
}

#[derive(Debug)]
struct Reassembly {
    created: Instant,
    parts: Vec<Option<Vec<u8>>>,
}

#[derive(Debug)]
struct Decoder {
    session: u64,
    highest_sequence: u64,
    finalized_sequence: u64,
    seen_sequences: BTreeSet<u64>,
    groups: BTreeMap<u64, Group>,
    packets: HashMap<u64, Reassembly>,
}

impl Decoder {
    fn new(session: u64) -> Self {
        Self {
            session,
            highest_sequence: 0,
            finalized_sequence: 0,
            seen_sequences: BTreeSet::new(),
            groups: BTreeMap::new(),
            packets: HashMap::new(),
        }
    }
    fn observe_seq(&mut self, seq: u64) -> bool {
        if self.highest_sequence == 0
            && self.finalized_sequence == 0
            && self.seen_sequences.is_empty()
        {
            self.finalized_sequence = seq.saturating_sub(1);
        }
        if seq <= self.finalized_sequence {
            return false;
        }
        self.highest_sequence = self.highest_sequence.max(seq);
        self.seen_sequences.insert(seq)
    }
    fn loss_report(&mut self) -> u32 {
        let cutoff = self.highest_sequence.saturating_sub(REORDER_WINDOW);
        if cutoff <= self.finalized_sequence {
            return 0;
        }
        let expected = cutoff - self.finalized_sequence;
        // A single missing report in an idle connection must not be represented
        // as 100% loss or drive the adaptive redundancy controller. Accumulate a
        // statistically useful window before finalizing a result.
        if expected < 32 {
            return 0;
        }
        let received = self
            .seen_sequences
            .range((self.finalized_sequence + 1)..=cutoff)
            .count() as u64;
        let missing = expected.saturating_sub(received);
        let ppm = ((missing as u128 * 1_000_000) / expected as u128) as u32;
        self.seen_sequences = self.seen_sequences.split_off(&(cutoff + 1));
        self.finalized_sequence = cutoff;
        ppm.min(1_000_000)
    }
    fn fragment(&mut self, shard: &[u8]) -> Vec<Vec<u8>> {
        if shard.len() < FRAGMENT_HEADER || shard.len() > SHARD {
            return vec![];
        }
        let packet = u64::from_be_bytes(shard[0..8].try_into().unwrap());
        let idx = u16::from_be_bytes(shard[8..10].try_into().unwrap()) as usize;
        let count = u16::from_be_bytes(shard[10..12].try_into().unwrap()) as usize;
        let len = u16::from_be_bytes(shard[12..14].try_into().unwrap()) as usize;
        if count == 0
            || count > 64
            || idx >= count
            || len > CHUNK
            || FRAGMENT_HEADER + len > shard.len()
        {
            return vec![];
        }
        let entry = self.packets.entry(packet).or_insert_with(|| Reassembly {
            created: Instant::now(),
            parts: vec![None; count],
        });
        if entry.parts.len() != count {
            return vec![];
        }
        entry.parts[idx] = Some(shard[14..14 + len].to_vec());
        if entry.parts.iter().all(Option::is_some) {
            let mut out = Vec::new();
            for p in &mut entry.parts {
                out.extend_from_slice(p.take().unwrap().as_slice());
            }
            self.packets.remove(&packet);
            return vec![out];
        }
        vec![]
    }
    fn frame(&mut self, frame: Frame) -> Result<Vec<Vec<u8>>> {
        if self.session != frame.session {
            bail!("session mismatch")
        }
        if !self.observe_seq(frame.sequence) {
            return Ok(vec![]);
        }
        if frame.kind == KIND_REPORT {
            return Ok(vec![]);
        }
        if !matches!(frame.kind, KIND_DATA | KIND_PARITY) {
            return Ok(vec![]);
        }
        let data = frame.data as usize;
        let parity = frame.parity as usize;
        if data == 0
            || data > 32
            || parity > 16
            || frame.index as usize >= data + parity
            || frame.payload.len() < FRAGMENT_HEADER
            || frame.payload.len() > SHARD
        {
            bail!("invalid fec frame")
        }
        self.prune();
        if !self.groups.contains_key(&frame.group) && self.groups.len() >= MAX_GROUPS {
            bail!("too many fec groups")
        }
        let pos = frame.index as usize;
        let (immediate, recovered) = {
            let g = self.groups.entry(frame.group).or_insert_with(|| Group {
                created: Instant::now(),
                data,
                parity,
                shards: vec![None; data + parity],
                delivered: vec![false; data],
            });
            if g.data != data || g.parity != parity {
                bail!("group mismatch")
            }
            if g.shards[pos].is_none() {
                g.shards[pos] = Some(frame.payload.clone());
            }
            let immediate = if pos < data && !g.delivered[pos] {
                g.delivered[pos] = true;
                Some(frame.payload.clone())
            } else {
                None
            };
            let present = g.shards.iter().filter(|x| x.is_some()).count();
            let mut recovered = Vec::new();
            if parity > 0 && present >= data && g.delivered.iter().any(|x| !*x) {
                let rs = ReedSolomon::new(data, parity)?;
                rs.reconstruct(&mut g.shards)?;
                recovered = (0..data)
                    .filter(|i| !g.delivered[*i])
                    .filter_map(|i| g.shards[i].clone())
                    .collect();
                for i in 0..data {
                    g.delivered[i] = true;
                }
            }
            (immediate, recovered)
        };
        let mut output = Vec::new();
        if let Some(s) = immediate {
            output.extend(self.fragment(&s));
        }
        for s in recovered {
            output.extend(self.fragment(&s));
        }
        self.prune();
        Ok(output)
    }
    fn prune(&mut self) {
        let now = Instant::now();
        // Keep completed groups as short-lived tombstones. Otherwise a late second
        // parity shard recreates the group, reconstructs it again, and duplicates
        // the inner UDP datagram (especially visible for one-data-shard groups).
        self.groups
            .retain(|_, g| now.duration_since(g.created) < GROUP_TTL);
        self.packets
            .retain(|_, p| now.duration_since(p.created) < REASSEMBLY_TTL);
        if self.packets.len() > MAX_REASSEMBLIES {
            let mut oldest: Vec<_> = self
                .packets
                .iter()
                .map(|(id, p)| (*id, p.created))
                .collect();
            oldest.sort_unstable_by_key(|(_, created)| *created);
            for (id, _) in oldest
                .into_iter()
                .take(self.packets.len() - MAX_REASSEMBLIES)
            {
                self.packets.remove(&id);
            }
        }
    }
}

fn key(raw: &str) -> [u8; 32] {
    *blake3::hash(raw.as_bytes()).as_bytes()
}

fn load_keyring(path: &PathBuf) -> Result<HashMap<u64, [u8; 32]>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            bail!("keyring must not be accessible by group or other users")
        }
    }
    let text = std::fs::read_to_string(path).context("read keyring")?;
    parse_keyring(&text)
}

fn parse_keyring(text: &str) -> Result<HashMap<u64, [u8; 32]>> {
    let mut result = HashMap::new();
    for (line_no, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let id: u64 = fields
            .next()
            .context("missing key id")?
            .parse()
            .with_context(|| format!("invalid key id at line {}", line_no + 1))?;
        let secret = fields.next().context("missing key secret")?;
        if id == 0 || secret.len() < 32 || fields.next().is_some() {
            bail!("invalid keyring entry at line {}", line_no + 1)
        }
        if result.insert(id, key(secret)).is_some() {
            bail!("duplicate key id at line {}", line_no + 1)
        }
        if result.len() > MAX_DEVICE_KEYS {
            bail!("keyring exceeds maximum device count")
        }
    }
    if result.is_empty() {
        bail!("keyring contains no device keys")
    }
    Ok(result)
}

fn decode_server_frame(
    bytes: &[u8],
    legacy_key: Option<&[u8; 32]>,
    keyring: &HashMap<u64, [u8; 32]>,
    selectors: &HashMap<[u8; V3_SELECTOR], (u64, [u8; 32])>,
) -> Result<(Frame, [u8; 32])> {
    if !bytes.starts_with(&MAGIC.to_be_bytes()) {
        if bytes.len() < V3_SELECTOR {
            bail!("short v3 envelope")
        }
        let selector: [u8; V3_SELECTOR] = bytes[..V3_SELECTOR].try_into().unwrap();
        let (key_id, selected) = selectors.get(&selector).context("unknown v3 selector")?;
        return Ok((Frame::decode_v3(bytes, *key_id, selected)?, *selected));
    }
    if bytes.len() < 6 {
        bail!("short legacy frame")
    }
    let selected = match bytes[4] {
        VERSION_V1 => legacy_key.context("legacy protocol disabled")?,
        VERSION_V2 => {
            if bytes.len() < HEADER_V2 + TAG {
                bail!("short v2 frame")
            }
            let id = u64::from_be_bytes(bytes[6..14].try_into().unwrap());
            keyring.get(&id).context("unknown key id")?
        }
        _ => bail!("unsupported protocol version"),
    };
    let frame = Frame::decode(bytes, selected)?;
    Ok((frame, *selected))
}

async fn send_frames(
    socket: &UdpSocket,
    peer: Option<SocketAddr>,
    frames: Vec<Frame>,
    key: &[u8; 32],
    pacer: &mut Pacer,
) -> Result<()> {
    for frame in frames {
        let bytes = match frame.encode_wire(key) {
            Ok(bytes) => bytes,
            Err(error) => {
                warn!(%error, "frame encryption failed");
                continue;
            }
        };
        pacer.wait(bytes.len()).await;
        let sent = if let Some(peer) = peer {
            socket.send_to(&bytes, peer).await
        } else {
            socket.send(&bytes).await
        };
        if let Err(e) = sent {
            warn!(error=%e, "udp send failed");
        }
    }
    Ok(())
}

#[derive(Debug)]
struct Pacer {
    bytes_per_second: f64,
    capacity: f64,
    tokens: f64,
    updated: Instant,
}

impl Pacer {
    fn new(rate_mbps: f64) -> Result<Self> {
        if !rate_mbps.is_finite() || !(1.0..=1_000.0).contains(&rate_mbps) {
            bail!("rate-mbps must be between 1 and 1000")
        }
        let bytes_per_second = rate_mbps * 1_000_000.0 / 8.0;
        // Refill in batches matching the deployed OpenWrt kernel's ~4 ms
        // scheduling granularity. At 30 Mbps this permits about 15 KB per
        // batch, avoiding both sub-tick sleeps and 10 ms / 37.5 KB bursts.
        // The floor guarantees that one maximum-size frame always fits.
        let capacity = (bytes_per_second * 0.004).max((HEADER + SHARD + TAG) as f64);
        Ok(Self {
            bytes_per_second,
            capacity,
            tokens: capacity,
            updated: Instant::now(),
        })
    }

    async fn wait(&mut self, bytes: usize) {
        let now = Instant::now();
        self.tokens = (self.tokens
            + now.duration_since(self.updated).as_secs_f64() * self.bytes_per_second)
            .min(self.capacity);
        self.updated = now;
        let needed = bytes as f64;
        if self.tokens < needed {
            let delay = (self.capacity - self.tokens) / self.bytes_per_second;
            time::sleep(Duration::from_secs_f64(delay)).await;
            self.updated = Instant::now();
            self.tokens = self.capacity;
        }
        self.tokens -= needed;
    }
}

async fn client(
    listen: SocketAddr,
    server: SocketAddr,
    secret: String,
    key_id: Option<u64>,
    rate_mbps: f64,
) -> Result<()> {
    if key_id == Some(0) {
        bail!("key-id 0 is reserved for legacy V1")
    }
    let key = key(&secret);
    let session = rand::thread_rng().gen::<u64>();
    let version = if key_id.is_some() {
        VERSION_V3
    } else {
        VERSION_V1
    };
    let local = UdpSocket::bind(listen)
        .await
        .context("bind client listen")?;
    let tunnel = UdpSocket::bind("0.0.0.0:0").await?;
    tunnel.connect(server).await?;
    let encoder = Arc::new(Mutex::new(Encoder::with_identity(
        session,
        version,
        key_id.unwrap_or(0),
    )));
    let mut decoder = Decoder::new(session);
    let mut app_peer = None;
    let mut local_buf = vec![0u8; 65535];
    let mut net_buf = vec![0u8; 2048];
    let mut report = time::interval(Duration::from_secs(2));
    let mut flush = time::interval(Duration::from_millis(5));
    let mut pacer = Pacer::new(rate_mbps)?;
    info!(%listen, %server, session, "client started");
    loop {
        tokio::select! {
            r = local.recv_from(&mut local_buf) => {
                let (n, peer) = r?; app_peer = Some(peer);
                let frames = encoder.lock().await.encode_datagram(&local_buf[..n])?;
                send_frames(&tunnel, None, frames, &key, &mut pacer).await?;
            }
            r = tunnel.recv(&mut net_buf) => {
                let n = match r { Ok(n) => n, Err(e) => { warn!(error=%e, "tunnel receive failed"); continue; } };
                match decode_client_frame(&net_buf[..n], key_id.unwrap_or(0), &key) {
                    Ok(f) if f.version != version || f.key_id != key_id.unwrap_or(0) || f.session != session => {
                        warn!("discard frame for different identity or session");
                    }
                    Ok(f) if f.kind == KIND_REPORT && f.payload.len() == 4 => {
                        if decoder.observe_seq(f.sequence) {
                            let loss = u32::from_be_bytes(f.payload[..4].try_into().unwrap());
                            encoder.lock().await.adaptive.report(loss);
                        }
                    }
                    Ok(f) => match decoder.frame(f) {
                        Ok(datagrams) => for d in datagrams { if let Some(peer) = app_peer { if let Err(e) = local.send_to(&d, peer).await { warn!(error=%e, "local send failed"); } } },
                        Err(e) => warn!(error=%e, "discard invalid fec frame"),
                    },
                    Err(e) => warn!(error=%e, "discard frame"),
                }
            }
            _ = report.tick() => {
                let loss = decoder.loss_report();
                let mut enc = encoder.lock().await;
                let parity = enc.adaptive.parity;
                let f = enc.report_frame(loss);
                drop(enc); send_frames(&tunnel, None, vec![f], &key, &mut pacer).await?;
                info!(loss_ppm=loss, tx_parity=parity, "link report");
            }
            _ = flush.tick() => {
                let frames = encoder.lock().await.flush()?;
                send_frames(&tunnel, None, frames, &key, &mut pacer).await?;
            }
        }
    }
}

struct SessionPacket {
    frame: Frame,
    peer: SocketAddr,
}

struct SessionEntry {
    sender: mpsc::Sender<SessionPacket>,
    last_seen: Arc<std::sync::Mutex<Instant>>,
    task: tokio::task::JoinHandle<()>,
}

struct SessionRuntime {
    public: Arc<UdpSocket>,
    upstream: SocketAddr,
    key: [u8; 32],
    version: u8,
    key_id: u64,
    session: u64,
    pacer: Arc<Mutex<Pacer>>,
    last_seen: Arc<std::sync::Mutex<Instant>>,
}

async fn send_session_frames(
    public: &UdpSocket,
    peer: SocketAddr,
    frames: Vec<Frame>,
    key: &[u8; 32],
    pacer: &Mutex<Pacer>,
) {
    for frame in frames {
        let bytes = match frame.encode_wire(key) {
            Ok(bytes) => bytes,
            Err(error) => {
                warn!(%error, "session encryption failed");
                continue;
            }
        };
        let mut limiter = pacer.lock().await;
        limiter.wait(bytes.len()).await;
        drop(limiter);
        if let Err(error) = public.send_to(&bytes, peer).await {
            warn!(%error, "session send failed");
        }
    }
}

async fn run_server_session(
    runtime: SessionRuntime,
    mut input: mpsc::Receiver<SessionPacket>,
) -> Result<()> {
    let upstream_socket = UdpSocket::bind("127.0.0.1:0").await?;
    upstream_socket.connect(runtime.upstream).await?;
    let mut decoder = Decoder::new(runtime.session);
    let mut encoder = Encoder::with_identity(runtime.session, runtime.version, runtime.key_id);
    let mut peer = None;
    let mut upstream_buf = vec![0u8; 65535];
    let mut report = time::interval(Duration::from_secs(2));
    let mut flush = time::interval(Duration::from_millis(5));
    loop {
        tokio::select! {
            packet = input.recv() => {
                let Some(packet) = packet else { return Ok(()) };
                peer = Some(packet.peer);
                let frame = packet.frame;
                if frame.session != runtime.session || frame.version != runtime.version || frame.key_id != runtime.key_id {
                    continue;
                }
                if frame.kind == KIND_REPORT && frame.payload.len() == 4 {
                    if decoder.observe_seq(frame.sequence) {
                        encoder.adaptive.report(u32::from_be_bytes(frame.payload[..4].try_into().unwrap()));
                    }
                } else {
                    match decoder.frame(frame) {
                        Ok(datagrams) => for datagram in datagrams {
                            if let Err(error) = upstream_socket.send(&datagram).await {
                                warn!(%error, "session upstream send failed");
                            }
                        },
                        Err(error) => warn!(%error, "discard invalid session frame"),
                    }
                }
            }
            received = upstream_socket.recv(&mut upstream_buf), if peer.is_some() => {
                let n = match received { Ok(n) => n, Err(error) => { warn!(%error, "session upstream receive failed"); continue; } };
                if let Ok(mut last_seen) = runtime.last_seen.lock() {
                    *last_seen = Instant::now();
                }
                match encoder.encode_datagram(&upstream_buf[..n]) {
                    Ok(frames) => send_session_frames(&runtime.public, peer.unwrap(), frames, &runtime.key, &runtime.pacer).await,
                    Err(error) => warn!(%error, "session encode failed"),
                }
            }
            _ = report.tick(), if peer.is_some() => {
                let loss = decoder.loss_report();
                let frame = encoder.report_frame(loss);
                send_session_frames(&runtime.public, peer.unwrap(), vec![frame], &runtime.key, &runtime.pacer).await;
            }
            _ = flush.tick(), if peer.is_some() => {
                match encoder.flush() {
                    Ok(frames) => send_session_frames(&runtime.public, peer.unwrap(), frames, &runtime.key, &runtime.pacer).await,
                    Err(error) => warn!(%error, "session flush failed"),
                }
            }
        }
    }
}

async fn server(
    listen: SocketAddr,
    upstream: SocketAddr,
    legacy_secret: Option<String>,
    keyring_path: Option<PathBuf>,
    max_sessions: usize,
    session_idle_secs: u64,
    rate_mbps: f64,
) -> Result<()> {
    if max_sessions == 0 || max_sessions > 65_536 {
        bail!("max-sessions must be between 1 and 65536")
    }
    if !(10..=86_400).contains(&session_idle_secs) {
        bail!("session-idle-secs must be between 10 and 86400")
    }
    let legacy_key = legacy_secret.as_deref().map(key);
    let keyring = match keyring_path {
        Some(path) => load_keyring(&path)?,
        None => HashMap::new(),
    };
    if legacy_key.is_none() && keyring.is_empty() {
        bail!("server requires --key for V1 migration and/or --keyring for V2")
    }
    let mut selectors = HashMap::new();
    for (&key_id, &device_key) in &keyring {
        if selectors
            .insert(v3_selector(&device_key), (key_id, device_key))
            .is_some()
        {
            bail!("keyring contains a V3 selector collision")
        }
    }
    let public = Arc::new(
        UdpSocket::bind(listen)
            .await
            .context("bind server listen")?,
    );
    let pacer = Arc::new(Mutex::new(Pacer::new(rate_mbps)?));
    let mut sessions: HashMap<(u64, u64), SessionEntry> = HashMap::new();
    let mut net_buf = vec![0u8; 2048];
    let mut cleanup = time::interval(Duration::from_secs(5));
    let idle = Duration::from_secs(session_idle_secs);
    info!(%listen, %upstream, v2_keys=keyring.len(), legacy=legacy_key.is_some(), max_sessions, "multi-user server started");
    loop {
        tokio::select! {
            received = public.recv_from(&mut net_buf) => {
                let (n, peer) = match received { Ok(v) => v, Err(error) => { warn!(%error, "public receive failed"); continue; } };
                let (frame, device_key) = match decode_server_frame(&net_buf[..n], legacy_key.as_ref(), &keyring, &selectors) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let session_key = (frame.key_id, frame.session);
                if !sessions.contains_key(&session_key) {
                    if sessions.len() >= max_sessions {
                        continue;
                    }
                    if frame.version == VERSION_V1 && sessions.keys().filter(|(id, _)| *id == 0).count() >= MAX_V1_MIGRATION_SESSIONS {
                        continue;
                    }
                    if matches!(frame.version, VERSION_V2 | VERSION_V3) && sessions.keys().filter(|(id, _)| *id == frame.key_id).count() >= MAX_V2_SESSIONS_PER_DEVICE {
                        continue;
                    }
                    let (sender, receiver) = mpsc::channel(256);
                    let version = frame.version;
                    let key_id = frame.key_id;
                    let session = frame.session;
                    let last_seen = Arc::new(std::sync::Mutex::new(Instant::now()));
                    let runtime = SessionRuntime {
                        public: public.clone(),
                        upstream,
                        key: device_key,
                        version,
                        key_id,
                        session,
                        pacer: pacer.clone(),
                        last_seen: last_seen.clone(),
                    };
                    let task = tokio::spawn(async move {
                        if let Err(error) = run_server_session(runtime, receiver).await {
                            warn!(%error, "session worker stopped");
                        }
                    });
                    sessions.insert(session_key, SessionEntry { sender, last_seen, task });
                    info!(key_id=frame.key_id, session=frame.session, "authenticated session started");
                }
                if let Some(entry) = sessions.get_mut(&session_key) {
                    if let Ok(mut last_seen) = entry.last_seen.lock() {
                        *last_seen = Instant::now();
                    }
                    // A bounded queue intentionally sheds excess authenticated traffic.
                    let _ = entry.sender.try_send(SessionPacket { frame, peer });
                }
            }
            _ = cleanup.tick() => {
                let now = Instant::now();
                let expired: Vec<_> = sessions.iter()
                    .filter(|(_, entry)| entry.task.is_finished() || entry.last_seen.lock().map_or(true, |last_seen| now.duration_since(*last_seen) >= idle))
                    .map(|(id, _)| *id).collect();
                for id in expired {
                    if let Some(entry) = sessions.remove(&id) {
                        entry.task.abort();
                        info!(key_id=id.0, session=id.1, "session expired");
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
struct BalanceUpstream {
    address: SocketAddr,
    healthy: AtomicBool,
    active: AtomicUsize,
}

async fn read_socks_address(stream: &mut TcpStream, atyp: u8) -> Result<Vec<u8>> {
    let mut address = Vec::new();
    match atyp {
        1 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await?;
            address.extend_from_slice(&rest);
        }
        3 => {
            let length = stream.read_u8().await?;
            if length == 0 {
                bail!("empty socks domain")
            }
            address.push(length);
            let mut rest = vec![0u8; length as usize + 2];
            stream.read_exact(&mut rest).await?;
            address.extend_from_slice(&rest);
        }
        4 => {
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest).await?;
            address.extend_from_slice(&rest);
        }
        _ => bail!("unsupported socks address type"),
    }
    Ok(address)
}

async fn socks_connect(upstream: SocketAddr, request: &[u8]) -> Result<(TcpStream, Vec<u8>)> {
    let mut stream = time::timeout(Duration::from_secs(4), TcpStream::connect(upstream))
        .await
        .context("socks upstream connect timeout")??;
    stream.write_all(&[5, 1, 0]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [5, 0] {
        bail!("socks upstream rejected authentication")
    }
    stream.write_all(request).await?;
    let mut head = [0u8; 4];
    time::timeout(Duration::from_secs(8), stream.read_exact(&mut head))
        .await
        .context("socks upstream response timeout")??;
    let tail = read_socks_address(&mut stream, head[3]).await?;
    let mut response = head.to_vec();
    response.extend_from_slice(&tail);
    if head[0] != 5 || head[1] != 0 {
        bail!("socks upstream connect failed code={}", head[1])
    }
    Ok((stream, response))
}

async fn handle_balanced_client(
    mut client: TcpStream,
    upstreams: Arc<Vec<BalanceUpstream>>,
    cursor: Arc<AtomicUsize>,
) -> Result<()> {
    let version = client.read_u8().await?;
    let methods = client.read_u8().await? as usize;
    if version != 5 || methods == 0 || methods > 32 {
        bail!("invalid socks greeting")
    }
    let mut offered = vec![0u8; methods];
    client.read_exact(&mut offered).await?;
    if !offered.contains(&0) {
        client.write_all(&[5, 0xff]).await?;
        bail!("socks client requires authentication")
    }
    client.write_all(&[5, 0]).await?;
    let mut head = [0u8; 4];
    client.read_exact(&mut head).await?;
    if head[0] != 5 || head[1] != 1 || head[2] != 0 {
        client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        bail!("only socks CONNECT is supported")
    }
    let address = read_socks_address(&mut client, head[3]).await?;
    let mut request = head.to_vec();
    request.extend_from_slice(&address);

    let start = cursor.fetch_add(1, Ordering::Relaxed) % upstreams.len();
    let mut chosen = None;
    let mut last_error = None;
    for healthy_only in [true, false] {
        for offset in 0..upstreams.len() {
            let index = (start + offset) % upstreams.len();
            let state = &upstreams[index];
            if healthy_only && !state.healthy.load(Ordering::Relaxed) {
                continue;
            }
            match socks_connect(state.address, &request).await {
                Ok((stream, response)) => {
                    state.healthy.store(true, Ordering::Relaxed);
                    chosen = Some((index, stream, response));
                    break;
                }
                Err(error) => {
                    state.healthy.store(false, Ordering::Relaxed);
                    last_error = Some(error);
                }
            }
        }
        if chosen.is_some() {
            break;
        }
    }
    let Some((index, mut remote, response)) = chosen else {
        client.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no healthy WARP upstream")));
    };
    client.write_all(&response).await?;
    upstreams[index].active.fetch_add(1, Ordering::Relaxed);
    let copied = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
    upstreams[index].active.fetch_sub(1, Ordering::Relaxed);
    copied?;
    Ok(())
}

async fn balance(listen: SocketAddr, addresses: Vec<SocketAddr>) -> Result<()> {
    if addresses.len() < 2 {
        bail!("balance requires at least two upstreams")
    }
    let listener = TcpListener::bind(listen)
        .await
        .context("bind balance listen")?;
    let upstreams = Arc::new(
        addresses
            .into_iter()
            .map(|address| BalanceUpstream {
                address,
                healthy: AtomicBool::new(true),
                active: AtomicUsize::new(0),
            })
            .collect::<Vec<_>>(),
    );
    let cursor = Arc::new(AtomicUsize::new(0));
    let health_upstreams = upstreams.clone();
    tokio::spawn(async move {
        let request = [&[5, 1, 0, 3, 15][..], b"www.gstatic.com", &[0x01, 0xbb]].concat();
        let mut interval = time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            for state in health_upstreams.iter() {
                let healthy = socks_connect(state.address, &request).await.is_ok();
                state.healthy.store(healthy, Ordering::Relaxed);
            }
        }
    });
    info!(%listen, upstreams=upstreams.len(), "WARP TCP balancer started");
    loop {
        let (client, peer) = listener.accept().await?;
        let states = upstreams.clone();
        let next = cursor.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_balanced_client(client, states, next).await {
                warn!(%peer, %error, "balanced connection failed");
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "smart_fec_tunnel=info".into()),
        )
        .init();
    match Cli::parse().command {
        Command::Client {
            listen,
            server,
            key,
            key_id,
            rate_mbps,
        } => client(listen, server, key, key_id, rate_mbps).await,
        Command::Server {
            listen,
            upstream,
            key,
            keyring,
            max_sessions,
            session_idle_secs,
            rate_mbps,
        } => {
            server(
                listen,
                upstream,
                key,
                keyring,
                max_sessions,
                session_idle_secs,
                rate_mbps,
            )
            .await
        }
        Command::Balance { listen, upstream } => balance(listen, upstream).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frame_auth_roundtrip() {
        let k = key("test");
        let f = Frame {
            version: VERSION_V1,
            key_id: 0,
            kind: KIND_DATA,
            session: 1,
            sequence: 2,
            group: 3,
            index: 0,
            data: 10,
            parity: 2,
            payload: vec![7; SHARD],
        };
        let b = f.encode(&k);
        let d = Frame::decode(&b, &k).unwrap();
        assert_eq!(d.sequence, 2);
        assert_eq!(d.payload, f.payload);
    }
    #[test]
    fn frame_rejects_tamper() {
        let k = key("test");
        let f = Frame {
            version: VERSION_V1,
            key_id: 0,
            kind: KIND_REPORT,
            session: 1,
            sequence: 1,
            group: 0,
            index: 0,
            data: 0,
            parity: 0,
            payload: vec![0; 4],
        };
        let mut b = f.encode(&k);
        b[20] ^= 1;
        assert!(Frame::decode(&b, &k).is_err());
    }
    #[test]
    fn v2_frame_selects_device_key_and_authenticates() {
        let device_key = key("device-secret-long-enough");
        let mut enc = Encoder::with_identity(77, VERSION_V2, 42);
        let frame = enc.report_frame(1234);
        let bytes = frame.encode(&device_key);
        let keys = HashMap::from([(42, device_key)]);
        let (decoded, selected) =
            decode_server_frame(&bytes, None, &keys, &HashMap::new()).unwrap();
        assert_eq!(decoded.version, VERSION_V2);
        assert_eq!(decoded.key_id, 42);
        assert_eq!(decoded.session, 77);
        assert_eq!(selected, device_key);
    }
    #[test]
    fn v2_frame_rejects_unknown_or_wrong_device_key() {
        let mut enc = Encoder::with_identity(77, VERSION_V2, 42);
        let bytes = enc.report_frame(0).encode(&key("correct-device-secret"));
        assert!(decode_server_frame(&bytes, None, &HashMap::new(), &HashMap::new()).is_err());
        let wrong = HashMap::from([(42, key("wrong-device-secret"))]);
        assert!(decode_server_frame(&bytes, None, &wrong, &HashMap::new()).is_err());
    }
    #[test]
    fn v3_envelope_hides_header_and_authenticates() {
        let device_key = key("v3-device-secret-at-least-32-bytes");
        let frame = Encoder::with_identity(91, VERSION_V3, 7).report_frame(9876);
        let bytes = frame.encode_wire(&device_key).unwrap();
        assert!(!bytes.starts_with(&MAGIC.to_be_bytes()));
        assert!(!bytes.windows(4).any(|window| window == MAGIC.to_be_bytes()));
        let selectors = HashMap::from([(v3_selector(&device_key), (7, device_key))]);
        let (decoded, _) = decode_server_frame(&bytes, None, &HashMap::new(), &selectors).unwrap();
        assert_eq!(decoded.version, VERSION_V3);
        assert_eq!(decoded.key_id, 7);
        assert_eq!(decoded.session, 91);
        let mut tampered = bytes;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(decode_server_frame(&tampered, None, &HashMap::new(), &selectors).is_err());
    }
    #[test]
    fn keyring_rejects_reserved_duplicate_and_short_entries() {
        assert!(parse_keyring("0 a-very-long-secret").is_err());
        assert!(parse_keyring("1 too-short").is_err());
        assert!(parse_keyring("1 first-secret-long\n1 second-secret-long").is_err());
        let parsed = parse_keyring(
            "# device keys\n1 first-device-secret-at-least-32-bytes\n2 second-device-secret-at-least-32-bytes",
        )
        .unwrap();
        assert_eq!(parsed.len(), 2);
    }
    #[test]
    fn duplicate_authenticated_frame_is_not_delivered_twice() {
        let mut enc = Encoder::with_identity(7, VERSION_V2, 3);
        enc.adaptive.parity = 0;
        enc.encode_datagram(b"payload").unwrap();
        let frame = enc.flush().unwrap().remove(0);
        let mut decoder = Decoder::new(7);
        assert_eq!(
            decoder.frame(frame.clone()).unwrap(),
            vec![b"payload".to_vec()]
        );
        assert!(decoder.frame(frame).unwrap().is_empty());
    }
    #[test]
    fn sessions_keep_independent_decoder_state() {
        let mut first_encoder = Encoder::with_identity(10, VERSION_V2, 1);
        let mut second_encoder = Encoder::with_identity(20, VERSION_V2, 2);
        first_encoder.adaptive.parity = 0;
        second_encoder.adaptive.parity = 0;
        first_encoder.encode_datagram(b"first").unwrap();
        second_encoder.encode_datagram(b"second").unwrap();
        let first = first_encoder.flush().unwrap().remove(0);
        let second = second_encoder.flush().unwrap().remove(0);
        let mut first_decoder = Decoder::new(10);
        let mut second_decoder = Decoder::new(20);
        assert_eq!(first_decoder.frame(first).unwrap(), vec![b"first".to_vec()]);
        assert_eq!(
            second_decoder.frame(second).unwrap(),
            vec![b"second".to_vec()]
        );
    }
    #[test]
    fn adaptive_has_hysteresis() {
        let mut a = Adaptive::default();
        for _ in 0..8 {
            a.report(200_000);
        }
        assert_eq!(a.parity, 3);
        for _ in 0..24 {
            a.report(0);
        }
        assert!(a.parity < 3);
        for _ in 0..20 {
            a.report(1_000_000);
        }
        assert_eq!(a.parity, MAX_PARITY);
    }
    #[test]
    fn adaptive_reacts_to_bursty_loss() {
        let mut a = Adaptive {
            parity: 0,
            ..Adaptive::default()
        };
        for loss in [0, 250_000, 0, 180_000, 0, 220_000, 0, 150_000] {
            a.report(loss);
        }
        assert!(a.parity >= 1);
        assert!(a.parity <= MAX_PARITY);
    }
    #[test]
    fn fec_recovers_missing_shard() {
        let mut enc = Encoder::new(9);
        enc.adaptive.parity = 2;
        let mut all = Vec::new();
        for i in 0..10 {
            all.extend(enc.encode_datagram(&[i as u8; 20]).unwrap());
        }
        let mut dec = Decoder::new(9);
        let mut output = Vec::new();
        for f in all
            .into_iter()
            .filter(|f| !(f.kind == KIND_DATA && f.index == 4))
        {
            output.extend(dec.frame(f).unwrap());
        }
        assert_eq!(output.len(), 10);
        assert!(output.iter().any(|x| x == &vec![4u8; 20]));
    }
    #[test]
    fn reorder_window_does_not_report_loss() {
        let mut d = Decoder::new(1);
        d.observe_seq(1);
        for block in 0..4u64 {
            let base = block * 50 + 1;
            for seq in (base + 1..=base + 50).rev() {
                d.observe_seq(seq);
            }
        }
        assert_eq!(d.loss_report(), 0);
    }
    #[test]
    fn finalized_window_reports_real_loss_once() {
        let mut d = Decoder::new(1);
        for seq in 1..=200 {
            if seq != 20 && seq != 100 {
                d.observe_seq(seq);
            }
        }
        let loss = d.loss_report();
        assert_eq!(loss, 2_000_000u32 / 136);
        assert_eq!(d.loss_report(), 0);
    }
    #[test]
    fn first_high_sequence_establishes_baseline() {
        let mut d = Decoder::new(1);
        for seq in 10_000..=10_200 {
            d.observe_seq(seq);
        }
        assert_eq!(d.loss_report(), 0);
    }
    #[test]
    fn empty_datagram_roundtrip() {
        let mut enc = Encoder::new(7);
        enc.adaptive.parity = 0;
        assert!(enc.encode_datagram(&[]).unwrap().is_empty());
        let frames = enc.flush().unwrap();
        let mut dec = Decoder::new(7);
        let mut output = Vec::new();
        for frame in frames {
            output.extend(dec.frame(frame).unwrap());
        }
        assert_eq!(output, vec![Vec::<u8>::new()]);
    }
}

use anyhow::{bail, Context, Result};
use blake3::Hasher;
use clap::{Parser, Subcommand};
use rand::Rng;
use reed_solomon_erasure::galois_8::ReedSolomon;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Mutex,
    time,
};
use tracing::{info, warn};

const MAGIC: u32 = 0x5346_4543; // SFEC
const VERSION: u8 = 1;
const KIND_DATA: u8 = 1;
const KIND_PARITY: u8 = 2;
const KIND_REPORT: u8 = 3;
const HEADER: usize = 36;
const TAG: usize = 16;
const SHARD: usize = 1050;
const FRAGMENT_HEADER: usize = 14;
const CHUNK: usize = SHARD - FRAGMENT_HEADER;
const DATA_SHARDS: usize = 10;
const GROUP_TTL: Duration = Duration::from_secs(2);
const REASSEMBLY_TTL: Duration = Duration::from_secs(3);
const REORDER_WINDOW: u64 = 64;
const MAX_GROUPS: usize = 2048;
const MAX_REASSEMBLIES: usize = 4096;
const MAX_PARITY: usize = 3;

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
        #[arg(long, default_value_t = 10.0)]
        rate_mbps: f64,
    },
    Server {
        #[arg(long, default_value = "0.0.0.0:4096")]
        listen: SocketAddr,
        #[arg(long, default_value = "127.0.0.1:443")]
        upstream: SocketAddr,
        #[arg(long, env = "SMART_FEC_KEY")]
        key: String,
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
        let mut out = Vec::with_capacity(HEADER + self.payload.len() + TAG);
        out.extend_from_slice(&MAGIC.to_be_bytes());
        out.push(VERSION);
        out.push(self.kind);
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
        if buf.len() < HEADER + TAG {
            bail!("short frame")
        }
        let body_len = buf.len() - TAG;
        let mut h = Hasher::new_keyed(key);
        h.update(&buf[..body_len]);
        if h.finalize().as_bytes()[..TAG] != buf[body_len..] {
            bail!("bad auth")
        }
        if u32::from_be_bytes(buf[0..4].try_into().unwrap()) != MAGIC || buf[4] != VERSION {
            bail!("bad protocol")
        }
        let payload_len = u16::from_be_bytes(buf[34..36].try_into().unwrap()) as usize;
        if HEADER + payload_len + TAG != buf.len() {
            bail!("bad length")
        }
        Ok(Self {
            kind: buf[5],
            session: u64::from_be_bytes(buf[6..14].try_into().unwrap()),
            sequence: u64::from_be_bytes(buf[14..22].try_into().unwrap()),
            group: u64::from_be_bytes(buf[22..30].try_into().unwrap()),
            index: u16::from_be_bytes(buf[30..32].try_into().unwrap()),
            data: buf[32],
            parity: buf[33],
            payload: buf[HEADER..HEADER + payload_len].to_vec(),
        })
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
    session: u64,
    sequence: u64,
    packet: u64,
    group: u64,
    shards: Vec<Vec<u8>>,
    adaptive: Adaptive,
}

impl Encoder {
    fn new(session: u64) -> Self {
        Self {
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
            let mut shard = vec![0u8; SHARD];
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
        let mut frames = Vec::with_capacity(data + parity);
        for (index, shard) in self.shards.iter().enumerate() {
            frames.push(Frame {
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
    fn reset(&mut self, session: u64) {
        *self = Self::new(session);
    }
    fn observe_seq(&mut self, seq: u64) {
        if self.highest_sequence == 0
            && self.finalized_sequence == 0
            && self.seen_sequences.is_empty()
        {
            self.finalized_sequence = seq.saturating_sub(1);
        }
        if seq <= self.finalized_sequence {
            return;
        }
        self.highest_sequence = self.highest_sequence.max(seq);
        self.seen_sequences.insert(seq);
    }
    fn loss_report(&mut self) -> u32 {
        let cutoff = self.highest_sequence.saturating_sub(REORDER_WINDOW);
        if cutoff <= self.finalized_sequence {
            return 0;
        }
        let expected = cutoff - self.finalized_sequence;
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
        if shard.len() != SHARD {
            return vec![];
        }
        let packet = u64::from_be_bytes(shard[0..8].try_into().unwrap());
        let idx = u16::from_be_bytes(shard[8..10].try_into().unwrap()) as usize;
        let count = u16::from_be_bytes(shard[10..12].try_into().unwrap()) as usize;
        let len = u16::from_be_bytes(shard[12..14].try_into().unwrap()) as usize;
        if count == 0 || count > 64 || idx >= count || len > CHUNK {
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
            self.reset(frame.session);
        }
        self.observe_seq(frame.sequence);
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
            || frame.payload.len() != SHARD
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

async fn send_frames(
    socket: &UdpSocket,
    peer: Option<SocketAddr>,
    frames: Vec<Frame>,
    key: &[u8; 32],
    pacer: &mut Pacer,
) -> Result<()> {
    for frame in frames {
        let bytes = frame.encode(key);
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
    rate_mbps: f64,
) -> Result<()> {
    let key = key(&secret);
    let session = rand::thread_rng().gen::<u64>();
    let local = UdpSocket::bind(listen)
        .await
        .context("bind client listen")?;
    let tunnel = UdpSocket::bind("0.0.0.0:0").await?;
    tunnel.connect(server).await?;
    let encoder = Arc::new(Mutex::new(Encoder::new(session)));
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
                match Frame::decode(&net_buf[..n], &key) {
                    Ok(f) if f.kind == KIND_REPORT && f.payload.len() == 4 => {
                        decoder.observe_seq(f.sequence);
                        let loss = u32::from_be_bytes(f.payload[..4].try_into().unwrap());
                        encoder.lock().await.adaptive.report(loss);
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

async fn server(
    listen: SocketAddr,
    upstream: SocketAddr,
    secret: String,
    rate_mbps: f64,
) -> Result<()> {
    let key = key(&secret);
    let public = UdpSocket::bind(listen)
        .await
        .context("bind server listen")?;
    let upstream_socket = UdpSocket::bind("127.0.0.1:0").await?;
    upstream_socket.connect(upstream).await?;
    let mut client_peer = None;
    let mut session = 0u64;
    let encoder = Arc::new(Mutex::new(Encoder::new(session)));
    let mut decoder = Decoder::new(session);
    let mut net_buf = vec![0u8; 2048];
    let mut upstream_buf = vec![0u8; 65535];
    let mut report = time::interval(Duration::from_secs(2));
    let mut flush = time::interval(Duration::from_millis(5));
    let mut pacer = Pacer::new(rate_mbps)?;
    info!(%listen, %upstream, "server started");
    loop {
        tokio::select! {
            r = public.recv_from(&mut net_buf) => {
                let (n, peer) = match r { Ok(v) => v, Err(e) => { warn!(error=%e, "public receive failed"); continue; } };
                match Frame::decode(&net_buf[..n], &key) {
                    Ok(f) => {
                        if session != f.session {
                            session = f.session; client_peer = Some(peer); decoder.reset(session);
                            *encoder.lock().await = Encoder::new(session);
                            info!(session, %peer, "active session");
                        } else { client_peer = Some(peer); }
                        if f.kind == KIND_REPORT && f.payload.len() == 4 {
                            decoder.observe_seq(f.sequence);
                            let loss = u32::from_be_bytes(f.payload[..4].try_into().unwrap());
                            encoder.lock().await.adaptive.report(loss);
                        } else { match decoder.frame(f) {
                            Ok(datagrams) => for d in datagrams { if let Err(e) = upstream_socket.send(&d).await { warn!(error=%e, "upstream send failed"); } },
                            Err(e) => warn!(error=%e, "discard invalid fec frame"),
                        } }
                    }
                    Err(e) => warn!(error=%e, %peer, "discard frame"),
                }
            }
            r = upstream_socket.recv(&mut upstream_buf), if client_peer.is_some() => {
                let n = match r { Ok(n) => n, Err(e) => { warn!(error=%e, "upstream receive failed"); continue; } };
                let frames = encoder.lock().await.encode_datagram(&upstream_buf[..n])?;
                send_frames(&public, client_peer, frames, &key, &mut pacer).await?;
            }
            _ = report.tick(), if client_peer.is_some() => {
                let loss = decoder.loss_report(); let mut enc = encoder.lock().await;
                let parity = enc.adaptive.parity; let f = enc.report_frame(loss); drop(enc);
                send_frames(&public, client_peer, vec![f], &key, &mut pacer).await?;
                info!(loss_ppm=loss, tx_parity=parity, "link report");
            }
            _ = flush.tick(), if client_peer.is_some() => {
                let frames = encoder.lock().await.flush()?;
                send_frames(&public, client_peer, frames, &key, &mut pacer).await?;
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
            rate_mbps,
        } => client(listen, server, key, rate_mbps).await,
        Command::Server {
            listen,
            upstream,
            key,
            rate_mbps,
        } => server(listen, upstream, key, rate_mbps).await,
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

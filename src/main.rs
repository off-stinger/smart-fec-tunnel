use anyhow::{bail, Context, Result};
use blake3::Hasher;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use clap::{Parser, Subcommand};
use rand::{Rng, RngCore};
use reed_solomon_erasure::galois_8::ReedSolomon;
use smart_fec_tunnel::quic_relay;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, Mutex},
    task::JoinSet,
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
const FEEDBACK_V2_MAGIC: [u8; 4] = *b"SFR2";
const FEEDBACK_V2_LEN: usize = 24;
const HEADER: usize = 36;
const HEADER_V2: usize = 44;
const V3_SELECTOR: usize = 8; // selector 总长度 = 4 字节 key_id 哈希前缀 + 4 字节随机后缀
const V3_SELECTOR_PREFIX: usize = 4; // 前 4 字节：key_id 的稳定哈希（仅定位密钥，非密钥指纹）
const V3_NONCE: usize = 24;
const V3_INNER_HEADER: usize = 31;
const TAG: usize = 16;
// V3 adds 79 bytes around a shard. 1340 therefore produces a 1419-byte UDP
// payload (1447 bytes with IPv4/UDP), leaving headroom for Internet paths whose
// effective MTU is below Ethernet's nominal 1500 bytes.
const SHARD: usize = 1340;
const FRAGMENT_HEADER: usize = 14;
const CHUNK: usize = SHARD - FRAGMENT_HEADER;
const DATA_SHARDS: usize = 10;
const GROUP_TTL: Duration = Duration::from_secs(2);
const REASSEMBLY_TTL: Duration = Duration::from_secs(3);
const REORDER_WINDOW: u64 = 64;
const MAX_GROUPS: usize = 2048;
const MAX_REASSEMBLIES: usize = 4096;
/// 冗余上限。取值依据：RS(10,k) 的期望收益要求 `(1-p)(10+k) > 10`，即
/// `p < 1 - 10/(10+k)`。k=8 时阈值为 44.4%，再高就连期望都补不回来。
const MAX_PARITY: usize = 8;
/// 常态冗余下限。
///
/// 实测教训：突发丢包到来时 parity 还停在 0，那一窗 18.3% 的丢包
/// `fec_recovered_symbols=0`——一个都没恢复。冗余必须**先于**丢包存在，
/// 否则控制器永远滞后于突发。代价是 ~10% 常态开销。
const MIN_PARITY: usize = 1;
// Loss reports also act as tunnel keepalives.  This reserved value preserves
// that traffic without teaching the adaptive controller that an undersized
// observation window is a real zero-loss sample.
const LOSS_SAMPLE_UNAVAILABLE: u32 = u32::MAX;
const MAX_V2_SESSIONS_PER_DEVICE: usize = 16;
const MAX_V1_MIGRATION_SESSIONS: usize = 64;
const MAX_DEVICE_KEYS: usize = 65_536;
const SESSION_TAKEOVER_MAX_SEQUENCE: u64 = 32;

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
    /// Carry the existing SFT/FEC UDP wire protocol inside authenticated QUIC DATAGRAMs.
    QuicClient {
        #[arg(long, default_value = "127.0.0.1:8444")]
        listen: SocketAddr,
        #[arg(long)]
        server: SocketAddr,
        #[arg(long)]
        server_name: String,
        #[arg(long)]
        ca_cert: PathBuf,
        #[arg(long, env = "SMART_FEC_KEY_ID")]
        key_id: u64,
        #[arg(long, env = "SMART_FEC_KEY")]
        key: String,
    },
    /// Accept authenticated QUIC on UDP/443 and relay SFT frames to a loopback server.
    QuicServer {
        #[arg(long, default_value = "0.0.0.0:443")]
        listen: SocketAddr,
        #[arg(long, default_value = "127.0.0.1:8443")]
        upstream: SocketAddr,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long, env = "SMART_FEC_KEYRING")]
        keyring: PathBuf,
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
        out.extend_from_slice(&v3_selector_prefix(self.key_id));
        let mut random_suffix = [0u8; V3_SELECTOR_PREFIX];
        rand::thread_rng().fill_bytes(&mut random_suffix);
        out.extend_from_slice(&random_suffix);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn decode_v3(buf: &[u8], key_id: u64, key: &[u8; 32]) -> Result<Self> {
        if buf.len() < V3_SELECTOR + V3_NONCE + V3_INNER_HEADER + TAG
            || buf[..V3_SELECTOR_PREFIX] != v3_selector_prefix(key_id)
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

fn v3_selector_prefix(key_id: u64) -> [u8; V3_SELECTOR_PREFIX] {
    let mut hasher = Hasher::new();
    hasher.update(b"smart-fec-v3-selector");
    hasher.update(&key_id.to_be_bytes());
    hasher.finalize().as_bytes()[..V3_SELECTOR_PREFIX]
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

/// `P(X > k)` for `X ~ Binomial(n, p)`.
///
/// `n` is tiny here (`DATA_SHARDS + MAX_PARITY` <= 18), so the exact sum is
/// cheap and avoids the normal approximation's tail error — which is precisely
/// the region this controller cares about.
fn binomial_exceedance(n: usize, p: f64, k: usize) -> f64 {
    if p <= 0.0 || k >= n {
        return 0.0;
    }
    if p >= 1.0 {
        return 1.0;
    }
    let q = 1.0 - p;
    let mut term = q.powi(n as i32);
    let mut cumulative = term;
    for i in 1..=k {
        term *= ((n - i + 1) as f64 / i as f64) * (p / q);
        cumulative += term;
    }
    (1.0 - cumulative).clamp(0.0, 1.0)
}

/// Expected goodput factor for sending `DATA_SHARDS + parity` shards to deliver
/// `DATA_SHARDS` source shards on a path losing `loss_ppm`:
///
/// ```text
/// (fraction of groups that decode) / (bandwidth overhead)
/// = (1 - P(losses > parity)) / (1 + parity / DATA_SHARDS)
/// ```
///
/// Chosen over "pick the largest parity that fits" because block Reed-Solomon
/// has very poor marginal returns at high loss: at 20 % loss, RS(10,4) leaves
/// ~13 % of groups undecodable while RS(10,8) only improves that to ~10 % for
/// double the overhead. Maximising this factor picks the knee instead of the
/// ceiling. (Rationale and the RFC 9265 contract for how FEC relates to
/// congestion control are documented on [`Adaptive`].)
fn fec_goodput_factor(loss_ppm: u32, parity: usize) -> f64 {
    let p = f64::from(loss_ppm.min(1_000_000)) / 1_000_000.0;
    let failure = binomial_exceedance(DATA_SHARDS + parity, p, parity);
    (1.0 - failure) / (1.0 + parity as f64 / DATA_SHARDS as f64)
}

/// Congestion-controlled, loss-driven FEC redundancy controller.
///
/// Layering contract (RFC 9265, "Forward Erasure Correction (FEC) Coding and
/// Congestion Control in Transport"): FEC exists to deliver data on time, and
/// must not be used to hide network loss from the *carrier's* congestion
/// controller. In this stack the carrier sits below FEC and sees the true UDP
/// loss, so that contract is satisfied by construction; what FEC must decide
/// here is only how much redundancy to buy.
///
/// The loss input is the receiver's own wire-frame gap (`sequence_gap_ppm`),
/// i.e. the loss observed on the network channel before recovery — not a
/// post-recovery view. That is the correct signal for sizing redundancy.
#[derive(Debug)]
struct Adaptive {
    parity: usize,
    /// Effective ceiling on parity, normally [`MAX_PARITY`].
    ///
    /// Why this is a knob rather than the output of a better model: deployment
    /// measurement (PRODUCT-MANUAL §10.13) found parity=1 beating parity=5 by
    /// **40.9 %** in median goodput on the same WAN at the same 15-35 % loss
    /// (permutation p ≈ 0.85 %), because the loss is bursty -- measured group
    /// failure 21.3 % against 2.0-8.7 % predicted by independence -- so extra
    /// redundancy did not buy proportional protection. Parity 5 paid 50 %
    /// overhead and still lost data.
    ///
    /// **No loss-based rule can find that optimum**: every such rule sees
    /// residual loss at parity 1 and raises. Finding it properly needs the
    /// receiver's *goodput* in the feedback path, which is a wire-format change
    /// (`FEEDBACK_V2_LEN` is already full). Until that exists, exposing the
    /// ceiling is the honest option -- it lets the measured optimum be used
    /// deliberately instead of being overridden by a model that measurement has
    /// already disproved.
    max_parity: usize,
    bad: u8,
    good: u16,
    last_loss_ppm: u32,
    smoothed_loss_ppm: u32,
    unavailable_reports: u8,
    /// 连续"有丢失但一个都没修回来"的报告次数（恢复驱动输入）。
    shortfall_reports: u8,
}

/// `SMART_FEC_MAX_PARITY` 的默认值：即 [`MAX_PARITY`]，行为与改动前一致。
fn configured_max_parity() -> usize {
    std::env::var("SMART_FEC_MAX_PARITY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse::<usize>().ok())
        .map(|parity| parity.clamp(MIN_PARITY, MAX_PARITY))
        .unwrap_or(MAX_PARITY)
}

impl Default for Adaptive {
    fn default() -> Self {
        Self {
            // 启动即带常态下限，而不是 0。
            //
            // 早先 `parity: 0` 的理由是"避免在拿到反馈前投机性发冗余"。但实测表明
            // 真正的代价在另一头：冗余晚于丢包存在就等于没有冗余（18.3% 突发、
            // `fec_recovered_symbols=0`）。MIN_PARITY 只有约 10% 开销，换的是"突发
            // 到来时一定有东西可用"，代价方向是可接受的。
            parity: MIN_PARITY,
            max_parity: configured_max_parity(),
            bad: 0,
            good: 0,
            last_loss_ppm: 0,
            smoothed_loss_ppm: 0,
            unavailable_reports: 0,
            shortfall_reports: 0,
        }
    }
}

/// 连续多少次"有丢失但一个都没修回来"就立刻抬一档冗余。
const FEC_SHORTFALL_REPORTS_TO_RAISE: u8 = 2;

impl Adaptive {
    /// 恢复驱动输入：把接收端的**修复结果**作为第二个、基于结果的控制信号。
    ///
    /// 与速率信号（`report()` 依据"丢了多少"）的分工：本方法依据"修回来没有"直接
    /// 纠偏。实测的失效模式正是速率信号看不见的那种 —— 丢包率均值尚可，但突发时
    /// 整组修不回来（18.3% 突发、`fec_recovered_symbols=0`）。只看丢包率无法区分
    /// "丢得多但都修好了"与"丢得不多但一组都没修好"。
    ///
    /// 已知局限（诚实记录）：丢失的**冗余分片**同样计入 `missing`，但它本来就不需要
    /// 修复，所以 `recovered == 0` 也可能是"只丢了冗余分片"。此时会多抬一档，随后由
    /// 速率信号正常衰减回来 —— 代价是一次轻微过冲，换来实现上零协议改动（准确定义
    /// 需要新增"丢失的数据分片数"字段，属于线格式变更）。
    fn note_repair_outcome(&mut self, missing: u32, recovered: u32) {
        if missing == 0 || recovered > 0 {
            // 没丢，或冗余确实修回来了：这次的档位是有效的。
            self.shortfall_reports = 0;
            return;
        }
        self.shortfall_reports = self.shortfall_reports.saturating_add(1);
        if self.shortfall_reports >= FEC_SHORTFALL_REPORTS_TO_RAISE {
            self.parity = (self.parity + 1).min(self.max_parity);
            self.good = 0;
            self.bad = 0;
            self.shortfall_reports = 0;
        }
    }
    /// Redundancy level that maximises expected goodput at this loss rate.
    ///
    /// `MIN_PARITY` is the lower bound of the search, which is how the
    /// always-have-some-redundancy rule is enforced.
    ///
    /// **This model is known to be wrong on this link** (§10.13: it predicts
    /// parity 5 where measurement shows parity 1 is 40.9 % faster). It is kept
    /// because it is still the right shape for a non-bursty path, and because
    /// `SMART_FEC_MAX_PARITY` now bounds its influence -- an operator who has
    /// measured their own link can cap the result instead of trusting it.
    fn target(loss_ppm: u32, max_parity: usize) -> usize {
        let mut best = MIN_PARITY;
        let mut best_score = f64::NEG_INFINITY;
        for parity in MIN_PARITY..=max_parity {
            let score = fec_goodput_factor(loss_ppm, parity);
            if score > best_score {
                best_score = score;
                best = parity;
            }
        }
        best
    }

    fn report(&mut self, loss: u32) {
        if loss == LOSS_SAMPLE_UNAVAILABLE {
            // 空闲/无样本：只累计空闲时长用于长时间降级，绝不打断连续丢包样本的
            // 上升/下降计数。否则真实 TUIC 流量的间歇性空闲会反复清零 bad，导致
            // parity 永远升不上去，FEC 形同虚设。
            self.unavailable_reports = self.unavailable_reports.saturating_add(1);
            // Reports arrive every two seconds.  If traffic has been too idle
            // to produce a real sample for 30 seconds, retire one stale parity
            // level.  This keeps the NAT heartbeat without freezing expensive
            // redundancy indefinitely after a previous burst.  The floor is
            // MIN_PARITY, never 0.
            if self.unavailable_reports >= 15 && self.parity > MIN_PARITY {
                self.parity -= 1;
                self.unavailable_reports = 0;
            }
            return;
        }
        self.unavailable_reports = 0;
        self.last_loss_ppm = loss;
        self.smoothed_loss_ppm = ((self.smoothed_loss_ppm as u64 * 3 + loss as u64) / 4) as u32;
        let target = Self::target(self.smoothed_loss_ppm, self.max_parity);

        if target > self.parity {
            // A jump of two or more levels is a burst: apply it at once instead
            // of spending two more report intervals (4 s) climbing. Parity that
            // lags a burst is exactly the failure mode that measured out as
            // `fec_recovered_symbols=0` on an 18.3 % burst.
            if target >= self.parity + 2 {
                self.parity = target;
                self.bad = 0;
                self.good = 0;
                return;
            }
            self.bad += 1;
            self.good = 0;
            if self.bad >= 2 {
                self.parity = (self.parity + 1).min(self.max_parity);
                self.bad = 0;
            }
        } else if target < self.parity {
            self.good += 1;
            self.bad = self.bad.saturating_sub(1);
            if self.good >= 15 {
                self.parity = self.parity.saturating_sub(1).max(MIN_PARITY);
                self.good = 0;
            }
        } else {
            self.bad = self.bad.saturating_sub(1);
            self.good = 0;
        }
    }

    fn report_feedback(&mut self, feedback: FecFeedback) {
        match feedback {
            FecFeedback::Legacy(loss) => self.report(loss),
            FecFeedback::Sample(sample) => {
                let parity_before = self.parity;
                self.report(sample.sequence_gap_ppm);
                // A useful reconstruction is evidence that the current parity is
                // buying delivery, so do not age it down on that same sample.
                // The loss input itself is the receiver's raw wire-frame gap
                // (pre-recovery), so this never hides loss from the sizing
                // decision -- it only prevents a needless one-step decay.
                if sample.fec_recovered_symbols > 0 && self.parity < parity_before {
                    self.parity = parity_before;
                    self.good = 0;
                }
                // 第二个控制信号：不看丢了多少，看修回来没有。
                self.note_repair_outcome(sample.missing, sample.fec_recovered_symbols);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FeedbackSample {
    sequence_gap_ppm: u32,
    expected: u32,
    missing: u32,
    fec_recovered_symbols: u32,
    fec_recovered_groups: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FecFeedback {
    Legacy(u32),
    Sample(FeedbackSample),
}

fn decode_fec_feedback(payload: &[u8]) -> Option<FecFeedback> {
    if payload.len() == 4 {
        return Some(FecFeedback::Legacy(u32::from_be_bytes(
            payload.try_into().ok()?,
        )));
    }
    if payload.len() != FEEDBACK_V2_LEN || payload[..4] != FEEDBACK_V2_MAGIC {
        return None;
    }
    let read = |offset| u32::from_be_bytes(payload[offset..offset + 4].try_into().unwrap());
    let sample = FeedbackSample {
        sequence_gap_ppm: read(4),
        expected: read(8),
        missing: read(12),
        fec_recovered_symbols: read(16),
        fec_recovered_groups: read(20),
    };
    if sample.sequence_gap_ppm > 1_000_000
        || sample.expected < 32
        || sample.missing > sample.expected
        || sample.fec_recovered_groups > sample.fec_recovered_symbols
    {
        return None;
    }
    let calculated_gap = ((sample.missing as u64 * 1_000_000) / sample.expected as u64) as u32;
    (calculated_gap == sample.sequence_gap_ppm).then_some(FecFeedback::Sample(sample))
}

fn encode_fec_feedback(sample: &SequenceReport) -> Vec<u8> {
    let mut payload = Vec::with_capacity(FEEDBACK_V2_LEN);
    payload.extend_from_slice(&FEEDBACK_V2_MAGIC);
    payload.extend_from_slice(&sample.sequence_gap_ppm.to_be_bytes());
    payload.extend_from_slice(&(sample.expected.min(u32::MAX as u64) as u32).to_be_bytes());
    payload.extend_from_slice(&(sample.missing.min(u32::MAX as u64) as u32).to_be_bytes());
    payload.extend_from_slice(
        &(sample.fec_recovered_symbols.min(u32::MAX as u64) as u32).to_be_bytes(),
    );
    payload.extend_from_slice(
        &(sample.fec_recovered_groups.min(u32::MAX as u64) as u32).to_be_bytes(),
    );
    payload
}

/// Interval length for the traffic-accounting record, in seconds.
const TRAFFIC_INTERVAL_SECS: u64 = 5;

/// Declares the process-wide traffic counters once, then derives the snapshot
/// struct plus its `read`/`delta` implementation from the same field list.
///
/// The single list matters: a hand-written snapshot that silently omits a field
/// is exactly the kind of instrumentation bug that makes the accounting fail to
/// close, which is the one thing this whole exercise exists to detect.
macro_rules! traffic_counters {
    ($($field:ident),* $(,)?) => {
        /// Process-wide FEC-layer traffic accounting.
        ///
        /// These counters exist to answer one question the existing telemetry
        /// cannot: the carrier reports ~zero packet loss and the FEC layer
        /// reports `missing=0`, yet the application receives only a fraction of
        /// what the server puts on the wire. One hypothesis -- that the inner
        /// UDP socket silently drops because its consumer (TUIC) is slow -- was
        /// falsified before writing this: `/proc/net/snmp` `RcvbufErrors` did
        /// not move at all under a sustained load. So the accounting has to
        /// happen in-process, at every boundary a byte crosses.
        ///
        /// Deliberately global rather than threaded through every send/receive
        /// path: a handle would touch far more code than a diagnostic is worth.
        /// Every field is monotonic; records emit deltas.
        struct Counters {
            $( $field: AtomicU64, )*
        }
        impl Counters {
            const fn new() -> Self {
                Self { $( $field: AtomicU64::new(0), )* }
            }
        }
        static COUNTERS: Counters = Counters::new();

/// Claims the single traffic-logging role on the server.
///
/// [`COUNTERS`] is process-wide but `run_server_session` runs once per device
/// session, so without this every concurrent session would emit its own record
/// of the *same* global totals -- overlapping deltas that look like duplicated
/// traffic. Exactly one session logs; the totals it reports are still complete.
static TRAFFIC_LOGGER_CLAIMED: AtomicBool = AtomicBool::new(false);

        #[derive(Clone, Copy, Default)]
        struct CounterSnapshot {
            $( $field: u64, )*
        }
        impl CounterSnapshot {
            fn read() -> Self {
                Self { $( $field: COUNTERS.$field.load(Ordering::Relaxed), )* }
            }
            fn delta(&self, previous: &Self) -> Self {
                Self { $( $field: self.$field.saturating_sub(previous.$field), )* }
            }
        }
    };
}

// Field list for `traffic_counters!`. Attributes cannot be attached to an
// `ident` fragment, so the explanations live here rather than as doc comments.
//
// inner_rx_bytes / inner_rx_datagrams -- bytes the inner side (TUIC) handed to
//   the tunnel, i.e. what the inner protocol actually offered.
// inner_tx_bytes / inner_tx_datagrams -- bytes the tunnel handed to the inner
//   side, i.e. what the application should have received.
// inner_tx_failures -- inner-side send failures. A silent drop here would
//   otherwise be indistinguishable from data that was never sent at all.
// wire_tx_bytes / wire_rx_bytes -- encrypted bytes handed to / received from
//   the carrier.
// wire_{tx,rx}_{data,parity,report}_frames -- frame mix, so FEC overhead can be
//   separated from payload without guessing the parity in force.
// groups_recovered -- FEC groups reconstructed successfully.
// groups_failed / unrecovered_shards -- groups that expired with data shards
//   still undelivered: the application data FEC failed to recover, and the only
//   loss number that matters to a user.
// frames_rejected -- malformed frames, or frames for another identity/session.
//   A spike means the two ends disagree about configuration, which would
//   otherwise look exactly like packet loss.
traffic_counters! {
    inner_rx_bytes,
    inner_rx_datagrams,
    inner_tx_bytes,
    inner_tx_datagrams,
    inner_tx_failures,
    wire_tx_bytes,
    wire_rx_bytes,
    wire_tx_data_frames,
    wire_tx_parity_frames,
    wire_tx_report_frames,
    wire_rx_data_frames,
    wire_rx_parity_frames,
    wire_rx_report_frames,
    groups_recovered,
    groups_failed,
    unrecovered_shards,
    frames_rejected,
}

/// Wall-clock aligned interval id, derived independently by both ends.
///
/// This is what makes the client's and the server's records comparable at all:
/// with NTP-synced clocks both land in the same 5-second bucket, so no
/// coordination protocol is needed to line the two sides up.
fn traffic_interval_id() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() / TRAFFIC_INTERVAL_SECS)
        .unwrap_or(0)
}

fn ratio_ppm(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    ((u128::from(numerator) * 1_000_000) / u128::from(denominator)) as u64
}

fn count_wire_tx(kind: u8) {
    match kind {
        KIND_DATA => COUNTERS.wire_tx_data_frames.fetch_add(1, Ordering::Relaxed),
        KIND_PARITY => COUNTERS
            .wire_tx_parity_frames
            .fetch_add(1, Ordering::Relaxed),
        KIND_REPORT => COUNTERS
            .wire_tx_report_frames
            .fetch_add(1, Ordering::Relaxed),
        _ => 0,
    };
}

fn count_wire_rx(kind: u8) {
    match kind {
        KIND_DATA => COUNTERS.wire_rx_data_frames.fetch_add(1, Ordering::Relaxed),
        KIND_PARITY => COUNTERS
            .wire_rx_parity_frames
            .fetch_add(1, Ordering::Relaxed),
        KIND_REPORT => COUNTERS
            .wire_rx_report_frames
            .fetch_add(1, Ordering::Relaxed),
        _ => 0,
    };
}

/// Emit one traffic-accounting record and return the counters it covered.
///
/// The derived ratios are logged next to the raw counters so a reader does not
/// have to recompute them and get it wrong:
/// * `fec_overhead_ppm` -- wire bytes spent per inner byte offered;
/// * `wire_to_inner_ppm` -- of the wire bytes received, how many reached the
///   inner side. **This is not a delivery ratio**: the denominator includes FEC
///   parity, so a healthy 60 % here can coexist with zero loss. It is the number
///   that was previously inferred from `curl` and attributed to the wrong layer.
/// * `parity_frame_ppm` -- the overhead term, so overhead and loss are separable.
fn log_traffic(role: &str, previous: &mut CounterSnapshot) {
    // Opt-out rather than opt-in: the whole point of these counters is to be
    // present when something goes wrong, and one record per 5 seconds is small
    // next to the existing 2-second sequence reports. Read live so it can be
    // toggled without a restart.
    if std::env::var("SMART_FEC_TRAFFIC_LOG").as_deref() == Ok("0") {
        return;
    }
    let current = CounterSnapshot::read();
    let delta = current.delta(previous);
    *previous = current;
    info!(
        role,
        interval = traffic_interval_id(),
        inner_rx_bytes = delta.inner_rx_bytes,
        inner_rx_datagrams = delta.inner_rx_datagrams,
        inner_tx_bytes = delta.inner_tx_bytes,
        inner_tx_datagrams = delta.inner_tx_datagrams,
        inner_tx_failures = delta.inner_tx_failures,
        wire_tx_bytes = delta.wire_tx_bytes,
        wire_rx_bytes = delta.wire_rx_bytes,
        wire_tx_data_frames = delta.wire_tx_data_frames,
        wire_tx_parity_frames = delta.wire_tx_parity_frames,
        wire_rx_data_frames = delta.wire_rx_data_frames,
        wire_rx_parity_frames = delta.wire_rx_parity_frames,
        groups_recovered = delta.groups_recovered,
        groups_failed = delta.groups_failed,
        unrecovered_shards = delta.unrecovered_shards,
        frames_rejected = delta.frames_rejected,
        fec_overhead_ppm = ratio_ppm(delta.wire_tx_bytes, delta.inner_rx_bytes),
        // Named for what it actually measures. It was `delivery_ppm`, which reads
        // as "how much was delivered" and misled a diagnosis: the denominator is
        // *wire* bytes, so the value is dominated by FEC parity overhead rather
        // than by loss. On the live downlink it read 29 % while `groups_failed`
        // was 0 and the carrier reported zero loss -- the other 71 % was parity
        // and Reed-Solomon padding, not loss at all.
        wire_to_inner_ppm = ratio_ppm(delta.inner_tx_bytes, delta.wire_rx_bytes),
        // The overhead term of the above, exposed separately so overhead and loss
        // can be told apart without arithmetic on the raw counts.
        parity_frame_ppm = ratio_ppm(delta.wire_tx_parity_frames, delta.wire_tx_data_frames),
        "FEC traffic accounting"
    );
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
    /// 诊断/实验用：固定 parity，绕过自适应。
    ///
    /// 一度只在 debug 构建生效（怕误设环境变量绕过自适应）。但生产链路因此**无法
    /// 固定 parity**，而"parity 的目标函数对不对"恰恰只能在真实链路上做受控 A/B
    /// 才能回答——这个缺口把验证能力也一起关掉了。现在 release 同样生效，代之以
    /// **显眼**：启用时打一条 WARN，且值夹到 `MAX_PARITY`。
    force_parity: Option<usize>,
}

impl Encoder {
    #[cfg(test)]
    fn new(session: u64) -> Self {
        Self::with_identity(session, VERSION_V1, 0)
    }
    fn with_identity(session: u64, version: u8, key_id: u64) -> Self {
        let force_parity = std::env::var("SMART_FEC_FORCE_PARITY")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .and_then(|value| value.parse::<usize>().ok())
            .map(|parity| parity.min(MAX_PARITY));
        if let Some(parity) = force_parity {
            // Loud on purpose. This bypasses the adaptive controller entirely, so
            // a link left in this state carries whatever redundancy was typed in
            // rather than what the path needs.
            warn!(
                parity,
                "SMART_FEC_FORCE_PARITY is set: adaptive redundancy is DISABLED and \
                 parity is pinned. Diagnostic/experiment use only."
            );
        }
        Self {
            version,
            key_id,
            session,
            sequence: 1,
            packet: 1,
            group: 1,
            shards: Vec::new(),
            adaptive: Adaptive::default(),
            force_parity,
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
    /// Build the periodic FEC feedback frame.
    ///
    /// A peer predating feedback V2 only accepts a 4-byte payload: it decodes
    /// with `try_into::<[u8; 4]>()`, so a 24-byte frame fails to parse and the
    /// whole report is dropped. Sending V2 unconditionally therefore leaves such
    /// a peer completely blind to loss rather than degrading it to the legacy
    /// sample, freezing its parity at whatever it held when the other end was
    /// upgraded. Until the peer proves it can produce a V2 sample itself, send
    /// the legacy frame every version understands.
    fn feedback_frame(&mut self, sample: Option<SequenceReport>, peer_supports_v2: bool) -> Frame {
        let mut frame = self
            .report_frame(sample.map_or(LOSS_SAMPLE_UNAVAILABLE, |sample| sample.sequence_gap_ppm));
        if let Some(sample) = sample.filter(|_| peer_supports_v2) {
            frame.payload = encode_fec_feedback(&sample);
        }
        frame
    }
    fn encode_datagram(&mut self, payload: &[u8]) -> Result<Vec<Frame>> {
        let packet_id = self.packet;
        self.packet += 1;
        let count = payload.len().max(1).div_ceil(CHUNK);
        if count > u16::MAX as usize {
            bail!("datagram too large")
        }
        let mut frames = Vec::new();
        // Split into **balanced** fragments, not greedy `CHUNK`-sized ones.
        //
        // This is a throughput fix with no wire-format change, and it was worth
        // ~2x on the downlink. `flush()` pads every source shard in a group up to
        // the group's longest shard, because Reed-Solomon needs equal-length
        // symbols. With greedy splitting, a payload of `CHUNK + 27` bytes -- which
        // is exactly what the inner TUIC flow produces (measured: 1353-byte
        // datagrams against CHUNK = 1326) -- becomes one full 1326-byte fragment
        // plus a 27-byte fragment, and that 27-byte fragment is then padded to a
        // full 1340-byte shard. Cost: 2680 wire bytes to carry 1353.
        //
        // Measured on the live carrier before the fix: 5327 data shards for 2694
        // inner datagrams (1.977 shards each) and `delivery_ppm` = 29 %. The
        // arithmetic closes exactly -- 1.98 (padding) x 1.67 (parity) = 3.30, and
        // 1/3.30 = 30 %.
        //
        // Balancing the split makes both fragments ~677 bytes instead, so the
        // padding has almost nothing to do. The receiver needs no change: it
        // already reads a per-fragment length from the header.
        let per = if payload.is_empty() {
            1
        } else {
            payload.len().div_ceil(count).max(1)
        };
        let chunks: Vec<&[u8]> = if payload.is_empty() {
            vec![&[]]
        } else {
            payload.chunks(per).collect()
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
        let parity = if let Some(p) = self.force_parity {
            p.min(data)
        } else if self.adaptive.parity == 0 {
            0
        } else if data < DATA_SHARDS {
            // Never emit more repair shards than source shards for a partial
            // group.  In particular, a single QUIC datagram needs at most one
            // duplicate to recover one loss.
            self.adaptive.parity.min(data)
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
        // Equal-sized source shards are required only when Reed-Solomon parity
        // is actually generated. Keeping variable lengths at parity=0 avoids
        // turning a tiny tail fragment into another full-sized wire packet.
        if parity > 0 {
            for shard in &mut self.shards {
                shard.resize(shard_len, 0);
            }
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
            all.extend((0..parity).map(|_| vec![0u8; shard_len]));
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
    start_sequence: u64,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SequenceReport {
    expected: u64,
    received: u64,
    missing: u64,
    /// Sequence gaps are observed wire-frame gaps, not necessarily unrecovered
    /// application datagrams. Recovery events are aligned to this finalized window.
    sequence_gap_ppm: u32,
    fec_recovered_symbols: u64,
    fec_recovered_groups: u64,
    late: u64,
    duplicates: u64,
    /// Data shards that were never delivered in this window: groups that expired
    /// with undelivered data.
    ///
    /// Unlike `missing` -- which counts wire-frame gaps and therefore includes
    /// lost **parity** shards that need no repair -- this is exactly the loss a
    /// user can see. Reporting it in the *same* window as `missing` is the point:
    /// `missing` alone cannot distinguish "lost a lot but all repaired" from
    /// "lost little but whole groups failed", and the ratio between the two is
    /// what separates burst loss from independent loss. The existing recovery
    /// signal had to approximate this from `missing` and `fec_recovered_symbols`
    /// precisely because the accurate number was unavailable.
    unrecovered_shards: u64,
    /// Groups that expired with undelivered data, in the same window.
    failed_groups: u64,
}

#[derive(Debug)]
struct Decoder {
    session: u64,
    highest_sequence: u64,
    finalized_sequence: u64,
    seen_sequences: BTreeSet<u64>,
    late_sequences: u64,
    duplicate_sequences: u64,
    /// 每个 FEC 组重建成功时记一次账，键是**被重建的那个数据分片自己的线上序号**，
    /// 值为 (重建出的符号数, 组数)。选择"丢失分片的序号"而不是"触发重建的分片序号"
    /// 是有意的：这样恢复就被计入"观测到该丢包的那个窗口"，也就是丢包与恢复同窗，
    /// `report_feedback` 的 `fec_recovered_symbols > 0` 门控才有意义。
    ///
    /// 保证：`sequence_report()` 用 `split_off(&(cutoff + 1))` 排空所有键 ≤ cutoff 的
    /// 条目，因此每个事件恰好被计入一次；若键早于已 finalize 的窗口，它只会推迟到
    /// 下一个窗口，绝不会丢失。也不会重复计数：重建后 `delivered` 全为 true，
    /// `any(|x| !*x)` 不再成立（即便该条件被放宽，`recovered_indices` 也已为空，
    /// 仍然不会重复记账）。
    ///
    /// 边界：cutoff 恒为 `highest_sequence - REORDER_WINDOW`，所以"最后 64 个序号内"
    /// 的事件必须等 `highest_sequence` 继续前进才会被排空。流量持续时这不是问题；
    /// 一旦连接停止，尾部最多一个窗口内的事件不会进入任何报告（有界，且只影响统计
    /// 口径，不影响数据面）。这一点由
    /// `fec_recovery_is_counted_once_per_group_across_window_boundaries` 覆盖。
    fec_recovery_events: BTreeMap<u64, (u64, u64)>,
    groups: BTreeMap<u64, Group>,
    packets: HashMap<u64, Reassembly>,
    /// Unrecovered data shards / failed groups accumulated since the last
    /// `sequence_report`.
    ///
    /// `prune` discovers these when a group expires, which is not the same moment
    /// the report window closes, so they are buffered and drained into whichever
    /// window is finalized next. Draining (rather than reporting the global
    /// total) keeps them in the same window as `missing`, which is what makes the
    /// two comparable.
    pending_unrecovered_shards: u64,
    pending_failed_groups: u64,
}

/// Counts FEC groups that have outlived [`GROUP_TTL`] while still holding
/// undelivered data shards, returning `(failed_groups, unrecovered_shards)`.
///
/// This is the *unrecovered application data* signal: the frames arrived at the
/// carrier (and were usually ACKed), and `sequence_report` counts wire-frame
/// arrival, so neither existing counter attributes a single one of them. An
/// unrecovered shard is an inner datagram the application never got.
///
/// Extracted as a pure function so the loss accounting can be unit-tested
/// without racing the process-wide counters, which are global by design.
fn expired_group_loss(groups: &BTreeMap<u64, Group>, now: Instant) -> (u64, u64) {
    let mut failed_groups = 0u64;
    let mut unrecovered_shards = 0u64;
    for group in groups.values() {
        if now.duration_since(group.created) < GROUP_TTL {
            continue;
        }
        let missing = group
            .delivered
            .iter()
            .filter(|delivered| !**delivered)
            .count();
        if missing > 0 {
            failed_groups = failed_groups.saturating_add(1);
            unrecovered_shards = unrecovered_shards.saturating_add(missing as u64);
        }
    }
    (failed_groups, unrecovered_shards)
}

impl Decoder {
    fn new(session: u64) -> Self {
        Self {
            session,
            highest_sequence: 0,
            finalized_sequence: 0,
            seen_sequences: BTreeSet::new(),
            late_sequences: 0,
            duplicate_sequences: 0,
            fec_recovery_events: BTreeMap::new(),
            groups: BTreeMap::new(),
            packets: HashMap::new(),
            pending_unrecovered_shards: 0,
            pending_failed_groups: 0,
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
            self.late_sequences = self.late_sequences.saturating_add(1);
            return false;
        }
        self.highest_sequence = self.highest_sequence.max(seq);
        if !self.seen_sequences.insert(seq) {
            self.duplicate_sequences = self.duplicate_sequences.saturating_add(1);
            return false;
        }
        true
    }
    fn sequence_report(&mut self) -> Option<SequenceReport> {
        let cutoff = self.highest_sequence.saturating_sub(REORDER_WINDOW);
        if cutoff <= self.finalized_sequence {
            return None;
        }
        let expected = cutoff - self.finalized_sequence;
        // A single missing report in an idle connection must not be represented
        // as 100% loss or drive the adaptive redundancy controller. Accumulate a
        // statistically useful window before finalizing a result.
        if expected < 32 {
            return None;
        }
        let received = self
            .seen_sequences
            .range((self.finalized_sequence + 1)..=cutoff)
            .count() as u64;
        let missing = expected.saturating_sub(received);
        let gap_ppm = ((missing as u128 * 1_000_000) / expected as u128) as u32;
        self.seen_sequences = self.seen_sequences.split_off(&(cutoff + 1));
        self.finalized_sequence = cutoff;
        let future_recoveries = self
            .fec_recovery_events
            .split_off(&cutoff.saturating_add(1));
        let finalized_recoveries =
            std::mem::replace(&mut self.fec_recovery_events, future_recoveries);
        let (fec_recovered_symbols, fec_recovered_groups) = finalized_recoveries.values().fold(
            (0u64, 0u64),
            |(symbols, groups), (next_symbols, next_groups)| {
                (
                    symbols.saturating_add(*next_symbols),
                    groups.saturating_add(*next_groups),
                )
            },
        );
        let report = SequenceReport {
            expected,
            received,
            missing,
            sequence_gap_ppm: gap_ppm.min(1_000_000),
            fec_recovered_symbols,
            fec_recovered_groups,
            late: std::mem::take(&mut self.late_sequences),
            duplicates: std::mem::take(&mut self.duplicate_sequences),
            unrecovered_shards: std::mem::take(&mut self.pending_unrecovered_shards),
            failed_groups: std::mem::take(&mut self.pending_failed_groups),
        };
        Some(report)
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
        let group_start_sequence = frame
            .sequence
            .checked_sub(pos as u64)
            .filter(|sequence| *sequence > 0)
            .context("invalid FEC group sequence")?;
        let (immediate, recovered) = {
            let g = self.groups.entry(frame.group).or_insert_with(|| Group {
                created: Instant::now(),
                start_sequence: group_start_sequence,
                data,
                parity,
                shards: vec![None; data + parity],
                delivered: vec![false; data],
            });
            if g.data != data || g.parity != parity || g.start_sequence != group_start_sequence {
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
                let recovered_indices = g
                    .delivered
                    .iter()
                    .enumerate()
                    .filter_map(|(index, delivered)| (!*delivered).then_some(index))
                    .collect::<Vec<_>>();
                let rs = ReedSolomon::new(data, parity)?;
                rs.reconstruct(&mut g.shards)?;
                COUNTERS.groups_recovered.fetch_add(1, Ordering::Relaxed);
                recovered = (0..data)
                    .filter(|i| !g.delivered[*i])
                    .filter_map(|i| g.shards[i].clone())
                    .collect();
                for i in 0..data {
                    g.delivered[i] = true;
                }
                for index in &recovered_indices {
                    let event = self
                        .fec_recovery_events
                        .entry(g.start_sequence.saturating_add(*index as u64))
                        .or_insert((0, 0));
                    event.0 = event.0.saturating_add(1);
                }
                if let Some(last_index) = recovered_indices.last() {
                    let event = self
                        .fec_recovery_events
                        .entry(g.start_sequence.saturating_add(*last_index as u64))
                        .or_insert((0, 0));
                    event.1 = event.1.saturating_add(1);
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
        // Count groups that are about to expire while still holding undelivered
        // data shards. Those are the inner datagrams FEC failed to recover --
        // the only loss that is visible to a user, and the number that was
        // missing from every existing counter: the carrier reports these frames
        // as sent (and often ACKed), and `sequence_report` counts wire-frame
        // arrival, so neither attributes them.
        let (failed_groups, unrecovered_shards) = expired_group_loss(&self.groups, now);
        if failed_groups > 0 {
            COUNTERS
                .groups_failed
                .fetch_add(failed_groups, Ordering::Relaxed);
            COUNTERS
                .unrecovered_shards
                .fetch_add(unrecovered_shards, Ordering::Relaxed);
            // Also buffer them for the next `sequence_report`, so the report
            // carries the accurate loss alongside `missing` in the same window.
            self.pending_failed_groups = self.pending_failed_groups.saturating_add(failed_groups);
            self.pending_unrecovered_shards = self
                .pending_unrecovered_shards
                .saturating_add(unrecovered_shards);
        }
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
    _legacy_key: Option<&[u8; 32]>,
    _keyring: &HashMap<u64, [u8; 32]>,
    selectors: &HashMap<[u8; V3_SELECTOR_PREFIX], (u64, [u8; 32])>,
) -> Result<(Frame, [u8; 32])> {
    if !bytes.starts_with(&MAGIC.to_be_bytes()) {
        if bytes.len() < V3_SELECTOR {
            bail!("short v3 envelope")
        }
        let prefix: [u8; V3_SELECTOR_PREFIX] = bytes[..V3_SELECTOR_PREFIX].try_into().unwrap();
        let (key_id, selected) = selectors.get(&prefix).context("unknown v3 selector")?;
        return Ok((Frame::decode_v3(bytes, *key_id, selected)?, *selected));
    }
    // MAGIC 开头 = legacy V1/V2 明文协议，已下线，统一拒绝。
    bail!("legacy V1/V2 protocol removed");
}

async fn send_frames(
    socket: &UdpSocket,
    peer: Option<SocketAddr>,
    frames: Vec<Frame>,
    key: &[u8; 32],
    pacer: &mut Pacer,
) -> Result<()> {
    for frame in frames {
        let kind = frame.kind;
        let bytes = match frame.encode_wire(key) {
            Ok(bytes) => bytes,
            Err(error) => {
                warn!(%error, "frame encryption failed");
                continue;
            }
        };
        COUNTERS
            .wire_tx_bytes
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        count_wire_tx(kind);
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
            // Refill in scheduler-sized batches. OpenWrt cannot reliably wake
            // for the sub-millisecond per-frame deficit at 30+ Mbit/s; doing so
            // collapses throughput because each nominal 0.3 ms wait rounds up.
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
        bail!("key-id 0 is reserved")
    }
    // V1/V2 明文 legacy 协议已下线，强制使用 V3 加密。
    let key_id = key_id.context("key-id required: legacy V1/V2 removed")?;
    let key = key(&secret);
    let session = rand::thread_rng().gen::<u64>();
    let version = VERSION_V3;
    let local = UdpSocket::bind(listen)
        .await
        .context("bind client listen")?;
    let tunnel = UdpSocket::bind("0.0.0.0:0").await?;
    tunnel.connect(server).await?;
    let encoder = Arc::new(Mutex::new(Encoder::with_identity(session, version, key_id)));
    let mut decoder = Decoder::new(session);
    // 对端是否已证明能解析 feedback V2。未证明前只发 4 字节 legacy 帧，
    // 否则旧版本对端会整帧丢弃并彻底失去丢包样本（详见 feedback_frame）。
    let mut peer_feedback_v2 = false;
    let mut app_peer = None;
    let mut local_buf = vec![0u8; 65535];
    let mut net_buf = vec![0u8; 2048];
    let mut report = time::interval(Duration::from_secs(2));
    let mut flush = time::interval(Duration::from_millis(5));
    let mut traffic = time::interval(Duration::from_secs(TRAFFIC_INTERVAL_SECS));
    let mut traffic_previous = CounterSnapshot::default();
    let mut pacer = Pacer::new(rate_mbps)?;
    info!(%listen, %server, session, "client started");
    loop {
        tokio::select! {
            r = local.recv_from(&mut local_buf) => {
                let (n, peer) = r?; app_peer = Some(peer);
                COUNTERS.inner_rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                COUNTERS.inner_rx_datagrams.fetch_add(1, Ordering::Relaxed);
                let frames = encoder.lock().await.encode_datagram(&local_buf[..n])?;
                send_frames(&tunnel, None, frames, &key, &mut pacer).await?;
            }
            r = tunnel.recv(&mut net_buf) => {
                let n = match r { Ok(n) => n, Err(e) => { warn!(error=%e, "tunnel receive failed"); continue; } };
                COUNTERS.wire_rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                match decode_client_frame(&net_buf[..n], key_id, &key) {
                    Ok(f) if f.version != version || f.key_id != key_id || f.session != session => {
                        COUNTERS.frames_rejected.fetch_add(1, Ordering::Relaxed);
                        warn!("discard frame for different identity or session");
                    }
                    Ok(f) if f.kind == KIND_REPORT => {
                        count_wire_rx(f.kind);
                        if decoder.observe_seq(f.sequence) {
                            if let Some(feedback) = decode_fec_feedback(&f.payload) {
                                if matches!(feedback, FecFeedback::Sample(_)) {
                                    peer_feedback_v2 = true;
                                }
                                encoder.lock().await.adaptive.report_feedback(feedback);
                            } else {
                                warn!(payload_len=f.payload.len(), "discard invalid FEC feedback");
                            }
                        }
                    }
                    Ok(f) => {
                        count_wire_rx(f.kind);
                        match decoder.frame(f) {
                            Ok(datagrams) => for d in datagrams {
                                let Some(peer) = app_peer else { continue };
                                match local.send_to(&d, peer).await {
                                    Ok(_) => {
                                        COUNTERS.inner_tx_bytes.fetch_add(d.len() as u64, Ordering::Relaxed);
                                        COUNTERS.inner_tx_datagrams.fetch_add(1, Ordering::Relaxed);
                                    }
                                    Err(e) => {
                                        COUNTERS.inner_tx_failures.fetch_add(1, Ordering::Relaxed);
                                        warn!(error=%e, "local send failed");
                                    }
                                }
                            },
                            Err(e) => {
                                COUNTERS.frames_rejected.fetch_add(1, Ordering::Relaxed);
                                warn!(error=%e, "discard invalid fec frame");
                            }
                        }
                    }
                    Err(e) => {
                        COUNTERS.frames_rejected.fetch_add(1, Ordering::Relaxed);
                        warn!(error=%e, "discard frame");
                    }
                }
            }
            _ = report.tick() => {
                let report = decoder.sequence_report();
                let mut enc = encoder.lock().await;
                let parity = enc.adaptive.parity;
                let f = enc.feedback_frame(report, peer_feedback_v2);
                drop(enc); send_frames(&tunnel, None, vec![f], &key, &mut pacer).await?;
                if let Some(sample) = report {
                    info!(
                        sequence_gap_ppm=sample.sequence_gap_ppm,
                        expected=sample.expected,
                        received=sample.received,
                        missing=sample.missing,
                        fec_recovered_symbols=sample.fec_recovered_symbols,
                        fec_recovered_groups=sample.fec_recovered_groups,
                        fec_counter_scope="finalized_sequence_window",
                        late=sample.late,
                        duplicates=sample.duplicates,
                        // The accurate loss, in the same window as `missing`.
                        // Comparing the two is what distinguishes burst loss from
                        // independent loss: under independent loss at these rates
                        // a group should almost never fail, so a group failure
                        // count that scales with `missing` means bursts.
                        unrecovered_shards=sample.unrecovered_shards,
                        failed_groups=sample.failed_groups,
                        tx_parity=parity,
                        "sequence report"
                    );
                } else {
                    info!(tx_parity=parity, "sequence report unavailable");
                }
            }
            _ = flush.tick() => {
                let frames = encoder.lock().await.flush()?;
                send_frames(&tunnel, None, frames, &key, &mut pacer).await?;
            }
            _ = traffic.tick() => {
                log_traffic("client", &mut traffic_previous);
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

fn superseded_sessions<T>(
    sessions: &HashMap<(u64, u64), T>,
    key_id: u64,
    session: u64,
    sequence: u64,
) -> Option<Vec<(u64, u64)>> {
    let existing: Vec<_> = sessions
        .keys()
        .filter(|(id, current)| *id == key_id && *current != session)
        .copied()
        .collect();
    if existing.is_empty() {
        return Some(existing);
    }
    // A freshly started authenticated client begins near sequence one.  Once
    // it takes over, delayed high-sequence reports from an old session must be
    // ignored or they can continuously replace the live session again.
    (sequence <= SESSION_TAKEOVER_MAX_SEQUENCE).then_some(existing)
}

async fn send_session_frames(
    public: &UdpSocket,
    peer: SocketAddr,
    frames: Vec<Frame>,
    key: &[u8; 32],
    pacer: &Mutex<Pacer>,
) {
    for frame in frames {
        let kind = frame.kind;
        let bytes = match frame.encode_wire(key) {
            Ok(bytes) => bytes,
            Err(error) => {
                warn!(%error, "session encryption failed");
                continue;
            }
        };
        COUNTERS
            .wire_tx_bytes
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        count_wire_tx(kind);
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
    // 同客户端：未证明对端能解析 feedback V2 前只发 legacy 帧。
    let mut peer_feedback_v2 = false;
    let mut upstream_buf = vec![0u8; 65535];
    let mut report = time::interval(Duration::from_secs(2));
    let mut flush = time::interval(Duration::from_millis(5));
    let mut traffic = time::interval(Duration::from_secs(TRAFFIC_INTERVAL_SECS));
    let mut traffic_previous = CounterSnapshot::default();
    let logs_traffic = TRAFFIC_LOGGER_CLAIMED
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok();
    let mut last_logged_parity = 0usize;
    loop {
        tokio::select! {
            packet = input.recv() => {
                let Some(packet) = packet else { return Ok(()) };
                peer = Some(packet.peer);
                let frame = packet.frame;
                if frame.session != runtime.session || frame.version != runtime.version || frame.key_id != runtime.key_id {
                    COUNTERS.frames_rejected.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                count_wire_rx(frame.kind);
                if frame.kind == KIND_REPORT {
                    if decoder.observe_seq(frame.sequence) {
                        if let Some(feedback) = decode_fec_feedback(&frame.payload) {
                            if matches!(feedback, FecFeedback::Sample(_)) {
                                peer_feedback_v2 = true;
                            }
                            encoder.adaptive.report_feedback(feedback);
                        } else {
                            warn!(payload_len=frame.payload.len(), "discard invalid FEC feedback");
                        }
                    }
                } else {
                    match decoder.frame(frame) {
                        Ok(datagrams) => for datagram in datagrams {
                            match upstream_socket.send(&datagram).await {
                                Ok(_) => {
                                    COUNTERS.inner_tx_bytes.fetch_add(datagram.len() as u64, Ordering::Relaxed);
                                    COUNTERS.inner_tx_datagrams.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(error) => {
                                    COUNTERS.inner_tx_failures.fetch_add(1, Ordering::Relaxed);
                                    warn!(%error, "session upstream send failed");
                                }
                            }
                        },
                        Err(error) => {
                            COUNTERS.frames_rejected.fetch_add(1, Ordering::Relaxed);
                            warn!(%error, "discard invalid session frame");
                        }
                    }
                }
            }
            received = upstream_socket.recv(&mut upstream_buf), if peer.is_some() => {
                let n = match received { Ok(n) => n, Err(error) => { warn!(%error, "session upstream receive failed"); continue; } };
                COUNTERS.inner_rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                COUNTERS.inner_rx_datagrams.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut last_seen) = runtime.last_seen.lock() {
                    *last_seen = Instant::now();
                }
                match encoder.encode_datagram(&upstream_buf[..n]) {
                    Ok(frames) => send_session_frames(&runtime.public, peer.unwrap(), frames, &runtime.key, &runtime.pacer).await,
                    Err(error) => warn!(%error, "session encode failed"),
                }
            }
            _ = report.tick(), if peer.is_some() => {
                let report = decoder.sequence_report();
                let parity = encoder.adaptive.parity;
                if parity != last_logged_parity {
                    // 只在 parity 变化时记录，避免每 2 秒一条刷屏（控制日志量）。
                    info!(tx_parity = parity, "server FEC parity changed");
                    last_logged_parity = parity;
                }
                let frame = encoder.feedback_frame(report, peer_feedback_v2);
                send_session_frames(&runtime.public, peer.unwrap(), vec![frame], &runtime.key, &runtime.pacer).await;
            }
            _ = flush.tick(), if peer.is_some() => {
                match encoder.flush() {
                    Ok(frames) => send_session_frames(&runtime.public, peer.unwrap(), frames, &runtime.key, &runtime.pacer).await,
                    Err(error) => warn!(%error, "session flush failed"),
                }
            }
            _ = traffic.tick() => {
                if logs_traffic {
                    log_traffic("server-session", &mut traffic_previous);
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
            .insert(v3_selector_prefix(key_id), (key_id, device_key))
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
                COUNTERS.wire_rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                let (frame, device_key) = match decode_server_frame(&net_buf[..n], legacy_key.as_ref(), &keyring, &selectors) {
                    Ok(value) => value,
                    Err(_) => {
                        COUNTERS.frames_rejected.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                let session_key = (frame.key_id, frame.session);
                if !sessions.contains_key(&session_key) {
                    if matches!(frame.version, VERSION_V2 | VERSION_V3) {
                        let Some(superseded) = superseded_sessions(
                            &sessions,
                            frame.key_id,
                            frame.session,
                            frame.sequence,
                        ) else {
                            continue;
                        };
                        for id in superseded {
                            if let Some(entry) = sessions.remove(&id) {
                                entry.task.abort();
                                info!(key_id=id.0, session=id.1, "session superseded");
                            }
                        }
                    }
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
    consecutive_failures: AtomicU8,
    consecutive_successes: AtomicU8,
    latency_ewma_us: AtomicU64,
}

impl BalanceUpstream {
    fn record_success(&self, latency: Option<Duration>) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        let successes = self
            .consecutive_successes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(1))
            })
            .unwrap_or(0)
            .saturating_add(1);
        if successes >= 2 {
            self.healthy.store(true, Ordering::Relaxed);
        }

        if let Some(latency) = latency {
            let sample = latency.as_micros().clamp(1, u64::MAX as u128) as u64;
            let _ = self.latency_ewma_us.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |previous| {
                    Some(
                        if previous == 0 {
                            sample
                        } else {
                            previous.saturating_mul(7).saturating_add(sample) / 8
                        }
                        .max(1),
                    )
                },
            );
        }
    }

    fn record_failure(&self) {
        self.consecutive_successes.store(0, Ordering::Relaxed);
        let failures = self
            .consecutive_failures
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(1))
            })
            .unwrap_or(0)
            .saturating_add(1);
        if failures >= 2 {
            self.healthy.store(false, Ordering::Relaxed);
        }
    }

    fn reserve(&self) {
        let _ = self
            .active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(1))
            });
    }

    fn release(&self) {
        let _ = self
            .active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_sub(1))
            });
    }
}

fn balance_order(upstreams: &[BalanceUpstream], cursor: usize, healthy_only: bool) -> Vec<usize> {
    let count = upstreams.len();
    if count == 0 {
        return Vec::new();
    }
    let start = cursor % count;
    let mut candidates = (0..count)
        .filter(|index| !healthy_only || upstreams[*index].healthy.load(Ordering::Relaxed))
        .collect::<Vec<_>>();
    candidates.sort_by_key(|index| {
        let state = &upstreams[*index];
        let latency = state.latency_ewma_us.load(Ordering::Relaxed);
        (
            state.active.load(Ordering::Relaxed),
            latency == 0,
            latency,
            (*index + count - start) % count,
        )
    });
    candidates
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
    let mut attempted = vec![false; upstreams.len()];
    for healthy_only in [true, false] {
        for index in balance_order(&upstreams, start, healthy_only) {
            if attempted[index] {
                continue;
            }
            attempted[index] = true;
            let state = &upstreams[index];
            state.reserve();
            match socks_connect(state.address, &request).await {
                Ok((stream, response)) => {
                    state.record_success(None);
                    chosen = Some((index, stream, response));
                    break;
                }
                Err(error) => {
                    state.release();
                    state.record_failure();
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
    let copied = async {
        client.write_all(&response).await?;
        tokio::io::copy_bidirectional(&mut client, &mut remote).await
    }
    .await;
    upstreams[index].release();
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
                consecutive_failures: AtomicU8::new(0),
                consecutive_successes: AtomicU8::new(0),
                latency_ewma_us: AtomicU64::new(0),
            })
            .collect::<Vec<_>>(),
    );
    let cursor = Arc::new(AtomicUsize::new(0));
    let health_upstreams = upstreams.clone();
    tokio::spawn(async move {
        let request = [&[5, 1, 0, 3, 15][..], b"www.gstatic.com", &[0x01, 0xbb]].concat();
        let mut interval = time::interval(Duration::from_secs(10));
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let mut probes = JoinSet::new();
            for index in 0..health_upstreams.len() {
                let states = health_upstreams.clone();
                let request = request.clone();
                probes.spawn(async move {
                    let started = Instant::now();
                    match time::timeout(
                        Duration::from_secs(4),
                        socks_connect(states[index].address, &request),
                    )
                    .await
                    {
                        Ok(Ok((_stream, _response))) => {
                            states[index].record_success(Some(started.elapsed()))
                        }
                        _ => states[index].record_failure(),
                    }
                });
            }
            while let Some(result) = probes.join_next().await {
                if let Err(error) = result {
                    warn!(%error, "WARP health probe task failed");
                }
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
        Command::QuicClient {
            listen,
            server,
            server_name,
            ca_cert,
            key_id,
            key,
        } => quic_relay::run_client(listen, server, &server_name, &ca_cert, key_id, &key).await,
        Command::QuicServer {
            listen,
            upstream,
            cert,
            private_key,
            keyring,
        } => quic_relay::run_server(listen, upstream, &cert, &private_key, &keyring).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_balance_upstream(
        port: u16,
        healthy: bool,
        active: usize,
        latency_ewma_us: u64,
    ) -> BalanceUpstream {
        BalanceUpstream {
            address: SocketAddr::from(([127, 0, 0, 1], port)),
            healthy: AtomicBool::new(healthy),
            active: AtomicUsize::new(active),
            consecutive_failures: AtomicU8::new(0),
            consecutive_successes: AtomicU8::new(0),
            latency_ewma_us: AtomicU64::new(latency_ewma_us),
        }
    }

    #[test]
    fn balance_prefers_healthy_low_load_and_low_latency() {
        let states = vec![
            test_balance_upstream(1, true, 2, 10_000),
            test_balance_upstream(2, true, 1, 80_000),
            test_balance_upstream(3, true, 1, 20_000),
            test_balance_upstream(4, false, 0, 1_000),
        ];
        assert_eq!(balance_order(&states, 0, true), vec![2, 1, 0]);
        assert_eq!(balance_order(&states, 0, false)[0], 3);
    }

    #[test]
    fn balance_health_uses_two_success_or_failure_hysteresis() {
        let state = test_balance_upstream(1, true, 0, 0);
        state.record_failure();
        assert!(state.healthy.load(Ordering::Relaxed));
        state.record_failure();
        assert!(!state.healthy.load(Ordering::Relaxed));
        state.record_success(Some(Duration::from_millis(20)));
        assert!(!state.healthy.load(Ordering::Relaxed));
        state.record_success(Some(Duration::from_millis(40)));
        assert!(state.healthy.load(Ordering::Relaxed));
        assert_eq!(state.latency_ewma_us.load(Ordering::Relaxed), 22_500);
    }

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
    fn v2_frame_is_rejected_after_removal() {
        let device_key = key("device-secret-long-enough");
        let mut enc = Encoder::with_identity(77, VERSION_V2, 42);
        let frame = enc.report_frame(1234);
        let bytes = frame.encode(&device_key);
        let keys = HashMap::from([(42, device_key)]);
        // V1/V2 明文协议已下线，服务端统一拒绝 legacy 帧。
        assert!(decode_server_frame(&bytes, None, &keys, &HashMap::new()).is_err());
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
        let selectors = HashMap::from([(v3_selector_prefix(7), (7, device_key))]);
        let (decoded, _) = decode_server_frame(&bytes, None, &HashMap::new(), &selectors).unwrap();
        assert_eq!(decoded.version, VERSION_V3);
        assert_eq!(decoded.key_id, 7);
        assert_eq!(decoded.session, 91);
        let mut tampered = bytes;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(decode_server_frame(&tampered, None, &HashMap::new(), &selectors).is_err());
    }
    #[test]
    fn feedback_frame_stays_legacy_until_the_peer_proves_v2() {
        let sample = SequenceReport {
            expected: 1000,
            received: 990,
            missing: 10,
            sequence_gap_ppm: 10_000,
            fec_recovered_symbols: 2,
            fec_recovered_groups: 1,
            late: 0,
            duplicates: 0,
            unrecovered_shards: 0,
            failed_groups: 0,
        };
        let mut encoder = Encoder::with_identity(1, VERSION_V3, 1);
        // A peer that has not proved V2 support must always receive a 4-byte
        // payload: its decoder cannot parse 24 bytes and would drop the report
        // entirely, going blind to loss rather than falling back to legacy.
        let legacy = encoder.feedback_frame(Some(sample), false);
        assert_eq!(legacy.payload.len(), 4);
        assert_eq!(
            decode_fec_feedback(&legacy.payload),
            Some(FecFeedback::Legacy(10_000))
        );
        // Once the peer has produced a V2 sample of its own, send the rich one.
        let rich = encoder.feedback_frame(Some(sample), true);
        assert_eq!(rich.payload.len(), FEEDBACK_V2_LEN);
        assert_eq!(
            decode_fec_feedback(&rich.payload),
            Some(FecFeedback::Sample(FeedbackSample {
                sequence_gap_ppm: 10_000,
                expected: 1000,
                missing: 10,
                fec_recovered_symbols: 2,
                fec_recovered_groups: 1,
            }))
        );
        // With no usable sample there is nothing rich to send, so the sentinel
        // must stay a legacy 4-byte frame even for a V2 peer.
        let idle = encoder.feedback_frame(None, true);
        assert_eq!(idle.payload.len(), 4);
        assert_eq!(
            decode_fec_feedback(&idle.payload),
            Some(FecFeedback::Legacy(LOSS_SAMPLE_UNAVAILABLE))
        );
    }

    #[test]
    fn a_pre_v2_peer_needs_exactly_four_bytes_and_ignores_a_v2_frame() {
        // 实测已部署版本（/root/sft-build，构建出当前运行中的二进制）的报告帧分支为：
        //     Ok(f) if f.kind == KIND_REPORT && f.payload.len() == 4 => { ...report(loss)... }
        //     Ok(f) => match decoder.frame(f) { ... }
        // 而 Decoder::frame 对 KIND_REPORT 直接 `return Ok(vec![])`。因此 24 字节
        // V2 载荷既不会被解析、也不会被误读：它先被长度等值判断挡下，再被解码器丢弃，
        // 于是对端的自适应控制器**完全收不到丢包样本**（parity 永久冻结），但也不会
        // 触发 bypass。这正是必须保留 legacy 帧、直到对端自证支持 V2 的原因。
        let sample = SequenceReport {
            expected: 1000,
            received: 990,
            missing: 10,
            sequence_gap_ppm: 10_000,
            fec_recovered_symbols: 2,
            fec_recovered_groups: 1,
            late: 0,
            duplicates: 0,
            unrecovered_shards: 0,
            failed_groups: 0,
        };
        let mut encoder = Encoder::with_identity(1, VERSION_V3, 1);
        let rich = encoder.feedback_frame(Some(sample), true);
        assert_eq!(rich.payload.len(), FEEDBACK_V2_LEN);
        assert_ne!(
            rich.payload.len(),
            4,
            "a pre-V2 peer matches report frames only when payload.len() == 4"
        );
        // 潜在危险：若旧版本改用 `payload[..4]` 无限读取（不带长度等值判断），
        // 魔数会被当成约 139.8% 丢包并被当成"极高丢包"喂给自适应控制器。
        // 当前已部署版本的长度判断挡住了它，这个断言把这个隐含依赖固定下来。
        assert_eq!(&rich.payload[..4], FEEDBACK_V2_MAGIC);
        assert!(u32::from_be_bytes(FEEDBACK_V2_MAGIC) > 1_000_000);
    }

    #[test]
    fn fec_feedback_accepts_legacy_and_validates_v2_samples() {
        assert_eq!(
            decode_fec_feedback(&1234u32.to_be_bytes()),
            Some(FecFeedback::Legacy(1234))
        );
        let sample = SequenceReport {
            expected: 1000,
            received: 990,
            missing: 10,
            sequence_gap_ppm: 10_000,
            fec_recovered_symbols: 2,
            fec_recovered_groups: 1,
            late: 0,
            duplicates: 0,
            unrecovered_shards: 0,
            failed_groups: 0,
        };
        let payload = encode_fec_feedback(&sample);
        assert_eq!(payload.len(), FEEDBACK_V2_LEN);
        assert_eq!(
            decode_fec_feedback(&payload),
            Some(FecFeedback::Sample(FeedbackSample {
                sequence_gap_ppm: 10_000,
                expected: 1000,
                missing: 10,
                fec_recovered_symbols: 2,
                fec_recovered_groups: 1,
            }))
        );
        let mut invalid = payload;
        invalid[7] ^= 1;
        assert_eq!(decode_fec_feedback(&invalid), None);
        assert_eq!(decode_fec_feedback(&[0; 8]), None);

        // Reconstructed symbols can also represent useful early recovery from
        // reordering even when the finalized wire-gap window later closes to 0.
        let reordered = SequenceReport {
            expected: 1000,
            received: 1000,
            missing: 0,
            sequence_gap_ppm: 0,
            fec_recovered_symbols: 1,
            fec_recovered_groups: 1,
            late: 0,
            duplicates: 0,
            unrecovered_shards: 0,
            failed_groups: 0,
        };
        assert!(matches!(
            decode_fec_feedback(&encode_fec_feedback(&reordered)),
            Some(FecFeedback::Sample(_))
        ));
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
    fn new_device_session_replaces_old_but_late_old_frames_cannot_take_over() {
        let sessions = HashMap::from([((7, 100), ())]);
        assert_eq!(
            superseded_sessions(&sessions, 7, 200, 1),
            Some(vec![(7, 100)])
        );
        assert_eq!(
            superseded_sessions(&sessions, 7, 200, SESSION_TAKEOVER_MAX_SEQUENCE + 1),
            None
        );
        assert_eq!(superseded_sessions(&sessions, 8, 300, 500), Some(vec![]));
    }
    #[test]
    fn adaptive_has_hysteresis() {
        let mut a = Adaptive::default();
        for _ in 0..8 {
            a.report(90_000);
        }
        assert!(a.parity >= 1);
        for _ in 0..45 {
            a.report(0);
        }
        // 干净链路会降冗余，但不会降到 0：MIN_PARITY 是常态下限（见其文档）。
        assert_eq!(a.parity, MIN_PARITY);
        for _ in 0..20 {
            a.report(1_000_000);
        }
        // 极端丢包下最优冗余是上限，而不是"关掉 FEC"。
        assert_eq!(a.parity, MAX_PARITY);
    }
    #[test]
    fn adaptive_keeps_parity_when_feedback_confirms_recovery() {
        let mut adaptive = Adaptive {
            parity: 1,
            good: 14,
            ..Adaptive::default()
        };
        adaptive.report_feedback(FecFeedback::Sample(FeedbackSample {
            sequence_gap_ppm: 10_000,
            expected: 1000,
            missing: 10,
            fec_recovered_symbols: 1,
            fec_recovered_groups: 1,
        }));
        assert_eq!(adaptive.parity, 1);
        assert_eq!(adaptive.good, 0);
    }
    #[test]
    fn adaptive_reacts_to_bursty_loss() {
        let mut a = Adaptive {
            parity: 0,
            ..Adaptive::default()
        };
        for loss in [0, 75_000, 0, 80_000, 0, 90_000, 0, 70_000] {
            a.report(loss);
        }
        assert!(a.parity >= 1);
        assert!(a.parity <= MAX_PARITY);
    }
    #[test]
    fn binomial_exceedance_is_exact_at_the_tails() {
        // P(X > n-1) for any p is p^n; P(X > k>=n) is 0.
        assert_eq!(binomial_exceedance(4, 0.5, 4), 0.0);
        assert_eq!(binomial_exceedance(4, 0.5, 9), 0.0);
        // Degenerate p.
        assert_eq!(binomial_exceedance(10, 0.0, 0), 0.0);
        assert_eq!(binomial_exceedance(10, 1.0, 0), 1.0);
        // P(X > 0) = 1 - (1-p)^n.
        let expected = 1.0 - 0.8f64.powi(10);
        assert!((binomial_exceedance(10, 0.2, 0) - expected).abs() < 1e-12);
        // P(X > 1) for Bin(10, 0.2) = 1 - 0.8^10 - 10*0.2*0.8^9.
        let expected = 1.0 - 0.8f64.powi(10) - 10.0 * 0.2 * 0.8f64.powi(9);
        assert!((binomial_exceedance(10, 0.2, 1) - expected).abs() < 1e-12);
    }

    #[test]
    fn fec_target_maximises_goodput_not_parity() {
        // 无丢包时不该买冗余：score = 1/(1+k/10) 在 k=MIN_PARITY 处最大。
        assert_eq!(Adaptive::target(0, MAX_PARITY), MIN_PARITY);

        // 随丢包上升，目标必须是单调不减的（不会出现"丢包更多反而冗余更少"）。
        let mut previous = MIN_PARITY;
        let mut loss = 0u32;
        while loss <= 600_000 {
            let target = Adaptive::target(loss, MAX_PARITY);
            assert!(
                target >= previous,
                "target must not decrease as loss grows (loss={loss}, {previous} -> {target})"
            );
            assert!((MIN_PARITY..=MAX_PARITY).contains(&target));
            previous = target;
            loss += 5_000;
        }

        // 关键结论：块状 RS 在高丢包下边际收益极差，所以"最优 k"必须严格小于
        // 上限——这正是本次改动要修的那类"无脑拉满冗余"。20% 丢包是实测工况。
        let at_20pct = Adaptive::target(200_000, MAX_PARITY);
        assert!(
            at_20pct < MAX_PARITY,
            "at 20% loss the goodput-optimal parity must be below the ceiling, got {at_20pct}"
        );
        assert!(at_20pct >= MIN_PARITY);

        // 而在极端丢包下它确实会向上限靠拢（此时更多冗余仍是最优的）。
        assert_eq!(Adaptive::target(900_000, MAX_PARITY), MAX_PARITY);
    }

    /// The measured optimum on this link is parity 1 (§10.13): parity 5 cost 50 %
    /// overhead and still lost data, delivering 40.9 % less median goodput. No
    /// loss-based rule finds that, so an operator who has measured their own link
    /// can bound the model instead of trusting it.
    #[test]
    fn fec_target_respects_the_configured_ceiling() {
        for loss in [0u32, 50_000, 200_000, 900_000] {
            assert_eq!(
                Adaptive::target(loss, MIN_PARITY),
                MIN_PARITY,
                "a ceiling at the floor must pin the target there (loss={loss})"
            );
            assert!(
                Adaptive::target(loss, 3) <= 3,
                "the ceiling must bound the target (loss={loss})"
            );
        }
    }

    #[test]
    fn fec_goodput_factor_penalises_overhead() {
        // 同样的恢复能力下，开销越小越好；同样的开销下，恢复越多越好。
        let zero_loss = fec_goodput_factor(0, MIN_PARITY);
        assert!(zero_loss < 1.0, "redundancy always costs bandwidth");
        assert!(zero_loss > 0.9);
        // 高丢包下增加冗余应当提升 goodput 因子（否则说明算错了）。
        assert!(fec_goodput_factor(200_000, 4) > fec_goodput_factor(200_000, MIN_PARITY));
    }

    #[test]
    fn adaptive_keeps_a_baseline_parity_floor() {
        // 实测教训：突发到来时 parity 停在 0 → 那一窗 18.3% 丢包一个都没恢复。
        // 因此稳态必须保有 MIN_PARITY，绝不回落到 0。
        let mut a = Adaptive {
            parity: MAX_PARITY,
            ..Adaptive::default()
        };
        for _ in 0..600 {
            a.report(0);
        }
        assert_eq!(a.parity, MIN_PARITY);

        // 而且**启动时**就该有下限：冗余晚于丢包存在等于没有冗余。
        assert_eq!(Adaptive::default().parity, MIN_PARITY);
    }

    #[test]
    fn adaptive_jumps_to_target_on_a_burst() {
        // 目标比当前高两档以上时立即生效，不再花两个报告周期（4 秒）逐级爬。
        let mut a = Adaptive {
            parity: MIN_PARITY,
            ..Adaptive::default()
        };
        // 连续高丢包把 smoothed 推高；首跳必须一次到位。
        a.report(400_000);
        a.report(400_000);
        assert!(a.parity > MIN_PARITY + 1, "burst must raise parity at once");
    }

    #[test]
    fn adaptive_single_loss_spike_does_not_reset_parity() {
        // 单次高丢包尖峰后回落，parity 不应被误降。
        let mut a = Adaptive {
            parity: 2,
            ..Adaptive::default()
        };
        a.report(600_000);
        let after_spike = a.parity;
        a.report(0);
        assert!(a.parity >= after_spike.saturating_sub(1));
        assert!(a.parity >= MIN_PARITY);
    }

    #[test]
    fn recovery_driven_input_raises_parity_when_losses_go_unrepaired() {
        // 速率信号看不见的失效模式：丢包率不高，但一组都没修回来。
        let mut a = Adaptive {
            parity: 1,
            ..Adaptive::default()
        };
        // 第一次"丢了没修回"只计数，不立刻抬档（避免单次抖动）。
        a.note_repair_outcome(8, 0);
        assert_eq!(a.parity, 1);
        assert_eq!(a.shortfall_reports, 1);
        // 连续第二次 → 立刻抬一档，不等速率信号。
        a.note_repair_outcome(6, 0);
        assert_eq!(a.parity, 2);
        assert_eq!(a.shortfall_reports, 0);
    }

    #[test]
    fn recovery_driven_input_holds_when_repairs_succeed() {
        let mut a = Adaptive {
            parity: 3,
            ..Adaptive::default()
        };
        // 丢了但修回来了 → 当前档位有效，不动 parity，并清空短欠计数。
        a.note_repair_outcome(20, 20);
        assert_eq!(a.parity, 3);
        assert_eq!(a.shortfall_reports, 0);
        // 没丢 → 同样不动。
        a.shortfall_reports = 1;
        a.note_repair_outcome(0, 0);
        assert_eq!(a.parity, 3);
        assert_eq!(a.shortfall_reports, 0);
    }

    #[test]
    fn recovery_driven_input_is_bounded_by_max_parity() {
        let mut a = Adaptive {
            parity: MAX_PARITY,
            ..Adaptive::default()
        };
        for _ in 0..20 {
            a.note_repair_outcome(50, 0);
        }
        assert_eq!(a.parity, MAX_PARITY, "must not exceed the parity ceiling");
    }

    #[test]
    fn adaptive_ignores_unavailable_loss_samples() {
        let mut a = Adaptive {
            parity: 2,
            max_parity: MAX_PARITY,
            bad: 1,
            good: 7,
            last_loss_ppm: 80_000,
            smoothed_loss_ppm: 70_000,
            unavailable_reports: 0,
            shortfall_reports: 0,
        };
        a.report(LOSS_SAMPLE_UNAVAILABLE);
        assert_eq!(a.parity, 2);
        // 空闲样本不打断连续丢包/正常样本的计数，也不改变当前 parity 或已测损失历史。
        assert_eq!(a.bad, 1);
        assert_eq!(a.good, 7);
        assert_eq!(a.last_loss_ppm, 80_000);
        assert_eq!(a.smoothed_loss_ppm, 70_000);
    }
    #[test]
    fn adaptive_rises_through_interleaved_idle_gaps() {
        // 真实 TUIC 流量是间歇性的：高丢包样本之间穿插空闲样本。空闲不得清零
        // bad，否则 parity 永远升不上去（FEC 失效）。
        let mut a = Adaptive::default();
        for loss in [90_000, u32::MAX, 90_000, u32::MAX, 90_000] {
            a.report(loss);
        }
        assert_eq!(a.parity, 1);
    }
    #[test]
    fn adaptive_retires_stale_parity_after_idle_timeout() {
        let mut a = Adaptive {
            parity: 2,
            ..Adaptive::default()
        };
        for _ in 0..14 {
            a.report(LOSS_SAMPLE_UNAVAILABLE);
        }
        assert_eq!(a.parity, 2);
        a.report(LOSS_SAMPLE_UNAVAILABLE);
        assert_eq!(a.parity, 1);
        for _ in 0..15 {
            a.report(LOSS_SAMPLE_UNAVAILABLE);
        }
        // 空闲退档到常态下限为止，不会退到 0（否则突发到来时无冗余可用）。
        assert_eq!(a.parity, MIN_PARITY);
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
            .filter(|f| !(f.kind == KIND_DATA && matches!(f.index, 4 | 5)))
        {
            output.extend(dec.frame(f).unwrap());
        }
        assert_eq!(output.len(), 10);
        assert!(output.iter().any(|x| x == &vec![4u8; 20]));
        assert!(output.iter().any(|x| x == &vec![5u8; 20]));
    }
    #[test]
    fn fec_recovery_is_counted_once_per_group_across_window_boundaries() {
        // 不变量：一个 FEC 组最多记一次账。
        // 触发条件里的 `any(|x| !*x)` 只是避免重复做 Reed-Solomon 运算；真正防止
        // 重复计数的是重建后把 delivered 全部置 true，使 recovered_indices 变空。
        // 因此"重建后继续到达的冗余分片"与"迟到的原数据分片"都不会再次计数。
        // 这里跨窗口累计，避免依赖窗口具体在哪里切开。
        let mut enc = Encoder::new(13);
        enc.adaptive.parity = 2;
        let mut dec = Decoder::new(13);
        let mut expected_symbols = 0u64;
        for group in 0..10u8 {
            let mut frames = Vec::new();
            for _ in 0..DATA_SHARDS {
                frames.extend(enc.encode_datagram(&[group; 20]).unwrap());
            }
            let data: Vec<_> = frames
                .iter()
                .filter(|frame| frame.kind == KIND_DATA)
                .cloned()
                .collect();
            let parity: Vec<_> = frames
                .iter()
                .filter(|frame| frame.kind == KIND_PARITY)
                .cloned()
                .collect();
            assert_eq!(data.len(), DATA_SHARDS);
            assert!(!parity.is_empty());
            let late = data
                .iter()
                .find(|frame| frame.index == 4)
                .expect("data shard 4")
                .clone();
            // 丢掉索引 4 的数据分片，用其余数据分片加一个冗余分片触发重建。
            for frame in data.iter().filter(|frame| frame.index != 4) {
                dec.frame(frame.clone()).unwrap();
            }
            dec.frame(parity[0].clone()).unwrap();
            expected_symbols += 1;
            // 重建之后才到达的冗余分片：不得重复计数。
            for frame in parity.iter().skip(1) {
                dec.frame(frame.clone()).unwrap();
            }
            // 迟到的原数据分片：同样不得重复计数。
            dec.frame(late).unwrap();
        }

        // 尾部事件只有等 highest_sequence 继续前进才会被排空，所以先灌入一组
        // 无丢包的组把窗口推过去，否则最后 REORDER_WINDOW 个序号内的恢复事件
        // 不会进入任何报告（这是已知且有界的边界，见 fec_recovery_events 注释）。
        for _ in 0..10 {
            for _ in 0..DATA_SHARDS {
                for frame in enc.encode_datagram(&[0xEE; 20]).unwrap() {
                    dec.frame(frame).unwrap();
                }
            }
        }

        let mut symbols = 0u64;
        let mut groups = 0u64;
        while let Some(report) = dec.sequence_report() {
            symbols += report.fec_recovered_symbols;
            groups += report.fec_recovered_groups;
        }
        // 每组只丢 1 个分片，故符号数应恰好等于组数。
        assert_eq!(symbols, expected_symbols, "每个被重建的符号只计一次");
        assert_eq!(groups, expected_symbols, "每组只计一次");
        assert_eq!(dec.sequence_report(), None);
    }

    #[test]
    fn sequence_report_distinguishes_wire_gaps_from_fec_recovery() {
        let mut enc = Encoder::new(9);
        enc.adaptive.parity = 2;
        let mut dec = Decoder::new(9);
        for group in 0..10u8 {
            let mut frames = Vec::new();
            for _ in 0..DATA_SHARDS {
                frames.extend(enc.encode_datagram(&[group; 20]).unwrap());
            }
            for frame in frames.into_iter().filter(|frame| {
                !(matches!(group, 0 | 9) && frame.kind == KIND_DATA && matches!(frame.index, 4 | 5))
            }) {
                dec.frame(frame).unwrap();
            }
        }

        let report = dec.sequence_report().unwrap();
        assert_eq!(report.missing, 2);
        assert_eq!(report.fec_recovered_symbols, 2);
        assert_eq!(report.fec_recovered_groups, 1);
        assert!(dec.sequence_report().is_none());
        for group in 10..20u8 {
            for _ in 0..DATA_SHARDS {
                for frame in enc.encode_datagram(&[group; 20]).unwrap() {
                    dec.frame(frame).unwrap();
                }
            }
        }
        let next = dec.sequence_report().unwrap();
        assert_eq!(next.fec_recovered_symbols, 2);
        assert_eq!(next.fec_recovered_groups, 1);
        assert!(dec.sequence_report().is_none());
    }
    #[test]
    fn decoder_rejects_fec_group_indexes_before_sequence_baseline() {
        let mut decoder = Decoder::new(9);
        let frame = Frame {
            version: VERSION_V3,
            key_id: 7,
            kind: KIND_DATA,
            session: 9,
            sequence: 1,
            group: 1,
            index: 1,
            data: 2,
            parity: 1,
            payload: vec![0; FRAGMENT_HEADER],
        };
        assert!(decoder.frame(frame).is_err());
    }
    /// An expired group that still holds undelivered data shards is the only
    /// counter that represents loss a *user* can see: the carrier reports those
    /// frames as sent, and `sequence_report` counts wire-frame arrival.
    #[test]
    fn expired_incomplete_groups_are_counted_as_unrecovered_loss() {
        let stale = Instant::now() - GROUP_TTL - Duration::from_secs(1);
        let mut groups = BTreeMap::new();
        // Two data shards delivered, two never arrived and parity could not repair.
        groups.insert(
            7u64,
            Group {
                created: stale,
                start_sequence: 1,
                data: 4,
                parity: 1,
                shards: vec![None; 5],
                delivered: vec![true, false, false, true],
            },
        );
        assert_eq!(expired_group_loss(&groups, Instant::now()), (1, 2));
    }

    #[test]
    fn fresh_and_complete_groups_are_not_reported_as_loss() {
        let now = Instant::now();
        let mut groups = BTreeMap::new();
        // Fresh, still incomplete: within GROUP_TTL, so still recoverable.
        groups.insert(
            1u64,
            Group {
                created: now,
                start_sequence: 1,
                data: 2,
                parity: 1,
                shards: vec![None; 3],
                delivered: vec![true, false],
            },
        );
        // Expired but fully delivered: a tombstone, not a loss.
        groups.insert(
            2u64,
            Group {
                created: now - GROUP_TTL - Duration::from_secs(1),
                start_sequence: 10,
                data: 2,
                parity: 1,
                shards: vec![None; 3],
                delivered: vec![true, true],
            },
        );
        assert_eq!(expired_group_loss(&groups, now), (0, 0));
    }

    #[test]
    fn traffic_ratio_ppm_handles_a_zero_denominator() {
        // An idle interval must report 0, not divide by zero or emit a bogus
        // ratio that would look like catastrophic overhead.
        assert_eq!(ratio_ppm(0, 0), 0);
        assert_eq!(ratio_ppm(5, 0), 0);
        assert_eq!(ratio_ppm(1, 4), 250_000);
        assert_eq!(ratio_ppm(4, 1), 4_000_000);
    }

    /// 生产报文尺寸下，编解码器自身的往返是否无损。
    ///
    /// 动机：集成测试显示 1200 字节报文在**零丢包环回**上到达率只有 ~23%，
    /// 与生产链路观测到的 ~22% 交付效率吻合，说明缺口在 FEC 层内部。但那个
    /// 测试跑的是两个真进程 + 一个 relay，无法区分"编解码器丢了"与"进程转发
    /// 环节丢了"。本用例把编解码器摘出来单独跑：无进程、无 socket、无时序依赖，
    /// 因此结果非黑即白。
    #[test]
    fn codec_round_trips_production_sized_datagrams_without_loss() {
        let key = [7u8; 32];
        let session = 0x5e55_10a0u64;
        let key_id = 1u64;
        let mut encoder = Encoder::with_identity(session, VERSION_V3, key_id);
        let mut decoder = Decoder::new(session);
        let total = 2000usize;
        let mut delivered = 0usize;
        for i in 0..total {
            let mut payload = vec![0xab; 1200];
            payload[..4].copy_from_slice(&(i as u32).to_be_bytes());
            let frames = encoder.encode_datagram(&payload).unwrap();
            for frame in frames {
                let wire = frame.encode_wire(&key).unwrap();
                let decoded = decode_client_frame(&wire, key_id, &key).unwrap();
                for datagram in decoder.frame(decoded).unwrap() {
                    assert_eq!(
                        datagram.len(),
                        1200,
                        "datagram {i} came back the wrong size"
                    );
                    delivered += 1;
                }
            }
        }
        // 尾组必须显式冲刷，否则最后不足 10 个分片的数据报永远不会发出——
        // 这与生产一致（生产由 5ms 定时器负责）。
        for frame in encoder.flush().unwrap() {
            let wire = frame.encode_wire(&key).unwrap();
            let decoded = decode_client_frame(&wire, key_id, &key).unwrap();
            delivered += decoder.frame(decoded).unwrap().len();
        }
        assert_eq!(
            delivered, total,
            "the codec itself lost datagrams on a lossless path"
        );
    }

    /// Regression for the padding waste that T1's accounting found on the live
    /// carrier.
    ///
    /// `CHUNK + 27` bytes is not an arbitrary choice: the measured average inner
    /// datagram on the production downlink was **1353** bytes against
    /// `CHUNK = 1326`. With greedy fragmentation that becomes a full 1326-byte
    /// fragment plus a 27-byte one, and `flush()` then pads every source shard up
    /// to the group's longest -- so the 27-byte fragment is transmitted as a full
    /// 1340-byte shard.
    ///
    /// Live measurement before the fix: 5327 data shards for 2694 inner datagrams
    /// (1.977 shards each) and `delivery_ppm` = 29 %. The arithmetic closes --
    /// 1.98 (padding) x 1.67 (parity) = 3.30, and 1/3.30 = 30 %.
    #[test]
    fn near_chunk_sized_datagrams_do_not_pay_reed_solomon_padding() {
        let mut encoder = Encoder::with_identity(1, VERSION_V3, 1);
        // Padding only happens when parity is generated, so parity must be on for
        // this to measure anything.
        encoder.force_parity = Some(2);
        let payload = vec![0xab; CHUNK + 27];
        let mut wire = 0usize;
        let mut datagrams = 0usize;
        // Five datagrams fill exactly one ten-shard group.
        for _ in 0..20 {
            for frame in encoder.encode_datagram(&payload).unwrap() {
                wire += frame.payload.len();
            }
            datagrams += 1;
        }
        for frame in encoder.flush().unwrap() {
            wire += frame.payload.len();
        }
        let inner = payload.len() * datagrams;
        let ratio = wire as f64 / inner as f64;
        // Balanced split: ~1.23 (1.2 parity + ~2 % residual padding).
        // Greedy split:   ~2.38. The gap is wide enough that the threshold does
        // not need tuning.
        assert!(
            ratio < 1.5,
            "wire/payload ratio {ratio:.3} for {}-byte datagrams -- greedy \
             fragmentation is padding them up to full shards again",
            payload.len()
        );
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
        assert_eq!(d.sequence_report().unwrap().sequence_gap_ppm, 0);
    }
    #[test]
    fn finalized_window_reports_real_loss_once() {
        let mut d = Decoder::new(1);
        for seq in 1..=200 {
            if seq != 20 && seq != 100 {
                d.observe_seq(seq);
            }
        }
        let report = d.sequence_report().unwrap();
        assert_eq!(report.sequence_gap_ppm, 2_000_000u32 / 136);
        assert_eq!(report.expected, 136);
        assert_eq!(report.received, 134);
        assert_eq!(report.missing, 2);
        assert_eq!(d.sequence_report(), None);
    }
    #[test]
    fn sequence_report_separates_late_and_duplicate_frames_from_gaps() {
        let mut d = Decoder::new(1);
        for seq in 1..=200 {
            d.observe_seq(seq);
        }
        assert!(!d.observe_seq(100));
        let first = d.sequence_report().unwrap();
        assert_eq!(first.sequence_gap_ppm, 0);
        assert_eq!(first.duplicates, 1);
        assert_eq!(first.late, 0);

        assert!(!d.observe_seq(10));
        for seq in 201..=336 {
            d.observe_seq(seq);
        }
        let second = d.sequence_report().unwrap();
        assert_eq!(second.sequence_gap_ppm, 0);
        assert_eq!(second.duplicates, 0);
        assert_eq!(second.late, 1);
    }
    #[test]
    fn first_high_sequence_establishes_baseline() {
        let mut d = Decoder::new(1);
        for seq in 10_000..=10_200 {
            d.observe_seq(seq);
        }
        assert_eq!(d.sequence_report().unwrap().sequence_gap_ppm, 0);
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

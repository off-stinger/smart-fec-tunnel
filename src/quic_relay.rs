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
    congestion::{
        BbrConfig, Controller, ControllerFactory, ControllerMetrics, CubicConfig, NewRenoConfig,
    },
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    rustls::{self, pki_types::CertificateDer, pki_types::PrivateKeyDer},
    ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig, TransportConfig,
};
use quinn_proto::RttEstimator;
use rand::RngCore;
use rustls::pki_types::pem::PemObject;
use std::{
    collections::HashMap,
    fs::File,
    io::BufReader,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, Mutex, Semaphore},
    task::JoinSet,
    time,
};
use tracing::{info, warn};

const ALPN: &[u8] = b"h3";
const EXPORTER_LABEL: &[u8] = b"EXPORTER-SFT-AUTH-v1";
const MAX_DATAGRAM: usize = 65_535;
const CARRIER_HEADER: usize = 12;
const MAX_CARRIER_FRAGMENTS: usize = 128;
const MAX_CARRIER_GROUPS: usize = 2048;
const CARRIER_TTL: Duration = Duration::from_secs(3);
const CARRIER_PING: &[u8] = b"SFT-Q-PING-1";
const CARRIER_PONG: &[u8] = b"SFT-Q-PONG-1";
const CARRIER_HEARTBEAT: Duration = Duration::from_secs(2);
const CARRIER_STATS_INTERVAL: Duration = Duration::from_secs(5);
// Multiple independently retransmitted lanes reorder TUIC datagrams deeply
// enough to cause severe stalls. Keep the product mode strictly ordered until
// flow-aware lane assignment is implemented and validated.
const MAX_STREAM_LANES: usize = 1;
const MIN_WIRE_LOSS_SAMPLE_PACKETS: u64 = 100;
const STREAM_LANE_PREFACE: u8 = 0x53;
// QUIC DATAGRAM is intentionally unreliable. A missing PONG alone is not proof
// that the path is dead, so count any authenticated server datagram as evidence
// that the carrier is alive while retaining fast failure detection.
const CARRIER_DEAD_TIMEOUT: Duration = Duration::from_secs(6);

#[derive(Clone, Copy, Debug, Default)]
struct CarrierStatsSnapshot {
    sent_packets: u64,
    lost_packets: u64,
    lost_bytes: u64,
    congestion_events: u64,
    black_holes_detected: u64,
    lost_plpmtud_probes: u64,
    udp_tx_datagrams: u64,
    udp_rx_datagrams: u64,
    udp_tx_bytes: u64,
    udp_rx_bytes: u64,
    datagram_tx: u64,
    datagram_rx: u64,
}

impl CarrierStatsSnapshot {
    /// 单调计数器的窗口增量。
    ///
    /// 用 `saturating_sub` 而不是裸减法：连接重建时对端计数器会归零，裸减法会得到
    /// 一个天文数字的"增量"，把一次重连误报成一次巨量丢包。
    fn delta(&self, previous: &Self) -> Self {
        Self {
            sent_packets: self.sent_packets.saturating_sub(previous.sent_packets),
            lost_packets: self.lost_packets.saturating_sub(previous.lost_packets),
            lost_bytes: self.lost_bytes.saturating_sub(previous.lost_bytes),
            congestion_events: self
                .congestion_events
                .saturating_sub(previous.congestion_events),
            black_holes_detected: self
                .black_holes_detected
                .saturating_sub(previous.black_holes_detected),
            lost_plpmtud_probes: self
                .lost_plpmtud_probes
                .saturating_sub(previous.lost_plpmtud_probes),
            udp_tx_datagrams: self
                .udp_tx_datagrams
                .saturating_sub(previous.udp_tx_datagrams),
            udp_rx_datagrams: self
                .udp_rx_datagrams
                .saturating_sub(previous.udp_rx_datagrams),
            udp_tx_bytes: self.udp_tx_bytes.saturating_sub(previous.udp_tx_bytes),
            udp_rx_bytes: self.udp_rx_bytes.saturating_sub(previous.udp_rx_bytes),
            datagram_tx: self.datagram_tx.saturating_sub(previous.datagram_tx),
            datagram_rx: self.datagram_rx.saturating_sub(previous.datagram_rx),
        }
    }
}

fn log_carrier_stats(
    connection: &Connection,
    previous: &mut CarrierStatsSnapshot,
    role: &'static str,
) {
    let stats = connection.stats();
    let current = CarrierStatsSnapshot {
        sent_packets: stats.path.sent_packets,
        lost_packets: stats.path.lost_packets,
        lost_bytes: stats.path.lost_bytes,
        congestion_events: stats.path.congestion_events,
        // 黑洞检测与 PLPMTUD 探测失败是解释"实测 MTU 在 1200-1472 之间波动"的直接证据，
        // 此前完全不可见。
        black_holes_detected: stats.path.black_holes_detected,
        lost_plpmtud_probes: stats.path.lost_plpmtud_probes,
        udp_tx_datagrams: stats.udp_tx.datagrams,
        udp_rx_datagrams: stats.udp_rx.datagrams,
        udp_tx_bytes: stats.udp_tx.bytes,
        udp_rx_bytes: stats.udp_rx.bytes,
        // 应用层 DATAGRAM 帧计数才是"载体实际投递了多少个数据报"的口径——FEC 就架在它
        // 上面，而 udp_* 只是下层的字节数。
        datagram_tx: stats.frame_tx.datagram,
        datagram_rx: stats.frame_rx.datagram,
    };
    let delta = current.delta(previous);
    let wire_loss_ppm = (delta.sent_packets >= MIN_WIRE_LOSS_SAMPLE_PACKETS).then(|| {
        ((delta.lost_packets as u128 * 1_000_000) / delta.sent_packets as u128).min(1_000_000)
            as u32
    });
    info!(
        role,
        wire_loss_ppm=?wire_loss_ppm,
        sent_packets=delta.sent_packets,
        lost_packets=delta.lost_packets,
        lost_bytes=delta.lost_bytes,
        congestion_events=delta.congestion_events,
        black_holes=delta.black_holes_detected,
        lost_plpmtud_probes=delta.lost_plpmtud_probes,
        datagram_tx=delta.datagram_tx,
        datagram_rx=delta.datagram_rx,
        udp_tx_datagrams=delta.udp_tx_datagrams,
        udp_rx_datagrams=delta.udp_rx_datagrams,
        tx_bytes=delta.udp_tx_bytes,
        rx_bytes=delta.udp_rx_bytes,
        rtt_ms=stats.path.rtt.as_millis(),
        cwnd_bytes=stats.path.cwnd,
        mtu=stats.path.current_mtu,
        "QUIC carrier stats"
    );
    *previous = current;
}

fn configured_stream_lanes() -> Result<usize> {
    let value = std::env::var("SMART_QUIC_STREAM_LANES").ok();
    parse_stream_lanes(value.as_deref())
}

/// Parses `SMART_QUIC_STREAM_LANES`.
///
/// Unset, blank, and an explicit `0` all mean DATAGRAM mode, which is the
/// default: Quinn must not retransmit, so the inner FEC layer repairs loss
/// instead (RFC 9221 §5.2). `1` switches to a single reliable stream lane.
///
/// An explicit `0` must be accepted -- `deploy/openwrt-smart-fec-quic.init`
/// and the manual both document `0` as DATAGRAM mode, so rejecting it turned a
/// documented default into a permanent reconnect loop (`quic_relay` logs
/// "QUIC relay reconnecting" every few seconds while the handshake itself
/// succeeds). Anything other than 0 or 1 is still rejected because parallel
/// lanes are not implemented.
fn parse_stream_lanes(value: Option<&str>) -> Result<usize> {
    let Some(value) = value else {
        return Ok(0);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(0);
    }
    let lanes: usize = value
        .parse()
        .context("SMART_QUIC_STREAM_LANES must be an integer")?;
    if lanes == 0 {
        return Ok(0);
    }
    if lanes != MAX_STREAM_LANES {
        bail!("SMART_QUIC_STREAM_LANES must be 0 (DATAGRAM) or {MAX_STREAM_LANES}")
    }
    Ok(lanes)
}

/// Selectable QUIC congestion controller for the carrier.
///
/// The carrier sits underneath the inner TUIC flow, which runs its own
/// congestion controller, so the carrier's only job is to keep the path busy
/// without collapsing on loss that FEC is already repairing. NewReno halves its
/// window on every loss event and drops to the RFC 9002 minimum under
/// persistent congestion, which on a 20-30 % loss path pins it near the floor.
/// Cubic and BBR are exposed so the difference can be measured instead of
/// guessed.
///
/// `Fixed` is the loss-tolerant option, for paths where the loss is **not**
/// congestion (measured: ~20 % random loss from the ISP/GFW on the home↔SG
/// path). See [`FixedRate`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CarrierController {
    NewReno,
    Cubic,
    Bbr,
    Fixed,
}

fn configured_congestion_controller() -> Result<CarrierController> {
    let value = std::env::var("SMART_QUIC_CONGESTION").ok();
    parse_congestion_controller(value.as_deref())
}

fn parse_congestion_controller(value: Option<&str>) -> Result<CarrierController> {
    let Some(value) = value else {
        return Ok(CarrierController::NewReno);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "new_reno" | "newreno" | "reno" => Ok(CarrierController::NewReno),
        "cubic" => Ok(CarrierController::Cubic),
        "bbr" => Ok(CarrierController::Bbr),
        "fixed" | "brutal" => Ok(CarrierController::Fixed),
        other => {
            bail!("SMART_QUIC_CONGESTION must be new_reno, cubic, bbr or fixed, got {other:?}")
        }
    }
}

/// `SMART_QUIC_FIXED_RATE_MBPS` 的默认值，与 FEC 侧 `--rate-mbps` 的默认 28 对齐。
const DEFAULT_FIXED_RATE_MBPS: u64 = 28;
/// 固定速率的上限保护：超过 10 Gbit/s 视为配置错误。
const MAX_FIXED_RATE_MBPS: u64 = 10_000;
/// 固定速率窗口的下限（以 MTU 计）：至少几个包，避免极小窗口把 pacer 卡死。
const FIXED_RATE_MIN_WINDOW_MTUS: u64 = 4;
/// 固定速率窗口的引导 RTT 估计。
///
/// `ControllerFactory::build` 只拿到 MTU、拿不到 RTT，所以先按这个值估算窗口，
/// 等第一个 ACK 带来真实 smoothed RTT 后由 `on_ack` 修正。
/// **注意窗口必须按 pacer 实际除的那个 RTT（smoothed）来定尺寸**，否则实际速率
/// 会被打折为 `rate * rtt_used / smoothed_rtt`。
const FIXED_RATE_BOOTSTRAP_RTT: Duration = Duration::from_millis(100);
/// 窗口尺寸计算时的 RTT 下限，避免退化到极小窗口。
const FIXED_RATE_MIN_RTT: Duration = Duration::from_millis(1);
/// ACK 成功率统计的槽位数（每槽 1 秒），用于反向补偿丢包。
const FIXED_RATE_ACK_SLOTS: usize = 5;
/// 样本不足时不补偿，避免起步阶段被噪声放大。
const FIXED_RATE_MIN_ACK_SAMPLES: u64 = 50;
/// ACK 成功率的下限：丢包再重也只把发送速率放大 1 / 0.8 = 1.25 倍。
const FIXED_RATE_MIN_ACK_RATE: f64 = 0.8;

/// ACK/丢包统计的一个时间槽（1 秒）。
#[derive(Clone, Copy, Debug, Default)]
struct AckSlot {
    /// 槽对应的秒序号；`i64::MIN` 表示空槽。
    ts: i64,
    ack: u64,
    loss: u64,
}

fn configured_fixed_rate() -> Result<u64> {
    let value = std::env::var("SMART_QUIC_FIXED_RATE_MBPS").ok();
    parse_fixed_rate_mbps(value.as_deref())
}

fn parse_fixed_rate_mbps(value: Option<&str>) -> Result<u64> {
    // A blank value means "not configured". `SMART_QUIC_FIXED_RATE_MBPS=` in an
    // env file, or an env var that the init script passes through as empty,
    // must fall back to the default rather than abort startup.
    let value = value.map(str::trim).filter(|value| !value.is_empty());
    let Some(value) = value else {
        return Ok(DEFAULT_FIXED_RATE_MBPS);
    };
    let mbps: u64 = value
        .parse()
        .context("SMART_QUIC_FIXED_RATE_MBPS must be an integer")?;
    if mbps == 0 || mbps > MAX_FIXED_RATE_MBPS {
        bail!("SMART_QUIC_FIXED_RATE_MBPS must be between 1 and {MAX_FIXED_RATE_MBPS}, got {mbps}")
    }
    Ok(mbps)
}

/// Window size for a target rate.
///
/// **Must be sized on the same RTT the pacer divides by.** quinn's pacer calls
/// `optimal_capacity(smoothed_rtt, window, mtu)` and refills the token bucket
/// with `window * 2ms / smoothed_rtt` bytes every 2 ms, so the send rate it
/// enforces is exactly `window / smoothed_rtt`. Sizing the window on `min_rtt`
/// therefore throttles the connection to `rate * min_rtt / smoothed_rtt` — on
/// this link (min 100 ms bootstrap vs 400 ms smoothed) that is a quarter of the
/// configured rate. `FixedRate::apply_rtt` is fed `RttEstimator::get()`, the
/// same smoothed value the pacer uses, so `window = rate * srtt` yields the
/// configured rate exactly.
///
/// Floored at a few MTUs so the pacer is never starved.
///
/// The `ack_rate` divisor is the second half of Brutal: sending at exactly
/// `rate` on a 20 % loss path only *delivers* `0.8 * rate`, so the window is
/// divided by the recent ACK success rate to compensate (20 % loss -> ~25 %
/// faster). Cross-checked against the quinn port of Hysteria2's Brutal
/// (`rsteria2::congestion`), which encodes the target rate into the window the
/// same way for the same reason: quinn has no independent pacer.
///
/// Extracted as a free function so the sizing rule can be tested directly —
/// `quinn_proto::RttEstimator` cannot be constructed outside quinn (no `Default`,
/// `new`/`update` are `pub(crate)`), so it is not usable in a unit test.
fn fixed_rate_window(
    rate_bytes_per_sec: u64,
    smoothed_rtt: Duration,
    mtu: u64,
    ack_rate: f64,
) -> u64 {
    let ack_rate = if ack_rate.is_finite() && ack_rate > 0.0 {
        ack_rate.clamp(FIXED_RATE_MIN_ACK_RATE, 1.0)
    } else {
        1.0
    };
    let bdp = rate_bytes_per_sec as f64 * smoothed_rtt.as_secs_f64() / ack_rate;
    let bdp = if bdp.is_finite() && bdp >= 1.0 {
        bdp as u64
    } else {
        0
    };
    bdp.max(FIXED_RATE_MIN_WINDOW_MTUS * mtu).max(1)
}

/// Fixed-rate, **loss-tolerant** carrier congestion controller.
///
/// Why this exists: this link was measured at ~20 % random packet loss and
/// ~400 ms RTT during peak hours. That loss is not a congestion signal — it is
/// the ISP/GFW dropping packets — yet NewReno and Cubic halve the window on
/// every loss event and BBR also yields once loss exceeds its 2 % objective, so
/// the measured window collapsed to the RFC 9002 minimum (2944 bytes) and
/// bandwidth utilisation fell to 17 %.
///
/// The approach follows Hysteria's "Brutal": send at a **known** rate and do not
/// yield on loss, leaving loss repair to the FEC layer above.
///
/// Implementation note: quinn's pacer derives its rate from
/// `congestion.window() / RTT` — `optimal_capacity()` refills the token bucket
/// with `window * 2ms / rtt` bytes every 2 ms and `delay()` applies the 4/5
/// factor recommended by RFC 9002 section 7.7 (quinn-proto
/// `connection/pacing.rs`). Returning a fixed window is therefore equivalent to
/// sending at a fixed rate: a window of `rate * min_rtt` is exactly the
/// bandwidth-delay product for the target rate.
///
/// This deliberately does **not** satisfy RFC 9002's congestion control
/// requirements, so it must only be enabled explicitly, on a dedicated link
/// whose capacity is known and whose loss is known not to be congestion.
#[derive(Debug, Clone)]
struct FixedRate {
    /// Target rate in bytes per second.
    rate: u64,
    /// Latest smoothed RTT — deliberately the same quantity quinn's pacer
    /// divides by, so that `window / rtt` equals `rate`.
    rtt: Duration,
    mtu: u64,
    /// First event time, used as the epoch for the ACK-rate slots.
    base: Option<Instant>,
    /// Recent ACK success rate in `[FIXED_RATE_MIN_ACK_RATE, 1.0]`.
    ack_rate: f64,
    slots: [AckSlot; FIXED_RATE_ACK_SLOTS],
    /// Counted for observability only; the controller keeps sending regardless.
    persistent_congestion_events: u64,
}

impl FixedRate {
    fn new(rate_bytes_per_sec: u64, current_mtu: u16) -> Self {
        let mtu = u64::from(current_mtu).max(1);
        Self {
            rate: rate_bytes_per_sec.max(1),
            rtt: FIXED_RATE_BOOTSTRAP_RTT,
            mtu,
            base: None,
            ack_rate: 1.0,
            slots: [AckSlot::default(); FIXED_RATE_ACK_SLOTS],
            persistent_congestion_events: 0,
        }
    }

    /// The window actually in force: `rate * srtt / ack_rate`, floored.
    fn window_bytes(&self) -> u64 {
        fixed_rate_window(self.rate, self.rtt, self.mtu, self.ack_rate)
    }

    /// Testable core of [`Controller::on_ack`].
    ///
    /// Always re-sizes rather than only tracking a minimum. Two reasons:
    /// 1. the pacer divides by the *smoothed* RTT, so the window must track it
    ///    in both directions to hold the rate constant;
    /// 2. after a persistent-congestion safety drop the window must return to
    ///    the target rate once the path carries traffic again — gating on a new
    ///    minimum would strand it at the floor forever on a stable path.
    ///
    /// Both failure modes were caught by
    /// `fixed_rate_controller_sizes_window_to_rate_and_ignores_random_loss`.
    fn apply_rtt(&mut self, smoothed_rtt: Duration) {
        self.rtt = smoothed_rtt.max(FIXED_RATE_MIN_RTT);
    }

    /// Record one second-bucketed observation of delivered vs lost packets and
    /// refresh [`Self::ack_rate`] from the last [`FIXED_RATE_ACK_SLOTS`] seconds.
    fn record(&mut self, now: Instant, acks: u64, losses: u64) {
        let base = *self.base.get_or_insert(now);
        let ts = now.saturating_duration_since(base).as_secs() as i64;
        let slot = &mut self.slots[(ts as usize) % FIXED_RATE_ACK_SLOTS];
        if slot.ts == ts {
            slot.ack = slot.ack.saturating_add(acks);
            slot.loss = slot.loss.saturating_add(losses);
        } else {
            slot.ts = ts;
            slot.ack = acks;
            slot.loss = losses;
        }

        let min_ts = ts - FIXED_RATE_ACK_SLOTS as i64;
        let (mut total_ack, mut total_loss) = (0u64, 0u64);
        for slot in &self.slots {
            if slot.ts < min_ts {
                continue;
            }
            total_ack = total_ack.saturating_add(slot.ack);
            total_loss = total_loss.saturating_add(slot.loss);
        }
        let total = total_ack.saturating_add(total_loss);
        if total < FIXED_RATE_MIN_ACK_SAMPLES {
            // Not enough evidence yet: do not amplify on noise.
            self.ack_rate = 1.0;
            return;
        }
        let rate = total_ack as f64 / total as f64;
        self.ack_rate = if rate.is_finite() {
            rate.clamp(FIXED_RATE_MIN_ACK_RATE, 1.0)
        } else {
            1.0
        };
    }
}

impl Controller for FixedRate {
    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.apply_rtt(rtt.get());
        self.record(now, 1, 0);
    }

    /// The whole point: a loss event must not shrink the window.
    ///
    /// Loss is still *counted*, but only to drive the ACK-rate compensation in
    /// [`FixedRate::record`] — a 20 % loss path must send ~25 % faster to
    /// deliver the configured rate. Random loss, which is what this controller
    /// exists for, therefore never reduces the window.
    ///
    /// The only safety valve kept is persistent congestion (consecutive PTOs
    /// with no progress), which drops the window to the floor so a genuinely
    /// dead path cannot be hammered forever.
    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        let lost_packets = (lost_bytes / self.mtu.max(1)).max(1);
        self.record(now, 0, lost_packets);
        if is_persistent_congestion {
            self.persistent_congestion_events = self.persistent_congestion_events.saturating_add(1);
            // Deliberately NOT a window change: the window is derived from
            // `rate`, `rtt` and `ack_rate`, and the ACK-rate floor already caps
            // how far the send rate can run ahead. Recorded and logged instead,
            // because persistent congestion means the path is dead rather than
            // merely lossy.
            warn!(
                rate_bytes_per_sec = self.rate,
                ack_rate = self.ack_rate,
                events = self.persistent_congestion_events,
                "fixed-rate carrier hit persistent congestion"
            );
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = u64::from(new_mtu).max(1);
    }

    fn window(&self) -> u64 {
        self.window_bytes()
    }

    fn metrics(&self) -> ControllerMetrics {
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window_bytes();
        // No ssthresh: the window is not governed by a slow-start threshold.
        metrics.ssthresh = None;
        // Reported for visibility only. quinn's pacer uses `window() / RTT`
        // rather than this field, so it is informational.
        let effective = (self.rate as f64 / self.ack_rate) as u64;
        metrics.pacing_rate = Some(effective.saturating_mul(8));
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.window_bytes()
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

#[derive(Debug)]
struct CarrierControllerFactory {
    kind: CarrierController,
    /// Only used by [`CarrierController::Fixed`]: target rate in bytes/second.
    fixed_rate_bytes_per_sec: u64,
}

impl ControllerFactory for CarrierControllerFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        // Use Quinn's maintained congestion controllers. A fixed window that
        // ignores losses can overload the path, even when the inner TUIC flow
        // also has its own congestion controller.
        //
        // RFC 9002 section 7.2: endpoints SHOULD use an initial congestion
        // window of ten times the maximum datagram size, limiting it to the
        // larger of 14,720 bytes or twice the maximum datagram size, and SHOULD
        // recalculate it when the maximum datagram size changes. Quinn's
        // `Default` for every bundled controller is the compile-time constant
        // `14720.clamp(2 * 1200, 10 * 1200)`, i.e. a fixed 12,000 bytes that
        // ignores the runtime MTU (v0.11.18, congestion.rs). Recompute it here
        // from the MTU the connection actually negotiated.
        let mtu = u64::from(current_mtu);
        let initial_window = (10 * mtu).min((2 * mtu).max(14_720));
        match self.kind {
            CarrierController::NewReno => {
                let mut config = NewRenoConfig::default();
                config.initial_window(initial_window);
                <NewRenoConfig as ControllerFactory>::build(Arc::new(config), now, current_mtu)
            }
            CarrierController::Cubic => {
                let mut config = CubicConfig::default();
                config.initial_window(initial_window);
                <CubicConfig as ControllerFactory>::build(Arc::new(config), now, current_mtu)
            }
            CarrierController::Bbr => {
                let mut config = BbrConfig::default();
                config.initial_window(initial_window);
                <BbrConfig as ControllerFactory>::build(Arc::new(config), now, current_mtu)
            }
            CarrierController::Fixed => {
                Box::new(FixedRate::new(self.fixed_rate_bytes_per_sec, current_mtu))
            }
        }
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

async fn write_stream_datagram(send: &mut SendStream, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_DATAGRAM {
        bail!("stream carrier datagram is too large")
    }
    send.write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    send.write_all(payload).await?;
    Ok(())
}

async fn read_stream_datagram(receive: &mut RecvStream) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    receive.read_exact(&mut header).await?;
    let size = u32::from_be_bytes(header) as usize;
    if size > MAX_DATAGRAM {
        bail!("stream carrier datagram is too large")
    }
    let mut payload = vec![0u8; size];
    receive.read_exact(&mut payload).await?;
    Ok(payload)
}

fn spawn_lane_readers(receives: Vec<RecvStream>) -> (mpsc::Receiver<Vec<u8>>, JoinSet<Result<()>>) {
    let (tx, rx) = mpsc::channel(1024);
    let mut tasks = JoinSet::new();
    for mut receive in receives {
        let tx = tx.clone();
        tasks.spawn(async move {
            loop {
                let payload = read_stream_datagram(&mut receive).await?;
                tx.send(payload)
                    .await
                    .context("stream lane receiver closed")?;
            }
        });
    }
    drop(tx);
    (rx, tasks)
}

fn transport_config() -> Result<Arc<TransportConfig>> {
    let mut transport = TransportConfig::default();
    // One bidirectional stream authenticates the device; optional reliable
    // carrier lanes use the remaining streams.
    transport.max_concurrent_bidi_streams(((MAX_STREAM_LANES + 1) as u32).into());
    transport.max_idle_timeout(Some(Duration::from_secs(20).try_into().unwrap()));
    transport.keep_alive_interval(Some(Duration::from_secs(2)));
    // 1472 bytes plus the IPv4 header is a standard 1500-byte packet. Quinn's
    // PMTU discovery and black-hole detection remain enabled and can lower it;
    // the carrier fragmentation layer handles the resulting smaller DATAGRAM.
    // `min_mtu` is deliberately left at its 1200 default: Quinn's own guidance is
    // to raise `initial_mtu` and let discovery adapt, because raising `min_mtu`
    // past the real path MTU causes unrepairable packet loss.
    transport.initial_mtu(1472);
    let controller = configured_congestion_controller()?;
    // Resolved once: reading the environment twice could in principle disagree
    // between the logged value and the value actually used.
    let fixed_rate_mbps = match controller {
        CarrierController::Fixed => Some(configured_fixed_rate()?),
        _ => None,
    };
    match controller {
        CarrierController::Bbr => warn!(
            ?controller,
            "carrier congestion controller selected; BBR is marked experimental by Quinn"
        ),
        CarrierController::Fixed => warn!(
            ?controller,
            rate_mbps = fixed_rate_mbps.unwrap_or(0),
            "carrier congestion controller selected; fixed rate ignores packet loss and does \
             not satisfy RFC 9002 -- only for dedicated links whose capacity is known and \
             whose loss is known not to be congestion. The configured rate must not exceed \
             the real link capacity, otherwise loss becomes permanent and FEC cannot cover it."
        ),
        _ => info!(?controller, "carrier congestion controller selected"),
    }
    let fixed_rate_bytes_per_sec =
        fixed_rate_mbps.map_or(0, |mbps| mbps.saturating_mul(1_000_000) / 8);
    transport.congestion_controller_factory(Arc::new(CarrierControllerFactory {
        kind: controller,
        fixed_rate_bytes_per_sec,
    }));
    // These are hard caps, not "unlimited": exceeding them makes Quinn drop the
    // oldest buffered datagram, and `None` for the receive buffer means "refuse
    // incoming datagrams", not "no limit". A drop here happens below FEC, so the
    // datagram has already consumed an FEC sequence number without ever reaching
    // the wire, and FEC cannot reconstruct a shard that was never sent. 4 MiB is
    // far above any plausible bandwidth-delay product on this path.
    transport.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
    transport.datagram_send_buffer_size(4 * 1024 * 1024);
    Ok(Arc::new(transport))
}

fn exporter(connection: &Connection, nonce: &[u8; 16]) -> Result<[u8; 32]> {
    let mut binding = [0u8; 32];
    connection
        .export_keying_material(&mut binding, EXPORTER_LABEL, nonce)
        .map_err(|_| anyhow::anyhow!("TLS exporter failed"))?;
    Ok(binding)
}

fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let reader = BufReader::new(
        File::open(path).with_context(|| format!("open certificate {}", path.display()))?,
    );
    let certificates: Vec<_> = CertificateDer::pem_reader_iter(reader)
        .collect::<std::result::Result<_, _>>()
        .context("parse certificate PEM")?;
    if certificates.is_empty() {
        bail!("certificate file is empty")
    }
    Ok(certificates)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path).context("parse private key PEM")
}

fn server_endpoint(listen: SocketAddr, cert: &Path, private_key: &Path) -> Result<Endpoint> {
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(load_certificates(cert)?, load_private_key(private_key)?)?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let mut config = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    config.transport_config(transport_config()?);
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
    config.transport_config(transport_config()?);
    let mut endpoint = Endpoint::client(bind).context("bind QUIC client")?;
    endpoint.set_default_client_config(config);
    Ok(endpoint)
}

fn parse_keyring(path: &Path) -> Result<HashMap<u64, String>> {
    // 与 main.rs 的 load_keyring 保持一致：密钥文件不得对组/其他用户可读。
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .with_context(|| format!("stat keyring {}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            bail!("keyring must not be accessible by group or other users");
        }
    }
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
        if id == 0 || secret.len() < 32 || fields.next().is_some() || keys.contains_key(&id) {
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
    let mut stats_tick = time::interval(CARRIER_STATS_INTERVAL);
    let mut previous_stats = CarrierStatsSnapshot::default();
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
            _ = stats_tick.tick() => {
                log_carrier_stats(&connection, &mut previous_stats, "server");
            }
        }
    }
}

async fn relay_laned_connection(
    connection: Connection,
    upstream: SocketAddr,
    lanes: usize,
) -> Result<()> {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await?;
    socket.connect(upstream).await?;
    let mut sends = Vec::with_capacity(lanes);
    let mut receives = Vec::with_capacity(lanes);
    for _ in 0..lanes {
        let (mut send, mut receive) = time::timeout(Duration::from_secs(5), connection.accept_bi())
            .await
            .context("carrier lane timeout")??;
        let mut preface = [0u8; 1];
        receive.read_exact(&mut preface).await?;
        if preface[0] != STREAM_LANE_PREFACE {
            bail!("invalid carrier lane preface")
        }
        send.write_all(&[STREAM_LANE_PREFACE]).await?;
        sends.push(send);
        receives.push(receive);
    }
    let (mut incoming_lanes, mut readers) = spawn_lane_readers(receives);
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    let mut next_lane = 0usize;
    let mut stats_tick = time::interval(CARRIER_STATS_INTERVAL);
    let mut previous_stats = CarrierStatsSnapshot::default();
    loop {
        tokio::select! {
            incoming = socket.recv(&mut buffer) => {
                let size = incoming?;
                write_stream_datagram(&mut sends[next_lane], &buffer[..size]).await?;
                next_lane = (next_lane + 1) % lanes;
            }
            incoming = incoming_lanes.recv() => {
                let payload = incoming.context("all carrier lane readers closed")?;
                socket.send(&payload).await?;
            }
            reader = readers.join_next() => {
                reader
                    .context("all carrier lane readers closed")?
                    .context("carrier lane reader panicked")??;
                bail!("carrier lane reader exited unexpectedly")
            }
            _ = stats_tick.tick() => {
                log_carrier_stats(&connection, &mut previous_stats, "server-lanes");
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
    // Bound concurrent handshakes/relay tasks so unauthenticated connection
    // floods cannot create an unbounded number of Tokio tasks and sockets.
    let connection_slots = Arc::new(Semaphore::new(256));
    info!(%listen, %upstream, "SFT QUIC relay server started");
    while let Some(connecting) = endpoint.accept().await {
        let permit = connection_slots
            .clone()
            .acquire_owned()
            .await
            .context("QUIC connection semaphore closed")?;
        let keys = keys.clone();
        let replays = replays.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let result = async {
                let connection = connecting.await?;
                let device_id = authenticate_server(&connection, &keys, &replays).await?;
                info!(device_id, remote = %connection.remote_address(), "QUIC device authenticated");
                let lanes = configured_stream_lanes()?;
                if lanes == 0 {
                    relay_connection(connection, upstream).await
                } else {
                    relay_laned_connection(connection, upstream, lanes).await
                }
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
    let mut stats_tick = time::interval(CARRIER_STATS_INTERVAL);
    heartbeat.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    let mut last_server_activity = Instant::now();
    let mut previous_stats = CarrierStatsSnapshot::default();
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
                _ = stats_tick.tick() => {
                    log_carrier_stats(connection, &mut previous_stats, "client");
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

async fn relay_laned_client_session(
    socket: &UdpSocket,
    connection: &Connection,
    lanes: usize,
) -> Result<()> {
    let mut sends = Vec::with_capacity(lanes);
    let mut receives = Vec::with_capacity(lanes);
    for _ in 0..lanes {
        let (mut send, mut receive) = connection.open_bi().await?;
        send.write_all(&[STREAM_LANE_PREFACE]).await?;
        let mut preface = [0u8; 1];
        receive.read_exact(&mut preface).await?;
        if preface[0] != STREAM_LANE_PREFACE {
            bail!("invalid carrier lane preface")
        }
        sends.push(send);
        receives.push(receive);
    }
    let (mut incoming_lanes, mut readers) = spawn_lane_readers(receives);
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    let mut next_lane = 0usize;
    let mut peer = None;
    let mut stats_tick = time::interval(CARRIER_STATS_INTERVAL);
    let mut previous_stats = CarrierStatsSnapshot::default();
    loop {
        tokio::select! {
            incoming = socket.recv_from(&mut buffer) => {
                let (size, source) = incoming?;
                peer = Some(source);
                write_stream_datagram(&mut sends[next_lane], &buffer[..size]).await?;
                next_lane = (next_lane + 1) % lanes;
            }
            incoming = incoming_lanes.recv() => {
                let payload = incoming.context("all carrier lane readers closed")?;
                if let Some(destination) = peer {
                    socket.send_to(&payload, destination).await?;
                }
            }
            reader = readers.join_next() => {
                reader
                    .context("all carrier lane readers closed")?
                    .context("carrier lane reader panicked")??;
                bail!("carrier lane reader exited unexpectedly")
            }
            _ = stats_tick.tick() => {
                log_carrier_stats(connection, &mut previous_stats, "client-lanes");
            }
        }
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
            let lanes = configured_stream_lanes()?;
            info!(%server, lanes, max_datagram = ?connection.max_datagram_size(), "QUIC relay connected and authenticated");
            delay = Duration::from_secs(1);
            if lanes == 0 {
                relay_client_session(&socket, &connection).await
            } else {
                relay_laned_client_session(&socket, &connection, lanes).await
            }
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
    fn stream_lane_mode_is_explicit_and_rejects_unvalidated_parallel_lanes() {
        // Unset, blank, and an explicit "0" all mean DATAGRAM mode. The init
        // script shipped in deploy/ passes "0" by default, so this must not be
        // an error; doing so previously produced an endless reconnect loop.
        for datagram in [None, Some(""), Some("  "), Some("0"), Some(" 0 ")] {
            assert_eq!(
                parse_stream_lanes(datagram).unwrap(),
                0,
                "{datagram:?} must mean DATAGRAM mode"
            );
        }
        assert_eq!(parse_stream_lanes(Some("1")).unwrap(), 1);
        for invalid in ["2", "16", "invalid", "-1"] {
            assert!(parse_stream_lanes(Some(invalid)).is_err());
        }
    }

    #[test]
    fn carrier_stats_delta_is_windowed_and_saturating() {
        let previous = CarrierStatsSnapshot {
            sent_packets: 100,
            lost_packets: 5,
            lost_bytes: 500,
            congestion_events: 2,
            black_holes_detected: 1,
            lost_plpmtud_probes: 3,
            udp_tx_datagrams: 50,
            udp_rx_datagrams: 40,
            udp_tx_bytes: 5_000,
            udp_rx_bytes: 4_000,
            datagram_tx: 10,
            datagram_rx: 9,
        };
        let current = CarrierStatsSnapshot {
            sent_packets: 160,
            lost_packets: 9,
            lost_bytes: 900,
            congestion_events: 3,
            black_holes_detected: 2,
            lost_plpmtud_probes: 5,
            udp_tx_datagrams: 80,
            udp_rx_datagrams: 70,
            udp_tx_bytes: 8_000,
            udp_rx_bytes: 7_000,
            datagram_tx: 20,
            datagram_rx: 18,
        };
        let delta = current.delta(&previous);
        assert_eq!(delta.sent_packets, 60);
        assert_eq!(delta.lost_packets, 4);
        assert_eq!(delta.lost_bytes, 400);
        assert_eq!(delta.congestion_events, 1);
        assert_eq!(delta.black_holes_detected, 1);
        assert_eq!(delta.lost_plpmtud_probes, 2);
        assert_eq!(delta.udp_tx_datagrams, 30);
        assert_eq!(delta.udp_rx_datagrams, 30);
        assert_eq!(delta.udp_tx_bytes, 3_000);
        assert_eq!(delta.udp_rx_bytes, 3_000);
        assert_eq!(delta.datagram_tx, 10);
        assert_eq!(delta.datagram_rx, 9);
        // 计数器归零（新连接）必须产出 0，而不是一个虚假的巨大增量。
        assert_eq!(previous.delta(&current).sent_packets, 0);
        assert_eq!(previous.delta(&current).lost_bytes, 0);
        assert_eq!(previous.delta(&current).datagram_rx, 0);
    }

    #[test]
    fn congestion_controller_uses_rfc_sized_initial_window() {
        // RFC 9002 section 7.2: min(10 * mtu, max(2 * mtu, 14720)), recalculated
        // from the MTU the connection actually negotiated rather than Quinn's
        // compile-time 12,000 constant.
        for kind in [
            CarrierController::NewReno,
            CarrierController::Cubic,
            CarrierController::Bbr,
        ] {
            let factory = Arc::new(CarrierControllerFactory {
                kind,
                fixed_rate_bytes_per_sec: 0,
            });
            let controller = factory.clone().build(std::time::Instant::now(), 1472);
            assert_eq!(controller.initial_window(), 14_720, "{kind:?} at mtu 1472");
            let controller = factory.build(std::time::Instant::now(), 1200);
            assert_eq!(controller.initial_window(), 12_000, "{kind:?} at mtu 1200");
        }
    }

    #[test]
    fn fixed_rate_controller_sizes_window_to_rate_and_ignores_random_loss() {
        // 28 Mbit/s = 3_500_000 bytes/s.
        let rate = 28u64 * 1_000_000 / 8;

        // Window sizing rule: window = rate x smoothed RTT / ack_rate, which
        // makes quinn's pacer (rate = window / smoothed_rtt) emit `rate`.
        assert_eq!(
            fixed_rate_window(rate, FIXED_RATE_BOOTSTRAP_RTT, 1472, 1.0),
            rate / 10,
            "bootstrap window is rate x 100ms"
        );
        assert_eq!(
            fixed_rate_window(rate, Duration::from_millis(400), 1472, 1.0),
            rate * 4 / 10,
            "at 400ms RTT the window is 1.4 MB, so the pacer holds 28 Mbit/s"
        );
        // Loss compensation: on a 20 % loss path Brutal sends ~25 % faster so
        // the *delivered* rate matches the configured rate.
        assert_eq!(
            fixed_rate_window(rate, Duration::from_millis(400), 1472, 0.8),
            rate * 5 / 10,
            "20% loss must enlarge the window by 1/0.8"
        );
        // The divisor is clamped: worse loss must not amplify without bound.
        assert_eq!(
            fixed_rate_window(rate, Duration::from_millis(400), 1472, 0.1),
            rate * 5 / 10,
            "ack_rate is clamped at FIXED_RATE_MIN_ACK_RATE"
        );
        // A nonsensical ack_rate must degrade to "no compensation".
        assert_eq!(
            fixed_rate_window(rate, Duration::from_millis(400), 1472, f64::NAN),
            rate * 4 / 10
        );
        // Floor: a tiny RTT must not produce a window smaller than a few MTUs.
        assert_eq!(
            fixed_rate_window(rate, Duration::from_micros(1), 1472, 1.0),
            FIXED_RATE_MIN_WINDOW_MTUS * 1472
        );
        // A zero rate must still yield a usable (non-zero) window.
        assert_eq!(
            fixed_rate_window(0, Duration::from_millis(400), 1200, 1.0),
            FIXED_RATE_MIN_WINDOW_MTUS * 1200
        );

        let mut controller = FixedRate::new(rate, 1472);
        assert_eq!(controller.window(), rate / 10);
        assert_eq!(controller.ack_rate, 1.0);

        // The contract that matters: random loss must NOT shrink the window.
        // This is the whole reason the controller exists -- NewReno/Cubic/BBR
        // all collapse here, which measured out at 2944 bytes (RFC minimum)
        // and 17 % bandwidth utilisation.
        let t0 = std::time::Instant::now();
        for i in 0..20 {
            controller.on_congestion_event(t0, t0, false, 1200);
            let _ = i;
        }
        assert_eq!(
            controller.window(),
            rate / 10,
            "random loss must not reduce the fixed window"
        );
        assert_eq!(controller.persistent_congestion_events, 0);

        // ...but loss IS counted, to drive the compensation. 50 acks + 50 losses
        // in the same second is a 50 % ACK rate, clamped to the 0.8 floor.
        let mut controller = FixedRate::new(rate, 1472);
        controller.apply_rtt(Duration::from_millis(400));
        for _ in 0..50 {
            controller.record(t0, 1, 0);
        }
        for _ in 0..50 {
            controller.record(t0, 0, 1);
        }
        assert_eq!(controller.ack_rate, FIXED_RATE_MIN_ACK_RATE);
        assert_eq!(controller.window(), rate * 5 / 10);

        // Below the sample threshold the estimator must not amplify on noise.
        let mut controller = FixedRate::new(rate, 1472);
        for _ in 0..10 {
            controller.record(t0, 1, 0);
        }
        for _ in 0..10 {
            controller.record(t0, 0, 1);
        }
        assert_eq!(controller.ack_rate, 1.0, "too few samples to compensate");

        // A clean path leaves the window at exactly rate x RTT.
        let mut controller = FixedRate::new(rate, 1472);
        controller.apply_rtt(Duration::from_millis(400));
        for _ in 0..100 {
            controller.record(t0, 1, 0);
        }
        assert_eq!(controller.ack_rate, 1.0);
        assert_eq!(controller.window(), rate * 4 / 10);

        // Persistent congestion is recorded and logged, but it is not a window
        // collapse: the ACK-rate floor already bounds how far ahead we can run.
        // It does contribute one loss sample, so the window may nudge up via the
        // compensation but must never fall.
        controller.on_congestion_event(t0, t0, true, 1200);
        assert_eq!(controller.persistent_congestion_events, 1);
        assert!(
            controller.window() >= rate * 4 / 10,
            "persistent congestion must not collapse the fixed window (got {})",
            controller.window()
        );
        assert!(
            controller.window() < rate * 45 / 100,
            "the one recorded loss may only nudge the window via ack_rate (got {})",
            controller.window()
        );

        // The window tracks the smoothed RTT in BOTH directions: a smaller RTT
        // shrinks it, a larger RTT grows it. Either way `window / rtt` stays
        // equal to `rate / ack_rate`. A fresh controller is used here so that
        // ack_rate is back to 1.0 and the pure RTT relation is observable.
        let mut controller = FixedRate::new(rate, 1472);
        controller.apply_rtt(Duration::from_millis(400));
        assert_eq!(controller.window(), rate * 4 / 10);
        controller.apply_rtt(Duration::from_millis(50));
        assert_eq!(controller.window(), rate / 20);
        controller.apply_rtt(Duration::from_millis(900));
        assert_eq!(controller.window(), rate * 9 / 10);
        // The degenerate case is clamped twice: FIXED_RATE_MIN_RTT (1 ms) then
        // the MTU floor, which wins because rate x 1 ms < 4 MTUs here.
        controller.apply_rtt(Duration::from_micros(1));
        assert_eq!(
            controller.window(),
            FIXED_RATE_MIN_WINDOW_MTUS * 1472,
            "the MTU floor must win at a degenerate RTT"
        );

        // An MTU update changes the floor and nothing else.
        controller.on_mtu_update(1200);
        assert_eq!(controller.window(), FIXED_RATE_MIN_WINDOW_MTUS * 1200);

        // Metrics must expose the window and a pacing rate for observability.
        let metrics = controller.metrics();
        assert_eq!(metrics.congestion_window, controller.window());
        assert_eq!(metrics.pacing_rate, Some(rate * 8));
        assert_eq!(metrics.ssthresh, None);
    }

    #[test]
    fn fixed_rate_parsing_rejects_zero_and_garbage() {
        // Unset or blank means "not configured" and falls back to the default;
        // an empty env var must never abort startup.
        for unset in [None, Some(""), Some("   ")] {
            assert_eq!(
                parse_fixed_rate_mbps(unset).unwrap(),
                DEFAULT_FIXED_RATE_MBPS,
                "{unset:?} must fall back to the default"
            );
        }
        assert_eq!(parse_fixed_rate_mbps(Some(" 100 ")).unwrap(), 100);
        assert_eq!(parse_fixed_rate_mbps(Some("1")).unwrap(), 1);
        assert_eq!(
            parse_fixed_rate_mbps(Some(&MAX_FIXED_RATE_MBPS.to_string())).unwrap(),
            MAX_FIXED_RATE_MBPS
        );
        for invalid in ["0", "abc", "-5", "10001", "1.5"] {
            assert!(
                parse_fixed_rate_mbps(Some(invalid)).is_err(),
                "{invalid:?} must be rejected"
            );
        }
    }

    #[test]
    fn fixed_rate_factory_honours_the_configured_rate() {
        let rate = 10u64 * 1_000_000 / 8;
        let factory = Arc::new(CarrierControllerFactory {
            kind: CarrierController::Fixed,
            fixed_rate_bytes_per_sec: rate,
        });
        let controller = factory.build(std::time::Instant::now(), 1472);
        // Bootstrap BDP from FIXED_RATE_BOOTSTRAP_RTT.
        assert_eq!(controller.initial_window(), rate / 10);
        // And it must be recognisably not one of the RFC-IW controllers.
        assert_ne!(controller.initial_window(), 14_720);
    }

    #[test]
    fn congestion_controller_selection_is_explicit() {
        assert_eq!(
            parse_congestion_controller(None).unwrap(),
            CarrierController::NewReno
        );
        assert_eq!(
            parse_congestion_controller(Some("reno")).unwrap(),
            CarrierController::NewReno
        );
        assert_eq!(
            parse_congestion_controller(Some("Cubic")).unwrap(),
            CarrierController::Cubic
        );
        assert_eq!(
            parse_congestion_controller(Some(" bbr ")).unwrap(),
            CarrierController::Bbr
        );
        // Loss-tolerant fixed-rate mode, including its documented alias.
        assert_eq!(
            parse_congestion_controller(Some("fixed")).unwrap(),
            CarrierController::Fixed
        );
        assert_eq!(
            parse_congestion_controller(Some("BRUTAL")).unwrap(),
            CarrierController::Fixed
        );
        // A typo must fail loudly instead of silently falling back to a
        // controller the operator did not choose.
        for invalid in ["", "vegas", "new-reno", "1"] {
            assert!(
                parse_congestion_controller(Some(invalid)).is_err(),
                "{invalid:?} must be rejected"
            );
        }
    }

    #[test]
    fn keyring_rejects_weak_duplicate_and_reserved_entries() {
        let path = std::env::temp_dir().join(format!("sft-quic-keyring-{}", std::process::id()));
        let write = |content: &[u8]| {
            File::create(&path).unwrap().write_all(content).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        };
        for invalid in [
            "",
            "0 abcdefghijklmnop",
            "1 short",
            "1 abcdefghijklmnop\n1 different-secret-value",
        ] {
            write(invalid.as_bytes());
            assert!(parse_keyring(&path).is_err());
        }
        write(b"7 a-very-long-device-secret-at-least-32\n8 another-very-long-device-secret-32\n");
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

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
/// 向对端公布的双向流上限：**协议默认值 100**，而不是本项目真正用到的 2。
///
/// 该值会被写进 TLS 握手里的传输参数，而 QUIC 的 Initial 包用的是公开 salt 派生的密钥
/// （RFC 9001 §5.2），**任何被动观察者都能解密并读到它**。真实 HTTP/3 部署一律是默认的
/// 100，公布 2 等于自报"这不是常规 HTTP/3 服务端"。它只约束对端能开多少流，所以改成默认
/// 值在功能上是中性的。
const QUIC_DEFAULT_BIDI_STREAMS: u32 = 100;

/// 公布给对端的双向流上限。
///
/// 单独抽成函数是为了**可守卫**：quinn 的 `TransportConfig` 只有 builder 式 setter、
/// 没有 getter，无法从配置里读回这个值；如果直接在 `transport_config()` 里写常量，任何人
/// 把它改回"贴合真实用量"的 2 都不会有任何用例报警。走这个函数之后，绕过它就等于让它变成
/// 死代码，而 CI 跑 `clippy -D warnings`，死代码会直接失败。
fn advertised_bidi_streams() -> u32 {
    QUIC_DEFAULT_BIDI_STREAMS
}
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
///
/// `Adaptive` is the default. It keeps `Fixed`'s defining property -- random
/// loss must not collapse the window -- but replaces the hand-configured rate
/// with a probe bounded by a hard budget ceiling. Both choices are driven by
/// measurement rather than taste:
///
/// * the server's egress is a **known, hard 30.8 Mbps**, so there is no capacity
///   to *discover*; the only question is how to stay inside the budget;
/// * `fixed` had no absolute ceiling: its ACK-rate compensation can push the
///   effective rate to 1.25x the configured value, so `fixed@30` asked for
///   37.5 Mbps on a 30.8 Mbps pipe and the shaper answered with 40-68 % burst
///   loss;
/// * RFC 9265 section 5: with FEC below the transport, losses are hidden from
///   the transport. That is a problem for *loss-based* detection but not for
///   *delay-based* detection -- so this controller must be delay-first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CarrierController {
    NewReno,
    Cubic,
    Bbr,
    Fixed,
    Adaptive,
}

fn configured_congestion_controller() -> Result<CarrierController> {
    let value = std::env::var("SMART_QUIC_CONGESTION").ok();
    parse_congestion_controller(value.as_deref())
}

fn parse_congestion_controller(value: Option<&str>) -> Result<CarrierController> {
    // Unset means `adaptive`. NewReno was the previous default, but it is
    // measurably unusable on this project's target path: it collapsed to the
    // RFC 9002 minimum window (2944 bytes) and delivered 4.5 KB/s, against
    // 42-49 KB/s... per second for bbr/fixed under the same conditions (see
    // PRODUCT-MANUAL section 10.6). The protocol's entire reason for existing is
    // lossy long-haul links, so the default must be the controller that survives
    // them.
    let Some(value) = value else {
        return Ok(CarrierController::Adaptive);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "new_reno" | "newreno" | "reno" => Ok(CarrierController::NewReno),
        "cubic" => Ok(CarrierController::Cubic),
        "bbr" => Ok(CarrierController::Bbr),
        "fixed" | "brutal" => Ok(CarrierController::Fixed),
        "adaptive" | "auto" => Ok(CarrierController::Adaptive),
        other => bail!(
            "SMART_QUIC_CONGESTION must be new_reno, cubic, bbr, fixed or adaptive, got {other:?}"
        ),
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

fn configured_max_rate() -> Result<u64> {
    let value = std::env::var("SMART_QUIC_MAX_RATE_MBPS").ok();
    parse_max_rate_mbps(value.as_deref())
}

/// Parses `SMART_QUIC_MAX_RATE_MBPS`: the hard ceiling on the carrier's
/// **effective** send rate.
///
/// This is the metered egress budget, not a target. On the server that is the
/// Tencent egress cap (measured 30.6-31.2 Mbps); on the router it is whatever the
/// home uplink allows. Blank falls back to the default so an empty entry in an
/// env file cannot abort startup.
fn parse_max_rate_mbps(value: Option<&str>) -> Result<u64> {
    let value = value.map(str::trim).filter(|value| !value.is_empty());
    let Some(value) = value else {
        return Ok(DEFAULT_MAX_RATE_MBPS);
    };
    let mbps: u64 = value
        .parse()
        .context("SMART_QUIC_MAX_RATE_MBPS must be an integer")?;
    if mbps == 0 || mbps > MAX_ALLOWED_RATE_MBPS {
        bail!("SMART_QUIC_MAX_RATE_MBPS must be between 1 and {MAX_ALLOWED_RATE_MBPS}, got {mbps}")
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
    ceiling_bytes_per_sec: u64,
) -> u64 {
    let ack_rate = if ack_rate.is_finite() && ack_rate > 0.0 {
        ack_rate.clamp(FIXED_RATE_MIN_ACK_RATE, 1.0)
    } else {
        1.0
    };
    // The budget ceiling must bind the **effective** rate, exactly as
    // `adaptive_window` does. Without this, `fixed@24` on a 20 % loss path asked
    // for `24 / 0.8 = 30` Mbps and, with quinn's pacer adding its own 1.25x
    // refill factor, could reach `24 / 0.8 * 1.25 = 37.5` Mbps -- over both the
    // configured budget and the server's 30.8 Mbps metered egress. `fixed` was
    // the only controller that could exceed the budget.
    let ceiling = if ceiling_bytes_per_sec == 0 {
        f64::INFINITY
    } else {
        ceiling_bytes_per_sec as f64
    };
    let effective = (rate_bytes_per_sec as f64 / ack_rate).min(ceiling);
    let bdp = effective * smoothed_rtt.as_secs_f64();
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
    /// Hard budget ceiling on the **effective** rate, bytes/s. `0` means "no
    /// ceiling". Shared with [`AdaptiveRate`]: whichever controller is chosen,
    /// ACK-rate compensation must not push the effective rate past the budget.
    ceiling: u64,
    /// First event time, used as the epoch for the ACK-rate slots.
    base: Option<Instant>,
    /// Recent ACK success rate in `[FIXED_RATE_MIN_ACK_RATE, 1.0]`.
    ack_rate: f64,
    slots: [AckSlot; FIXED_RATE_ACK_SLOTS],
    /// Counted for observability only; the controller keeps sending regardless.
    persistent_congestion_events: u64,
}

impl FixedRate {
    fn new(rate_bytes_per_sec: u64, ceiling_bytes_per_sec: u64, current_mtu: u16) -> Self {
        let mtu = u64::from(current_mtu).max(1);
        Self {
            rate: rate_bytes_per_sec.max(1),
            rtt: FIXED_RATE_BOOTSTRAP_RTT,
            mtu,
            ceiling: ceiling_bytes_per_sec,
            base: None,
            ack_rate: 1.0,
            slots: [AckSlot::default(); FIXED_RATE_ACK_SLOTS],
            persistent_congestion_events: 0,
        }
    }

    /// The window actually in force: `rate * srtt / ack_rate`, clamped so the
    /// effective rate never exceeds the budget, floored so the pacer never starves.
    fn window_bytes(&self) -> u64 {
        fixed_rate_window(self.rate, self.rtt, self.mtu, self.ack_rate, self.ceiling)
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
        self.ack_rate = refresh_ack_rate(&mut self.slots, &mut self.base, now, acks, losses);
    }
}

/// Updates one second-bucketed ACK/loss slot and returns the ACK success rate
/// over the retained window, clamped to the compensation floor.
///
/// Shared by [`FixedRate`] and [`AdaptiveRate`]: both need the same Brutal-style
/// compensation (a 20 % loss path must send ~25 % faster to deliver the target
/// rate), and duplicating this logic would duplicate its subtlety -- the
/// sample-count gate exists so a quiet path is not amplified on noise, and that
/// was worth keeping in exactly one place.
fn refresh_ack_rate(
    slots: &mut [AckSlot; FIXED_RATE_ACK_SLOTS],
    base: &mut Option<Instant>,
    now: Instant,
    acks: u64,
    losses: u64,
) -> f64 {
    let epoch = *base.get_or_insert(now);
    let ts = now.saturating_duration_since(epoch).as_secs() as i64;
    let slot = &mut slots[(ts as usize) % FIXED_RATE_ACK_SLOTS];
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
    for slot in slots.iter() {
        if slot.ts < min_ts {
            continue;
        }
        total_ack = total_ack.saturating_add(slot.ack);
        total_loss = total_loss.saturating_add(slot.loss);
    }
    let total = total_ack.saturating_add(total_loss);
    if total < FIXED_RATE_MIN_ACK_SAMPLES {
        // Not enough evidence yet: do not amplify on noise.
        return 1.0;
    }
    let rate = total_ack as f64 / total as f64;
    if rate.is_finite() {
        rate.clamp(FIXED_RATE_MIN_ACK_RATE, 1.0)
    } else {
        1.0
    }
}

/// Default hard ceiling on the **effective** carrier send rate, in Mbps.
///
/// Measured: this server's Tencent egress is 30.6-31.2 Mbps over three upload
/// runs. Tencent meters egress only -- the "20-72 MB/s server egress" figure from
/// an earlier round was actually *ingress*, which is unmetered, and reading it as
/// egress was an analysis error. 30 is therefore the number the carrier must
/// never exceed. The earlier advice to configure `fixed` at 24 was accidentally
/// right: 24 x the 1.25 ACK-rate compensation = 30 exactly.
const DEFAULT_MAX_RATE_MBPS: u64 = 30;
const MAX_ALLOWED_RATE_MBPS: u64 = 10_000;
/// Floor for the adaptive target: below this the link is unusable, so the
/// controller stops probing downward.
const ADAPTIVE_MIN_RATE_MBPS: u64 = 2;
/// Control interval. Long enough to accumulate many ACKs at this link's measured
/// 349 ms RTT, short enough to react within a few seconds.
const ADAPTIVE_INTERVAL: Duration = Duration::from_millis(500);
/// Per-interval increase while nothing adverse is observed (5 %). Deliberately
/// slower than [`ADAPTIVE_TEST_DROP_PPM`]: probing up must be cheap to undo.
const ADAPTIVE_PROBE_PPM: u64 = 50_000;
/// Size of the step taken when an adverse signal appears (30 %).
///
/// Large enough that the *response* is measurable within a few intervals --
/// which is the whole point, since the controller no longer decides whether a
/// signal means congestion from the signal's size.
const ADAPTIVE_TEST_DROP_PPM: u64 = 300_000;
/// Intervals observed at the reduced rate before concluding anything.
///
/// Six, not one. The previous version decided from a *single* post-drop
/// interval, which on this link is a coin flip: measured loss jumps between
/// 8 % and 35 % from one interval to the next, so "the next interval happened to
/// be lower" was read as "the loss responded". The deployed log shows 12
/// `test_confirm` against 14 `test_drop` -- congestion confirmed on noise -- and
/// the controller ratcheted to the floor exactly like the bug it replaced.
const ADAPTIVE_TEST_INTERVALS: u32 = 6;
/// Intervals to hold after congestion is confirmed, before probing resumes.
const ADAPTIVE_COOLDOWN_INTERVALS: u32 = 8;
/// EWMA shift for the loss baseline: weight `1/2^shift` on the newest interval.
/// Purely for the log line; loss does not steer the rate.
const ADAPTIVE_BASELINE_SHIFT: u32 = 2;
/// How far queueing must fall to count as having responded.
const ADAPTIVE_QUEUE_RESPONSE_MARGIN: Duration = Duration::from_millis(10);
/// Loss at or above this is treated as congestion regardless of whether it
/// responds to slowing down (90 %).
///
/// Without this, "the loss did not respond so the path is merely lossy" taken to
/// its logical end would hold the rate up on a path that is delivering almost
/// nothing -- which is saturation or a dead path, not a lossy one. The learning
/// path is for partial loss that is genuinely rate-independent.
const ADAPTIVE_TOTAL_LOSS_PPM: u64 = 900_000;
/// How far smoothed RTT may exceed the windowed minimum before it counts as
/// queueing at all.
const ADAPTIVE_QUEUE_TARGET: Duration = Duration::from_millis(25);

/// One control interval's observations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct IntervalSample {
    delivered_bytes: u64,
    lost_bytes: u64,
    smoothed_rtt: Duration,
    base_rtt: Duration,
    app_limited: bool,
}

/// What the controller is currently doing.
///
/// There is no "loss" phase because loss does not drive the rate at all -- see
/// [`AdaptiveRate`]. That is not a simplification for convenience: three
/// deployed attempts to infer congestion from loss on this link failed (the
/// size threshold collapsed to the floor, and the single-interval and
/// window-averaged response tests both confirmed congestion on noise), because
/// the signal being reasoned about is 20 % wide and does not respond to rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdaptPhase {
    /// Increasing gently.
    Steady,
    /// Reduced the rate and is measuring whether queueing responded.
    Testing,
    /// Congestion confirmed; holding before probing again.
    Cooldown,
}

/// Controller state the pure step function reads and writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AdaptState {
    target: u64,
    /// Smoothed loss, maintained purely for logging and diagnosis.
    ///
    /// It deliberately does **not** influence the rate. Three deployed attempts
    /// to infer congestion from loss on this link failed -- a size threshold
    /// collapsed to the floor, and both a single-interval and a window-averaged
    /// response test confirmed congestion on noise -- because the signal is
    /// ~20 % wide, swings 8-35 % between adjacent intervals, and does not respond
    /// to the sending rate at all. Reporting it is useful; steering on it is not.
    baseline_loss_ppm: u64,
    phase: AdaptPhase,
    /// Intervals spent in the current phase.
    steps: u32,
    /// Rate to restore if the test shows queueing was not congestion.
    pre_test_rate: u64,
    /// Queueing measured when the test was opened: the reference the test
    /// compares against.
    pre_test_queue: Duration,
    /// Accumulated queueing over the test window, so the verdict rests on
    /// `ADAPTIVE_TEST_INTERVALS` samples rather than one.
    test_queue_sum_ms: u64,
}

impl AdaptState {
    fn new(target: u64) -> Self {
        Self {
            target,
            baseline_loss_ppm: 0,
            phase: AdaptPhase::Steady,
            steps: 0,
            pre_test_rate: target,
            pre_test_queue: Duration::ZERO,
            test_queue_sum_ms: 0,
        }
    }
}

/// Why the target moved. Kept as a value for logging and for tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdaptStep {
    /// Queueing appeared: dropped the rate to test whether it responds.
    TestDrop,
    /// Queueing fell after slowing down, so it was congestion: stay low.
    TestConfirm,
    /// Queueing did not fall, so it was not congestion: restore the rate.
    TestRevert,
    /// The path is delivering almost nothing: drop immediately, no test.
    SaturationDrop,
    Probe,
    Hold,
}

impl AdaptStep {
    fn as_str(self) -> &'static str {
        match self {
            AdaptStep::TestDrop => "test_drop",
            AdaptStep::TestConfirm => "test_confirm",
            AdaptStep::TestRevert => "test_revert",
            AdaptStep::SaturationDrop => "saturation_drop",
            AdaptStep::Probe => "probe",
            AdaptStep::Hold => "hold",
        }
    }
}

fn scale_ppm(value: u64, ppm: u64, up: bool) -> u64 {
    let delta = ((u128::from(value) * u128::from(ppm)) / 1_000_000) as u64;
    if up {
        value.saturating_add(delta)
    } else {
        value.saturating_sub(delta)
    }
}

fn loss_ppm(received: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    ((u128::from(total.saturating_sub(received)) * 1_000_000) / u128::from(total)) as u64
}

/// Pure control step: state plus one interval's observations in, next state and
/// the reason out.
///
/// Pure so the whole decision table can be unit-tested without a QUIC
/// connection -- `quinn_proto::RttEstimator` cannot be constructed outside
/// quinn, so anything touching it is untestable by construction.
fn adapt_step(
    state: AdaptState,
    ceiling: u64,
    floor: u64,
    sample: IntervalSample,
) -> (AdaptState, AdaptStep) {
    let clamp = |value: u64| value.min(ceiling).max(floor);
    let total = sample.delivered_bytes.saturating_add(sample.lost_bytes);
    let mut next = state;
    if total == 0 {
        // No evidence either way. An idle interval must not ratchet the target
        // up, and must not be read as 100 % loss either.
        return (next, AdaptStep::Hold);
    }
    let loss = loss_ppm(sample.delivered_bytes, total);
    let queueing = sample.smoothed_rtt.saturating_sub(sample.base_rtt);

    if state.phase == AdaptPhase::Testing {
        next.test_queue_sum_ms = state
            .test_queue_sum_ms
            .saturating_add(queueing.as_millis() as u64);
        if state.steps.saturating_add(1) < ADAPTIVE_TEST_INTERVALS {
            next.steps = state.steps.saturating_add(1);
            return (next, AdaptStep::Hold);
        }
        // Decide once, on the window's mean. Deciding early -- on the first
        // post-drop interval -- is what made the earlier version confirm
        // congestion on this link's interval-to-interval noise.
        let window_queue =
            Duration::from_millis(state.test_queue_sum_ms / u64::from(ADAPTIVE_TEST_INTERVALS));
        next.test_queue_sum_ms = 0;
        if window_queue.saturating_add(ADAPTIVE_QUEUE_RESPONSE_MARGIN) < state.pre_test_queue {
            // Congestion, confirmed by the only evidence that can confirm it:
            // slowing down made the queue drain.
            next.phase = AdaptPhase::Cooldown;
            next.steps = 0;
            return (next, AdaptStep::TestConfirm);
        }
        // The queue did not drain, so it was not congestion. Restore the rate.
        next.phase = AdaptPhase::Steady;
        next.steps = 0;
        next.target = clamp(state.pre_test_rate);
        return (next, AdaptStep::TestRevert);
    }

    if sample.app_limited {
        return (next, AdaptStep::Hold);
    }

    // Loss is recorded but never steers: on this path it is ~20 % wide, swings
    // 8-35 % between adjacent intervals, and does not respond to rate. See
    // `AdaptState::baseline_loss_ppm`. The EWMA is seeded on first observation.
    next.baseline_loss_ppm = if state.baseline_loss_ppm == 0 {
        loss
    } else {
        let shift = u64::from(ADAPTIVE_BASELINE_SHIFT);
        (state.baseline_loss_ppm * ((1 << shift) - 1) + loss) >> shift
    };

    if state.phase == AdaptPhase::Cooldown {
        if state.steps.saturating_add(1) < ADAPTIVE_COOLDOWN_INTERVALS {
            next.steps = state.steps.saturating_add(1);
            return (next, AdaptStep::Hold);
        }
        next.phase = AdaptPhase::Steady;
        next.steps = 0;
        // Fall through to probing.
    }

    // Saturation guard. A path delivering almost nothing is not "merely lossy",
    // and unlike partial loss it must not be reasoned about statistically --
    // drop immediately rather than spending six intervals proving the obvious.
    if loss >= ADAPTIVE_TOTAL_LOSS_PPM {
        next.phase = AdaptPhase::Cooldown;
        next.steps = 0;
        next.target = clamp(scale_ppm(state.target, ADAPTIVE_TEST_DROP_PPM, false));
        return (next, AdaptStep::SaturationDrop);
    }

    if queueing >= ADAPTIVE_QUEUE_TARGET {
        next.phase = AdaptPhase::Testing;
        next.steps = 0;
        next.pre_test_rate = state.target;
        next.pre_test_queue = queueing;
        next.test_queue_sum_ms = 0;
        next.target = clamp(scale_ppm(state.target, ADAPTIVE_TEST_DROP_PPM, false));
        return (next, AdaptStep::TestDrop);
    }

    next.target = clamp(scale_ppm(state.target, ADAPTIVE_PROBE_PPM, true));
    (next, AdaptStep::Probe)
}

/// Window for a target rate, with the ceiling applied to the **effective** rate.
///
/// quinn's pacer produces `window / srtt`, and the ACK-rate compensation divides
/// the target by `ack_rate`, so the rate actually sent can reach
/// `target / 0.8` = 1.25x the target. Clamping the effective value -- not the
/// target -- is what makes the budget ceiling absolute. `fixed` never did this,
/// which is why `fixed@30` asked a 30.8 Mbps pipe for 37.5 Mbps and got 40-68 %
/// burst loss back.
fn adaptive_window(
    target_bytes_per_sec: u64,
    smoothed_rtt: Duration,
    mtu: u64,
    ack_rate: f64,
    ceiling_bytes_per_sec: u64,
) -> u64 {
    let ack_rate = if ack_rate.is_finite() && ack_rate > 0.0 {
        ack_rate.clamp(FIXED_RATE_MIN_ACK_RATE, 1.0)
    } else {
        1.0
    };
    let effective = (target_bytes_per_sec as f64 / ack_rate).min(ceiling_bytes_per_sec as f64);
    let bdp = effective * smoothed_rtt.as_secs_f64();
    let bdp = if bdp.is_finite() && bdp >= 1.0 {
        bdp as u64
    } else {
        0
    };
    bdp.max(FIXED_RATE_MIN_WINDOW_MTUS * mtu).max(1)
}

/// Budget-aware, delay-only adaptive carrier controller.
///
/// Deliberately **not** a capacity estimator. The server's egress is a known,
/// hard 30.8 Mbps, so there is no capacity to discover; the only question is how
/// to stay usefully inside the budget. That inverts the usual design: instead of
/// "probe until something breaks", it is "probe toward the ceiling and retreat
/// when the path pushes back".
///
/// **Packet loss does not steer the rate at all**, and that conclusion was bought
/// by measurement, not preference. Three loss-based designs were deployed on this
/// link and all three collapsed to the 2 Mbps floor:
///
/// 1. a size threshold (5 % loss = congestion) -- the link has three overlapping
///    regimes (0.05-0.6 %, 5-15 %, 40-68 %) so no threshold separates them;
/// 2. a single-interval *response* test -- confirmed congestion on 12 of 14
///    tests because loss swings 8-35 % between adjacent intervals;
/// 3. a window-averaged response test against a smoothed baseline -- still
///    collapsed, and the regression test using the real observed loss sequence
///    reproduced it.
///
/// The signal simply does not carry the information: it is ~20 % wide, its
/// interval-to-interval noise exceeds any response a 30 % rate change produces,
/// and it is the ISP dropping packets rather than a queue filling. RFC 9265
/// section 5 reaches the same place from the other direction -- with FEC below
/// the transport, loss is the signal that gets hidden and delay is the one that
/// survives. So delay is the *only* input, with a saturation guard for the one
/// case where loss is unambiguous.
#[derive(Debug, Clone)]
struct AdaptiveRate {
    /// Hard ceiling on the effective send rate, bytes/s.
    ceiling: u64,
    floor: u64,
    /// Current target send rate, bytes/s.
    target: u64,
    /// Smoothed RTT -- the same quantity the pacer divides by.
    rtt: Duration,
    /// Windowed minimum RTT, used as the no-queueing baseline. Taken from
    /// `RttEstimator::min()` rather than tracked here, because quinn's is
    /// windowed and therefore follows a path change; a global minimum would be
    /// poisoned forever by whichever WAN happened to be in use at startup.
    base_rtt: Duration,
    mtu: u64,
    ack_rate: f64,
    base: Option<Instant>,
    slots: [AckSlot; FIXED_RATE_ACK_SLOTS],
    interval_started: Option<Instant>,
    interval_delivered: u64,
    interval_lost: u64,
    interval_app_limited: bool,
    adapt: AdaptState,
    last_step: AdaptStep,
    steps: u64,
    persistent_congestion_events: u64,
}

impl AdaptiveRate {
    fn new(ceiling_bytes_per_sec: u64, floor_bytes_per_sec: u64, current_mtu: u16) -> Self {
        let ceiling = ceiling_bytes_per_sec.max(1);
        let floor = floor_bytes_per_sec.max(1).min(ceiling);
        // Start at half the ceiling. Probing up from the floor would take many
        // intervals, and starting *at* the ceiling would immediately over-drive
        // a path whose behaviour we have not observed yet.
        let target = (ceiling / 2).max(floor);
        Self {
            ceiling,
            floor,
            target,
            rtt: FIXED_RATE_BOOTSTRAP_RTT,
            base_rtt: FIXED_RATE_BOOTSTRAP_RTT,
            mtu: u64::from(current_mtu).max(1),
            ack_rate: 1.0,
            base: None,
            slots: [AckSlot::default(); FIXED_RATE_ACK_SLOTS],
            interval_started: None,
            interval_delivered: 0,
            interval_lost: 0,
            interval_app_limited: false,
            adapt: AdaptState::new(target),
            last_step: AdaptStep::Hold,
            steps: 0,
            persistent_congestion_events: 0,
        }
    }

    fn window_bytes(&self) -> u64 {
        adaptive_window(self.target, self.rtt, self.mtu, self.ack_rate, self.ceiling)
    }

    /// Close the current control interval if it has elapsed, and act on it.
    fn maybe_adapt(&mut self, now: Instant) {
        let started = *self.interval_started.get_or_insert(now);
        if now.saturating_duration_since(started) < ADAPTIVE_INTERVAL {
            return;
        }
        self.interval_started = Some(now);
        let sample = IntervalSample {
            delivered_bytes: self.interval_delivered,
            lost_bytes: self.interval_lost,
            smoothed_rtt: self.rtt,
            base_rtt: self.base_rtt,
            app_limited: self.interval_app_limited,
        };
        let (next, step) = adapt_step(self.adapt, self.ceiling, self.floor, sample);
        if step != AdaptStep::Hold || next.target != self.target {
            info!(
                from_bytes_per_sec = self.target,
                to_bytes_per_sec = next.target,
                step = step.as_str(),
                phase = ?next.phase,
                delivered_bytes = sample.delivered_bytes,
                lost_bytes = sample.lost_bytes,
                loss_ppm = loss_ppm(
                    sample.delivered_bytes,
                    sample.delivered_bytes + sample.lost_bytes
                ),
                queue_ms = sample
                    .smoothed_rtt
                    .saturating_sub(sample.base_rtt)
                    .as_millis() as u64,
                // Recorded for diagnosis only; it never steers the rate. Seeing
                // this track the path's actual loss is how an operator confirms
                // the controller is not fighting non-congestion loss.
                baseline_loss_ppm = next.baseline_loss_ppm,
                "adaptive carrier target changed"
            );
        }
        self.adapt = next;
        self.target = next.target;
        self.last_step = step;
        self.steps = self.steps.saturating_add(1);
        self.interval_delivered = 0;
        self.interval_lost = 0;
        self.interval_app_limited = false;
    }
}

impl Controller for AdaptiveRate {
    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.rtt = rtt.get().max(FIXED_RATE_MIN_RTT);
        let observed_min = rtt.min();
        if observed_min > Duration::ZERO {
            self.base_rtt = observed_min.max(FIXED_RATE_MIN_RTT);
        }
        // `bytes.max(1)`: a zero-byte ACK still proves the path is alive, and
        // dropping it would let an interval look idle when it was not.
        self.interval_delivered = self.interval_delivered.saturating_add(bytes.max(1));
        self.interval_app_limited |= app_limited;
        self.ack_rate = refresh_ack_rate(&mut self.slots, &mut self.base, now, 1, 0);
        self.maybe_adapt(now);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.interval_lost = self.interval_lost.saturating_add(lost_bytes.max(1));
        let lost_packets = (lost_bytes / self.mtu.max(1)).max(1);
        self.ack_rate = refresh_ack_rate(&mut self.slots, &mut self.base, now, 0, lost_packets);
        if is_persistent_congestion {
            self.persistent_congestion_events = self.persistent_congestion_events.saturating_add(1);
            // Persistent congestion means the path is dead, not merely lossy.
            // Unlike `fixed` -- which deliberately kept sending -- a dead path
            // is dropped straight to the floor so the carrier cannot hammer it.
            warn!(
                target_bytes_per_sec = self.target,
                events = self.persistent_congestion_events,
                "adaptive carrier hit persistent congestion; dropping to the floor"
            );
            self.target = self.floor;
            // Restart the state machine from the floor, in cooldown, so recovery
            // is a bounded wait rather than something that has to be earned back
            // through intervals that may never qualify as "clean".
            self.adapt = AdaptState::new(self.floor);
            self.adapt.phase = AdaptPhase::Cooldown;
            self.adapt.steps = 0;
        }
        self.maybe_adapt(now);
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
        metrics.ssthresh = None;
        // Informational only: quinn's pacer uses `window() / RTT`, not this.
        let effective = (self.target as f64 / self.ack_rate).min(self.ceiling as f64);
        metrics.pacing_rate = Some((effective as u64).saturating_mul(8));
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
    /// Absolute ceiling on the *effective* send rate, for **both** `Fixed` and
    /// `Adaptive`. `Fixed` used to ignore it, which let ACK-rate compensation
    /// (and quinn's own 1.25x pacer factor) push the real rate past the budget.
    ceiling_bytes_per_sec: u64,
    /// Floor the `Adaptive` controller will not probe below.
    adaptive_floor_bytes_per_sec: u64,
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
            CarrierController::Fixed => Box::new(FixedRate::new(
                self.fixed_rate_bytes_per_sec,
                self.ceiling_bytes_per_sec,
                current_mtu,
            )),
            CarrierController::Adaptive => Box::new(AdaptiveRate::new(
                self.ceiling_bytes_per_sec,
                self.adaptive_floor_bytes_per_sec,
                current_mtu,
            )),
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
    // **Advertise the protocol default, not our real usage.**
    //
    // This number is a fingerprint. Transport parameters live in the TLS
    // handshake, and QUIC Initial packets are protected with keys derived from a
    // publicly known salt (RFC 9001 §5.2), so any passive observer can decrypt
    // them and read `initial_max_streams_bidi` in the clear. Advertising our true
    // usage — one auth stream plus at most `MAX_STREAM_LANES` carrier lanes, i.e.
    // 2 — is trivially distinguishable from every real HTTP/3 deployment, which
    // advertises the protocol default of 100. The value only bounds what the
    // *peer* may open, so raising it to the default is functionally inert.
    transport.max_concurrent_bidi_streams(advertised_bidi_streams().into());
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
    // Read for both rate-governing controllers. `Fixed` used to skip this
    // entirely, which is how `fixed@24` could ask a 30.8 Mbps pipe for more than
    // its budget once ACK-rate compensation and quinn's 1.25x pacer factor
    // applied.
    let max_rate_mbps = match controller {
        CarrierController::Adaptive | CarrierController::Fixed => Some(configured_max_rate()?),
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
        CarrierController::Adaptive => info!(
            ?controller,
            max_rate_mbps = max_rate_mbps.unwrap_or(0),
            "carrier congestion controller selected; delay-only with a response test, \
             hard-capped on the effective send rate so ACK-rate compensation cannot exceed \
             the budget. Packet loss does not steer the rate: measured on this path it is \
             ~20 % wide, swings 8-35 % between adjacent intervals, and does not respond to \
             rate, so all three loss-based designs tried here collapsed to the floor."
        ),
        _ => info!(?controller, "carrier congestion controller selected"),
    }
    let fixed_rate_bytes_per_sec =
        fixed_rate_mbps.map_or(0, |mbps| mbps.saturating_mul(1_000_000) / 8);
    let ceiling_bytes_per_sec = max_rate_mbps.map_or(0, |mbps| mbps.saturating_mul(1_000_000) / 8);
    transport.congestion_controller_factory(Arc::new(CarrierControllerFactory {
        kind: controller,
        fixed_rate_bytes_per_sec,
        ceiling_bytes_per_sec,
        adaptive_floor_bytes_per_sec: ADAPTIVE_MIN_RATE_MBPS.saturating_mul(1_000_000) / 8,
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

/// Reads one DER TLV element: returns `(tag, content, total_len)`.
///
/// Deliberately minimal -- only what [`certificate_is_self_signed`] needs. It
/// handles short and long form lengths and rejects indefinite length (which DER
/// forbids anyway). No dependency is added for this: the dependency tree has no
/// x509 parser, and pulling one in for a single boolean is not worth the supply
/// chain and offline-build risk.
fn der_element(input: &[u8]) -> Option<(u8, &[u8], usize)> {
    let tag = *input.first()?;
    let first_len = *input.get(1)?;
    let (content_len, header_len) = if first_len & 0x80 == 0 {
        (first_len as usize, 2usize)
    } else {
        let count = (first_len & 0x7f) as usize;
        // 0x80 would be indefinite length, which DER forbids.
        if count == 0 || count > 4 {
            return None;
        }
        let mut value = 0usize;
        for index in 0..count {
            value = (value << 8) | (*input.get(2 + index)? as usize);
        }
        (value, 2 + count)
    };
    let end = header_len.checked_add(content_len)?;
    let content = input.get(header_len..end)?;
    Some((tag, content, end))
}

/// Iterates the direct children of a constructed DER value.
fn der_children(mut content: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    while !content.is_empty() {
        let (tag, inner, used) = der_element(content)?;
        out.push((tag, inner));
        content = &content[used..];
    }
    Some(out)
}

/// `Some(true)` when the certificate is self-signed, `Some(false)` when it is
/// not, `None` when the DER could not be parsed.
///
/// **This needs no trust store, and that is the point.** A publicly trusted TLS
/// server certificate is never self-signed, so `Some(true)` means any
/// standards-compliant client -- including an active prober doing exactly what
/// this function does -- will reject the chain. That makes it a decisive test of
/// the fingerprint this server presents, without shipping a root bundle or
/// adding a certificate-parsing dependency.
///
/// Self-signed is defined here the way RFC 5280 defines it: `subject` and
/// `issuer` are the same distinguished name. Comparing the raw DER of the two
/// Name structures is the same comparison a validator makes, and avoids having
/// to decode X.501 at all.
fn certificate_is_self_signed(der: &[u8]) -> Option<bool> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let (_, certificate, _) = der_element(der)?;
    let children = der_children(certificate)?;
    let (_, tbs) = *children.first()?;
    // TBSCertificate ::= SEQUENCE {
    //   version [0] EXPLICIT OPTIONAL, serialNumber INTEGER, signature,
    //   issuer Name, validity, subject Name, ... }
    let fields = der_children(tbs)?;
    let mut index = 0usize;
    // The optional explicit version is context tag [0] (0xa0).
    if matches!(fields.first().map(|(tag, _)| *tag), Some(0xa0)) {
        index += 1;
    }
    // serialNumber, signature, then issuer.
    let issuer = fields.get(index + 2)?.1;
    // validity, then subject.
    let subject = fields.get(index + 4)?.1;
    Some(issuer == subject)
}

/// Environment switch for QUIC address validation (RFC 9000 section 8.1.2).
const ADDRESS_VALIDATION_ENV: &str = "SMART_QUIC_ADDRESS_VALIDATION";
/// When set to `1`, a self-signed server certificate aborts startup instead of
/// warning. Off by default so an existing deployment is never taken down by an
/// audit that is about to be fixed.
const REQUIRE_TRUSTED_CERT_ENV: &str = "SMART_QUIC_REQUIRE_TRUSTED_CERT";

fn env_flag(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(value) => !matches!(value.trim(), "0" | "false" | "no"),
        Err(_) => default,
    }
}

/// 地址验证（Retry）的触发策略。
///
/// **为什么需要第三种策略**：Retry 是 RFC 9000 §8.1.3 的放大防护，但"**每个**新连接都
/// Retry"本身就是一处**握手顺序指纹**——主流 QUIC 部署（CDN、浏览器可达的服务端）
/// 在轻载时直接回 ServerHello，只在高负载/可疑时发 Retry。原实现是 `address_validation &&
/// incoming.may_retry()`，即对新连接一律 Retry，于是握手的第一步就与常规部署不同。
///
/// 默认改为 [`AddressValidation::UnderLoad`]：**轻载不做地址验证、接近并发上限时才做**。
/// 防护没有削弱——它恰好在我们真正需要它的负载区间生效——但握手顺序在常态下与常规一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressValidation {
    /// 从不 Retry。
    Off,
    /// 每次新连接都 Retry（旧默认行为，保留以便复现与回退）。
    Always,
    /// 只在并发连接接近上限时 Retry。
    UnderLoad,
}

/// 并发连接（含握手中的）硬上限。见 `connection_slots` 的语义：它不是一个"软"限制，
/// 达到它就拒绝服务，所以地址验证的触发阈值必须**由它推导**，而不是另写一个字面量。
const MAX_CONCURRENT_CONNECTIONS: usize = 256;

/// `UnderLoad` 的触发阈值：可用 permit 降到这个数及以下时开始 Retry。
///
/// **由上限定**（1/4）：因此"阈值严格小于上限"是构造性成立的，不需要额外断言；同时它也
/// 不可能被悄悄改成等于上限——那会让 `UnderLoad` 退化成 `Always`。
const ADDRESS_VALIDATION_LOAD_SLOTS: usize = MAX_CONCURRENT_CONNECTIONS / 4;

/// 该策略在给定可用 permit 数下是否应当 Retry。
///
/// 抽成纯函数是为了可测：accept 循环里的真实负载无法在单测中构造。
fn should_retry_address_validation(policy: AddressValidation, available_slots: usize) -> bool {
    match policy {
        AddressValidation::Off => false,
        AddressValidation::Always => true,
        AddressValidation::UnderLoad => available_slots <= ADDRESS_VALIDATION_LOAD_SLOTS,
    }
}

/// 解析 `SMART_QUIC_ADDRESS_VALIDATION`。
///
/// 未设/空白 → `UnderLoad`（新默认）。`0`/`off`/`false` → `Off`；`1`/`on`/`true` →
/// `Always`（与旧文档兼容）；`auto`/`load` → `UnderLoad`。**无法识别的值不静默回落**，
/// 而是打 WARN 后按默认走——与 `SMART_FEC_MAX_PARITY` 同一约定：配置被无声忽略比报错更危险。
fn parse_address_validation(value: Option<&str>) -> AddressValidation {
    let Some(raw) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return AddressValidation::UnderLoad;
    };
    match raw.to_ascii_lowercase().as_str() {
        "0" | "off" | "false" | "no" => AddressValidation::Off,
        "1" | "on" | "true" => AddressValidation::Always,
        "auto" | "load" | "under_load" => AddressValidation::UnderLoad,
        _ => {
            warn!(
                value = %raw,
                "SMART_QUIC_ADDRESS_VALIDATION is not a recognised value \
                 (expected 0/1/auto); falling back to the default 'auto'"
            );
            AddressValidation::UnderLoad
        }
    }
}

/// Audits the certificate the QUIC server is about to present.
///
/// Why this exists: the deployed server presents a **self-signed** certificate
/// whose subject claims `www.microsoft.com` (measured: `openssl verify` fails
/// with error 18). That combination is not neutral camouflage -- it is a
/// *positive* indicator, because a genuine Microsoft endpoint never does it, and
/// active probing is exactly how such an endpoint would be found. The risk is
/// easy to miss in a config file, so it is made explicit here, with the concrete
/// remediation rather than a generic warning.
fn audit_server_certificate(cert: &Path) -> Result<()> {
    let certificates = load_certificates(cert)?;
    let Some(leaf) = certificates.first() else {
        bail!("certificate file is empty")
    };
    match certificate_is_self_signed(leaf.as_ref()) {
        Some(true) => {
            let require_trusted = env_flag(REQUIRE_TRUSTED_CERT_ENV, false);
            let message = "the QUIC carrier is presenting a SELF-SIGNED certificate. Any \
                 standards-compliant client -- including an active prober -- rejects this \
                 chain, so the endpoint is trivially distinguishable from the real service \
                 the --server-name claims. This is a positive fingerprint, not neutral \
                 camouflage. Fix by deploying a publicly trusted certificate for a name you \
                 control, or stop advertising a third-party name. Set \
                 SMART_QUIC_REQUIRE_TRUSTED_CERT=1 to make this fatal.";
            if require_trusted {
                bail!("{message}");
            }
            warn!(cert = %cert.display(), certificates = certificates.len(), "{message}");
        }
        Some(false) => info!(
            cert = %cert.display(),
            chain_len = certificates.len(),
            "QUIC carrier certificate is not self-signed"
        ),
        None => warn!(
            cert = %cert.display(),
            "could not parse the QUIC carrier certificate; fingerprint posture unverified"
        ),
    }
    Ok(())
}

fn server_endpoint(listen: SocketAddr, cert: &Path, private_key: &Path) -> Result<Endpoint> {
    audit_server_certificate(cert)?;
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
    let connection_slots = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    // RFC 9000 section 8.1 requires address validation before a server commits
    // state to an unvalidated address; section 8.1.3 is the Retry packet
    // mechanism itself. Validating bounds amplification.
    //
    // 但"每个新连接都 Retry"是**握手顺序指纹**：常规 QUIC 部署在轻载时直接回
    // ServerHello。默认策略因此改为 `UnderLoad` —— 防护在逼近并发上限时才生效。
    // 注意发射顺序：先取 permit 用量，再决定是否 Retry。
    let address_validation =
        parse_address_validation(std::env::var(ADDRESS_VALIDATION_ENV).ok().as_deref());
    info!(
        %listen,
        %upstream,
        policy = ?address_validation,
        load_threshold = ADDRESS_VALIDATION_LOAD_SLOTS,
        "SFT QUIC relay server started"
    );
    while let Some(incoming) = endpoint.accept().await {
        let retry = should_retry_address_validation(
            address_validation,
            connection_slots.available_permits(),
        );
        if retry && incoming.may_retry() {
            if let Err(error) = incoming.retry() {
                // `may_retry()` said yes, so this should not happen. The client
                // simply retries with a token; nothing is lost by moving on.
                warn!(%error, "QUIC address validation retry failed");
            }
            continue;
        }
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
                let connection = incoming.await?;
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

    /// 地址验证策略：默认必须**轻载不 Retry、接近上限才 Retry**。
    ///
    /// "每个新连接都 Retry"是握手顺序指纹（常规 QUIC 部署轻载直接回 ServerHello）。
    /// 本用例同时钉住**防护仍然存在**：逼近并发上限时必须开始 Retry，否则这次改动就
    /// 变成了"为了伪装而拆掉防护"。
    #[test]
    fn address_validation_is_load_gated_by_default_and_still_protects_under_load() {
        // 未设 / 空白 = 默认策略
        assert_eq!(parse_address_validation(None), AddressValidation::UnderLoad);
        assert_eq!(
            parse_address_validation(Some("   ")),
            AddressValidation::UnderLoad
        );
        // 兼容旧写法
        assert_eq!(parse_address_validation(Some("0")), AddressValidation::Off);
        assert_eq!(
            parse_address_validation(Some("off")),
            AddressValidation::Off
        );
        assert_eq!(
            parse_address_validation(Some("1")),
            AddressValidation::Always
        );
        assert_eq!(
            parse_address_validation(Some("on")),
            AddressValidation::Always
        );
        assert_eq!(
            parse_address_validation(Some("auto")),
            AddressValidation::UnderLoad
        );
        assert_eq!(
            parse_address_validation(Some("load")),
            AddressValidation::UnderLoad
        );
        // 无法识别不静默回落到 Off（那会削弱防护），而是按默认 UnderLoad
        assert_eq!(
            parse_address_validation(Some("yes-please")),
            AddressValidation::UnderLoad,
            "an unrecognised value must fall back to the default, never to Off"
        );

        // 轻载：不 Retry —— 这才是与常规部署一致的握手顺序
        assert!(
            !should_retry_address_validation(AddressValidation::UnderLoad, 256),
            "an idle server must NOT send Retry; that is the fingerprint"
        );
        assert!(!should_retry_address_validation(
            AddressValidation::UnderLoad,
            ADDRESS_VALIDATION_LOAD_SLOTS + 1
        ));
        // 逼近上限：必须开始 Retry —— 防护不能被这次改动拿掉
        assert!(
            should_retry_address_validation(
                AddressValidation::UnderLoad,
                ADDRESS_VALIDATION_LOAD_SLOTS
            ),
            "under load the amplification guard MUST engage"
        );
        assert!(should_retry_address_validation(
            AddressValidation::UnderLoad,
            0
        ));
        // 显式策略不看负载
        assert!(should_retry_address_validation(
            AddressValidation::Always,
            256
        ));
        assert!(!should_retry_address_validation(AddressValidation::Off, 0));
        // 阈值由上限推导（1/4），因此"严格小于上限"是构造性成立的。
        assert_eq!(
            ADDRESS_VALIDATION_LOAD_SLOTS,
            MAX_CONCURRENT_CONNECTIONS / 4
        );
    }

    /// 传输参数是在**明文可读**的 Initial 包里公布的（QUIC Initial 用公开 salt 派生的
    /// 密钥，RFC 9001 §5.2），所以"公布的双向流上限"是指纹，不是内部常量。
    ///
    /// 本用例钉住它必须是协议默认值 100，防止有人为了"贴合真实用量"改回 1–2：那会让被动
    /// 观察者一眼认出这不是常规 HTTP/3 服务端。
    #[test]
    fn advertised_stream_limit_is_the_protocol_default_not_our_usage() {
        assert_eq!(
            advertised_bidi_streams(),
            100,
            "the advertised bidi stream limit is a cleartext fingerprint and must stay at the \
             protocol default"
        );
        assert!(
            (MAX_STREAM_LANES as u32 + 1) < advertised_bidi_streams(),
            "our real usage (auth stream + lanes) must stay well below the advertised default; \
             if it ever approaches it, this guard no longer means anything"
        );
    }

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
                ceiling_bytes_per_sec: 0,
                adaptive_floor_bytes_per_sec: 0,
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
        // The last argument is the budget ceiling; 0 means "no ceiling", which is
        // what isolates the sizing rule being tested here.
        assert_eq!(
            fixed_rate_window(rate, FIXED_RATE_BOOTSTRAP_RTT, 1472, 1.0, 0),
            rate / 10,
            "bootstrap window is rate x 100ms"
        );
        assert_eq!(
            fixed_rate_window(rate, Duration::from_millis(400), 1472, 1.0, 0),
            rate * 4 / 10,
            "at 400ms RTT the window is 1.4 MB, so the pacer holds 28 Mbit/s"
        );
        // Loss compensation: on a 20 % loss path Brutal sends ~25 % faster so
        // the *delivered* rate matches the configured rate.
        assert_eq!(
            fixed_rate_window(rate, Duration::from_millis(400), 1472, 0.8, 0),
            rate * 5 / 10,
            "20% loss must enlarge the window by 1/0.8"
        );
        // The divisor is clamped: worse loss must not amplify without bound.
        assert_eq!(
            fixed_rate_window(rate, Duration::from_millis(400), 1472, 0.1, 0),
            rate * 5 / 10,
            "ack_rate is clamped at FIXED_RATE_MIN_ACK_RATE"
        );
        // A nonsensical ack_rate must degrade to "no compensation".
        assert_eq!(
            fixed_rate_window(rate, Duration::from_millis(400), 1472, f64::NAN, 0),
            rate * 4 / 10
        );
        // Floor: a tiny RTT must not produce a window smaller than a few MTUs.
        assert_eq!(
            fixed_rate_window(rate, Duration::from_micros(1), 1472, 1.0, 0),
            FIXED_RATE_MIN_WINDOW_MTUS * 1472
        );
        // A zero rate must still yield a usable (non-zero) window.
        assert_eq!(
            fixed_rate_window(0, Duration::from_millis(400), 1200, 1.0, 0),
            FIXED_RATE_MIN_WINDOW_MTUS * 1200
        );

        // **The budget ceiling binds the effective rate.** On a 20 % loss path the
        // window above was `rate * 1.25`; with a ceiling of `rate`, the window must
        // fall back to the un-compensated size. This is the fix for `fixed` being
        // the only controller that could exceed the metered budget.
        assert_eq!(
            fixed_rate_window(rate, Duration::from_millis(400), 1472, 0.8, rate),
            rate * 4 / 10,
            "the ceiling must cancel ACK-rate compensation once it would exceed the budget"
        );
        // A ceiling above the compensated rate must not bind at all.
        assert_eq!(
            fixed_rate_window(rate, Duration::from_millis(400), 1472, 0.8, rate * 2),
            rate * 5 / 10,
            "a ceiling above the compensated rate must not change anything"
        );

        let mut controller = FixedRate::new(rate, 0, 1472);
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
        let mut controller = FixedRate::new(rate, 0, 1472);
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
        let mut controller = FixedRate::new(rate, 0, 1472);
        for _ in 0..10 {
            controller.record(t0, 1, 0);
        }
        for _ in 0..10 {
            controller.record(t0, 0, 1);
        }
        assert_eq!(controller.ack_rate, 1.0, "too few samples to compensate");

        // A clean path leaves the window at exactly rate x RTT.
        let mut controller = FixedRate::new(rate, 0, 1472);
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
        let mut controller = FixedRate::new(rate, 0, 1472);
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
            ceiling_bytes_per_sec: 0,
            adaptive_floor_bytes_per_sec: 0,
        });
        let controller = factory.build(std::time::Instant::now(), 1472);
        // Bootstrap BDP from FIXED_RATE_BOOTSTRAP_RTT.
        assert_eq!(controller.initial_window(), rate / 10);
        // And it must be recognisably not one of the RFC-IW controllers.
        assert_ne!(controller.initial_window(), 14_720);
    }

    #[test]
    fn max_rate_parsing_defaults_on_blank_and_rejects_zero() {
        for unset in [None, Some(""), Some("   ")] {
            assert_eq!(parse_max_rate_mbps(unset).unwrap(), DEFAULT_MAX_RATE_MBPS);
        }
        assert_eq!(parse_max_rate_mbps(Some(" 30 ")).unwrap(), 30);
        assert_eq!(
            parse_max_rate_mbps(Some(&MAX_ALLOWED_RATE_MBPS.to_string())).unwrap(),
            MAX_ALLOWED_RATE_MBPS
        );
        for invalid in ["0", "abc", "-1", "10001", "1.5"] {
            assert!(
                parse_max_rate_mbps(Some(invalid)).is_err(),
                "{invalid:?} must be rejected"
            );
        }
    }

    /// The budget ceiling must bind the **effective** rate, not the target.
    /// This is the concrete fix for `fixed`'s unbounded 1.25x ACK-rate
    /// compensation: `fixed@30` asked a measured 30.8 Mbps pipe for 37.5 Mbps.
    #[test]
    fn adaptive_window_ceiling_survives_ack_rate_compensation() {
        let ceiling = 30u64 * 1_000_000 / 8;
        let srtt = Duration::from_millis(350);
        let window = adaptive_window(ceiling, srtt, 1200, FIXED_RATE_MIN_ACK_RATE, ceiling);
        let effective = window as f64 / srtt.as_secs_f64();
        assert!(
            effective <= ceiling as f64 + 1.0,
            "effective rate {effective} exceeded the {ceiling} byte/s ceiling"
        );

        // And when compensation is not in play, the window must reproduce the
        // requested rate exactly -- sizing on the wrong RTT silently throttles
        // (the bug caught in T1).
        let half = ceiling / 2;
        let window = adaptive_window(half, srtt, 1200, 1.0, ceiling);
        let effective = window as f64 / srtt.as_secs_f64();
        assert!((effective - half as f64).abs() < half as f64 * 0.01);
    }

    fn adaptive_bounds() -> (u64, u64) {
        (
            30u64 * 1_000_000 / 8,
            ADAPTIVE_MIN_RATE_MBPS * 1_000_000 / 8,
        )
    }

    fn clean_sample(delivered: u64, lost: u64, base_rtt: Duration) -> IntervalSample {
        IntervalSample {
            delivered_bytes: delivered,
            lost_bytes: lost,
            smoothed_rtt: base_rtt,
            base_rtt,
            app_limited: false,
        }
    }

    /// Run the controller forward and return the final state.
    fn drive(
        mut state: AdaptState,
        ceiling: u64,
        floor: u64,
        sample: IntervalSample,
        intervals: usize,
    ) -> AdaptState {
        for _ in 0..intervals {
            state = adapt_step(state, ceiling, floor, sample).0;
        }
        state
    }

    /// **Regression test for the defect that deployment exposed.**
    ///
    /// A path with sustained loss that does *not* respond to slowing down must
    /// not pin the controller at the floor. The first version classified a
    /// signal as congestion by its size (a 5 % threshold) and reset its
    /// clean-interval counter on every backoff, so this link's 5-15 % random
    /// loss -- measured on the fast WAN -- produced a backoff every interval
    /// forever. Target sat at `250000` (= the 2 Mbps floor, `from` equal to `to`
    /// in the deployed log) and throughput fell from ~942 KB/s to 28 KB/s.
    ///
    /// This link has at least three loss regimes that overlap -- 0.05-0.6 %
    /// (good WAN), 5-15 % (bad WAN, still random), 40-68 % (shaper) -- so no
    /// single threshold can separate them. The controller must therefore decide
    /// from the *response to slowing down*, not from the size of the signal.
    #[test]
    fn adaptive_never_collapses_on_loss_that_ignores_rate_reduction() {
        let (ceiling, floor) = adaptive_bounds();
        let base_rtt = Duration::from_millis(52);
        // 12 % loss, identical regardless of the rate we send at.
        let lossy = clean_sample(880_000, 120_000, base_rtt);
        let state = drive(AdaptState::new(ceiling), ceiling, floor, lossy, 400);
        assert!(
            state.target > floor * 2,
            "controller collapsed to {} on loss that ignores rate reduction (floor {})",
            state.target,
            floor
        );
        // And loss must never open a test at all on this path: every step is a
        // probe or a hold, never a test or a drop.
        let mut state = AdaptState::new(ceiling / 2);
        for _ in 0..200 {
            let (next, step) = adapt_step(state, ceiling, floor, lossy);
            assert!(
                matches!(step, AdaptStep::Probe | AdaptStep::Hold),
                "loss opened a rate test: {step:?}"
            );
            assert!(next.target >= state.target, "loss reduced the rate");
            state = next;
        }
    }

    /// Loss sequence captured from the live carrier, in ppm.
    ///
    /// Every value is a real observation from the interval in which `adaptive`
    /// collapsed: 8.4 %-34.7 %, mean ~19.5 %. The essential property is not the
    /// mean but the **spread** -- and that it does not respond to the sending
    /// rate, because the loss is the ISP dropping packets.
    const OBSERVED_NOISY_LOSS_PPM: [u64; 20] = [
        123_546, 84_339, 209_666, 160_892, 201_767, 141_710, 227_758, 157_290, 210_766, 347_478,
        253_313, 191_110, 160_820, 164_139, 281_574, 201_955, 172_140, 122_454, 263_727, 239_671,
    ];

    /// **The test the previous version needed and did not have.**
    ///
    /// Its regression test fed a *constant* 12 % loss, which the controller
    /// handled correctly -- so the test passed while the deployed carrier failed.
    /// The live link delivers loss that swings between 8 % and 35 % from one
    /// interval to the next, and against that the single-interval response test
    /// confirmed congestion on 12 of 14 tests and ratcheted to the floor, giving
    /// 33 KB/s against `fixed@24`'s 602 KB/s.
    ///
    /// A fixture without the noise therefore tested the one property that was
    /// never in doubt. This one is the measurement.
    #[test]
    fn adaptive_survives_the_loss_sequence_actually_observed() {
        let (ceiling, floor) = adaptive_bounds();
        let base_rtt = Duration::from_millis(84);
        let mut state = AdaptState::new(ceiling);
        let mut confirms = 0usize;
        for _ in 0..40 {
            for ppm in OBSERVED_NOISY_LOSS_PPM {
                // ppm is already parts-per-million, so the sample's total is
                // exactly this many bytes and the derived loss rate is `ppm`.
                let sample = clean_sample(1_000_000 - ppm, ppm, base_rtt);
                let (next, step) = adapt_step(state, ceiling, floor, sample);
                if step == AdaptStep::TestConfirm {
                    confirms += 1;
                }
                state = next;
            }
        }
        assert!(
            state.target > floor * 4,
            "collapsed to {} under the loss sequence actually observed (floor {floor})",
            state.target
        );
        assert!(
            confirms <= 2,
            "confirmed congestion {confirms} times on loss that does not respond to rate"
        );
    }

    /// Queueing that *does* drain after slowing down is congestion, and the
    /// reduced rate must be held. The verdict rests on the whole test window.
    #[test]
    fn adaptive_confirms_congestion_when_queueing_responds() {
        let (ceiling, floor) = adaptive_bounds();
        let base_rtt = Duration::from_millis(52);
        let congested = IntervalSample {
            smoothed_rtt: base_rtt + ADAPTIVE_QUEUE_TARGET,
            ..clean_sample(1_000_000, 0, base_rtt)
        };
        let (mut state, step) = adapt_step(AdaptState::new(ceiling), ceiling, floor, congested);
        assert_eq!(step, AdaptStep::TestDrop);
        assert!(state.target < ceiling);

        // The queue drains over the whole window: congestion, confirmed, and the
        // reduced rate is held rather than immediately undone.
        let drained = clean_sample(1_000_000, 0, base_rtt);
        let mut step = AdaptStep::Hold;
        for _ in 0..ADAPTIVE_TEST_INTERVALS {
            let (next, s) = adapt_step(state, ceiling, floor, drained);
            state = next;
            step = s;
        }
        assert_eq!(step, AdaptStep::TestConfirm);
        assert_eq!(state.phase, AdaptPhase::Cooldown);
    }

    /// Queueing that persists at the lower rate is not congestion caused by us.
    #[test]
    fn adaptive_restores_the_rate_when_queueing_does_not_respond() {
        let (ceiling, floor) = adaptive_bounds();
        let base_rtt = Duration::from_millis(52);
        let queueing = IntervalSample {
            smoothed_rtt: base_rtt + ADAPTIVE_QUEUE_TARGET,
            ..clean_sample(1_000_000, 0, base_rtt)
        };
        let (mut state, step) = adapt_step(AdaptState::new(ceiling), ceiling, floor, queueing);
        assert_eq!(step, AdaptStep::TestDrop);
        let reduced = state.target;

        let mut step = AdaptStep::Hold;
        for _ in 0..ADAPTIVE_TEST_INTERVALS {
            let (next, s) = adapt_step(state, ceiling, floor, queueing);
            state = next;
            step = s;
        }
        assert_eq!(step, AdaptStep::TestRevert);
        assert!(
            state.target > reduced,
            "the rate was not restored after queueing proved unresponsive"
        );
    }

    /// Sustained 10 % loss must leave the controller probing upward, not
    /// testing downward. This is the property the whole delay-only design
    /// exists to provide, and the one the three previous versions got wrong.
    #[test]
    fn adaptive_ignores_sustained_loss_entirely() {
        let (ceiling, floor) = adaptive_bounds();
        let base_rtt = Duration::from_millis(52);
        let lossy = clean_sample(900_000, 100_000, base_rtt);
        let settled = drive(AdaptState::new(ceiling), ceiling, floor, lossy, 100);
        assert_eq!(settled.phase, AdaptPhase::Steady);
        // With the level learned, a further interval at that level probes up
        // instead of testing down.
        let (_, step) = adapt_step(settled, ceiling, floor, lossy);
        assert_eq!(step, AdaptStep::Probe);
    }

    /// Delay is the primary signal: RFC 9265 section 5 says FEC below the
    /// transport hides loss but leaves delay intact.
    #[test]
    fn adaptive_tests_on_queueing_and_holds_when_app_limited() {
        let (ceiling, floor) = adaptive_bounds();
        let base_rtt = Duration::from_millis(349);
        let queueing = IntervalSample {
            smoothed_rtt: base_rtt + ADAPTIVE_QUEUE_TARGET,
            ..clean_sample(1_000_000, 0, base_rtt)
        };
        let (dropped, step) = adapt_step(AdaptState::new(ceiling), ceiling, floor, queueing);
        assert_eq!(step, AdaptStep::TestDrop);
        assert!(dropped.target < ceiling);

        // Queueing that persists at the lower rate is real queueing, not
        // measurement noise: after the test window the controller restores the
        // rate rather than collapsing, and the loop keeps re-testing -- bounded,
        // never pinned.
        let settled = drive(AdaptState::new(ceiling), ceiling, floor, queueing, 6);
        assert!(settled.target >= floor);

        // App-limited: the interval says nothing about capacity.
        let quiet = IntervalSample {
            app_limited: true,
            ..clean_sample(1_000_000, 0, base_rtt)
        };
        let state = AdaptState::new(ceiling / 2);
        let (next, step) = adapt_step(state, ceiling, floor, quiet);
        assert_eq!(step, AdaptStep::Hold);
        assert_eq!(next.target, state.target);
    }

    #[test]
    fn adaptive_never_leaves_the_budget() {
        let (ceiling, floor) = adaptive_bounds();
        let base_rtt = Duration::from_millis(349);
        let clean = clean_sample(1_000_000, 0, base_rtt);
        let mut state = AdaptState::new(ceiling);
        for _ in 0..2000 {
            let (next, step) = adapt_step(state, ceiling, floor, clean);
            assert_eq!(step, AdaptStep::Probe);
            assert!(
                next.target <= ceiling,
                "{} exceeded the ceiling {ceiling}",
                next.target
            );
            state = next;
        }
        // Total loss forever still must not fall below the floor.
        let dead = clean_sample(1, 1_000_000, base_rtt);
        for _ in 0..500 {
            let (next, _) = adapt_step(state, ceiling, floor, dead);
            assert!(
                next.target >= floor,
                "{} fell below the floor {floor}",
                next.target
            );
            state = next;
        }
    }

    /// An idle interval carries no evidence. It must neither ratchet the target
    /// up nor be mistaken for total loss.
    #[test]
    fn adaptive_holds_without_evidence() {
        let (ceiling, floor) = adaptive_bounds();
        let state = AdaptState::new(ceiling / 2);
        let (next, step) = adapt_step(state, ceiling, floor, IntervalSample::default());
        assert_eq!(step, AdaptStep::Hold);
        assert_eq!(next.target, state.target);
    }

    #[test]
    fn adaptive_factory_starts_inside_the_budget() {
        let (ceiling, floor) = adaptive_bounds();
        let factory = Arc::new(CarrierControllerFactory {
            kind: CarrierController::Adaptive,
            fixed_rate_bytes_per_sec: 0,
            ceiling_bytes_per_sec: ceiling,
            adaptive_floor_bytes_per_sec: floor,
        });
        let controller = factory.build(std::time::Instant::now(), 1200);
        let window = controller.initial_window();
        let at_bootstrap = ceiling * FIXED_RATE_BOOTSTRAP_RTT.as_millis() as u64 / 1000;
        assert!(
            window <= at_bootstrap,
            "bootstrap window {window} implies more than the {ceiling} byte/s ceiling"
        );
        assert!(window >= FIXED_RATE_MIN_WINDOW_MTUS * 1200);
    }

    /// Minimal DER encoder for building certificate fixtures.
    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else {
            let bytes = len.to_be_bytes();
            let first = bytes.iter().position(|byte| *byte != 0).unwrap();
            let count = bytes.len() - first;
            out.push(0x80 | count as u8);
            out.extend_from_slice(&bytes[first..]);
        }
        out.extend_from_slice(content);
        out
    }

    fn der_seq(parts: &[Vec<u8>]) -> Vec<u8> {
        der(0x30, &parts.concat())
    }

    /// Builds a structurally valid (but cryptographically meaningless)
    /// certificate, which is all `certificate_is_self_signed` inspects.
    fn cert_with(issuer: &[u8], subject: &[u8], with_version: bool) -> Vec<u8> {
        let mut fields = Vec::new();
        if with_version {
            fields.push(der(0xa0, &der(0x02, &[2])));
        }
        fields.push(der(0x02, &[1])); // serialNumber
        fields.push(der_seq(&[der(0x06, &[0x2a])])); // signature
        fields.push(der(0x30, issuer)); // issuer Name
        fields.push(der_seq(&[
            der(0x17, b"240101000000Z"),
            der(0x17, b"250101000000Z"),
        ])); // validity
        fields.push(der(0x30, subject)); // subject Name
        fields.push(der_seq(&[der(0x03, &[0])])); // subjectPublicKeyInfo
        let tbs = der_seq(&fields);
        der_seq(&[
            tbs,
            der_seq(&[der(0x06, &[0x2a])]),
            der(0x03, &[0x00, 0x01]),
        ])
    }

    /// The decisive check: a publicly trusted server certificate is never
    /// self-signed, so this boolean is exactly what an active prober computes.
    #[test]
    fn certificate_self_signedness_is_decided_by_subject_equalling_issuer() {
        let name = der_seq(&[der(0x06, &[0x55, 0x04, 0x03])]);
        // Self-signed: subject and issuer are the same DN.
        let self_signed = cert_with(&name, &name, true);
        assert_eq!(certificate_is_self_signed(&self_signed), Some(true));
        // Same, but without the optional [0] version field, which shifts every
        // subsequent index: getting this wrong would silently report the
        // validity block as the issuer.
        let self_signed = cert_with(&name, &name, false);
        assert_eq!(certificate_is_self_signed(&self_signed), Some(true));

        // Issued by something else: not self-signed.
        let issuer = der_seq(&[der(0x06, &[0x55, 0x04, 0x03, 0x01])]);
        let issued = cert_with(&issuer, &name, true);
        assert_eq!(certificate_is_self_signed(&issued), Some(false));
    }

    #[test]
    fn certificate_parsing_reports_none_instead_of_guessing() {
        // Truncated / malformed input must not produce a verdict, because a
        // wrong `false` would silently clear the fingerprint audit.
        assert_eq!(certificate_is_self_signed(&[]), None);
        assert_eq!(certificate_is_self_signed(&[0x30]), None);
        assert_eq!(certificate_is_self_signed(&[0x30, 0x10, 0x01]), None);
    }

    #[test]
    fn der_reader_handles_long_form_and_rejects_indefinite_length() {
        // Long form: 200-byte content uses a two-byte length.
        let long = der(0x04, &[0u8; 200]);
        let (tag, content, used) = der_element(&long).unwrap();
        assert_eq!(tag, 0x04);
        assert_eq!(content.len(), 200);
        assert_eq!(used, long.len());
        // Indefinite length (0x80) is forbidden in DER and must be rejected
        // rather than parsed as a zero-length element.
        assert!(der_element(&[0x30, 0x80, 0x00, 0x00]).is_none());
        assert!(der_element(&[0x30]).is_none());
    }

    /// Opt-in check against a **real** certificate.
    ///
    /// Synthetic fixtures exercise the DER walker's indexing, but they cannot
    /// prove it behaves on a certificate actually produced by a CA or by
    /// openssl. Set `SFT_TEST_CERT` to a PEM path to run this; without the
    /// variable it passes vacuously so the default suite stays hermetic and
    /// independent of the filesystem.
    #[test]
    fn self_signedness_is_decided_on_a_real_certificate_when_provided() {
        let Ok(path) = std::env::var("SFT_TEST_CERT") else {
            return;
        };
        let certificates = load_certificates(Path::new(&path)).expect("parse real certificate");
        let verdict = certificate_is_self_signed(certificates[0].as_ref());
        eprintln!(
            "SFT_TEST_CERT={path} self_signed={verdict:?} chain_len={}",
            certificates.len()
        );
        assert!(
            verdict.is_some(),
            "a real certificate must parse, not fall through to None"
        );
    }

    #[test]
    fn congestion_controller_selection_is_explicit() {
        // Unset now means `adaptive`, not `new_reno`. This is a deliberate
        // default change: NewReno measured 4.5 KB/s on this project's target path
        // (window pinned at the RFC 9002 minimum) against 42-49 KB/s for
        // bbr/fixed, and the protocol exists precisely for lossy long-haul links.
        assert_eq!(
            parse_congestion_controller(None).unwrap(),
            CarrierController::Adaptive
        );
        assert_eq!(
            parse_congestion_controller(Some("adaptive")).unwrap(),
            CarrierController::Adaptive
        );
        assert_eq!(
            parse_congestion_controller(Some("AUTO")).unwrap(),
            CarrierController::Adaptive
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

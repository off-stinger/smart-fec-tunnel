//! FEC 有效性集成测试（Rust 版）。
//!
//! 启动编译好的 client/server 二进制，中间插入随机丢包 relay，量化
//! Reed-Solomon 在固定 parity 下的应用层恢复能力，并验证自适应修复后
//! parity 能随丢包上升。
//!
//! **本文件的用例串行执行**（见 `HARNESS_LOCK`）：端口彼此独立，但 CPU 与 UDP
//! 收发时序不是，并行会互相抢 CPU 并按固定阈值判定到达率，导致假失败。

use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

const KEY: &str = "integration-test-key-32bytes-long-enough";
const PAYLOAD_SIZE: usize = 100;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_smart-fec-tunnel")
}

/// 确定性 LCG，避免给测试 crate 引入额外依赖。
struct Lcg(u64);
impl Lcg {
    fn next_f64(&mut self) -> f64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 33) as f64) / ((1u64 << 31) as f64)
    }
}

fn spawn_echo(stop: Arc<AtomicBool>, sock: UdpSocket) {
    thread::spawn(move || {
        sock.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buf = [0u8; 65535];
        while !stop.load(Ordering::Relaxed) {
            if let Ok((n, peer)) = sock.recv_from(&mut buf) {
                let _ = sock.send_to(&buf[..n], peer);
            }
        }
    });
}

fn spawn_relay(stop: Arc<AtomicBool>, sock: UdpSocket, server: SocketAddr, loss: f64, seed: u64) {
    thread::spawn(move || {
        sock.set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let mut client = None;
        let mut rng = Lcg(seed);
        let mut buf = [0u8; 65535];
        while !stop.load(Ordering::Relaxed) {
            if let Ok((n, peer)) = sock.recv_from(&mut buf) {
                let from_server = peer == server;
                if !from_server {
                    client = Some(peer);
                }
                let target = if from_server { client } else { Some(server) };
                let Some(target) = target else { continue };
                if rng.next_f64() < loss {
                    continue;
                }
                let _ = sock.send_to(&buf[..n], target);
            }
        }
    });
}

struct Harness {
    stop: Arc<AtomicBool>,
    children: Vec<Child>,
    client_port: u16,
    keyring_path: std::path::PathBuf,
    /// 见 [`HARNESS_LOCK`]：本 harness 存活期间独占时序敏感资源。
    _serial: MutexGuard<'static, ()>,
}

/// 时序敏感用例的全局串行锁。
///
/// 本文件的用例**端口**由系统动态分配，但**CPU 与 UDP 收发
/// 时序不是**：每个 harness 要跑 2 个子进程 + relay 线程 + echo 线程 + 发送与
/// 接收两个线程，并且用固定间隔灌包、按固定阈值判定到达率。四个用例在同一
/// 测试二进制里并行时，观测到 `production_sized_datagrams_survive_ten_percent_loss`
/// 偶发跌破 0.80（空载重跑 3/3 通过，24.4s）——即测到的是**测试台互相抢 CPU**，
/// 不是 FEC 层回归。
///
/// 文件头原先写"测试可并行"，那句话只对端口成立，对时序不成立，已删除。
/// 串行化会拉长这个二进制的墙钟时间（实测约 27s → 约 90s），但**一个会随机
/// 失败的守卫比一个慢的守卫更贵**：假失败会训练人去忽略它。
static HARNESS_LOCK: Mutex<()> = Mutex::new(());

/// 取全局串行锁。**忽略中毒**：某个用例 panic 不应该让其余用例跟着报一个与
/// 自身无关的错误；每个用例的断言已经各自给出诊断。
fn serial_guard() -> MutexGuard<'static, ()> {
    HARNESS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Harness {
    fn new(loss: f64, force_parity: Option<usize>) -> Self {
        // 先取锁再起任何线程/进程：否则锁只保护了后半段，前一个用例的残留
        // 线程仍在抢 CPU。
        let serial = serial_guard();
        let stop = Arc::new(AtomicBool::new(false));
        // Keep the echo and relay sockets bound while choosing child-process
        // ports, then move them into their worker threads. This avoids fixed
        // test ports colliding with other local services or parallel test runs.
        let echo_socket = UdpSocket::bind("127.0.0.1:0").expect("bind echo");
        let relay_socket = UdpSocket::bind("127.0.0.1:0").expect("bind relay");
        let echo_port = echo_socket.local_addr().unwrap().port();
        let relay_port = relay_socket.local_addr().unwrap().port();
        let server_reservation = UdpSocket::bind("127.0.0.1:0").expect("reserve server port");
        let client_reservation = UdpSocket::bind("127.0.0.1:0").expect("reserve client port");
        let server_port = server_reservation.local_addr().unwrap().port();
        let client_port = client_reservation.local_addr().unwrap().port();
        drop((server_reservation, client_reservation));

        let server_addr: SocketAddr = ([127, 0, 0, 1], server_port).into();
        spawn_echo(stop.clone(), echo_socket);
        spawn_relay(
            stop.clone(),
            relay_socket,
            server_addr,
            loss,
            0x9e37_79b9_7f4a_7c15,
        );

        let mut env_base: Vec<(String, String)> = Vec::new();
        env_base.push(("SMART_FEC_KEY".to_string(), KEY.to_string()));
        env_base.push(("SMART_FEC_KEY_ID".to_string(), "1".to_string()));
        // 默认静默；设 SFT_TEST_LOG=info 可让被测二进制把 T1 的
        // `FEC traffic accounting` 记录打到测试输出（配合 --nocapture），
        // 用于定位"字节在哪一层消失"。
        let log = std::env::var("SFT_TEST_LOG").unwrap_or_else(|_| "warn".to_string());
        env_base.push(("RUST_LOG".to_string(), log));
        if let Some(p) = force_parity {
            env_base.push(("SMART_FEC_FORCE_PARITY".to_string(), p.to_string()));
        }

        // V3 模式需要 keyring；权限 0600 以通过 keyring 权限检查。
        let keyring_path = std::env::temp_dir().join(format!(
            "sft-test-keyring-{}-{}",
            std::process::id(),
            server_port
        ));
        std::fs::write(&keyring_path, format!("1 {KEY}\n")).expect("write keyring");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&keyring_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }

        // 在闭包内构造 Stdio：`Stdio` 不是 Copy，若在闭包外捕获会把它变成
        // FnOnce，而这里需要为 server/client 两个子进程各调用一次。
        let inherit_logs = std::env::var("SFT_TEST_LOG").is_ok();
        let spawn = |args: &[&str]| {
            Command::new(bin())
                .args(args)
                .envs(env_base.iter().cloned())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(if inherit_logs {
                    Stdio::inherit()
                } else {
                    Stdio::null()
                })
                .spawn()
                .expect("spawn smart-fec-tunnel")
        };

        // 必须显式给 pacer 速率。`--rate-mbps` 默认只有 10 Mbps：本用例以
        // 1200 字节 / 1ms（约 9.6 Mbps 载荷）双向灌入，加上 FEC 开销就超过
        // 10 Mbps，pacer 一阻塞，被测进程就停止读取前置 socket，内核随即丢弃
        // ——量到的是"测试台把 pacer 饿死了"，不是 FEC 层丢数据。
        // 这里给足余量，让 pacer 永远不是瓶颈；pacer 本身另有单元测试覆盖。
        let rate = std::env::var("SFT_TEST_RATE_MBPS").unwrap_or_else(|_| "200".to_string());
        let server = spawn(&[
            "server",
            "--listen",
            &format!("127.0.0.1:{server_port}"),
            "--upstream",
            &format!("127.0.0.1:{echo_port}"),
            "--keyring",
            keyring_path.to_str().unwrap(),
            "--rate-mbps",
            &rate,
        ]);
        let client = spawn(&[
            "client",
            "--listen",
            &format!("127.0.0.1:{client_port}"),
            "--server",
            &format!("127.0.0.1:{relay_port}"),
            "--key-id",
            "1",
            "--rate-mbps",
            &rate,
        ]);

        Self {
            stop,
            children: vec![server, client],
            client_port,
            keyring_path,
            _serial: serial,
        }
    }

    /// 发送 count 个带序号的数据报，返回应用层到达率。
    /// `pump` 为 true 时，预热阶段持续发送数据以驱动 report 闭环、让自适应
    /// parity 先升上去（模拟持续流量），再开始统计。
    fn measure(&self, count: usize, warmup_secs: f64, pump: bool) -> f64 {
        self.measure_with(
            count,
            PAYLOAD_SIZE,
            Duration::from_millis(1),
            warmup_secs,
            pump,
        )
    }

    /// 同 [`Harness::measure`]，但可指定报文尺寸与发送间隔。
    ///
    /// 存在的理由：原有用例用 100 字节 / 1ms（约 10 KB/s），而生产链路是
    /// 1200 字节 / 20+ Mbps 量级——差三个数量级。分片、分组、RS 填充、pacer
    /// 批量的行为在小报文低速下都测不出来，所以必须在接近生产的尺寸与速率下
    /// 单独量一次，才能判断"线上字节去哪了"到底是不是 FEC 层的责任。
    fn measure_with(
        &self,
        count: usize,
        payload_size: usize,
        gap: Duration,
        warmup_secs: f64,
        pump: bool,
    ) -> f64 {
        // **预热与测量共用同一个 socket。**
        //
        // 原先预热用一个临时 socket、测量再 bind 一个新 socket，于是隧道客户端看到
        // **两个不同的内层对端**。这既不忠实于生产（生产只有一个内层对端），又会在
        // "客户端锁定内层对端"之后让测量阶段的每个数据报都被当成第二个对端拒绝——
        // 表现为到达率塌到 0，看起来像 FEC 回归，实际是测试台自己在换端口。
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind test socket");
        sock.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();

        if pump {
            let end = Instant::now() + Duration::from_secs_f64(warmup_secs);
            let mut i = 0u32;
            while Instant::now() < end {
                let mut p = vec![0xab; payload_size];
                p[..4].copy_from_slice(&i.to_be_bytes());
                let _ = sock.send_to(&p, ("127.0.0.1", self.client_port));
                i = i.wrapping_add(1);
                thread::sleep(Duration::from_millis(8));
            }
        } else {
            thread::sleep(Duration::from_secs_f64(warmup_secs));
        }

        // 预热阶段的回包必须**排空**，否则它们的序号会被计入测量结果而虚高。
        let mut drain = [0u8; 65535];
        while sock.recv_from(&mut drain).is_ok() {}

        // Drain replies concurrently with the sender. Otherwise the host UDP
        // receive queue can overflow while the test is still transmitting,
        // which measures harness drops instead of tunnel behavior.
        let sender = sock.try_clone().expect("clone test socket");
        let client_port = self.client_port;
        let sending = thread::spawn(move || {
            for i in 0..count {
                let mut payload = Vec::with_capacity(payload_size);
                payload.extend_from_slice(&(i as u32).to_be_bytes());
                payload.resize(payload_size, 0xab);
                sender
                    .send_to(&payload, ("127.0.0.1", client_port))
                    .unwrap();
                thread::sleep(gap);
            }
        });

        let mut received = vec![false; count];
        let mut remaining = count;
        let deadline = Instant::now() + Duration::from_secs(12);
        let mut buf = [0u8; 65535];
        while remaining > 0 && Instant::now() < deadline {
            match sock.recv_from(&mut buf) {
                Ok((n, _)) if n >= 4 => {
                    let seq = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                    if seq < count && !received[seq] {
                        received[seq] = true;
                        remaining -= 1;
                    }
                }
                Ok(_) => {}
                Err(_) => {}
            }
        }
        sending.join().expect("sender thread");
        (count - remaining) as f64 / count as f64
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_file(&self.keyring_path);
        thread::sleep(Duration::from_millis(300));
    }
}

#[test]
fn force_parity_recovers_random_loss() {
    // 10% 双向随机丢包。parity=0 的到达率应接近 (1-0.1)^2=81%，
    // parity=2 应显著更高（>90%），证明 FEC 协议本身有效。
    let no_fec = Harness::new(0.10, Some(0)).measure(1000, 1.0, false);
    let with_fec = Harness::new(0.10, Some(2)).measure(1000, 1.0, false);

    eprintln!("no-fec(parity=0)={no_fec:.3}  fec(parity=2)={with_fec:.3}");
    assert!(
        no_fec > 0.75 && no_fec < 0.90,
        "unexpected no-fec arrival {no_fec}"
    );
    assert!(
        with_fec > no_fec + 0.08,
        "FEC should improve arrival substantially: no_fec={no_fec} fec={with_fec}"
    );
}

#[test]
fn adaptive_parity_rises_without_force() {
    // 修复后，10% 丢包下自适应应能自行把 parity 升到 >=1（无需 force），
    // 到达率应明显高于纯无 FEC 基线（~81%）。
    //
    // 阈值 0.83 留了很大余量：实测三次分别为 0.976 / 0.985 / 0.986，基线 0.807。
    // 本文件内的并行竞争已由 `HARNESS_LOCK` 消除；**外部**负载（例如同时编译）仍
    // 会压低到达率，因此一次失败不要当成回归，先空载重跑；真正的回归会稳定失败。
    let h = Harness::new(0.10, None);
    // 12 秒持续流量：debug 构建较慢，需更长预热让自适应 parity 充分升上去。
    let arrival = h.measure(2000, 12.0, true);
    eprintln!("adaptive arrival={arrival:.3}");
    assert!(arrival > 0.83, "adaptive arrival too low: {arrival}");
}

/// 生产报文尺寸下的零丢包到达率。
///
/// 这是"线上字节去哪了"的**责任划分实验**：生产链路上交付效率恒定在
/// 19–27%（8 倍速率范围内无拐点），而载体两端都报零丢包、FEC 序号报
/// `missing=0`。如果本用例在 1200 字节 / 无丢包下到达率接近 1，则 FEC 层
/// 洗清了嫌疑，缺口在载体或上层 TUIC；如果显著低于 1，则问题就在 FEC 层，
/// 且此处可本地复现、可二分。
///
/// 用 1200 字节而不是默认的 100 字节，是因为分片（CHUNK=1326）、成组
/// （DATA_SHARDS=10）、RS 等长填充与 pacer 批量的行为都只在接近 MTU 的
/// 报文尺寸下才显现；100 字节的用例把这些路径全绕开了。
#[test]
fn production_sized_datagrams_survive_zero_loss() {
    let h = Harness::new(0.0, None);
    let arrival = h.measure_with(1000, 1200, Duration::from_millis(1), 1.0, false);
    eprintln!("1200B/zero-loss arrival={arrival:.4}");
    assert!(
        arrival > 0.99,
        "the FEC layer itself must not drop datagrams on a clean link: {arrival}"
    );
}

/// 生产报文尺寸 + 10% 双向丢包 + 自适应 parity。
///
/// 阈值比小报文用例（0.83）更宽松：1200 字节报文的分组更大，突发丢包更容易
/// 打穿一个整组，而分块 RS 对组内连续丢包无能为力（RFC 9265 §2.5 指出可解码
/// 概率取决于"编码窗口大小、编码率与**信道删余的分布**"）。
///
/// 本用例是 `HARNESS_LOCK` 串行化的**直接原因**：并行运行时曾偶发跌破 0.80，
/// 而空载单跑 3/3 通过（每次约 24.4s）。
#[test]
fn production_sized_datagrams_survive_ten_percent_loss() {
    let h = Harness::new(0.10, None);
    let arrival = h.measure_with(1000, 1200, Duration::from_millis(1), 12.0, true);
    eprintln!("1200B/10%-loss adaptive arrival={arrival:.4}");
    assert!(
        arrival > 0.80,
        "adaptive FEC should keep most 1200-byte datagrams across 10% loss: {arrival}"
    );
}

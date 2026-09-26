//! FEC 有效性集成测试（Rust 版）。
//!
//! 启动编译好的 client/server 二进制，中间插入随机丢包 relay，量化
//! Reed-Solomon 在固定 parity 下的应用层恢复能力，并验证自适应修复后
//! parity 能随丢包上升。使用动态端口，测试可并行。

use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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

fn spawn_echo(stop: Arc<AtomicBool>, port: u16) {
    thread::spawn(move || {
        let sock = UdpSocket::bind(("127.0.0.1", port)).expect("bind echo");
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

fn spawn_relay(stop: Arc<AtomicBool>, port: u16, server: SocketAddr, loss: f64, seed: u64) {
    thread::spawn(move || {
        let sock = UdpSocket::bind(("127.0.0.1", port)).expect("bind relay");
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
}

impl Harness {
    fn new(loss: f64, force_parity: Option<usize>, base: u16) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let echo_port = base;
        let server_port = base + 1;
        let relay_port = base + 2;
        let client_port = base + 3;

        let server_addr: SocketAddr = ([127, 0, 0, 1], server_port).into();
        spawn_echo(stop.clone(), echo_port);
        spawn_relay(
            stop.clone(),
            relay_port,
            server_addr,
            loss,
            0x9e37_79b9_7f4a_7c15,
        );

        let mut env_base: Vec<(String, String)> = Vec::new();
        env_base.push(("SMART_FEC_KEY".to_string(), KEY.to_string()));
        env_base.push(("SMART_FEC_KEY_ID".to_string(), "1".to_string()));
        env_base.push(("RUST_LOG".to_string(), "warn".to_string()));
        if let Some(p) = force_parity {
            env_base.push(("SMART_FEC_FORCE_PARITY".to_string(), p.to_string()));
        }

        // V3 模式需要 keyring；权限 0600 以通过 keyring 权限检查。
        let keyring_path =
            std::env::temp_dir().join(format!("sft-test-keyring-{}-{}", std::process::id(), base));
        std::fs::write(&keyring_path, format!("1 {KEY}\n")).expect("write keyring");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&keyring_path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }

        let spawn = |args: &[&str]| {
            Command::new(bin())
                .args(args)
                .envs(env_base.iter().cloned())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn smart-fec-tunnel")
        };

        let server = spawn(&[
            "server",
            "--listen",
            &format!("127.0.0.1:{server_port}"),
            "--upstream",
            &format!("127.0.0.1:{echo_port}"),
            "--keyring",
            keyring_path.to_str().unwrap(),
        ]);
        let client = spawn(&[
            "client",
            "--listen",
            &format!("127.0.0.1:{client_port}"),
            "--server",
            &format!("127.0.0.1:{relay_port}"),
            "--key-id",
            "1",
        ]);

        Self {
            stop,
            children: vec![server, client],
            client_port,
            keyring_path,
        }
    }

    /// 发送 count 个带序号的数据报，返回应用层到达率。
    /// `pump` 为 true 时，预热阶段持续发送数据以驱动 report 闭环、让自适应
    /// parity 先升上去（模拟持续流量），再开始统计。
    fn measure(&self, count: usize, warmup_secs: f64, pump: bool) -> f64 {
        if pump {
            let wsock = UdpSocket::bind("127.0.0.1:0").expect("bind warmup");
            let end = Instant::now() + Duration::from_secs_f64(warmup_secs);
            let mut i = 0u32;
            while Instant::now() < end {
                let mut p = [0xab; PAYLOAD_SIZE];
                p[..4].copy_from_slice(&i.to_be_bytes());
                let _ = wsock.send_to(&p, ("127.0.0.1", self.client_port));
                i = i.wrapping_add(1);
                thread::sleep(Duration::from_millis(8));
            }
        } else {
            thread::sleep(Duration::from_secs_f64(warmup_secs));
        }

        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind test socket");
        // Drain replies concurrently with the sender. Otherwise the host UDP
        // receive queue can overflow while the test is still transmitting,
        // which measures harness drops instead of tunnel behavior.
        sock.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let sender = sock.try_clone().expect("clone test socket");
        let client_port = self.client_port;
        let sending = thread::spawn(move || {
            for i in 0..count {
                let mut payload = Vec::with_capacity(PAYLOAD_SIZE);
                payload.extend_from_slice(&(i as u32).to_be_bytes());
                payload.resize(PAYLOAD_SIZE, 0xab);
                sender
                    .send_to(&payload, ("127.0.0.1", client_port))
                    .unwrap();
                thread::sleep(Duration::from_millis(1));
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
    let no_fec = Harness::new(0.10, Some(0), 15555).measure(1000, 1.0, false);
    let with_fec = Harness::new(0.10, Some(2), 15555).measure(1000, 1.0, false);

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
    // 注意本用例对时序敏感——注入丢包的 pump 间隔固定，机器负载高（例如同时在进行
    // 编译）时到达率会掉到阈值以下，曾观测到过一次失败而紧接着三次通过。因此**不要
    // 把它的一次失败当成回归**，先空载重跑；真正的回归会稳定失败。
    let h = Harness::new(0.10, None, 25555);
    // 12 秒持续流量：debug 构建较慢，需更长预热让自适应 parity 充分升上去。
    let arrival = h.measure(2000, 12.0, true);
    eprintln!("adaptive arrival={arrival:.3}");
    assert!(arrival > 0.83, "adaptive arrival too low: {arrival}");
}

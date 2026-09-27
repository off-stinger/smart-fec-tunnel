//! 综合审计用：锁住"二进制读取的环境变量"与"路由器 init 转发"之间的耦合。
//!
//! 起因是 T5 综合审计发现的真实缺口：T3 引入了 `SMART_QUIC_MAX_RATE_MBPS`，
//! 但路由器 init 没有转发它，在 `/etc/smart-fec-quic.env` 里设置会被**静默忽略**。
//!
//! 之后的演进（每一版都是被一次真实事故推着走的）：
//!
//! 1. 只扫 `src/quic_relay.rs` → `SMART_FEC_MAX_PARITY` 加在 `main.rs`，扫不到；
//! 2. 改成硬编码的两项清单 → 新增第三个源文件仍会漏；
//! 3. 改成运行时枚举 `src/**/*.rs` → 覆盖面够了；
//! 4. **但仍然给出过假保证**：它只检查"变量名出现在 init 文本里"，而路由器上有**两个**
//!    独立的 init——`openwrt-smart-fec-quic.init`（启动**载体** `quic-client`）与
//!    `openwrt-install.sh` 里生成的 `/etc/init.d/smart-fec-client`（启动**FEC 层**
//!    `client`）。当时把 `SMART_FEC_MAX_PARITY` / `SMART_FEC_INTERLEAVE` 转发进了**载体**
//!    init，而载体不读它们，真正读它们的 FEC client 一个都没拿到——本用例却**通过**了。
//!    实测确认：路由器上 `smart-fec-tunnel client` 的 `/proc/<pid>/environ` 里
//!    只有 `SMART_FEC_KEY` 与 `RUST_LOG`。
//!
//! 因此现在按**读取该变量的源文件**决定它必须出现在哪个 init 里：
//!
//! * `src/quic_relay.rs`（载体）→ `deploy/openwrt-smart-fec-quic.init`
//! * `src/main.rs`（FEC 层）→ `deploy/openwrt-install.sh` 生成的 FEC client init
//!
//! 这条映射正是"配置到底有没有到达读它的那个进程"的答案，也是本用例唯一想守住的东西。
//!
//! 仍然存在的局限（诚实标注）：以变量形式传名的读取（例如
//! `std::env::var(ADDRESS_VALIDATION_ENV)`、`std::env::var(INTERLEAVE_ENV)`）以及 clap 的
//! `#[arg(env = "...")]`（例如 `SMART_FEC_KEY`）不会被字面量扫描扫到。
//! `CONST_NAMED` 为已知的常量名读取单独兜底——`SMART_FEC_INTERLEAVE` 就属于这一类，
//! 而它**真的**漏过一次。

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// 变量由哪个进程读取，决定它必须被哪个 init 转发。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owner {
    /// 载体（`quic-client`），由 `deploy/openwrt-smart-fec-quic.init` 启动。
    Carrier,
    /// FEC 层（`client`），由 `deploy/openwrt-install.sh` 生成的 init 启动。
    FecClient,
}

/// 每个源文件里读的变量归哪个进程；第二个元素是**扫描自检**下限。
///
/// 覆盖面由运行时枚举保证；下限只是让"扫描失效"必然失败。
const SCANNED: &[(&str, usize, Owner)] = &[
    ("src/quic_relay.rs", 4, Owner::Carrier),
    // SMART_FEC_MAX_PARITY / SMART_FEC_TRAFFIC_LOG / SMART_FEC_FORCE_PARITY
    ("src/main.rs", 3, Owner::FecClient),
];

/// 二进制会读、但**有意不**由路由器 init 转发的变量，附理由。
///
/// 这份名单受 `not_forwarded_list_only_contains_variables_the_binary_reads` 审计：
/// 曾在此列出的 `SMART_QUIC_UPSTREAM` 早已改成 clap 的 `--upstream` 参数、不再是
/// 环境变量，属于名单腐烂，已删除。
const NOT_FORWARDED: &[(&str, &str)] = &[
    (
        "SMART_QUIC_ADDRESS_VALIDATION",
        "只在 run_server 的 accept 循环里读，属于服务端行为",
    ),
    (
        "SMART_QUIC_REQUIRE_TRUSTED_CERT",
        "只在 audit_server_certificate 里读，属于服务端行为",
    ),
    (
        "SMART_FEC_FORCE_PARITY",
        "诊断/受控实验用，由服务端 systemd EnvironmentFile 提供",
    ),
];

/// 按常量名读取、因此扫不到的变量：必须在这里显式列出并单独校验。
const CONST_NAMED: &[(&str, Owner)] = &[("SMART_FEC_INTERLEAVE", Owner::FecClient)];

const MANIFEST: &str = env!("CARGO_MANIFEST_DIR");
const MARKER: &str = "std::env::var(\"SMART_";

fn read(relative: &str) -> String {
    fs::read_to_string(format!("{MANIFEST}/{relative}"))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

/// 该 owner 对应的 init 文本与用于报错的可读名字。
///
/// FEC client 的 init 在仓库里并不存在——它是 `deploy/openwrt-install.sh` 用 heredoc
/// 生成的，所以校验对象是**安装脚本**。
fn owner_init(owner: Owner) -> (&'static str, String) {
    match owner {
        Owner::Carrier => (
            "deploy/openwrt-smart-fec-quic.init",
            read("deploy/openwrt-smart-fec-quic.init"),
        ),
        Owner::FecClient => (
            "deploy/openwrt-install.sh (FEC client init heredoc)",
            read("deploy/openwrt-install.sh"),
        ),
    }
}

/// 运行时枚举 `src/` 下的全部 `.rs`（含 `src/bin/`）。
fn discovered_sources() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(Path::new(MANIFEST).join("src").as_path(), &mut out);
    out.sort();
    out
}

/// 抽出一个源文件里所有 `std::env::var("<name>")` 字面量的变量名。
fn scanned_names(source: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for line in source.lines() {
        let Some(start) = line.find(MARKER) else {
            continue;
        };
        let rest = &line[start + "std::env::var(\"".len()..];
        let Some(end) = rest.find('"') else {
            continue;
        };
        names.insert(rest[..end].to_string());
    }
    names
}

/// 每个变量都必须出现在**读取它的那个进程**的 init 里。
#[test]
fn every_env_var_reaches_the_init_that_launches_the_process_reading_it() {
    let exempt: BTreeSet<&str> = NOT_FORWARDED.iter().map(|(name, _)| *name).collect();

    let mut checked = 0usize;
    let mut missing: Vec<String> = Vec::new();
    for (path, floor, owner) in SCANNED {
        let found = scanned_names(&read(path));
        assert!(
            found.len() >= *floor,
            "scan of {path} found only {found:?} (expected >= {floor}); the scan itself is broken"
        );
        let (target, text) = owner_init(*owner);
        for name in &found {
            if exempt.contains(name.as_str()) {
                continue;
            }
            checked += 1;
            if !text.contains(name.as_str()) {
                missing.push(format!("{name} (read by {path}) 未在 {target} 中转发"));
            }
        }
    }
    // 常量名读取的变量扫不到，但同样必须到达正确的进程。
    for (name, owner) in CONST_NAMED {
        checked += 1;
        let (target, text) = owner_init(*owner);
        if !text.contains(name) {
            missing.push(format!("{name} 未在 {target} 中转发"));
        }
    }

    // 一个恒真的守卫比没有守卫更糟：必须真的检查过东西。
    assert!(checked >= 6, "only {checked} variables were checked");
    assert!(
        missing.is_empty(),
        "配置无法到达读取它的进程（在 env 文件里设置会被静默忽略）：{missing:#?}"
    );
}

/// `SMART_FEC_INTERLEAVE` 是常量名读取的，字面量扫描扫不到它。
///
/// 这条用例的存在理由是它**真的**漏过一次：它曾被转发进载体 init，而载体不读它，
/// 真正读它的 FEC client 从未拿到——部署守卫当时通过。现在单独钉住它。
#[test]
fn interleave_is_forwarded_to_the_fec_client_process() {
    let fec_init = read("deploy/openwrt-install.sh");
    assert!(
        fec_init.contains("SMART_FEC_INTERLEAVE"),
        "SMART_FEC_INTERLEAVE 由 main.rs（FEC client）读取，但生成的 \
         /etc/init.d/smart-fec-client 没有转发它，于是在 /etc/smart-fec.env 里设置它\
         会被静默忽略"
    );
    let carrier_init = read("deploy/openwrt-smart-fec-quic.init");
    assert!(
        !carrier_init.contains("SMART_FEC_INTERLEAVE"),
        "载体不读 SMART_FEC_INTERLEAVE；把它转发到载体 init 正是当初的缺陷"
    );
}

/// FEC 层变量不得再出现在载体 init 里——那正是"看似生效、实际无效"的来源。
#[test]
fn fec_layer_vars_are_not_forwarded_to_the_carrier() {
    let carrier_init = read("deploy/openwrt-smart-fec-quic.init");
    for name in ["SMART_FEC_TRAFFIC_LOG", "SMART_FEC_MAX_PARITY"] {
        assert!(
            !carrier_init.contains(name),
            "{name} 由 main.rs（FEC 层）读取，载体不读它；把它转发到载体 init 会让配置\
             看起来生效，却从未到达读取它的进程"
        );
    }
}

/// 豁免名单本身也要被审计：写进 `NOT_FORWARDED` 的变量必须仍然被二进制提及。
///
/// 判据是"在源码里出现过带引号的字面量"，而不是"被扫描到"：服务端专用的几项是
/// 以常量传名的（`std::env::var(ADDRESS_VALIDATION_ENV)`），扫描扫不到，但常量
/// 定义里仍有 `"SMART_QUIC_ADDRESS_VALIDATION"` 这个字面量。
#[test]
fn not_forwarded_list_only_contains_variables_the_binary_reads() {
    let mut sources = String::new();
    for path in discovered_sources() {
        sources.push_str(&fs::read_to_string(&path).unwrap_or_default());
    }

    let stale: Vec<&str> = NOT_FORWARDED
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| !sources.contains(&format!("\"{name}\"")))
        .collect();

    assert!(
        stale.is_empty(),
        "NOT_FORWARDED 里的 {stale:?} 已不再出现在被扫描源码中，请删除以免名单腐烂"
    );
}

/// 枚举必须真的覆盖到已知有读取的文件——否则"运行时发现"可能悄悄变成空集，
/// 而上面两个用例都会因为缺少输入而通过。
#[test]
fn discovery_reaches_the_files_known_to_read_env_vars() {
    let found: BTreeSet<String> = discovered_sources()
        .iter()
        .map(|p| {
            p.strip_prefix(MANIFEST)
                .unwrap_or(p)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    for (name, _, _) in SCANNED {
        assert!(
            found.contains(*name),
            "discovery missed {name}; the guard is no longer looking where the reads are"
        );
    }
}

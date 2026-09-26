//! 综合审计用：锁住"二进制读取的环境变量"与"路由器 init 转发"之间的耦合。
//!
//! 起因是 T5 综合审计发现的真实缺口：T3 引入了 `SMART_QUIC_MAX_RATE_MBPS`，
//! 但 `deploy/openwrt-smart-fec-quic.init` 没有转发它。在
//! `/etc/smart-fec-quic.env` 里设置这个变量会被**静默忽略**——没有任何日志、
//! 没有任何报错，只是行为与预期不符。这与上一轮修掉的 procd `env` 覆盖问题
//! 属于同一类"静默配置丢失"，而人手审查显然漏掉了它。
//!
//! 本用例最初的扫描范围只有 `src/quic_relay.rs`，并在注释里"诚实标注"了这个
//! 局限。**该局限随后就命中了**：`SMART_FEC_MAX_PARITY` 加在 `src/main.rs`，
//! 于是它可以被设置、被静默忽略，而本用例不响。所以现在扫描 `src/` 下所有
//! 读取 `std::env::var("SMART_...")` 字面量的源文件，并对每个文件断言它至少
//! 被扫出 N 个变量——**扫描本身失效时必须失败，而不是空过**。
//!
//! 仍然存在的局限（诚实标注）：以变量形式传名的读取（例如
//! `std::env::var(ADDRESS_VALIDATION_ENV)`）以及 clap 的 `#[arg(env = "...")]`
//! （例如 `SMART_FEC_KEY`，由 clap 读）不会被扫到。后者当前由 init 行 30 的
//! 显式拼接覆盖，但没有自动守卫。

use std::collections::BTreeSet;
use std::fs;

/// 扫描范围：(源文件, 该文件至少要扫出的变量个数)。
///
/// 个数下限是**扫描自检**：正则/写法一旦变化导致扫不到东西，用例必须失败。
const SCANNED: &[(&str, usize)] = &[
    ("src/quic_relay.rs", 4),
    // SMART_FEC_MAX_PARITY / SMART_FEC_TRAFFIC_LOG / SMART_FEC_FORCE_PARITY
    ("src/main.rs", 3),
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
        "诊断/受控实验用，由服务端 systemd EnvironmentFile 提供；\
         路由器上若需要应显式加入 init，而不是靠继承",
    ),
];

const MANIFEST: &str = env!("CARGO_MANIFEST_DIR");
const MARKER: &str = "std::env::var(\"SMART_";

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

#[test]
fn openwrt_init_forwards_every_client_side_env_var() {
    let init = fs::read_to_string(format!("{MANIFEST}/deploy/openwrt-smart-fec-quic.init"))
        .expect("read openwrt init");

    let mut names = BTreeSet::new();
    for (path, floor) in SCANNED {
        let source = fs::read_to_string(format!("{MANIFEST}/{path}"))
            .unwrap_or_else(|error| panic!("read {path}: {error}"));
        let found = scanned_names(&source);
        // 一个恒真的守卫比没有守卫更糟：扫描失效必须在这里失败。
        assert!(
            found.len() >= *floor,
            "scan of {path} found only {found:?} (expected >= {floor}); the scan itself is broken"
        );
        names.extend(found);
    }

    let exempt: BTreeSet<&str> = NOT_FORWARDED.iter().map(|(name, _)| *name).collect();
    let missing: Vec<&String> = names
        .iter()
        .filter(|name| !exempt.contains(name.as_str()) && !init.contains(name.as_str()))
        .collect();

    assert!(
        missing.is_empty(),
        "路由器 init 未转发 {missing:?}；在 /etc/smart-fec-quic.env 里设置它们会被静默忽略"
    );
}

/// 豁免名单本身也要被审计：写进 `NOT_FORWARDED` 的变量必须仍然被二进制**提及**，
/// 否则名单会腐烂成一张永远无人核对的清单。
///
/// 判据是"在源码里出现过带引号的字面量"，而不是"被扫描到"：服务端专用的几项是
/// 以常量传名的（`std::env::var(ADDRESS_VALIDATION_ENV)`），扫描扫不到，但常量
/// 定义里仍有 `"SMART_QUIC_ADDRESS_VALIDATION"` 这个字面量。
#[test]
fn not_forwarded_list_only_contains_variables_the_binary_reads() {
    let mut sources = String::new();
    for (path, _) in SCANNED {
        let source = fs::read_to_string(format!("{MANIFEST}/{path}"))
            .unwrap_or_else(|error| panic!("read {path}: {error}"));
        sources.push_str(&source);
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

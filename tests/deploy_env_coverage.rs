//! 综合审计用：锁住"二进制读取的环境变量"与"路由器 init 转发"之间的耦合。
//!
//! 起因是 T5 综合审计发现的真实缺口：T3 引入了 `SMART_QUIC_MAX_RATE_MBPS`，
//! 但 `deploy/openwrt-smart-fec-quic.init` 没有转发它。在
//! `/etc/smart-fec-quic.env` 里设置这个变量会被**静默忽略**——没有任何日志、
//! 没有任何报错，只是行为与预期不符。这与上一轮修掉的 procd `env` 覆盖问题
//! 属于同一类"静默配置丢失"，而人手审查显然漏掉了它。
//!
//! 扫描范围与局限（诚实标注）：本用例只扫描 `src/quic_relay.rs` 中写成
//! `std::env::var("SMART_...")` 字面量的读取点。以变量形式传名的读取
//! （例如 `std::env::var(ADDRESS_VALIDATION_ENV)`）不会被扫到；那几处是
//! 服务端专用，本来也不该出现在客户端 init 里。新增客户端侧环境变量若采用
//! 字面量读取，本用例即可拦住。

use std::collections::BTreeSet;
use std::fs;

/// 二进制会读、但**有意不**由路由器 init 转发的变量，附理由。
const NOT_FORWARDED: &[(&str, &str)] = &[
    (
        "SMART_QUIC_UPSTREAM",
        "服务端 unit 通过 ExecStart 的 --upstream 与 EnvironmentFile 提供",
    ),
    (
        "SMART_QUIC_ADDRESS_VALIDATION",
        "只在 run_server 的 accept 循环里读，属于服务端行为",
    ),
    (
        "SMART_QUIC_REQUIRE_TRUSTED_CERT",
        "只在 audit_server_certificate 里读，属于服务端行为",
    ),
];

#[test]
fn openwrt_init_forwards_every_client_side_env_var() {
    let source = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/quic_relay.rs"))
        .expect("read quic_relay.rs");
    let init = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/deploy/openwrt-smart-fec-quic.init"
    ))
    .expect("read openwrt init");

    let marker = "std::env::var(\"SMART_";
    let mut names = BTreeSet::new();
    for line in source.lines() {
        let Some(start) = line.find(marker) else {
            continue;
        };
        let rest = &line[start + "std::env::var(\"".len()..];
        let Some(end) = rest.find('"') else {
            continue;
        };
        names.insert(rest[..end].to_string());
    }
    // 若扫描本身失效（比如读取方式被重构），本用例必须失败而不是空过——
    // 一个恒真的守卫比没有守卫更糟。
    assert!(
        names.len() >= 4,
        "env-var scan found only {names:?}; the scan itself is broken"
    );

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

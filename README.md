# Smart FEC Tunnel

面向 OpenWrt 旁路由与 Linux 服务端的 TUIC 外层 FEC、限速整形和多 WARP 分流方案。`0.2.0-alpha.4` 使用 FEC V3 加密信封和 MTU 安全的动态 shard：公网不再暴露固定魔数及 FEC 元数据，典型 QUIC 数据报无需二次分片，小包也不再固定填充至统一长度；冷启动从零冗余开始，避免在限速链路上由投机冗余触发拥塞雪崩。项目不修改 sing-box/TUIC 源码。

## 数据路径

```text
Passwall -> TUIC -> smart-fec client (OpenWrt)
          -> UDP/443 FEC -> smart-fec server (Linux)
          -> 127.0.0.1:4443 sing-box TUIC inbound
          -> TCP: WARP A/B/C 按连接负载
          -> UDP: 默认稳定 WARP B
```

TCP/443 可继续由现有 Reality/VLESS 使用，FEC 服务只占用 UDP/443。所有内部 TUIC、mixed worker 和负载端口仅监听回环地址。

## 功能

- 认证报文、FEC 丢包恢复、乱序窗口和内存上限
- FEC V2 每设备 `key_id`、独立密钥、独立会话与上游 socket；服务端会话总量及单设备数量有界
- FEC V3 使用 XChaCha20-Poly1305 加密全部内部元数据，外层只保留不透明密钥选择器和随机 nonce
- 默认按服务端 30 Mbps 峰值整形，避免 UDP 突发
- 三路 WARP 是按 TCP 连接负载，不是 urltest 择优，也不复制业务请求
- Google 搜索可固定走服务器稳定公网，规避共享 WARP IP 被 Google 错标为中国地区
- sing-box 无损合并：保留 Reality/VLESS、DNS 和非托管路由
- 部署前配置校验、原子替换、启动失败自动回滚
- Debian/systemd、OpenWrt/procd 一键安装

## 一键部署

先复制并填写 [`configs/sing-box-deployment.example.json`](configs/sing-box-deployment.example.json)。该文件含 TUIC 密码、UUID 和 WARP 私钥，必须保存在 Git 仓库之外。

```powershell
.\deploy\deploy-all.ps1 `
  -Server root@203.0.113.10 `
  -OpenWrt root@192.0.2.1 `
  -ServerIdentityFile C:\keys\server.pem `
  -Binary .\smart-fec-tunnel-linux-amd64 `
  -ServerEndpoint 203.0.113.10:443 `
  -FecKey '<至少32字符随机密钥>' `
  -FecKeyId 1 `
  -SingBoxSpec C:\secure\sing-box-deployment.json `
  -StableGoogleEgress `
  -RateMbps 30
```

执行顺序是：备份并合并服务端 sing-box、校验并重启、安装服务端 FEC/WARP balancer、安装 OpenWrt 客户端。任何 sing-box 激活故障都会恢复备份。脚本不会自动切换 Passwall 节点，避免部署途中切断管理链路。

如果省略 `-SingBoxSpec`，脚本只更新 FEC 组件并明确告警，sing-box 不会被修改。完整说明见 [`docs/DEPLOYMENT.zh-CN.md`](docs/DEPLOYMENT.zh-CN.md)。

产品能力、默认策略、接入与验收边界见 [`docs/PRODUCT-MANUAL.zh-CN.md`](docs/PRODUCT-MANUAL.zh-CN.md)；运营商网络与 GFW 场景的优势、限制和隐私模型见 [`docs/PRIVACY-AND-NETWORK.zh-CN.md`](docs/PRIVACY-AND-NETWORK.zh-CN.md)。

`-StableGoogleEgress` 会安装每日自动维护器：从 Google 官方 `goog.json` 中扣除 `cloud.json` 的客户网段，只在服务网段实际变化且候选配置校验成功时更新并重启 sing-box；失败时自动回滚。

## 构建与测试

```sh
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo test
python3 -m unittest tests/test_sing_box_merge.py
cargo build --release --target x86_64-unknown-linux-musl
SMART_FEC_BIN=./target/x86_64-unknown-linux-musl/release/smart-fec-tunnel python3 tests/integration_loopback.py
SMART_FEC_BIN=./target/x86_64-unknown-linux-musl/release/smart-fec-tunnel python3 tests/integration_multiuser.py
```

## 安全

不要提交实际的 `.env`、证书、TUIC 凭据、WARP 私钥或 GitHub Token。部署规范会以 `0600` 保存到服务端 `/etc/smart-fec/sing-box-deployment.json`，每次 sing-box 变更都会备份到 `/root/smart-fec-sing-box-backup-*`。

生产部署前应撤销曾经出现在聊天或终端历史中的凭据并重新生成。

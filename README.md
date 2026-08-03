# Smart FEC Tunnel

面向高丢包 UDP 链路的 TUIC sidecar：在不修改 TUIC 和 sing-box 源码的前提下，为外层 UDP增加认证、自适应 Reed-Solomon FEC、均匀发包和多 WARP TCP负载分配。

项目适合 OpenWrt/ImmortalWrt 旁路由、ESXi虚拟化路由、海外轻量服务器及存在随机丢包的跨境链路。所有服务均可使用独立端口和凭据，因此可以复刻到多条线路并行运行。

## 功能

- 系统码 Reed-Solomon FEC：原始数据立即发送，校验片只用于恢复丢片。
- 自适应冗余：根据平滑丢包反馈在 0–3 个校验片之间调整，带迟滞避免频繁抖动。
- 认证封装：每帧使用 keyed BLAKE3标签，错误密钥和被篡改报文会被丢弃。
- TUIC报文分片/重组：支持空 UDP报文与最大 64分片，带内存上限和过期清理。
- 重排窗口：64序列窗口避免把乱序误判为丢包。
- 低突发整形：默认 30 Mbps，按约4ms调度窗口批量补充令牌。
- 多 WARP TCP负载：每个新 TCP连接轮询分配到 A/B/C，连接生命周期内固定出口。
- WARP健康检查和建连失败重试；UDP可固定到单个稳定 WARP。
- Debian/systemd 与 OpenWrt/procd 一键安装、备份和卸载。
- Windows PowerShell跨两端编排，兼容不提供SFTP的OpenWrt Dropbear。
- 强制丢片集成测试，检测恢复失败与重复包。

## 架构

```text
LAN / Passwall
      |
      | TUIC -> 127.0.0.1:3333/udp
      v
smart-fec client (OpenWrt)
      |
      | authenticated FEC / UDP 443
      v
smart-fec server (Linux)
      |
      | 127.0.0.1:4443/udp
      v
sing-box TUIC inbound
      |
      +-- TCP -> 127.0.0.1:18080 -> round robin -> WARP A / B / C
      `-- UDP ------------------------------------> stable WARP B
```

TCP 443可以继续由 Reality/VLESS占用；SMARTFEC仅使用 UDP 443。内层 TUIC与三个 WARP worker只监听回环地址，避免绕过FEC认证或暴露本地 SOCKS端口。

## 快速开始

### 1. 构建

```sh
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release --target x86_64-unknown-linux-musl
SMART_FEC_BIN=./target/x86_64-unknown-linux-musl/release/smart-fec-tunnel \
  python3 tests/integration_loopback.py
```

### 2. 准备 sing-box

参考 [`configs/sing-box-server.example.json`](configs/sing-box-server.example.json)，将TUIC、三个WARP endpoint、三个 loopback mixed worker和路由规则合并到自己的配置。模板中的所有 `REPLACE_*` 都必须替换。

```sh
sing-box check -c /etc/sing-box/config.json
```

### 3. 一键部署

```powershell
.\deploy\deploy-all.ps1 `
  -Server root@203.0.113.10 `
  -OpenWrt root@192.0.2.1 `
  -ServerIdentityFile C:\keys\server.pem `
  -Binary .\dist\smart-fec-tunnel-linux-amd64 `
  -ServerEndpoint 203.0.113.10:443 `
  -FecKey '<至少32字符的随机密钥>' `
  -RateMbps 30
```

脚本会备份旧服务并安装两端组件，但故意不自动切换 Passwall主节点。完整步骤、验收和回滚见 [`docs/DEPLOYMENT.zh-CN.md`](docs/DEPLOYMENT.zh-CN.md)。

## 命令

```sh
smart-fec-tunnel client \
  --listen 127.0.0.1:3333 --server SERVER:443 --rate-mbps 30

smart-fec-tunnel server \
  --listen 0.0.0.0:443 --upstream 127.0.0.1:4443 --rate-mbps 30

smart-fec-tunnel balance \
  --listen 127.0.0.1:18080 \
  --upstream 127.0.0.1:18101 127.0.0.1:18102 127.0.0.1:18103
```

密钥可以通过 `SMART_FEC_KEY`环境变量提供。生产环境不要把密钥放在命令行参数、Git仓库或公开日志中。

## 多 WARP语义

这里的“多线负载”不是urltest择优，也不会复制同一个请求：

- TCP以连接为负载单位，按轮询分配。
- 已建立连接不会中途切换 WARP。
- SOCKS CONNECT失败时才安全重试其他 worker。
- 建连成功后不能盲目重放业务数据，否则可能重复非幂等请求。
- 三条逻辑 WARP仍共享服务器物理网卡和公网带宽。
- 推荐每个 WARP endpoint使用独立账户/私钥/隧道地址，避免共享身份导致出口状态耦合。

## 可靠性设计

- 完成的FEC组保留短期 tombstone，阻止迟到校验片导致重复交付。
- 组表、重组表和分片数量均有硬限制，避免恶意报文耗尽内存。
- 短暂 UDP错误只记录告警，不终止主循环。
- 首个高序列号建立基线，重启后不会把历史序列误计为丢包。
- 4ms令牌桶批次适配常见 OpenWrt内核调度粒度，避免亚毫秒 sleep被放大。

## 测试范围

单元测试覆盖认证、篡改拒绝、FEC恢复、乱序、真实丢包结算、自适应迟滞、高序列基线与空报文。集成测试在双向链路中对每个FEC组固定丢弃0号数据片，连续验证400个报文、最大8196字节，并拒绝重复交付。

## 限制

- FEC会消耗额外带宽；高丢包时有效载荷吞吐必然低于外层速率。
- 它修复随机丢包，不能修复目标网站对某个 WARP出口不可达。
- WARP健康探测只代表探测目标可达，不代表所有网站都可达。
- 跨大版本升级 OpenWrt/ImmortalWrt前，应先验证二进制架构和依赖。

## 仓库安全

`.gitignore`默认排除 `.env`、密钥、证书和构建产物。提交前仍应运行：

```sh
rg -n -i 'password|private.key|secret|token|ghp_|uuid' .
```

如果凭据曾进入聊天、终端历史或Git历史，应立即吊销并重新生成，仅从Git历史删除文件并不足够。


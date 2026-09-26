# Smart Gateway 第一版产品说明书

> 文档状态：第一版产品设计基线
> 当前仓库版本：`smart-fec-tunnel 0.2.0-alpha.9`
> 适用对象：部署管理员、OpenWrt/Passwall 用户、Windows/v2rayN 用户、开发与测试人员

## 1. 产品目标

Smart Gateway 的目标是把弱网恢复、加密代理、多出口调度和多用户管理收敛成一个易部署、易接入、可诊断、可回滚的网络产品。用户选择使用场景，系统负责协议、端口、依赖、健康检查和失败恢复。

第一版遵循四项原则：

1. 服务端以 Rust Controller 为最终控制核心，Shell 仅作为下载和启动引导。
2. 每台设备具有独立身份和凭据；用户、设备与会话相互隔离。
3. 所有变更先生成计划并验证，成功后原子生效，失败自动回滚。
4. Passwall 和 v2rayN 是接入适配器，不是服务端状态的权威来源。

本产品不承诺消除所有丢包、不保证绕过任何网络管控，也不能突破服务器、接入链路或上游出口的物理带宽上限。

## 2. 版本状态说明

本文用以下标记避免把路线图误认为现成功能：

- **已实现**：当前仓库中存在代码或部署流程，并有相应测试。
- **第一版目标**：本轮产品化需要交付，但当前尚未全部实现。
- **后续规划**：不属于第一版承诺，必须经过实验和安全评审后再进入生产。
- **实验功能**：默认关闭，不提供生产稳定性承诺。

### 2.1 当前能力矩阵

| 能力 | 状态 | 当前边界 |
|---|---|---|
| Rust FEC 客户端/服务端 | 已实现 | V3 AEAD 加密信封、Reed-Solomon FEC、乱序与内存上限；V1/V2 仅用于迁移 |
| UDP 速率整形 | 已实现 | 通过 `--rate-mbps` 配置；不是完整公平调度器 |
| WARP TCP 按连接调度 | 已实现 | 健康优先，按活跃连接数和 `www.gstatic.com:443` TCP 探测 EWMA 延迟排序；连续 2 次失败下线、2 次成功恢复，单条 TCP 流固定在已选出口，不叠加带宽 |
| UDP 稳定 WARP | 已实现于 sing-box 示例 | 默认固定到 `warp-b`，不是动态健康决策 |
| sing-box 无损合并 | 已实现 | 按托管 tag 合并并保留非托管配置 |
| sing-box 校验与失败回滚 | 已实现 | 候选配置检查、原子替换、启动失败恢复 |
| Google 稳定出口规则维护 | 已实现 | 可选安装；依赖官方网段数据和 GeoIP 现实差异 |
| OpenWrt/procd 安装 | 已实现 | 安装本地 FEC 客户端，不自动切换 Passwall 主节点 |
| PowerShell 双端编排 | 已实现 | 需管理员准备二进制、密钥和私密 sing-box 规范 |
| 多用户、多设备 | Alpha 已实现 | FEC V2 每设备密钥、独立会话与独立上游 socket；尚无用户级公平队列和在线撤销 |
| Rust Controller/事务 Revision | Alpha 骨架 | 已有类型化 Profile、只读端口规划、候选验证与 Revision 回滚原语；部署适配仍在脚本中 |
| Passwall 自动创建节点 | 第一版目标 | 当前需手工把 TUIC 指向本地 FEC 入口 |
| Windows Agent/v2rayN 导入 | 第一版目标 | 当前未实现 |
| QUIC 可靠有序载体 | Alpha 实验能力 | 两端显式设置 `SMART_QUIC_STREAM_LANES=1`；直接承载 TUIC 时旁路 FEC，避免双重恢复；部署模板默认仍为 DATAGRAM，需先完成目标网络验收 |
| 自适应 FEC、PMTU | Alpha 已实现（有限闭环） | FEC 反馈区分序列缺口与按窗口对齐的重建符号，获益样本会阻止 parity 过早降档；QUIC PMTU 动态分片已实现；参数仍须按真实链路验收 |
| 内核能力检测与自动调优 | 第一版目标 | 当前未实现 |
| MASQUE | 后续实验 | 当前未实现，默认关闭 |
| DoQ | 后续实验 | 当前未实现，不能替代现有 DoH 默认链路 |
| ODoH/隐私分区 | 后续规划 | 需要独立代理和解析目标，当前未实现 |

## 3. 当前数据路径

```text
Passwall / 本地代理
  -> TUIC 客户端
  -> OpenWrt smart-fec client (127.0.0.1:3333)
  -> 认证 FEC UDP/443
  -> Linux smart-fec server
  -> sing-box TUIC inbound (127.0.0.1:4443)
  -> TCP: WARP A/B/C 按新连接分配
  -> UDP: 稳定 WARP B
  -> 特定 Google 服务: 可选服务器稳定公网出口
```

TCP/443 可以继续提供现有 Reality/VLESS；Smart FEC 默认使用 UDP/443。内部端口应只监听回环，不应开放到公网。

实测发现，将 TUIC 依次嵌套在 FEC 与不可靠 QUIC DATAGRAM 中会放大重传和错误序号缺口。可靠有序载体作为可选实验模式：OpenWrt QUIC 客户端监听 Passwall 指向的本地端口，服务端 QUIC 直接转发到 sing-box TUIC 入站，中间 FEC 进程保持停用。该模式必须两端一致配置并先在备用线路验收；systemd 模板默认 DATAGRAM，不代表可靠流模式已是所有网络的稳定生产默认值。

```text
OpenWrt: SMART_QUIC_LOCAL_PORT=3333
两端:    SMART_QUIC_STREAM_LANES=1
服务端:  SMART_QUIC_UPSTREAM=127.0.0.1:4443
```

多条可靠流的轮询实验会造成 TUIC 报文深度乱序，当前版本明确拒绝大于 `1` 的通道数。DATAGRAM+FEC 作为兼容/实验路径保留，但不再是本环境的推荐默认路径。

监测中必须区分 QUIC 协议栈确认的 `wire_loss_ppm` 与 FEC 层的 `sequence_gap_ppm`。后者是经过重排序窗口结算的 SFT 帧缺口，可能包括数据、冗余或反馈帧，不能称为公网物理丢包率；`fec_recovered_symbols`/`fec_recovered_groups` 是独立的 FEC 重建结果。新反馈仍接受旧版 4 字节 loss 报告；旧版端点会忽略新版扩展反馈，所以要使用恢复收益自适应必须两端都升级。少于 100 个已发送 QUIC 包的窗口不计算 QUIC 丢包百分比，只保留原始包数。

## 4. 第一版产品架构

第一版目标拆分为低频控制面和高频数据面：

```text
smart-gateway-controller
  配置、身份、模块、端口、部署、升级、回滚、诊断
            |
            | 经过验证的期望状态
            v
smart-gateway-dataplane
  多用户 FEC、会话、批量 UDP、pacing、公平调度、实时指标
            |
            +-> sing-box / TUIC
            +-> Direct / WARP 出口池
```

建议服务端仅保留一个权威配置 `/etc/smart-gateway/config.yaml`；用户、设备、策略和 Revision 保存到 SQLite。生成的 sing-box JSON、systemd unit 和防火墙规则属于派生状态，不能由多个入口分别维护。

## 5. 场景预设与模块默认值

普通用户不直接面对全部开关，而是选择预设。管理员可在高级模式中覆盖单项。

### 5.1 预设

| 预设 | 适用场景 | 默认组合 |
|---|---|---|
| 标准稳定 | 普通自托管 | TUIC、FEC Auto、PMTU、Direct、DoH/DoT |
| 跨境增强（推荐） | 多出口及弱网 | TUIC、FEC Auto、PMTU、多 WARP、稳定 UDP、稳定 Google 出口 |
| 低资源 | 小内存或低核设备 | 少 worker、Direct、轻量指标、FEC Auto |
| 实验室 | 技术验证 | 可开启 MASQUE/DoQ/详细 trace；不作为生产默认 |

### 5.2 模块默认策略

| 模块 | 建议默认 | 说明 |
|---|---:|---|
| TUIC | 开启 | 第一版生产传输 |
| Adaptive FEC | Auto | 第一版需实现闭环；当前版本为固定算法参数 |
| PMTU 探测 | 开启 | 第一版需实现，避免分片和 MTU 黑洞 |
| Direct 出口 | 开启 | 基础出口与明确配置的回退路径 |
| Multi-WARP | Auto | 只有凭据完整、检查通过时启用 |
| UDP 稳定出口 | 开启 | 已建立 UDP 会话不跨出口迁移 |
| Google 稳定出口 | Auto | 启用多 WARP 时建议开启，可单独关闭 |
| DoH | 开启 | 默认远程加密 DNS |
| DoT | 备用 | DoH 故障回退，不降级为公网明文 DNS |
| DoQ | 关闭 | 实验功能；避免默认形成 QUIC 套 QUIC |
| MASQUE | 关闭 | 后续实验传输后端 |
| ODoH | 关闭 | 后续隐私 DNS，需要真正分离的代理与目标 |
| 内核优化 | Auto | 仅应用已检测、已验证、可回滚的优化 |
| 自动规则更新 | 开启 | 内容变化且候选配置验证成功才激活 |
| 程序自动跨版本升级 | 关闭 | 默认提示管理员，避免静默破坏兼容性 |
| 自动回滚 | 强制开启 | 产品安全底线 |

模块关闭时必须停止对应服务、释放端口并删除由本产品创建的派生规则；不得删除用户原有的同名外部配置。

## 6. 服务端安装与生命周期

### 6.1 当前可用部署

当前版本的完整部署方法见 `docs/DEPLOYMENT.zh-CN.md`。管理员需准备：

- Linux/systemd 服务端和 OpenWrt/procd 客户端；
- sing-box、证书、TUIC 与 WARP 私密参数；
- 编译好的静态二进制；
- 至少 32 字符的随机 FEC 密钥；
- 可用且无冲突的公网 UDP 端口。

PowerShell 编排会先部署或合并 sing-box，再部署服务端 FEC/WARP balancer，最后安装 OpenWrt 客户端。部署不会自动切换 Passwall 主链路。

### 6.2 第一版目标体验

```bash
smart-gateway install
smart-gateway plan
smart-gateway apply
smart-gateway status
smart-gateway doctor
smart-gateway upgrade
smart-gateway rollback
```

交互输入应不超过：场景、域名/地址、总带宽、证书方式和 WARP 选择。安装器自动完成系统检测、端口规划、配置生成、离线检查、影子验证、原子切换和全链路验收。

### 6.3 事务与回滚

每次变更创建一个 Revision，至少记录：产品配置、派生配置、服务定义、防火墙状态、二进制版本和校验清单。

```text
解析 -> 依赖检查 -> 端口检查 -> 候选生成 -> 离线校验
     -> 影子健康检查 -> 原子激活 -> 验收 -> 提交 Revision
```

激活前失败不得改变运行状态；激活后失败必须恢复上一 Revision。连续修复失败时进入隔离状态，避免无限重启风暴。

## 7. 多用户、设备和会话

第一版身份模型：

```text
Tenant（预留） -> User -> Device -> Session
```

每个设备必须拥有独立的 TUIC UUID/password、FEC key/key ID、设备 ID 和撤销状态。禁止多个设备共享长期密钥。

目标命令：

```bash
smart-gateway user create USER
smart-gateway user disable USER
smart-gateway device create USER --target passwall
smart-gateway device create USER --target v2rayn
smart-gateway device revoke DEVICE
smart-gateway device rotate DEVICE
smart-gateway quota set USER --max-mbps 10
```

配对码应一次有效、十分钟过期、限制失败次数，并仅交换设备专属凭据。长期密钥不得出现在命令行、URL、日志或 Git 仓库中。

### 7.1 公平调度

服务器总带宽是硬约束，FEC 冗余也计入总量。推荐采用服务器、用户、设备、会话四层调度：单用户活跃时可使用空闲容量；多用户同时活跃时按权重公平分享，并支持用户最大速率。第一版不得将每个用户都配置成服务器总峰值后相互争抢。

## 8. Passwall/Passwall2 接入

### 8.1 当前状态

OpenWrt 安装脚本会创建 `smart-fec-client` procd 服务，监听 `127.0.0.1:3333`。管理员仍需在确认链路健康后，手工将 TUIC 目标接到本地 FEC 入口。脚本不自动改当前主节点，以避免 SSH 管理链路中断。

### 8.2 第一版适配目标

交付 `smart-gateway-agent.ipk` 和可选 LuCI 包：

- 使用一次性配对码获取设备凭据；
- 自动创建由产品标记的 Passwall/Passwall2 节点；
- 不修改 `/tmp` 下 Passwall 临时配置；
- 部署后先检测，不自动切换当前主节点；
- 卸载时只删除本产品创建的节点；
- 支持恢复原节点与导出脱敏诊断包。

Passwall 继续负责透明代理、LAN 访问控制和分流；Agent 负责 FEC、PMTU、凭据、健康检查和本地端口。

## 9. v2rayN/Windows 接入

Windows 第一版目标是提供常驻 Agent/Service，而不是让用户维护自定义 JSON：

- 输入一次性配对码；
- 使用 Windows 安全存储保护设备凭据；
- 运行本地 Smart FEC 入口；
- 输出标准分享链接或导入文件；
- 优先使用 v2rayN 支持的导入机制，不直接编辑其数据库；
- v2rayN 不存在时仍可导出独立配置和诊断信息。

当前仓库尚未提供 Windows Agent 或 v2rayN 自动导入，不能按已实现功能宣传。

## 10. 诊断与可观测性

第一版 `doctor` 应检查：服务、端口、配置语法、证书、系统时间、DNS、TUIC、FEC 双向流量、WARP worker、稳定出口、PMTU、防火墙、规则更新时间、数据库、磁盘、内存与 CPU。

普通状态只显示可行动的信息，例如：

```text
[正常] TUIC 可达，RTT 62 ms
[正常] WARP 3/3
[警告] 路径 MTU 下降到 1380
[处理] FEC 安全载荷已降低
```

默认收集性能计数，不记录 URL、业务内容或完整域名历史。诊断包必须脱敏，并明确列出包含的字段。

### 10.1 载体拥塞控制器调优与 A/B 实测

载体的拥塞控制是**发送端本地行为，不参与握手协商**，因此可以只改一端做单侧对照。
可选值由 `SMART_QUIC_CONGESTION` 控制：

| 值 | 说明 |
| --- | --- |
| `new_reno`（默认） | quinn 默认控制器。每次丢包事件把窗口砍半，持续拥塞时降到 `2 × MTU` |
| `cubic` | RFC 8312 控制器 |
| `bbr` | 带宽-时延积模型。quinn 官方标注为实验性，选中时进程以 warn 级别记录 |

设置位置：服务端写 `/etc/smart-fec/quic.env`，旁路由写 `/etc/smart-fec-quic.env`；
两者都已被既有的 unit / init 读取，不需要改单元文件。非法取值会让进程在启动时直接失败，
不会静默回退到操作者没有选择的控制器。

三种控制器统一按 RFC 9002 §7.2 计算初始窗口
（`min(10 × MTU, max(2 × MTU, 14720))`，取连接实际协商到的 MTU），
而不是 quinn `Default` 里那个忽略 MTU 的编译期常量 12000。

对照实验时只看 `QUIC carrier stats` 这一行（默认 5 秒一条）：

```text
wire_loss_ppm / sent_packets / lost_packets / lost_bytes / congestion_events /
black_holes / lost_plpmtud_probes / datagram_tx / datagram_rx /
udp_tx_datagrams / udp_rx_datagrams / tx_bytes / rx_bytes / rtt_ms /
cwnd_bytes / mtu
```

判读要点：

- `cwnd_bytes` 长期贴近 `2 × mtu`：控制器已被丢包打到下限，瓶颈在载体而不是 FEC；
- `congestion_events` 的增速直接反映控制器对丢包的反应频率；
- `wire_loss_ppm` 与 FEC 层的 `sequence_gap_ppm` 对比，可判断丢包发生在载体之内还是之上；
- `black_holes` / `lost_plpmtud_probes` / `mtu` 三者一起解释路径 MTU 的波动；
- `datagram_tx` / `datagram_rx` 是 FEC 之下的真实投递量，`udp_*_datagrams` 用于对照每个
  UDP 报文承载了几个数据报。

一个容易被忽略的因果：RFC 9221 §5.4 允许发送端在拥塞控制不允许时**直接丢弃** DATAGRAM
而不发送。这类丢弃发生时数据报已经占用 FEC 序号却从未上线，FEC 无法重建从未发出的分片。
所以拥塞控制器不只影响吞吐，也会影响 FEC 的实际有效性。

### 10.2 FEC 反馈协商与升级顺序

V2 反馈帧（24 字节）比旧版 4 字节帧多携带"重建符号数 / 组数"。已部署的旧版本只在
`payload.len() == 4` 时解析报告帧，其他长度会被解码器丢弃，因此：

- 若无条件只发 24 字节帧，**未升级那一端会完全收不到丢包样本**，其自适应 parity 永久
  冻结——既不因丢包上升，也不因空闲衰减；
- 现在发送端先发 4 字节帧，直到对端自证能产生 V2 样本后才切换为 24 字节帧。

结果是两端可以任意顺序升级，不再需要"同时升级"。混合版本期间唯一的代价是：未升级那一端
不贡献"重建符号数 / 组数"这两个富字段，但仍然正常收到丢包率并照常自适应。
若要绝对保守，升级一端后观察 5 分钟再升级另一端。

> 更正与界定：§10.2 描述的是 **pre-V2 构建**的行为（由一份 pre-V2 源码树核对：报告帧
> 分支为 `kind == KIND_REPORT && payload.len() == 4`，其他长度交给解码器后被丢弃）。
> 本链路在本次部署前，两端运行的是同一份 24 字节 V2 反馈实现（`md5 94f26a8f…`），
> 因此当时**并不存在**混合版本静音问题。能力协商的价值在于保证此后任何单端升级或
> 回滚都不会把对端的自适应控制器打成静音。

### 10.3 实测基线（本链路，2026-09-26 部署 audit-fixes-v3 后）

测量方式：旁路由上 `curl --socks5-hostname 127.0.0.1:1070`，即与 LAN 客户端完全相同的
SMARTFEC 节点路径。

| 项目 | 实测结果 |
| --- | --- |
| 出口 IP | Cloudflare WARP；`warp=on` `loc=SG` `colo=SIN`；连续 3 次为 104.28.222.47 / 104.28.254.46 |
| 家宽 IP 是否泄露 | 否。服务端看到的隧道对端为 120.85.127.231 / 183.12.3.146，均未出现在任何出口 |
| IPv6 泄露 | 无路径：旁路由无全局 IPv6、无 v6 默认路由、Passwall 关闭 IPv6 代理 |
| DNS 泄露 | 无：`www.google.com`/`www.youtube.com` 解析为真实 Google IP（142.251.x.x），未被污染 |
| 明文 FEC 特征 | UDP/443 抓包中 `SFEC` / `SFR2` 出现 **0 次**（FEC 完全封装在 QUIC 内） |
| TCP/443 指纹 | VLESS-Reality 呈现**真实** www.microsoft.com 证书链（Microsoft TLS G2 → DigiCert Global Root G2） |
| UDP/443 指纹 | QUIC 载体使用**自签名** `CN=www.microsoft.com` 证书，`openssl verify` 报 error 18 —— 主动探测可区分 |
| 服务端出口能力 | 直连 59.8 MB/s；经 WARP 14.5 MB/s；YouTube 首页 0.31s |
| 端到端吞吐（NewReno） | 10 MB × 3 = 146 / 297 / 197 KB/s（均值 ≈213 KB/s） |
| 端到端吞吐（BBR） | 10 MB × 3 = 699 / 488 / 746 KB/s（均值 ≈644 KB/s，**约 3.0×**） |
| YouTube 首页 | NewReno 3.05 / 3.08 s → BBR 2.80 / 1.78 s |
| 载体丢包（满载） | `wire_loss_ppm=Some(0)`、`lost_packets=0`（稳态几乎不丢包） |
| 载体 RTT | 空闲 84 ms → 满载 405–445 ms（约 5× 排队时延） |

由此得到三条与直觉相反的结论：

1. **瓶颈不是丢包，而是 cwnd/RTT。** NewReno 把家宽上行缓冲填满后 RTT 从 84 ms 膨胀到
   ~430 ms，吞吐被压到 ≈213 KB/s（服务端 cwnd 240–265 KB，240000/0.43 ≈ 560 KB/s 上限）。
   这正是 BBR 的适用场景，实测提升约 3 倍。
2. **FEC 在稳态下不提供任何保护。** 自适应控制器把 `tx_parity` 降到 0（这是"正确"的），
   但同一时段出现过 `sequence_gap_ppm=183399`（18.3%，232 个数据报丢失）而
   `fec_recovered_symbols=0` —— **突发丢包到来时没有冗余可用，一个符号都没恢复**。
3. **因此"FEC 有没有用"的答案是：当前参数下对稳态无用，对突发也来不及。** 载体是
   QUIC DATAGRAM（RFC 9221 不重传），这些丢失只能由内层 TUIC 重传，代价是一个 430 ms
   的 RTT。要让它真正起作用，应给 parity 设一个**常态下限**（例如常态 ≥1，即 10% 开销），
   而不是让自适应控制器在无丢包时降到 0。

**遗留风险**：BBR 在本链路把服务端 cwnd 推到 45–59 MB（远超实际 BDP），虽然实测更快，
但会抢占家宽缓冲区、可能影响同网其他设备。建议按真实使用观察后再决定是否长期启用。
回滚：把 `/etc/smart-fec/quic.env` 中的 `SMART_QUIC_CONGESTION` 改回 `new_reno`，
然后 `systemctl restart smart-fec-quic`。

### 10.4 Google 搜索显示"广东省 中国"且极慢的根因（已修复）

现象：Google 搜索页页脚显示"广东省 中国 - 是根据您的 IP 地址推断出来的"，且页面加载极慢。

逐项实测后排除掉两个常见猜测：

- **不是 IP 泄露。** 在出问题的浏览器里实测 `https://api.ip.sb/geoip` 返回
  `ip=104.28.222.43`、`organization=Cloudflare Warp`、`country=Singapore`，与经 SOCKS
  测得的出口完全一致。浏览器确实走了代理。
- **不是 DNS 泄露。** `www.google.com` 解析为真实 Google IP（142.251.x.x），未被污染。

真正的原因有两条：

1. **Google 对 Cloudflare WARP 该 IP 段的地理库是错的。** Cloudflare trace（`loc=SG`）、
   ip.sb、ip-api 三方一致判定该出口为 Singapore，服务端自身 IP（腾讯云）也是 Singapore；
   全链路里**唯一 geolocate 到广东省广州市的是家宽 IP**（120.85.127.231 China Unicom /
   183.12.3.146 Chinanet GD），而它并未出现在出口路径上。Google 把被大量复用的 WARP 出口
   判成了广东。
2. **同一个 WARP 出口被 Google 判为异常流量。** 实测 `GET https://www.google.com/search`
   经 WARP 返回 `302 → /sorry/index`（反机器人拦截页），经服务端直连返回 `200` 且无 CAPTCHA。
   浏览器在拦截与重试之间打转，表现为"极慢"。

**修复**：在 sing-box 路由中把 `google.com` 从 `warp-balance` 拆出来改走 `direct`
（服务端自身出口）；`googleapis.com / gstatic.com / youtube* / googlevideo.com / ytimg.com`
仍走 `warp-balance`。**规则顺序关键**：`google.com` 规则必须插在原规则之前（sing-box 首条
匹配生效）。

修复后实测：

| 项目 | 修复前（WARP） | 修复后（direct） |
| --- | --- | --- |
| Google 搜索 | `302 → /sorry/`（CAPTCHA） | **`200`，无 CAPTCHA，1.27–1.96 s** |
| Google CDN 8 MB | 737 KB/s | **918 KB/s** |
| YouTube 首页 | `200` | `200`（未变，仍走 WARP） |

回滚：`cp -p /etc/sing-box/config.json.bak-googlefix-<时间戳> /etc/sing-box/config.json && systemctl restart sing-box`

**经验**：Cloudflare WARP 出口被大量用户复用，Google 对它的反机器人判定和地理位置都不可靠。
凡是有风控的 Google 服务（搜索、账号）优先走 `direct`（自有机房 IP）；视频 CDN
（googlevideo / ytimg）走 WARP 没有问题。

### 10.5 丢包容忍优化（T1–T3）的运维契约

针对"400 ms RTT + 20% 随机丢包"这条链路做了三处改动，但**它们之间有一个必须理解的
带宽预算耦合**，配错会让结果更差。

#### 三层带宽关系

```
链路容量 ≥ 载体发送速率 × FEC 开销
            ↑                  ↑
     rate / ack_rate       (10 + k) / 10
```

- **载体发送速率不是 `SMART_QUIC_FIXED_RATE_MBPS`**。`fixed` 控制器按 ACK 成功率
  反向补偿丢包（`window = rate × srtt / ack_rate`），所以实际发送速率最高到
  `配置值 / 0.8 = 1.25 ×`。
- **FEC 开销从载体预算里出**。修复分片也是载体载荷，所以有效载荷速率 ≈
  `载体速率 / (1 + k/10)`。

#### 配置规则

设链路容量为 C（你是 30 Mbps）：

| 项 | 建议值 | 依据 |
| --- | --- | --- |
| `SMART_QUIC_FIXED_RATE_MBPS` | **≈ C / 1.25**（30 Mbps → 24） | 补偿最多放大 1.25 倍，避免持续超发 |
| 期望有效载荷 | 载体速率 / (1 + k/10) | 20% 丢包下 k 最优点约 4，即 ÷1.4 |

**不要把 `SMART_QUIC_FIXED_RATE_MBPS` 直接设成链路容量** —— 那会让实际发送速率达到
1.25C，持续超发、丢包进一步上升。

#### 三处改动各自负责什么

| 改动 | 负责 | 不负责 |
| --- | --- | --- |
| T1 `fixed` 控制器 | 丢包**不缩窗**，按已知带宽稳定发送 | 不判断链路容量，配错就超发 |
| T2 冗余最优化 | 按丢包率选使**期望有效吞吐最大**的 k | 看不见突发导致的整组失败 |
| T3 恢复驱动输入 | **有丢失却一个都没修回来**时立刻抬一档 | 不做真正的 rateless |

#### 尚未做的（按 RFC 8681/8682 的后续路径）

T3 只完成了"恢复驱动"，**没有**改成真正的 rateless。滑窗随机线性码（RLC）需要新增
REPAIR 帧（`Repair_Key` / `NSS` / `DT` / `NRS`）、把按组编解码换成编码窗口、并改动线
格式。收益明确：块状 RS 在组内丢包少于 k 时冗余白费、多于 k 时整组报废，这两处浪费
在滑窗下都不存在 —— 也就是 T2 实测到的"多付一倍开销只换 3 个百分点"。
依据：[RFC 8681](https://www.rfc-editor.org/rfc/rfc8681)、
[RFC 8682](https://www.rfc-editor.org/rfc/rfc8682)、
[draft-roca-nwcrg-rlc-fec-scheme-for-quic-03](https://datatracker.ietf.org/doc/html/draft-roca-nwcrg-rlc-fec-scheme-for-quic-03)。

**位置判定的最终验证**（服务端直连取回的 Google 页面里有两处独立证据）：

```html
<div class="O3yKUb">Singapore</div>      <!-- Google 渲染的位置元素 -->
<a href=".../preferences?hl=en-SG&fg=1"> <!-- Google 把区域判定为 en-SG -->
```

即 Google 对 `direct`（腾讯云新加坡）出口的判定是 **Singapore**；而对 WARP 出口判定为广东省。
**注意**：Google 会把推断出的位置写进 `NID` cookie（有效期数月），切换出口后浏览器仍会沿用
旧值。若页脚仍显示旧位置，点页脚的"更新位置信息"，或清除 google.com 的 cookie / 用无痕窗口，
即可看到新判定。

#### 10.4.1 真正的坑：域名规则匹配不到"以 IP 到达"的连接

只把 `google.com` 改成 `direct` 之后，位置仍显示中国城市。原因在服务端 sing-box 的日志里：

```text
107 www.google.com        direct   ← 带域名的连接，规则命中
 15 142.250.109.94        socks    ← Google IP，规则无法匹配 → 落到兜底 network:tcp
  8 192.178.211.84        socks    ← 同上
  6 209.85.165.198        socks    ← 同上
```

浏览器先解析域名再连接，Passwall 传给服务端的往往是**目的 IP**；而 sing-box 的
`domain_suffix` 规则只能匹配域名，匹配不到 IP，于是这些连接全部落到兜底的
`{"network":"tcp" → warp-balance}` —— 也就是走了被 Google 判成中国且被 302 拦截的 WARP。

三处修复：

1. **开启域名嗅探**：在 `route.rules` 最前面加 `{"action":"sniff"}`，从 TLS SNI 恢复域名，
   使既有域名规则对 IP 连接也生效。
   **超时必须放大**：`timeout` 设 300ms 时仍有一半连接嗅探失败（本链路 RTT ≈ 430ms，
   ClientHello 还没到就超时），改成 `1500ms` 后命中率明显提升。
2. **按 Google 官方 IP 段做确定性路由**：从 `https://www.gstatic.com/ipranges/goog.json`
   取 130 个 IPv4 + 15 个 IPv6 段，作为 `ip_cidr` 规则路由到 `direct`。这条不依赖嗅探，
   是兜底保障。
3. **把所有 Google 服务挪到 `direct`**：`google.com / googleapis.com / gstatic.com /
   googleusercontent.com / ggpht.com / youtube.com / youtube-nocookie.com /
   youtubei.googleapis.com` 全部走机房 IP；只保留视频 CDN（`googlevideo.com` / `ytimg.com`）
   走 WARP。**位置/遥测接口就在 gstatic/googleapis 上**，之前把它们留在 WARP 是位置一直
   显示中国的原因之一。

修复后实测（服务端 sing-box 决策统计）：

| 目标 | direct | 仍走 WARP |
| --- | --- | --- |
| Google 域名 | **9 / 9** | 0 |
| Google IP 段 | **22 / 25** | 3 |

走 WARP 的剩余目标为 Cloudflare（`172.64.x` / `104.18.x`）与 Akamai（`2.18.67.211`），
这些本来就不属于 Google，保持 WARP 是预期的。

## 11. 内核感知优化阶段

内核优化按能力和验证结果分级，不以固定 `sysctl` 大全作为产品功能。

### Portable（第一版基础）

- 批量 UDP I/O（`recvmmsg`/`sendmmsg`）；
- 预分配缓冲池；
- 有上限的 socket buffer；
- 应用层 pacing；
- 跨 Linux/OpenWrt 的保守兼容路径。

### Accelerated（第一版条件启用）

- UDP GRO/GSO；
- `SO_REUSEPORT` 多 worker；
- CPU/IRQ/RPS/XPS 建议或受控应用；
- nftables 快速过滤；
- 可选 reuseport eBPF 引流。

### Extreme（后续实验）

- XDP/AF_XDP；
- 独占队列、CPU 与 NUMA 调优。

ESXi、虚拟网卡、低 vCPU 和低带宽服务器必须使用保守策略。30 Mbps 环境通常优先减少复制、锁和排队，不应默认启用 AF_XDP。所有自动调优必须记录基线，只保留产生实际收益且未恶化 P95/P99 延迟的变更。

## 12. MASQUE、DoQ 与 ODoH 路线

- **MASQUE**：作为后续 `CONNECT-UDP`/`CONNECT-IP` 传输后端及双跳隐私结构的候选。它本身不提供匿名性、FEC、多路径或带宽提升。
- **DoQ**：作为实验 DNS 传输。它加密 DNS 链路，但解析器仍可看到查询；经 TUIC 承载时可能形成 QUIC 套 QUIC，因此默认关闭。
- **ODoH**：用于把客户端来源与 DNS 查询内容分离。只有代理和解析目标由不同信任域运行时，才具有实质隐私收益。

这些能力进入生产前必须完成互操作、资源上限、故障回退、隐私声明和对照基准测试。

## 13. 安全基线

- 管理 API 默认只监听本机或管理网络；
- 内部 TUIC、WARP worker 和负载端口只监听回环；
- 每设备独立凭据，可即时撤销与轮换；
- FEC 帧具有认证与防重放状态；
- 无效身份、会话创建、重组内存和日志速率均有硬上限；
- 密钥文件 `0600`，备份必须加密并控制访问；
- 更新包必须验证签名和哈希；
- 不执行拼接的 Shell 命令；
- 默认不记录访问目标，不上传遥测；
- 关闭模块不得残留公网监听或授权规则。

## 14. 第一版验收标准

第一版发布前至少满足：

- 新服务器一条命令完成受控安装；
- 手工输入不超过五项，不要求编辑 sing-box JSON；
- 多用户、多设备并发不串流；
- 设备撤销立即阻止新会话；
- 100 个模拟用户下资源有界；
- 单用户利用空闲带宽，多用户公平分享；
- Passwall 节点可生成且不强制切换；
- v2rayN 可通过标准方式导入；
- 端口冲突、下载中断、配置损坏、服务失败均能停止或回滚；
- 1%、3%、5%、10% 随机及突发丢包有可复现实验报告；
- MTU 黑洞、网络切换、NAT 重绑定、WARP 故障均有测试；
- 日志和诊断包通过密钥与隐私扫描。

## 15. 已知限制

当前 `0.2.0-alpha.9` 默认使用 FEC V3：设备 ID、会话、序列和 FEC 参数均位于 XChaCha20-Poly1305 加密信封内；动态 shard 最大1380字节，使常见1200–1350字节 QUIC数据报保持单片，并降低小包固定长度特征。公网仍可观察不透明选择器、密文长度及时序；V1/V2 仅用于迁移。它仍不应作为未经压测和外部审计的多人商业服务直接部署：尚未实现用户级公平队列、选择器轮换、在线撤销/热加载、无效认证速率限制和 100 用户验收。

在用户级公平调度、凭据在线撤销、完整 Controller 部署适配及计划中的验收全部完成前，本版本保持 Alpha 内测定位。

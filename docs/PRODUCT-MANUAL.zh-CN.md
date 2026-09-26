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

### 10.6 T1–T3 部署实测：拥塞控制器 A/B（本链路，2026-09-26 23:00 前后）

部署对象：服务器 `<SERVER_PUBLIC_IP>`（Tencent Cloud 新加坡，2 核）+ 旁路由 `<ROUTER_LAN_IP>`
（ImmortalWrt 24.10.6 / J4125，2 核 2GB）。两端二进制 md5 均为
`bda8f056775933527e17d3796bcd5c49`。A/B 只切换**服务器侧**（下行发送端）的控制器，
路由器侧保持 `fixed@24`；每轮先记录链路 truth，再跑 3×10MB。

| 服务端控制器 | dl1 (B/s) | dl2 | dl3 | 均值 | 服务端载体看到的丢包 | 服务端 cwnd |
| --- | --- | --- | --- | --- | --- | --- |
| `new_reno` | 5,130 | 547 | 7,914 | **4,530** | — | **2,944**（RFC 9002 下限） |
| `bbr` | 414,793 | 459,550 | 405,820 | **426,721** | 36.4% | 4,800 → 3,528,791 |
| `fixed` 24 Mbps | 431,482 | 501,283 | 493,092 | **475,286** | 28.1% | 315,449 |
| `fixed` 30 Mbps | 488,669 | 463,247 | 503,096 | **485,004** | 25.2% | 386,967 |

同样时段、同一链路、**不走代理的直连对照**（目标仍是 Cloudflare，5×10MB）：
492,240 / 530,036 / 539,754 / 464,048 / 561,290 B/s，均值 **517,474 B/s**；
走隧道 5×10MB：531,423 / 553,962 / 515,797 / 556,232 B/s（第 5 次因载体重连失败），
均值 **539,354 B/s**。

结论（按证据强度排序）：

1. **`new_reno` 在本链路上是崩塌的**：窗口被压到 RFC 9002 下限 `2944` 字节，
   吞吐 4.5 KB/s。这直接验证了 T1 的前提——对丢包敏感的控制器在"400ms RTT +
   两位数随机丢包"的链路上不可用。
2. **`bbr` 与 `fixed` 在本链路上等价**（42.7 / 47.5 / 48.5 万 B/s，差异在链路自身
   波动范围内），但 `fixed` 的窗口**稳定**（31–39 万字节）而 `bbr` 会在 4.8KB 与
   3.5MB 之间剧烈摆动。24 与 30 Mbps 没有可分辨差异，因此仍按 §10.5 取 24。
3. **隧道已经不是瓶颈**：直连 517 KB/s vs 走隧道 539 KB/s。协议层（QUIC 载体 +
   FEC + 加密）没有吃掉任何有效吞吐，与裸链路持平。
4. **路由器 CPU 不是瓶颈**：一次完整下载期间 `smart-fec-*` 合计约 2743 jiffies
   / 70.5s，整机非空闲约 23%（2 核）。二者都远未饱和。

也就是：**"30 Mbps 宽带"并不是到该目的地的可用速率**。这条路径当前只能交付
约 4.1–4.3 Mbps，且与是否走隧道无关。

用 2MB 端点（`__down?bytes=2000000`）在 23:14 复测，隧道 5 次为
518,617 / 544,083 / 570,451 / 482,491 / 546,657 B/s（均值 **532,460**），
直连 5 次为 462,736 / 538,315 / 536,720 / 320,727 / 511,291 B/s（均值
**473,958**），结论一致：隧道不慢于裸链路。

> **测速方法上的坑（务必注意）**：`speed.cloudflare.com/__down?bytes=10000000`
> 会被按源 IP 限流。连续跑几十次 10MB 之后会开始返回 **HTTP 429**，响应体只有
> **1 字节**、耗时 0.2–1.2 秒。这个形态**极易被误读成隧道故障**（"下载瞬间失败"）。
> 判定方法：看 `http_code` 与 `size_download`——429/1 字节是限流，
> 不是链路问题；直连同一 URL 也会同样返回 429。复测时换端点或换字节数。

### 10.7 T5 部署暴露并修复的两个缺陷（否则隧道起不来）

这两个缺陷都属于"文档/脚本承诺的取值与代码实际接受的取值不一致"，此前的单测
**看不见**——因为单测断言的是代码当时的行为，而不是文档承诺的契约。

1. **procd 的 `env` 参数会被后续调用整体覆盖。** `/lib/functions/procd.sh` 中
   `env` 走 `_procd_set_param → _procd_add_table → json_add_object("env")`，每次
   `procd_set_param env` 都新开一个同名 `"env"` 对象，JSON 解析后**只有最后一次
   生效，前面的环境变量被静默丢弃**。把 `SMART_QUIC_CONGESTION` 追加成第二次调用
   之后，`SMART_FEC_KEY` 就没了，`quic-client` 以缺少 `--key` 崩溃并进入 crash loop。
   上游 OpenWrt 也修过同一个坑（`autossh`: "gets overwritten by the second
   `procd_set_param env` call"）。修复：合并成一个字符串，只调用一次。
2. **`SMART_QUIC_STREAM_LANES=0` 被拒绝，但 unset 就等于 0。**
   `parse_stream_lanes` 对未设置返回 `Ok(0)`（DATAGRAM 模式），却对显式 `"0"`
   报错；而 `deploy/openwrt-smart-fec-quic.init` 默认就传 `0`，手册也把 `0` 写成
   DATAGRAM 模式。表现为**握手每次都成功、随后立刻断开重连**，日志刷
   `QUIC relay reconnecting error=SMART_QUIC_STREAM_LANES currently supports only 1`。
   修复：unset / 空白 / `"0"` 统一按 DATAGRAM 处理，只有 `1` 开启可靠 stream lane。
   同时把 `SMART_QUIC_FIXED_RATE_MBPS` 的空白值按"未配置"处理，回落到默认 28。

### 10.8 仍然限制吞吐的因素（本次实测证据）

1. **双 WAN 漂移是首要因素。** 旁路由挂在 iKuai（`<IKUAI_LAN_IP>`）后面，家里有两条
   WAN：`183.12.3.146`（电信）与 `120.85.127.231`（联通）。服务端近 90 分钟看到的
   隧道对端来源 IP 分布为 **27 : 8**——即同一条隧道被两条 WAN 交替承载。
   逐包 ping 同时存在 **~52ms** 与 **~400–500ms** 两个 RTT 峰，说明两条路径的时延
   差约 400ms。负载均衡把同一条 QUIC 连接的数据报撒在时延差 400ms 的两条路径上，
   产生大量乱序与突发丢包。
2. **载体重连频繁。** 服务端近 90 分钟 `QUIC device authenticated` **35 次**、
   `QUIC connection closed` **28 次**（19 次 `closed by peer: 0`、9 次 `timed out`），
   即平均约 2.5 分钟重建一次会话；路由器侧对应日志为
   `relay reconnecting error=QUIC carrier heartbeat timeout`。
3. **分块 RS 无法覆盖突发丢包，parity 已经打满。** 服务端 FEC parity 在本轮实测中
   升到 **5 → 6 → 8**（`MAX_PARITY` 上限）后停住。按
   `goodput = (1 − P(X>k)) / (1 + k/10)`、`X ~ Bin(10+k, p)` 计算：

   | 观测丢包 p | 最优 parity | 对应有效吞吐系数 |
   | --- | --- | --- |
   | 11.5%（ICMP 测得） | 3 | 0.728 |
   | 20% | 5 | 0.626 |
   | 28%（载体测得） | 7 | 0.545 |

   parity=8 在 p=28% 时的整组不可解概率仍为 3.95%，因此**继续加大 `MAX_PARITY`
   收益已经很小**；真正有效的是降低丢包本身（即第 1 条）。这也为"用滑动窗口 RLC
   替代分块 RS"提供了实测依据：分块 RS 对**连续突发**丢包无能为力，突发长度超过
   parity 就整组报废。
4. **服务端 journald 没有容量上限**：`journalctl --disk-usage` 已 **1000 MB**，
   `/etc/systemd/journald.conf` 未显式限制。

### 10.9 下一步优先级（按收益/成本排序）

1. **在 iKuai 上把到 `<SERVER_PUBLIC_IP>` 的流量钉到单条 WAN**，或把多 WAN 从负载均衡改为
   主备。这是唯一能同时改善丢包、乱序、重连频率与 FEC 开销的动作，且不改代码。
2. 给 journald 加 `SystemMaxUse=200M`。
3. 若第 1 条之后仍有突发丢包，再评估滑动窗口 RLC（T3 当时按"诚实标注"缩减为仅做
   恢复驱动，见 §10.5）。

### 10.10 自适应载体控制器：三次基于丢包的设计全部失败，最终改为纯时延

这是本项目记录得最完整的一次"被实测推翻"，写在这里是因为踩过的坑比结论更有价值。

链路实测（快/丢包那条 WAN）：载体丢包 **约 20%**，**逐区间在 8%–35% 之间跳动**，
且**不随发送速率变化**。三个基于丢包的设计依次部署、依次塌到 2 Mbps 地板：

| 版本 | 判据 | 部署结果 |
| --- | --- | --- |
| T3 | 丢包 > 5% 即判拥塞 | 三段分布重叠（0.05–0.6% / 5–15% / 40–68%），阈值不可能分开；吞吐 942 KB/s → **28 KB/s** |
| T3b | 降 30% 后看**单区间**丢包是否下降 | 14 次 `test_drop` 对 **12 次 `test_confirm`**——噪声被当成响应；**33 KB/s** |
| T3c 前 | **窗口均值 + 相对余量**（对平滑基线） | 仍塌陷。用真实观测序列做夹具的回归测试**如实复现**：`collapsed to 250000 ... floor 250000` |

T3b 还有一个独立的纯逻辑缺陷：`BurstBackoff` 把 `clean_intervals` 归零，而该计数
只在 `Probe`/`Hold` 时递增，于是持续丢包下**恢复路径不可达**，地板成了死锁态。已修为
状态机内的有界冷却。

**结论**：这个信号不携带可用的拥塞信息——宽度约 20%，区间间噪声幅度超过 30% 降速所能
产生的响应。继续在它上面做统计加工，是在给一个不含答案的量增加算力。RFC 9265 §5 从
另一个方向给出同一结论：FEC 置于传输层之下时**被屏蔽的是丢包、存活的是时延**。

**最终控制律（T3c）**：只有排队（`srtt − min_rtt`）能移动速率；超过阈值时降 30% 开一个
测试窗口，在 6 个区间上**累加排队**再判定——排掉了是拥塞（冷却保持），没排掉就恢复原
速率。丢包**只记录不参与决策**。另加饱和保护：丢包 ≥90% 时不走统计路径，直接降速并
冷却（交付几乎为零的路径是饱和或已死，不该用统计论证显而易见的事）。

**部署实测（同时段 A/B，03:29–03:31）**：

| 配置 | 3×5MB 均值 | 控制器行为 |
| --- | --- | --- |
| `adaptive` | **408,947 B/s** | **50 次 `probe`，0 次测试**；`loss_ppm` 9–31% 全程被忽略，目标从 980,013 单调爬到 **2,866,775 B/s**（22.9 Mbps，仍朝 30 Mbps 上限） |
| `fixed@24` | 419,282 B/s | — |

**两者持平**（差值落在 275–575 KB/s 的 run-to-run 方差内）。所以 `adaptive` 现在**不再
更差**，但**也没有更好**。

**同时暴露的更重要事实**：两种配置的交付都只有约 3.3 Mbps，而载体实际在按 **23.8 Mbps**
发送（`tx_bytes`），丢包 22.6%。**"线上字节去哪了"这个原始缺口仍然存在，并重新成为
首要限制因素**——这正是 T1 的账目要回答的问题，也是下一步该做的，而不是继续调控制器。

### 10.11 运维契约更新

- `SMART_QUIC_MAX_RATE_MBPS` 是**有效**发送速率的硬顶（不是目标），所以填 30 就是 30，
  不会被 1.25 倍 ACK 补偿放大越界。与 `SMART_QUIC_FIXED_RATE_MBPS` 的区别见 §10.5。
- `SMART_QUIC_CONGESTION` 未设置时默认 `adaptive`。**本链路实测 `adaptive` 与 `fixed@24`
  持平**；若追求可预测性，`fixed@24` 仍是合理选择。
- `SMART_QUIC_REQUIRE_TRUSTED_CERT=1` 会让自签证书直接拒绝启动。当前 UDP/443 载体出示的
  就是自签证书（§10.7 同批审计），**该指纹问题尚未修复**，需要一张指向自有域名的公开
  信任证书。
- `SMART_FEC_FORCE_PARITY=<n>` 固定 FEC parity、**关闭自适应冗余**。release 亦生效，
  启用时打 WARN。仅用于诊断/受控实验，不要长期留在生产上。
- `SMART_FEC_MAX_PARITY=<n>` 给自适应 parity 加**有效上限**（夹在 `[1, 8]`，默认 8 =
  与改动前一致）。它**不改控制律**，只是让实测出来的最优点能被显式使用；理由见 §10.14。
  下行方向由**服务端**的该变量决定（冗余由服务端生成）。

### 10.12 长期"效率恒定 22–29%"缺口的真正根因（已修复）

§10.6–§10.8 记录过一个反复出现、无法归因的现象：**两端都报零丢包**（载体
`wire_loss_ppm=Some(0)`、`lost_packets=0`，FEC 序号 `missing=0`、`groups_failed=0`），
但交付效率恒定在 **22–29%**，且**跨 8 倍速率范围没有拐点**。

T1 的统一账目对齐两端同一 interval 后，一个典型下行区间给出了答案：

| 量 | 值 |
| --- | --- |
| `wire_rx_bytes` | 12,527,422 |
| ├ 数据帧 5327 / 校验帧 3558 | 1410 B/帧 |
| `inner_tx_bytes` | 3,645,319 |
| `inner_tx_datagrams` | 2694 → **1353 B/数据报** |
| `groups_failed` / `unrecovered_shards` | 0 / 0 |

关键比值：**5327 ÷ 2694 = 1.977 片/数据报**。

**根因**：`CHUNK = SHARD − FRAGMENT_HEADER = 1340 − 14 = 1326`，而生产下行实测的内层
数据报**平均 1353 字节**——只超出 27 字节。贪心切分把每个数据报切成 `[1326, 27]`，
而 `flush()` 因 Reed-Solomon 要求等长符号，会把组内**每个源分片填充到组内最长分片**，
于是那个 27 字节碎片被当作整片 1340 发出。

**每个 1353 字节数据报花掉 2680 字节线上载荷 → 1.98×。** 算术闭合：

    1.98（填充）× 1.67（parity）= 3.30   →   1/3.30 = 30.3%（实测 delivery_ppm 29.1%）

这是**格式导致的固定倍数浪费**，与速率无关——所以怎么调拥塞控制器都不会动，这正是
它此前一直无法归因的原因。

**修复**：分片改均衡切分（`per = ceil(len/count)`），1353 字节 → `677 + 676`，
填充无事可做。**无任何线格式变更**：接收端本就按 `FRAGMENT_HEADER` 里的 per-fragment
`len` 截取。

**部署实测（03:32 修复前 vs 03:37 修复后，同一时段、同一链路、同一配置 `fixed@24`）**：

| | dl1 | dl2 | dl3 | dl4 | dl5 | `delivery_ppm` |
| --- | --- | --- | --- | --- | --- | --- |
| 修复前 | 508,681 | 583,831 | 683,736 | 469,396 | 654,572 | **29.1%** |
| 修复后 | 277,263 | 897,549 | 935,896 | **1,092,301** | 839,190 | **57.5–60.8%** |

**下行效率 29% → 57–61%（约 2×），吞吐峰值从 0.94 MB/s 提到 1.09 MB/s。**
§10.8 列出的"首要限制因素"至此已被消除。

**仍未达成**：交付 20+ Mbps 未实现（当前峰值约 8.7 Mbps）。

#### 修复后的完整归因（四边界账目，同 interval 对齐）

修复后再测一个下行区间（`interval=358090294`）：

| 项 | 值 |
| --- | --- |
| `wire_rx_bytes` | 10,626,504（2.13 MB/s = 17.0 Mbps） |
| `inner_tx_bytes` | 6,341,191（1.27 MB/s = 10.1 Mbps） |
| `wire_to_inner_ppm` | 59.7% |
| 数据帧 / 校验帧 | 8478 / 4558 → **parity 开销 0.538×** |
| 数据帧 ÷ 数据报 | 1.79 |

分解：总比 `1/0.597 = 1.676×` = **parity 1.538×** × **非 parity 项 1.090×**。

**非 parity 项（头部 + 残留填充）已从 1.98× 降到 1.090×**——即本次修复的对象；剩余
的 1.538× 是 FEC 校验开销，由**当前 WAN 的 15.7–21.8% 丢包**直接导致。

校验 parity 控制器是否合理：按 `(1 − P(X>k)) / (1 + k/10)` 计算，

| 链路丢包 | 最优 parity | 线上开销 | 含格式 1.090× 后的总效率 |
| --- | --- | --- | --- |
| 0.05%（好 WAN） | 1 | 1.10× | **83.5%** |
| 5% | 2 | 1.20× | 75.0% |
| 15.6% | 4 | 1.40× | 62.0% |
| 20% | 5 | 1.50× | 57.5% |
| 21.8% | 5 | 1.50× | 55.9% |

实测 parity 5.38、效率 59.7%，落在 15.6%–21.8% 两行之间——**控制器选得是对的**。

#### "交付 20 Mbps"在本链路可达性的判定

服务端出方向硬顶实测 **30.8 Mbps**。要交付 20 Mbps：

    20 × 1.5 (parity@20%丢包) × 1.09 (格式) = 32.7 Mbps  >  30.8 Mbps   ✗ 不可能
    20 × 1.1 (parity@0.05%丢包) × 1.09 (格式) = 24.0 Mbps <  30.8 Mbps   ✓ 可达

**结论：在载体当前所在的那条 20% 丢包 WAN 上，"交付 20 Mbps"物理上不可达；换到
0.05% 丢包的那条 WAN 后可达，且预计效率从 59.7% 升到约 83.5%。**

所以剩下的唯一大杠杆是**路径选择**（iKuai 策略路由），不是代码。加大 `DATA_SHARDS`
（10→32）理论上再得约 7%（62.0%→66.3%@15.6% 丢包），但会被 5ms flush 定时器稀释，
且增加分组延迟，收益/风险不划算。

另记（T1 埋点的一次自我纠错）：该比值原名为 `delivery_ppm`，读作"投递率"，
导致我在 T3 期间把 29% 误读为丢包。它的分母是**线上字节**（含 parity），所以数值由
校验开销主导而非丢包。已更名为 `wire_to_inner_ppm` 并单列 `parity_frame_ppm`，
使开销与丢包可以分开读。

### 10.13 冗余的目标函数：RFC 9265 直接预测了一个反直觉的结果

#### 观测

同窗口埋点显示 `missing` 与真实数据损失 `unrecovered_shards` **解耦甚至反相关**：

| 时刻 | `missing` | `unrecovered_shards` | `failed_groups` |
| --- | --- | --- | --- |
| 03:49:04 | 274 | 0 | 0 |
| 03:49:06 | **0** | **213** | **62** |
| 03:49:12 | **0** | **315** | **81** |
| 03:49:14 | 373 | 0 | 0 |

而 parity 控制器正是由 `missing` 派生的 `smoothed_loss_ppm` 驱动的。

#### 规范核验：RFC 9265 §3/§4 预测"对可靠传输，冗余主要是降低有效吞吐"

原文（<https://www.rfc-editor.org/rfc/rfc9265.txt>）：

> §3："For reliable transfers, **coding usage does not guarantee better performance;
> instead, it would mainly reduce goodput**."
>
> §4："For reliable transfers, **including redundancy reduces goodput for long
> transfers** … There is a trade-off between 1) the capacity that could have been
> exploited by application data instead of transmitting source packets and 2) the
> benefits derived from transmitting repair symbols."

**适用条件由本项目自己的架构决定**：RFC 9265 §5（FEC 置于传输层之下）说这种摆放
"Including redundancy adds traffic **without reducing goodput**"——但那成立的前提是冗余
**在传输层速率之外额外增加**。而本项目里 **FEC pacer 与载体速率出自同一份预算**
（§10.5 的耦合；实测 FEC pacer 28 Mbps 与载体上限 30 Mbps 抢同一根管子），所以冗余是
**从载荷里扣**的，落在 §3/§4 的情形。

内层又是 TUIC（可靠传输），**失败的数据会被重传**——所以一次组失败的真实代价远低于
`target()` 模型假设的"完全丢失"：

    模型：(1 − P(组失败)) / (1 + parity/10)     隐含"组失败 = 数据彻底丢失"
    真实： 组失败 → TUIC 重传一次              代价 ≈ 一个额外往返，不是丢一份数据

若重传 20% 的代价低于用 50% 开销（parity=5）去避免它，则模型给出的最优 parity **偏高**。
这与 T2/T3 三轮工作的方向相反——那三轮都在让 parity 更及时地升上去。

#### 受控 A/B：**因双 WAN 漂移而失败**

同一时段固定 parity = 1 / 3 / 5 各测一轮，结果载体**中途翻了 WAN**：

| 轮次 | 载体 `rtt_ms` | 载体丢包 | 路径 |
| --- | --- | --- | --- |
| parity=1 | **67** | 4.5% | 快/丢包那条 |
| parity=3 | **386** | 0% | **干净那条** |
| parity=5 | **350** | 0% | **干净那条** |

parity 1 与 parity 3/5 测的不是同一条路径，**比较无效**。另有一处测量设计错误：脚本读取的
`tx_parity` 是**客户端自己上行**的 parity，不是服务端被固定的下行 parity。

**方法论结论（比这一轮的数字更有价值）**：**双 WAN 漂移的翻转尺度是分钟级，因此任何长于
一分钟的 A/B 都不可靠。** 这与 §10.8 的吞吐结论同根，只不过这次它毁掉的是**实验能力**
而不只是吞吐。**受控 A/B 在 iKuai 钉住单条 WAN 之前无法进行。**

#### 修正：改用长采样 + 按 WAN 分层后，A/B 做成了

前两次尝试失败在**测量台**上，不是实验设计上：

1. 交错短轮（1,3,5,1,3,5…）用了 9 次服务重启——每次改 parity 都要重启 FEC 服务并中断
   隧道，12 秒不够恢复，多数轮次量到 `dl_bps=0`；
2. 长采样版依赖路由器的 `logread` 读 WAN/丢包字段，而 **`logread` 在负载下会触发 libc 的
   general protection fault**（`dmesg: traps: logread[24076] general protection fault …
   in libc.so`），脚本卡死、编排器的恢复分支不执行，`SMART_FEC_FORCE_PARITY` 被留在生产上
   （已发现并清除，进程级核实为 0 次）。

第三版：**只改两次 parity、每次连续采样 4–5 分钟、WAN 判定改用 `ping`**（52–90 ms 是
快/丢包条，350–370 ms 是干净条），完全不碰 `logread`。

**结果（同一条 WAN：快/丢包条，ping 52–90 ms，载体丢包 15–35%）**：

| parity | n | 中位数 | 均值 | 范围 |
| --- | --- | --- | --- | --- |
| 5 | 18 | 1,142,952 B/s | 1,075,883 | 662,529 – 1,401,190 |
| **1** | 7 | **1,610,632 B/s** | 1,319,289 | 762,743 – 1,628,176 |

**中位数差 +40.9%，置换检验 p ≈ 0.85%。parity=1 显著快于 parity=5。**

#### 为什么理论模型给不出这个结论——它漏了"突发"

`fec_goodput_factor` 算的是 `(1 − P(组失败)) / (1 + parity/10)`，在 p=20% 时给出
parity 1 → 0.293、parity 5 → 0.626，即**强烈偏好高 parity**。把代价模型改成"组失败不是
数据丢失、而是被内层重传"（`1/((1+r)(1+f))`）后，最优仍在 parity 4–5 附近。**两种模型都
指向 parity 5，而实测反过来。**

原因在**突发**：实测组失败率 21.3%，而同样丢包率下独立模型的预期只有 2.0–8.7%。也就是说
**在这条链路上，提高 parity 并不能按比例换来保护**——parity=5 期间 `unrecovered_shards`
依然出现 662 / 1217 / 505 / 305 这样的值。于是它付出了 50% 开销，却仍旧漏数据，
**两项都输给 parity=1**。

**所以正确的控制律不是修一个系数，而是换输入**：不要再由"推测的丢包率"经模型反推 parity，
而应由**实测的未恢复数据量**（T1 的 `unrecovered_shards`）驱动——在残余损失可接受的前提下
取**最低** parity。这与 T2/T3 三轮的方向相反，那三轮都在让 parity 更及时地升上去。

**本轮未实现该改动**：按 T3/T3b/T3c 三次"未在真实链路验证就部署"的教训，控制器改动必须
配套可验证的实验，而实验台是这一轮才做成的。

**仍未达成**：交付 20+ Mbps。本链路（快/丢包条）上 parity=1 的中位数为 1.61 MB/s
（≈12.9 Mbps）。

### 10.14 实现：`SMART_FEC_MAX_PARITY`（给已知错误的模型加边界，而不是继续信它）

§10.13 的结论是**换控制律**（由实测 `unrecovered_shards` 驱动，而不是由推测丢包率经模型
反推），但那需要把**接收端 goodput** 放进反馈帧，而 `FEEDBACK_V2_LEN=24` 已经占满，属于
线格式变更 + 三级协商，不能顺手做。**在那之前，能做且诚实的只有一件事：让模型的结果可以被
运维按实测覆盖。**

改动只有一个字段：

```rust
struct Adaptive { parity: usize, max_parity: usize, /* … */ }
fn configured_max_parity() -> usize { /* SMART_FEC_MAX_PARITY，clamp 到 [MIN_PARITY, MAX_PARITY] */ }
fn target(loss_ppm: u32, max_parity: usize) -> usize { for parity in MIN_PARITY..=max_parity { … } }
```

两条升级路径（`report()` 里 `target > parity` 的跳升、以及 `bad >= 2` 的逐级上升）也都
`.min(self.max_parity)`，所以上限在任何路径下都成立。**默认值等于 `MAX_PARITY`，行为与
改动前逐位一致**——这不是一个"默认开启的优化"。

#### 为什么不做成"自动找 parity 1"

因为**任何由丢包驱动的规则都找不到 parity 1**：parity 1 时残余丢包必然存在（§10.13 实测
`unrecovered_shards` 662 / 1217 / 505 / 305），规则看到它就会升。要找到最优点，输入必须是
**交付量**而不是**损失量**——这正是 §10.13 末尾那条"换输入"的路，需要线格式变更。

用 `SMART_FEC_MAX_PARITY=1` 等于**用运维的实测判断替换掉一个已被实测否证的模型**。这与
T3/T3b/T3c 三次"控制器改完直接上生产"的教训一致：没有配套可验证实验的控制器改动不上生产，
而在实验台已具备（§10.13 第三版）之后，这个决定是可以被测的。

#### 测试

`fec_target_respects_the_configured_ceiling`：对 loss ∈ {0, 5%, 20%, 90%} 断言
`target(loss, MIN_PARITY) == MIN_PARITY`（上限压到地板时必须钉死）且 `target(loss, 3) <= 3`。
`fec_target_maximises_goodput_not_parity` 保持原样（在 `max_parity = MAX_PARITY` 下），
**原模型的形状没有被改动**，改动前后 86 项测试全绿。

#### 联网查证：独立文献复述了同一条结论

本项目的 §10.13 是**先测出来、再回头看规范**。查证到一篇 2025 年的 ACM 论文独立复述了
同一现象，且它正是该论文的立论动机：

> "This **sparse- yet- bursty** nature makes it difficult for **reactive FEC schemes** to
> configure an appropriate redundancy rate."
> —— *Triage: Boosting Cross-region Video Conferencing with Proactive FEC on Overlay
> Network*, Proc. ACM Netw. (CoNEXT) 2025, DOI
> [10.1145/3830396](https://dl.acm.org/doi/abs/10.1145/3830396)

这与 §10.13 的实测同向：**突发**（实测组失败率 21.3% vs 独立模型预期 2.0–8.7%）使"反应式"
FEC 冗余控制无法定出合适的冗余率——本项目三轮基于丢包的设计（T2/T3/T3b）全部失败，是同一
原因的不同表现。该论文的解法是 **proactive**（不等丢包、提前编码），而不是把反应式系数调得
更好；本项目 §10.13 末尾"换输入"（用交付量而不是损失量）属于同一方向。

**注意这条引用的边界**：它支持"反应式+突发⇒冗余率定不准"，**不支持**"parity 就该是 1"。
后者目前只有本项目自己在一条 WAN 上的 A/B 证据（n=25，p≈0.85%），不构成普适结论——这正是
把它做成**可配置上限**而不是改成默认值的原因。

#### 本次改动的审计发现（同批修复）

改完自查发现三处问题，都已修并有守卫：

1. **部署守卫有盲区（真缺口，会静默失效）**：`tests/deploy_env_coverage.rs` 只扫描
   `src/quic_relay.rs`，并在注释里"诚实标注"了这个局限。而 `SMART_FEC_MAX_PARITY` 加在
   `src/main.rs`——于是它可以被设置、被**静默忽略**，守卫却毫无反应，即守卫存在的理由本身。
   现在扫描 `src/` 下所有读取 `std::env::var("SMART_...")` 字面量的文件，并对每个文件断言
   最少扫出 N 个变量（扫描失效必须失败，恒真的守卫比没有守卫更糟）。
   同时路由器 init 转发该变量（**上行**冗余由客户端生成，所以在路由器上有效）。
2. **豁免名单腐烂（守卫升级后立刻抓到）**：`NOT_FORWARDED` 里列着 `SMART_QUIC_UPSTREAM`，
   但它早已改成 clap 的 `--upstream` 参数、不再是环境变量。新增的
   `not_forwarded_list_only_contains_variables_the_binary_reads` 用例把它抓了出来。
3. **拼写错误静默回落**：初版对无法解析的值无声回落到 `MAX_PARITY`，即"以为设了上限、其实
   没设"，与第 1 条是同一类伤害。现在越界打 WARN 并钳到最近端点、无法解析打 WARN 并说明
   "上限未生效"。解析抽成纯函数 `parse_max_parity(Option<&str>)` 以便测试（不依赖进程环境，
   并发下 `set_var` 不安全）。

**测试时序假失败（同批修复）**：`production_sized_datagrams_survive_ten_percent_loss` 在
四个用例并行时偶发跌破 0.80，空载单跑 3/3 通过（每次约 24.4s）。原因是每个 harness 要跑
2 个子进程 + 3 个线程并按固定间隔灌包，**网络端口独立但 CPU 与时序不独立**。已加全局
`HARNESS_LOCK` 串行化（27s → 79s），并把文件头"使用动态端口，测试可并行"这句只对端口成立的
话删掉。理由：**一个会随机失败的守卫比一个慢的守卫更贵**，假失败会训练人去忽略它。

门禁：`cargo fmt --check` 与 `cargo clippy --all-targets -- -D warnings` 干净，
`cargo test` **88 项全绿**（37 lib + 45 bin + 2 deploy_env_coverage + 4 fec_loss_integration）。

#### 仍未达成

交付 20+ Mbps。本链路（快/丢包条）parity=1 中位数 1.61 MB/s ≈ 12.9 Mbps，受 §10.12/§10.8
的 30.8 Mbps 出口硬顶与 1.09× 非冗余项共同约束（`20 × 1.1 × 1.09 = 24.0 Mbps < 30.8`，即在
干净那条 WAN 上可达，在快/丢包条上 `20 × 1.5 × 1.09 = 32.7 > 30.8` 物理不可达）。

### 10.15 记账仪器本身是坏的：第一个 session 结束后永久静默（已修复）

这是本轮最重要的发现，且**它削弱了 §10.12/§10.13 的证据基础**。

#### 症状

线上观察到互相矛盾的四个事实（同一次 5 MB 下载，2026-09-27 04:55）：

| 证据 | 观测 |
| --- | --- |
| 服务端 eth0 | rx **+6.25 MB**，tx **+8.33 MB** |
| UDP/443 QUIC 载体 counters | `tx_bytes` **+7.69 MB** |
| TCP/443 sing-box VLESS | **0 个已建立连接，0 字节**（排除了旁路假设） |
| `smart-fec-server` 的 `FEC traffic accounting` | **0 行** |

即：流量确实走 FEC 隧道（载体搬了 7.69 MB），但记账**一行都没有**。

#### 根因

```rust
let logs_traffic = TRAFFIC_LOGGER_CLAIMED
    .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
    .is_ok();
```

`TRAFFIC_LOGGER_CLAIMED` 的**原意**是"避免 N 个并发 session 各自上报同一份全局总量的
重叠增量"，但它是一个 `AtomicBool`，**置位后永不释放**。于是它不是"同一时刻只有一个
session 记账"，而是"**整个进程只有第一个 session 记账**"。

生产上 session 几分钟就重连一次（实测 04:40:06 / 04:40:45 / 04:46:34 / 04:47:17 四次），
所以 04:47:17 那个 session 接管之后，**该进程余生再无任何账目**——而那正是隧道最忙的时候。
一个不出错的死仪器比吵闹的仪器更危险：**"没有记录"会被读成"没有流量"**。

#### 修复

改成 RAII 守卫 `TrafficLoggerClaim`，session 结束时 `Drop` 归还名额，语义才真正等于注释
里写的"恰好一个**存活** session 记账"：

```rust
let _traffic_claim = TrafficLoggerClaim::try_acquire();   // 具名绑定，不能用 `let _ =`
let logs_traffic = _traffic_claim.is_some();
```

回归用例 `traffic_logger_claim_is_released_when_the_session_ends` 钉住该行为：并发第二个
claim 必须失败、**前一个结束后后来者必须能接管**。已按"先证明用例能抓住旧实现"的方式验证：
把 `Drop` 改成空实现后，用例以
`a later session must be able to take over after the previous one ended` 失败。

**部署后实测**：重启 100 秒内账目 **21 行**、期间 **2 次 session 建立**——重连后确实继续
记账。修复前同一场景为 0 行。

#### 对已有结论的影响（诚实标注）

§10.12/§10.13 的归因全部建立在这个仪器上。修复前它只在**每次重启后的第一个 session** 里
有效，因此那些"同窗口埋点"的数字只可能来自那段窗口；若当时落在别的 session 上，读到的是
**几乎空载的账目**——本轮就抓到过 `wire_to_inner_ppm=28490`（2.8%）这种与"空闲窗口"特征
一致的值。这不推翻 §10.12 的 RS 填充结论（那是用**帧数比** `5327/2694=1.977` 算的，与字节
口径无关），但**字节口径的效率数字需要重测**。

#### 同期修好的仪器缺陷（否则新测量同样不可信）

1. **采样器太短**：A/B 用的 5 MB 下载测的是 **TCP 慢启动**，不是稳态——同一个 URL
   5 MB → 1.67 MB/s，80 MB → **13.8 MB/s**。
2. **`ping` 不能当 WAN 标签**：负载均衡按流哈希，ICMP 与 UDP/443 落在不同 WAN——同一时刻
   `ping=51ms` 而载体 `rtt_ms=384ms`。**权威标签是载体自己的 `rtt_ms`/`wire_loss_ppm`**。
   这使 §10.13 那次 A/B 的"同一条 WAN"分层不可靠。
3. **方向配对**：`wire_to_inner_ppm = inner_tx/wire_rx` 把**上行**载荷配**下行**字节，只有
   双向对称时才有意义；下行效率的正确配对是 `inner_rx/wire_tx`。

#### 用修好的仪器测到的真实分解（40 MB 下载，丢包那条 WAN）

载体 `rtt=52–65 ms`、丢包 **12.8–22.9%**；自适应 parity 升到 **4→5**。

| 量 | 值 |
| --- | --- |
| `inner_rx_bytes`（下行载荷） | 47.30 MB |
| `wire_tx_bytes`（线上字节） | 77.38 MB |
| `wire/inner` | **1.636（效率 61.1%）** |
| `frames/datagram` | 1.969 |
| `parity/data` | **0.436** |
| 线上速率 | 77.38 MB / 34 s = **18.2 Mbps** |
| 端到端下载 | 40 MB / 29.9 s = **1.336 MB/s ≈ 10.7 Mbps** |

**关键推论**：`1.636 = 1.139`（数据面：1344 B 报文分两片 + 帧头）`× 1.436`（FEC 冗余）。
**服务端只用了 18.2 Mbps，远低于 30 Mbps 出口硬顶——瓶颈不是出口计费带宽**，而是载体在
18–23% 丢包下的拥塞控制（每秒 959–1631 次 `congestion_events`）。因此把 parity 压到 1
（冗余 0.436→0.1）预计把线上字节降到 1.253×，在 `fixed@24` 固定速率下**载荷吞吐 +23%**
（≈1.34 → 1.65 MB/s ≈ 13.2 Mbps），**仍不足以达到 20 Mbps**。

#### 本轮的部署状态与未决

- 两端二进制 `a0c5252bb01363361ba08f7b67eef237`；`SMART_FEC_MAX_PARITY` **未设置**
  （保持改动前行为）——本轮的受控 A/B **因 WAN 漂移而不成立**（两个 arm 分别落在
  载体 `rtt` 384/450–490 ms 与 64–84 ms，且控制器在两个 arm 里都停在 parity 1，
  上限根本没生效），**因此不以那次 A/B 为依据改动生产**。
- 是否设 `SMART_FEC_MAX_PARITY=1` 需要用修好的仪器重测：**大载荷（≥40 MB）**、
  以**载体 `rtt_ms`** 分层、两 arm 各 ≥5 分钟。
- **真正的瓶颈已从"FEC 冗余"转移到"载体在 20% 丢包下的速率控制"**：下一步应针对
  `congestion_events` 每秒上千次这一事实，而不是继续调 parity。

### 10.16 FEC pacer 把睡眠超时丢掉：28 Mbps 只发出 19 Mbps（已修复）

§10.15 把记账修好之后，第一个可用的分解立刻暴露了一个**与拥塞控制无关**的限速点。

#### 定位过程

同一窗口里三个数字指向同一处：

| 层 | 实测 | 该层的目标 |
| --- | --- | --- |
| FEC 层 `wire_tx_bytes` | 81.14 MB / 34 s = **19.1 Mbps** | `--rate-mbps 28` |
| 载体 UDP 发送 | 与 FEC 层**相等**（FEC 给多少就发多少） | `fixed@24`，丢包时**不缩窗**，目标 `24/0.79 ≈ 30 Mbps` |
| 端到端下载 | 1.336 MB/s ≈ 10.7 Mbps | — |

载体不是瓶颈（`FixedRate::on_congestion_event` 明确不缩窗，只记 `ack_rate`），于是瓶颈落在
FEC 层的 [`Pacer`]。

#### 根因：睡到桶满，且不记超时

旧实现是一个 token bucket：配额不足时 `sleep((capacity - tokens) / bps)` —— 睡到**桶满**
—— 然后无条件 `tokens = capacity`。**无论实际睡了多久，都只换回"一桶"配额，超时那部分是
净损失。**

28 Mbps 下 `capacity = rate × 4 ms = 14 KB`。标称 4 ms 的 sleep 若实际耗时 6 ms，长期速率
就是 `14 KB / 6 ms = 2.33 MB/s = 18.7 Mbps` —— **目标的 67%**。

**与实测吻合到小数点后一位**：实测 2.386 MB/s（= 目标的 68.2%），模型 2.33 MB/s。

#### 修复：虚拟时钟（GCRA）

每次 `wait` 只把虚拟时钟向前推 `bytes / bps`，发送不早于虚拟时钟；睡眠超时使虚拟时钟
落后于真实时钟，于是后续调用立即发送直到追平——**超时被记在账上**。长期速率因此精确等于
`bytes_per_second`，与调度器抖动无关。`max_debt = 40 ms` 限制最大追赶突发。

决策部分抽成纯函数 `pace_step`，因为真实 `sleep` 的超时在单测里无法复现，而"超时如何记账"
正是这里唯一的逻辑。

#### 验证：把新旧两种记账放在同一超时下对比

`tests::pacer_repays_sleep_overshoot`（线上参数：28 Mbps、1392 B/帧、标称 4 ms 实际 6 ms）：

    目标 3.500 MB/s  虚拟时钟 = 3.500 (100.0%)  旧 token bucket = 2.332 (66.6%)

用例同时断言**旧实现达不到目标**，以防有人把记账方式改回去。

**诚实标注**：这是单元级的确定性验证。**生产上的吞吐收益尚未确认**——修复部署后载体换到了
另一条 WAN（rtt 370 ms、0 丢包），与修复前那次（rtt 52 ms、18–23% 丢包）不可比。

#### 同一批测量解决的另一个问题：`SMART_FEC_MAX_PARITY` 不需要设置

无丢包那条 WAN 上，控制器**自己就选了 parity 1**：40 MB 下载窗口内 `parity/data = 0.123`、
`wire/inner = 1.274`（**效率 78.5%**）、`groups_failed = 0`。也就是说 §10.14 那个上限在
这条 WAN 上根本不生效，**不需要**动它。生产保持未设置（§10.15 的决定得到支持）。

顺带：这也让 T5 的"效率 22%→40%+"目标以 **78.5%** 超额达成。

#### 关键新事实：上限在隧道**内部**，不在源站、不在 WARP、不在计费带宽

在服务器本机对同一个 URL 直接测速（30 MB）：

| 路径 | 速率 |
| --- | --- |
| 服务器直连（无代理） | **16.93 MB/s**（135 Mbps） |
| 服务器经 WARP | **16.84 MB/s** |
| 服务器经本地 socks 18080 | 10.95 MB/s |
| WARP 三个 worker | 12.2 / 5.3 / 15.3 MB/s |
| **经整条隧道到路由器** | **1.686 MB/s** |

**源站与 WARP 那条腿有 135 Mbps，隧道只交出 13.5 Mbps——约 90% 的能力在隧道栈内部丢失。**
这排除了"出口计费带宽"与"上游太慢"两种解释，把问题锁定在隧道自身的限速/拥塞控制上（FEC
pacer、quinn pacer 或内层 TUIC 的 CC）。§10.15 曾把它归因于载体拥塞控制；本节的对比说明
载体控制器**不是**缩窗的那一个，真正的限速点在 pacer 的记账上。

### 10.17 单变量探针：限速点**不在** FEC pacer，而在内层 TUIC

§10.16 的分解仍留下一个歧义：19.1 Mbps 的线上速率究竟是 pacer 自己丢掉了超时，还是下游
（载体 socket 背压 / 内层 TUIC）本来就只喂这么多？两者都会让"FEC 层线上字节"落在这个数上。

#### 实验设计

只改一个变量：把服务端 FEC pacer 的目标从 `--rate-mbps 28` 提到 **200**（7.1 倍），
其余全部不动（用 systemd drop-in，便于精确还原）。

| 配置 | 端到端下载 | FEC 层线上速率 |
| --- | --- | --- |
| `--rate-mbps 28` | 1.686 MB/s | 1.686 MB/s |
| `--rate-mbps 200` | **1.768 MB/s**（+4.9%） | 1.861 MB/s |

**把限速器提高 7 倍，吞吐只动了 4.9%。所以 FEC pacer 不是限速点。**

#### 真正的限速点

同一次 200 Mbps 探针窗口里，方向配对后的分解是：

| 量 | 值 |
| --- | --- |
| `inner_rx_bytes`（**内层 TUIC 交给 FEC 层的载荷**） | 40.88 MB / 27 s = **1.514 MB/s = 12.1 Mbps** |
| `wire_tx_bytes`（FEC 层发到线上） | 50.25 MB / 27 s = 1.861 MB/s |
| `wire/inner` | 1.289（效率 77.6%） |
| `parity/data` | 0.124（控制器自选 parity 1） |
| 载体丢包 | 0（rtt 335 ms） |

也就是说：**内层 TUIC 只交出 12.1 Mbps，FEC 层忠实地把它按 1.289 倍搬到线上，载体一个包
都没丢。** 瓶颈在内层 TUIC **自己**的拥塞控制上——它在一个 335–370 ms 的路径上跑可靠传输，
窗口被自己的 CC 限制住了。

这与"源站/WARP 有 135 Mbps"（§10.16）合起来给出完整结论：

    源站→WARP 可用      135 Mbps
    内层 TUIC 交出       12.1 Mbps   <-- 瓶颈在这里
    FEC 层放大 1.289x    15.6 Mbps
    线上实际             14.9 Mbps
    端到端交付           14.1 Mbps

#### 一个反直觉的推论：低 RTT 的丢包 WAN 可能优于高 RTT 的干净 WAN

实测两条 WAN 上的端到端下载：

| WAN | 载体 rtt | 载体丢包 | 端到端 |
| --- | --- | --- | --- |
| 快/丢包那条 | 52 ms | 18–23% | 1.336 MB/s |
| 干净那条 | 335–370 ms | ~0% | 1.686–1.768 MB/s |

差距只有 ~1.3 倍，而 RTT 差 6.4 倍。**因为瓶颈是内层可靠协议的窗口，RTT 直接影响它**：
把流量钉到 370 ms 那条"干净"WAN 并不显然更优，而 iKuai 的按流哈希会让同一条隧道在不
同 WAN 之间漂移——这本身就是吞吐不稳定的一个来源。**这也意味着"钉到单条 WAN"这个待办
必须先确定钉哪一条，而不是随便钉。**

#### 与既有文献/规范的对应

这正是 TECC（NSDI '24，阿里）指出的问题：**内外两条连接的发送行为不匹配**——内层
可靠连接不知道外层隧道的真实网络状态，于是用自己的 CC 在一个被隧道改变了 RTT/丢包
特征的路径上做决策。TECC 的做法是把隧道服务端观测到的网络信息反馈给内层连接
（其报告中位数 FCT 降低 30%）。本项目 §10.14 结尾那条"换输入"的结论在这里第二次出现：
**要继续提升吞吐，要动的是内层的速率控制，而不是 FEC 的冗余。**

#### 本轮未做（下一轮的第一个任务）

内层 TUIC 的 CC 与窗口由 sing-box 提供，本项目无法直接改其控制器。可动的杠杆按可行性排序：

1. **让内层"以为"路径更好**：隧道已终结了丢包，但内层仍按端到端 RTT 估计 BDP。可评估
   sing-box 侧 TUIC 的 `congestion_control`（cubic/bbr/new_reno）与窗口相关参数，
   做与 §10.6 同规格的 A/B；
2. **减少内层往返放大**：确认 FEC 层的乱序/抖动是否让内层把 RTT 估高（§10.13 已记录
   RFC 9265 §5.5 的"spurious retransmissions"风险）；
3. **内外协同（TECC 式）**：把载体观测到的 rtt/loss 反馈给内层，属较大改动。

**注意**：第 1 条必须先在**同一条 WAN**上做 A/B，而 WAN 漂移正是 §10.13/§10.15 反复
失败的原因——**iKuai 侧的 WAN 固定应先于任何内层 CC 实验完成**。

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

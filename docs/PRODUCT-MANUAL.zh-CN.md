# Smart Gateway 第一版产品说明书

> 文档状态：第一版产品设计基线
> 当前仓库版本：`smart-fec-tunnel 0.2.0-alpha.1`
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
| Rust FEC 客户端/服务端 | 已实现 | 认证帧、Reed-Solomon FEC、乱序与内存上限 |
| UDP 速率整形 | 已实现 | 通过 `--rate-mbps` 配置；不是完整公平调度器 |
| WARP TCP 按连接轮询 | 已实现 | 三个 SOCKS 上游；失败时尝试其他上游 |
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
| 自适应 FEC、PMTU | 第一版目标 | 当前参数不是闭环自适应 |
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

当前 `0.2.0-alpha.1` 已用 FEC V2 实现每设备密钥、多活动会话和独立上游 UDP socket，并设置全局与单设备会话上限；V1 共享密钥仅用于迁移。但它仍不应作为未经压测和外部审计的多人商业服务直接部署：尚未实现用户级公平队列、在线撤销/热加载、无效认证速率限制和 100 用户验收。当前 WARP TCP balancer 是按连接轮询与失败尝试，不是完整的带权健康池。

在用户级公平调度、凭据在线撤销、完整 Controller 部署适配及计划中的验收全部完成前，本版本保持 Alpha 内测定位。

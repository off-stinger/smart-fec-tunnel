# 完整部署流程

## 前提

- 服务端：Linux、systemd、Python 3、sing-box，TCP/443 可由 Reality/VLESS 占用，UDP/443 空闲。
- 旁路由：OpenWrt/ImmortalWrt、procd、可通过 SSH 管理。
- 服务端须允许 UDP/443；内部端口 4443、18080、18101-18103 不应暴露公网。

## 1. 准备私密配置

复制 `configs/sing-box-deployment.example.json` 到仓库外，替换全部 `REPLACE_*`。三个 WARP endpoint 推荐使用独立账户/私钥/隧道地址；它们仍共享服务器公网 30 Mbps 上限。

部署规范只描述本项目托管的 TUIC inbound、WARP workers/endpoints/outbound 和路由。合并器不会重写现有日志、DNS、证书、Reality/VLESS 或其他出站。

`route_position` 默认 `first`，示例使用 `last`，让现有域名/IP 特例先命中，再执行通用 TCP/UDP 分流。`route_final` 仅在规范显式提供时修改。

## 2. 执行一键编排

```powershell
.\deploy\deploy-all.ps1 `
  -Server root@服务器IP `
  -OpenWrt root@旁路由IP `
  -ServerIdentityFile C:\keys\server.pem `
  -Binary .\smart-fec-tunnel-linux-amd64 `
  -ServerEndpoint 服务器IP:443 `
  -FecKey '<至少32字符随机值>' `
  -FecKeyId 1 `
  -SingBoxSpec C:\secure\sing-box-deployment.json `
  -StableGoogleEgress `
  -RateMbps 30
```

sing-box 阶段会依次：保存原配置和部署规范、生成候选配置、执行 `sing-box check`、原子替换、重启并检查 active 状态。校验或启动失败时不会继续部署；激活失败会恢复原配置并重启旧服务。

`-FecKeyId` 使用非零整数标识设备。相同设备重复部署会原子更新服务端 keyring 中对应条目，不影响其他设备；每台设备必须使用不同 ID 和随机密钥。省略或传入 `0` 仅用于旧版 V1 迁移，不建议新部署使用。keyring 权限为 `0600`，修改后需重启服务加载。

## 3. 验收

服务端：

```sh
systemctl is-active sing-box smart-fec-server smart-warp-balance
ss -lntup | grep -E ':(443|4443|18080|18101|18102|18103)\b'
journalctl -u sing-box -u smart-fec-server -u smart-warp-balance --since '-10 min' --no-pager
sing-box check -c /etc/sing-box/config.json
```

旁路由：

```sh
/etc/init.d/smart-fec-client status
logread -e smart-fec
```

确认无误后，再把 Passwall 的 TUIC 服务端改为本机 FEC 监听地址；脚本不会替你切换主链路。

### 3.1 单端 A/B 与升级顺序

载体的拥塞控制是发送端本地行为、不参与协商，因此可以只改一端做对照：

```sh
# 服务端（Debian）：写入既有 EnvironmentFile，不需要改 unit
echo 'SMART_QUIC_CONGESTION=cubic' >> /etc/smart-fec/quic.env
systemctl restart smart-fec-quic

# 旁路由（ImmortalWrt）：写入既有 env 文件，init 已转发该变量
echo 'SMART_QUIC_CONGESTION=cubic' >> /etc/smart-fec-quic.env
/etc/init.d/smart-fec-quic restart
```

对照时观察 `QUIC carrier stats`（5 秒一条）中的 `cwnd_bytes`、`congestion_events`、
`wire_loss_ppm`、`mtu`、`black_holes`，判读方法见产品说明书 §10.1。
**对照结束后不要改回 `new_reno`**：本链路实测 `new_reno` 的窗口会被压到
RFC 9002 下限（2944 字节）、吞吐 4.5 KB/s，而 `bbr` 与 `fixed` 都在 42–49 万 B/s。
丢包率明确（链路专线或已知随机丢包）时用 `fixed` 并配 `SMART_QUIC_FIXED_RATE_MBPS`，
否则用 `bbr`。完整对照见产品说明书 §10.6。

**不要用 `fixed` 超过链路真实容量**：`fixed` 是按配置速率发送、对丢包不做退让，
配高了丢包会变成永久性丢包，FEC 也补不回来（代码启动时会打印同样的告警）。
另外实际发送速率上限是配置值的 **1.25 倍**（ACK 速率补偿），且 FEC 开销出自同一
预算，因此 30 Mbps 链路应填 24 而不是 30（§10.5）。

### 3.2 旁路由 init 脚本的两条硬约束

`deploy/openwrt-smart-fec-quic.init` 的写法受两个 procd/解析器行为约束，改动时不要破坏：

1. **`procd_set_param env` 只能调用一次。** 该参数走
   `_procd_add_table → json_add_object("env")`，多次调用会生成重复的 `"env"` 键，
   JSON 解析后只有最后一次生效，**前面的环境变量被静默丢弃**。曾因此把
   `SMART_FEC_KEY` 弄丢，`quic-client` 以缺少 `--key` 崩溃并 crash loop。
   要加分项环境变量时，请追加到既有的那个 `envs` 字符串里。
2. **`SMART_QUIC_STREAM_LANES` 只在等于 `1` 时才传。** 不传即 DATAGRAM 模式（默认）。
   脚本不再传 `"0"`，以兼容不认识 `0` 的旧二进制；新版本解析器已把
   unset / 空白 / `"0"` 统一当作 DATAGRAM 处理。

FEC 反馈帧自本版本起带能力协商（先发 4 字节，确认对端支持后才发 24 字节），
因此两端**不再需要同时升级**，可以任意顺序滚动；若想绝对保守，升级一端后观察 5 分钟
再动另一端。详见产品说明书 §10.2。

Google/YouTube 稳定出口维护器每天刷新显式域名规则，将 Google 网页、API、静态资源以及 YouTube 页面/视频 CDN 的 TCP 请求统一交给 `warp-balance`；不再依据 Google 公布的云网段生成直连规则，也不依赖不断变动的 Google IP 列表。只有规则变化时才备份、校验并重启 sing-box；查看状态：

```sh
systemctl status smart-fec-google-route.timer
journalctl -u smart-fec-google-route.service --since '-7 days' --no-pager
```

## 4. 回滚

sing-box 备份目录为 `/root/smart-fec-sing-box-backup-时间戳/`。手工回滚：

```sh
cp -a /root/smart-fec-sing-box-backup-时间戳/config.json /etc/sing-box/config.json
sing-box check -c /etc/sing-box/config.json
systemctl restart sing-box
```

FEC 组件可运行 `deploy/uninstall.sh` 卸载；卸载不会删除 sing-box 配置或备份。

## 复刻到其他链路

每条链路使用独立的 FEC 密钥、TUIC 凭据和 WARP 私钥；调整公网端口及所有回环端口，确保不冲突。先在备用节点完成部署和验收，再切换 Passwall。不要把一份含真实私钥的规范复用或提交到 Git。

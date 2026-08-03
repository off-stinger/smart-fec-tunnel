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
  -SingBoxSpec C:\secure\sing-box-deployment.json `
  -RateMbps 30
```

sing-box 阶段会依次：保存原配置和部署规范、生成候选配置、执行 `sing-box check`、原子替换、重启并检查 active 状态。校验或启动失败时不会继续部署；激活失败会恢复原配置并重启旧服务。

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

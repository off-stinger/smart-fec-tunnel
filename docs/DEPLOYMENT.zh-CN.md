# 完整部署流程

## 1. 前置条件

- 服务端：Debian/Ubuntu、systemd、sing-box 1.13 或更新版本。
- 客户端：x86_64 OpenWrt/ImmortalWrt、procd、Passwall。
- 云防火墙允许服务端 UDP 443；TCP 443 可继续由 Reality/VLESS 使用。
- TUIC 服务端仅监听 `127.0.0.1:4443`。
- 三个 WARP mixed worker 仅监听 `127.0.0.1:18101..18103`。

## 2. 安全准备

生成独立 FEC 密钥：

```sh
openssl rand -hex 32
```

不要复用 TUIC、SSH、WARP 或 GitHub 凭据。不要把 `.env`、证书私钥、WARP私钥提交到仓库。

## 3. 服务端 sing-box

以 `configs/sing-box-server.example.json` 为结构参考，将自己的 TUIC TLS 和三个 WARP endpoint 合并到现有配置。先检查后重启：

```sh
sing-box check -c /etc/sing-box/config.json
systemctl restart sing-box
```

确认 4443、18101、18102、18103 都只监听回环地址。

## 4. 一键安装

在 Windows 管理机执行：

```powershell
.\deploy\deploy-all.ps1 `
  -Server root@203.0.113.10 `
  -OpenWrt root@192.0.2.1 `
  -ServerIdentityFile C:\keys\server.pem `
  -Binary .\dist\smart-fec-tunnel-linux-amd64 `
  -ServerEndpoint 203.0.113.10:443 `
  -FecKey '<随机密钥>' `
  -RateMbps 30
```

脚本会先备份旧文件，再安装两端服务。它不会自动切换 Passwall 主节点，避免部署错误导致断网。

## 5. Passwall 节点

建立 TUIC 节点，地址使用 `127.0.0.1`、端口使用 `3333`；UUID、密码、SNI、ALPN必须与服务端 TUIC 一致。先作为备用节点测试，验收通过后再手工切换 TCP/UDP 主节点。

## 6. 验收

```sh
systemctl is-active sing-box smart-fec-server smart-warp-balance
/etc/init.d/smart-fec-client status
```

建议测试：

1. 连续 DNS 查询。
2. 100 个短 HTTPS 请求。
3. 三路不同源站并发下载。
4. WARP A/B/C 分配计数。
5. 临时断开一个 worker，确认新连接由其他 worker承接。
6. 分别重启客户端和服务端，等待 30 秒后复测。

## 7. 跨链路复刻

每条新链路使用独立的 FEC 密钥、TUIC凭据、systemd服务名和回环端口。公网 UDP端口也应独立；若服务器IP不同，可继续使用 UDP 443。不要把同一请求复制到多条 WARP；负载单位是 TCP连接，一条连接始终固定在一个 WARP worker。

## 8. 回滚

安装脚本会输出备份目录。Passwall切换前记录原 TCP/UDP节点。出现失败时先切回原节点，再恢复备份或运行 `deploy/uninstall.sh`。卸载脚本故意保留二进制与密钥，防止误删后无法恢复。


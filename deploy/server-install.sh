#!/bin/sh
set -eu

usage() {
    echo "Usage: SMART_FEC_KEY=... $0 <binary> [rate-mbps] [tuic-upstream]" >&2
    exit 2
}

[ "$(id -u)" = 0 ] || { echo "Run as root" >&2; exit 1; }
[ "$#" -ge 1 ] || usage
[ -n "${SMART_FEC_KEY:-}" ] || { echo "SMART_FEC_KEY is required" >&2; exit 1; }

binary=$1
rate=${2:-30}
upstream=${3:-127.0.0.1:4443}
balance_listen=${SMART_WARP_BALANCE_LISTEN:-127.0.0.1:18080}
balance_upstreams=${SMART_WARP_UPSTREAMS:-"127.0.0.1:18101 127.0.0.1:18102 127.0.0.1:18103"}

[ -f "$binary" ] || { echo "Binary not found: $binary" >&2; exit 1; }
case "$rate" in *[!0-9.]*|'') echo "Invalid rate: $rate" >&2; exit 1;; esac

backup=/root/smart-fec-backup-$(date +%Y%m%d-%H%M%S)
mkdir -p "$backup"
[ ! -e /usr/local/bin/smart-fec-tunnel ] || cp -a /usr/local/bin/smart-fec-tunnel "$backup/"
[ ! -e /etc/smart-fec/server.env ] || cp -a /etc/smart-fec/server.env "$backup/"
[ ! -e /etc/systemd/system/smart-fec-server.service ] || cp -a /etc/systemd/system/smart-fec-server.service "$backup/"
[ ! -e /etc/systemd/system/smart-warp-balance.service ] || cp -a /etc/systemd/system/smart-warp-balance.service "$backup/"

install -m 0755 "$binary" /usr/local/bin/smart-fec-tunnel
mkdir -p /etc/smart-fec
umask 077
printf 'SMART_FEC_KEY=%s\n' "$SMART_FEC_KEY" > /etc/smart-fec/server.env

cat > /etc/systemd/system/smart-fec-server.service <<EOF
[Unit]
Description=Smart authenticated UDP FEC tunnel server
After=network-online.target sing-box.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/smart-fec/server.env
ExecStart=/usr/local/bin/smart-fec-tunnel server --listen 0.0.0.0:443 --upstream $upstream --rate-mbps $rate
Restart=always
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/smart-warp-balance.service <<EOF
[Unit]
Description=Smart WARP per-connection TCP load balancer
After=network-online.target sing-box.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/smart-fec-tunnel balance --listen $balance_listen --upstream $balance_upstreams
Restart=always
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemd-analyze verify /etc/systemd/system/smart-fec-server.service /etc/systemd/system/smart-warp-balance.service
systemctl daemon-reload
systemctl enable --now smart-fec-server smart-warp-balance
sleep 2
systemctl is-active --quiet smart-fec-server
systemctl is-active --quiet smart-warp-balance
echo "Installed successfully. Backup: $backup"


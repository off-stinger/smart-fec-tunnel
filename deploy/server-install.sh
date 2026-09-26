#!/bin/sh
set -eu

usage() {
    echo "Usage: SMART_FEC_KEY=... $0 <binary> [rate-mbps] [tuic-upstream]" >&2
    exit 2
}

[ "$(id -u)" = 0 ] || { echo "Run as root" >&2; exit 1; }
[ "$#" -ge 1 ] || usage
[ -n "${SMART_FEC_KEY:-}" ] || { echo "SMART_FEC_KEY is required" >&2; exit 1; }
case "$SMART_FEC_KEY" in *[[:space:]]*) echo "SMART_FEC_KEY must not contain whitespace" >&2; exit 1;; esac
[ "${SMART_FEC_KEY_ID:-}" = 0 ] && SMART_FEC_KEY_ID=
if [ -n "${SMART_FEC_KEY_ID:-}" ]; then
    case "$SMART_FEC_KEY_ID" in 0|*[!0-9]*) echo "SMART_FEC_KEY_ID must be a non-zero integer" >&2; exit 1;; esac
fi

binary=$1
rate=${2:-30}
upstream=${3:-127.0.0.1:4443}
balance_listen=${SMART_WARP_BALANCE_LISTEN:-127.0.0.1:18080}
balance_upstreams=${SMART_WARP_UPSTREAMS:-"127.0.0.1:18101 127.0.0.1:18102 127.0.0.1:18103"}

[ -f "$binary" ] || { echo "Binary not found: $binary" >&2; exit 1; }
case "$rate" in *[!0-9.]*|'') echo "Invalid rate: $rate" >&2; exit 1;; esac

backup=/root/smart-fec-backup-$(date +%Y%m%d-%H%M%S)
mkdir -m 0700 "$backup"
success=0
was_fec_active=0
was_balance_active=0
was_fec_enabled=0
was_balance_enabled=0
systemctl is-active --quiet smart-fec-server && was_fec_active=1 || true
systemctl is-active --quiet smart-warp-balance && was_balance_active=1 || true
systemctl is-enabled --quiet smart-fec-server && was_fec_enabled=1 || true
systemctl is-enabled --quiet smart-warp-balance && was_balance_enabled=1 || true
[ ! -e /usr/local/bin/smart-fec-tunnel ] || cp -a /usr/local/bin/smart-fec-tunnel "$backup/"
[ ! -e /etc/smart-fec/server.env ] || cp -a /etc/smart-fec/server.env "$backup/"
[ ! -e /etc/smart-fec/server.keys ] || cp -a /etc/smart-fec/server.keys "$backup/"
[ ! -e /etc/systemd/system/smart-fec-server.service ] || cp -a /etc/systemd/system/smart-fec-server.service "$backup/"
[ ! -e /etc/systemd/system/smart-warp-balance.service ] || cp -a /etc/systemd/system/smart-warp-balance.service "$backup/"

rollback() {
    [ "$success" -eq 1 ] && return 0
    echo "Installation failed; restoring previous Smart FEC files from $backup" >&2
    rm -f /usr/local/bin/smart-fec-tunnel.new
    if [ -e "$backup/smart-fec-tunnel" ]; then cp -a "$backup/smart-fec-tunnel" /usr/local/bin/smart-fec-tunnel; else rm -f /usr/local/bin/smart-fec-tunnel; fi
    for name in server.env server.keys; do
        if [ -e "$backup/$name" ]; then cp -a "$backup/$name" "/etc/smart-fec/$name"; else rm -f "/etc/smart-fec/$name"; fi
    done
    rm -f /etc/smart-fec/server.keys.new
    for unit in smart-fec-server smart-warp-balance; do
        if [ -e "$backup/$unit.service" ]; then
            cp -a "$backup/$unit.service" "/etc/systemd/system/$unit.service"
        else
            rm -f "/etc/systemd/system/$unit.service"
        fi
    done
    systemctl daemon-reload || true
    if [ "$was_fec_enabled" -eq 1 ]; then systemctl enable smart-fec-server || true; else systemctl disable smart-fec-server || true; fi
    if [ "$was_balance_enabled" -eq 1 ]; then systemctl enable smart-warp-balance || true; else systemctl disable smart-warp-balance || true; fi
    if [ "$was_fec_active" -eq 1 ]; then systemctl restart smart-fec-server || true; else systemctl stop smart-fec-server || true; fi
    if [ "$was_balance_active" -eq 1 ]; then systemctl restart smart-warp-balance || true; else systemctl stop smart-warp-balance || true; fi
}
trap rollback EXIT
trap 'exit 1' HUP INT TERM

install -m 0755 "$binary" /usr/local/bin/smart-fec-tunnel.new
mv -f /usr/local/bin/smart-fec-tunnel.new /usr/local/bin/smart-fec-tunnel
mkdir -p /etc/smart-fec
umask 077
if [ -n "${SMART_FEC_KEY_ID:-}" ]; then
    keyring_tmp=/etc/smart-fec/server.keys.new
    if [ -f /etc/smart-fec/server.keys ]; then
        awk -v id="$SMART_FEC_KEY_ID" '$1 != id' /etc/smart-fec/server.keys > "$keyring_tmp"
    else
        : > "$keyring_tmp"
    fi
    printf '%s %s\n' "$SMART_FEC_KEY_ID" "$SMART_FEC_KEY" >> "$keyring_tmp"
    chmod 0600 "$keyring_tmp"
    mv "$keyring_tmp" /etc/smart-fec/server.keys
    [ -f /etc/smart-fec/server.env ] || : > /etc/smart-fec/server.env
else
    printf 'SMART_FEC_KEY=%s\n' "$SMART_FEC_KEY" > /etc/smart-fec/server.env
fi

server_auth_args=
[ ! -s /etc/smart-fec/server.keys ] || server_auth_args='--keyring /etc/smart-fec/server.keys'

cat > /etc/systemd/system/smart-fec-server.service <<EOF
[Unit]
Description=Smart authenticated UDP FEC tunnel server
After=network-online.target sing-box.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/smart-fec/server.env
ExecStart=/usr/local/bin/smart-fec-tunnel server --listen 0.0.0.0:443 --upstream $upstream --rate-mbps $rate $server_auth_args
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
systemctl restart smart-fec-server smart-warp-balance
sleep 2
systemctl is-active --quiet smart-fec-server
systemctl is-active --quiet smart-warp-balance
echo "Installed successfully. Backup: $backup"
success=1

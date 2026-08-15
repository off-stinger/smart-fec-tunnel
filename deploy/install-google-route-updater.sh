#!/bin/sh
set -eu

[ "$(id -u)" = 0 ] || { echo "Run as root" >&2; exit 1; }
[ "$#" -eq 1 ] || { echo "Usage: $0 <add-google-stable-route.py>" >&2; exit 2; }
patcher=$1
[ -f "$patcher" ] || { echo "Patcher not found: $patcher" >&2; exit 1; }
command -v python3 >/dev/null
command -v sing-box >/dev/null
command -v systemctl >/dev/null

install -d -m 0755 /usr/local/lib/smart-fec
install -m 0755 "$patcher" /usr/local/lib/smart-fec/add-google-stable-route.py

cat > /usr/local/sbin/smart-fec-update-google-route <<'EOF'
#!/bin/sh
set -eu

config=/etc/sing-box/config.json
candidate=$config.google-auto-new
lock=/run/smart-fec-google-route.lock

if ! mkdir "$lock" 2>/dev/null; then
    echo "Google route update is already running" >&2
    exit 0
fi
cleanup() {
    rm -f "$candidate"
    rmdir "$lock" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

[ -f "$config" ] || { echo "Missing $config" >&2; exit 1; }
python3 /usr/local/lib/smart-fec/add-google-stable-route.py "$config" "$candidate"
chmod 0600 "$candidate"
sing-box check -c "$candidate"

if cmp -s "$config" "$candidate"; then
    echo "Google service ranges unchanged"
    exit 0
fi

backup=/root/sing-box-google-auto-backup-$(date +%Y%m%d-%H%M%S).json
cp -a "$config" "$backup"
mv "$candidate" "$config"
if ! systemctl restart sing-box || ! systemctl is-active --quiet sing-box; then
    echo "Activation failed; restoring $backup" >&2
    cp -a "$backup" "$config"
    systemctl restart sing-box || true
    exit 1
fi
echo "Google service routes updated. Backup: $backup"
EOF
chmod 0755 /usr/local/sbin/smart-fec-update-google-route

cat > /etc/systemd/system/smart-fec-google-route.service <<'EOF'
[Unit]
Description=Refresh stable Google egress routes from official ranges
After=network-online.target sing-box.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/smart-fec-update-google-route
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/etc/sing-box /root /run
PrivateTmp=true
EOF

cat > /etc/systemd/system/smart-fec-google-route.timer <<'EOF'
[Unit]
Description=Daily refresh of stable Google egress routes

[Timer]
OnBootSec=5min
OnUnitActiveSec=1d
RandomizedDelaySec=1h
Persistent=true
Unit=smart-fec-google-route.service

[Install]
WantedBy=timers.target
EOF

systemd-analyze verify /etc/systemd/system/smart-fec-google-route.service /etc/systemd/system/smart-fec-google-route.timer
systemctl daemon-reload
systemctl enable --now smart-fec-google-route.timer
systemctl start smart-fec-google-route.service
systemctl is-active --quiet smart-fec-google-route.timer
echo "Google route auto-updater installed"

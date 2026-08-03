#!/bin/sh
set -eu

usage() {
    echo "Usage: SMART_FEC_KEY=... $0 <binary> <server-ip:port> [rate-mbps]" >&2
    exit 2
}

[ "$(id -u)" = 0 ] || { echo "Run as root" >&2; exit 1; }
[ "$#" -ge 2 ] || usage
[ -n "${SMART_FEC_KEY:-}" ] || { echo "SMART_FEC_KEY is required" >&2; exit 1; }

binary=$1
server=$2
rate=${3:-30}
[ -f "$binary" ] || { echo "Binary not found: $binary" >&2; exit 1; }
case "$rate" in *[!0-9.]*|'') echo "Invalid rate: $rate" >&2; exit 1;; esac

backup=/root/smart-fec-backup-$(date +%Y%m%d-%H%M%S)
mkdir -p "$backup"
[ ! -e /usr/bin/smart-fec-tunnel ] || cp -a /usr/bin/smart-fec-tunnel "$backup/"
[ ! -e /etc/smart-fec.env ] || cp -a /etc/smart-fec.env "$backup/"
[ ! -e /etc/init.d/smart-fec-client ] || cp -a /etc/init.d/smart-fec-client "$backup/"

cp "$binary" /usr/bin/smart-fec-tunnel
chmod 0755 /usr/bin/smart-fec-tunnel
umask 077
{
    printf 'SMART_FEC_KEY=%s\n' "$SMART_FEC_KEY"
    printf 'SMART_FEC_SERVER=%s\n' "$server"
    printf 'SMART_FEC_RATE_MBPS=%s\n' "$rate"
} > /etc/smart-fec.env

cat > /etc/init.d/smart-fec-client <<'EOF'
#!/bin/sh /etc/rc.common
USE_PROCD=1
START=96
STOP=10

start_service() {
    . /etc/smart-fec.env
    procd_open_instance
    procd_set_param command /usr/bin/smart-fec-tunnel client \
        --listen 127.0.0.1:3333 \
        --server "$SMART_FEC_SERVER" \
        --rate-mbps "$SMART_FEC_RATE_MBPS"
    procd_set_param env SMART_FEC_KEY="$SMART_FEC_KEY" RUST_LOG=info
    procd_set_param respawn 3600 5 5
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
EOF
chmod 0755 /etc/init.d/smart-fec-client
/bin/sh -n /etc/init.d/smart-fec-client
/etc/init.d/smart-fec-client enable
/etc/init.d/smart-fec-client restart
sleep 2
/etc/init.d/smart-fec-client status | grep -q running
echo "Installed successfully. Backup: $backup"


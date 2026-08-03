#!/bin/sh
set -eu

[ "$(id -u)" = 0 ] || { echo "Run as root" >&2; exit 1; }
[ "$#" -ge 2 ] || { echo "Usage: $0 <merge.py> <deployment-spec.json> [config.json]" >&2; exit 2; }

merger=$1
spec=$2
config=${3:-/etc/sing-box/config.json}
[ -f "$merger" ] || { echo "Merger not found: $merger" >&2; exit 1; }
[ -f "$spec" ] || { echo "Deployment spec not found: $spec" >&2; exit 1; }
[ -f "$config" ] || { echo "sing-box config not found: $config" >&2; exit 1; }
command -v python3 >/dev/null
command -v sing-box >/dev/null
command -v systemctl >/dev/null

stamp=$(date +%Y%m%d-%H%M%S)
backup=/root/smart-fec-sing-box-backup-$stamp
candidate=$config.smart-fec-new
mkdir -m 0700 "$backup"
cp -a "$config" "$backup/config.json"
cp -a "$spec" "$backup/deployment-spec.json"
chmod 0600 "$backup/deployment-spec.json"

rollback() {
    echo "sing-box activation failed; restoring $backup/config.json" >&2
    cp -a "$backup/config.json" "$config"
    systemctl restart sing-box || true
    rm -f "$candidate"
}

python3 "$merger" --base "$config" --spec "$spec" --output "$candidate"
chmod 0600 "$candidate"
sing-box check -c "$candidate"

mkdir -p /etc/smart-fec
install -m 0600 "$spec" /etc/smart-fec/sing-box-deployment.json
mv "$candidate" "$config"
if ! systemctl restart sing-box || ! systemctl is-active --quiet sing-box; then
    rollback
    exit 1
fi
sleep 2
if ! systemctl is-active --quiet sing-box; then
    rollback
    exit 1
fi
echo "sing-box deployment succeeded. Backup: $backup"

#!/bin/sh
set -eu

usage() {
    echo "Usage: SMART_FEC_KEY=... $0 <binary> <server-ip:port> [rate-mbps]" >&2
    exit 2
}

[ "$(id -u)" = 0 ] || { echo "Run as root" >&2; exit 1; }
[ "$#" -ge 2 ] || usage
[ -n "${SMART_FEC_KEY:-}" ] || { echo "SMART_FEC_KEY is required" >&2; exit 1; }
case "$SMART_FEC_KEY" in *[[:space:]]*) echo "SMART_FEC_KEY must not contain whitespace" >&2; exit 1;; esac
[ "${SMART_FEC_KEY_ID:-}" = 0 ] && SMART_FEC_KEY_ID=
if [ -n "${SMART_FEC_KEY_ID:-}" ]; then
    case "$SMART_FEC_KEY_ID" in 0|*[!0-9]*) echo "SMART_FEC_KEY_ID must be a non-zero integer" >&2; exit 1;; esac
fi

binary=$1
server=$2
rate=${3:-30}
[ -f "$binary" ] || { echo "Binary not found: $binary" >&2; exit 1; }
case "$rate" in *[!0-9.]*|'') echo "Invalid rate: $rate" >&2; exit 1;; esac

backup=/root/smart-fec-backup-$(date +%Y%m%d-%H%M%S)
mkdir -m 0700 "$backup"
success=0
was_active=0
/etc/init.d/smart-fec-client status 2>/dev/null | grep -q running && was_active=1 || true
[ ! -e /usr/bin/smart-fec-tunnel ] || cp -a /usr/bin/smart-fec-tunnel "$backup/"
[ ! -e /etc/smart-fec.env ] || cp -a /etc/smart-fec.env "$backup/"
[ ! -e /etc/init.d/smart-fec-client ] || cp -a /etc/init.d/smart-fec-client "$backup/"

rollback() {
    [ "$success" -eq 1 ] && return 0
    echo "Installation failed; restoring previous OpenWrt Smart FEC files from $backup" >&2
    rm -f /usr/bin/smart-fec-tunnel.new
    for pair in "smart-fec-tunnel:/usr/bin/smart-fec-tunnel" "smart-fec.env:/etc/smart-fec.env" "smart-fec-client:/etc/init.d/smart-fec-client"; do
        source=${pair%%:*}
        target=${pair#*:}
        if [ -e "$backup/$source" ]; then cp -a "$backup/$source" "$target"; else rm -f "$target"; fi
    done
    if [ "$was_active" -eq 1 ]; then /etc/init.d/smart-fec-client restart || true; else /etc/init.d/smart-fec-client stop || true; fi
}
trap rollback EXIT
trap 'exit 1' HUP INT TERM

cp "$binary" /usr/bin/smart-fec-tunnel.new
chmod 0755 /usr/bin/smart-fec-tunnel.new
mv -f /usr/bin/smart-fec-tunnel.new /usr/bin/smart-fec-tunnel
umask 077
{
    printf 'SMART_FEC_KEY=%s\n' "$SMART_FEC_KEY"
    printf 'SMART_FEC_KEY_ID=%s\n' "${SMART_FEC_KEY_ID:-}"
    printf 'SMART_FEC_SERVER=%s\n' "$server"
    printf 'SMART_FEC_RATE_MBPS=%s\n' "$rate"
} > /etc/smart-fec.env

cat > /etc/init.d/smart-fec-client <<'EOF'
#!/bin/sh /etc/rc.common
USE_PROCD=1
START=96
STOP=10

start_service() {
    # 本进程是**上行方向的 FEC 编码器**，`SMART_FEC_*` 全部由它读取；载体
    # （smart-fec-quic）不读其中任何一个。把 FEC 层变量放进 quic 环境文件是无效的。
    #
    # procd 的 env 参数走 _procd_add_table -> json_add_object("env")：**只能调用一次**，
    # 多次调用会生成重复的 "env" 键，JSON 解析后只有最后一次生效，前面的变量被静默丢弃
    # （曾因此丢掉 SMART_FEC_KEY，client 以缺少 --key 崩溃并 crash loop）。所以下面
    # 合并成一个 $envs 字符串，只调用一次。
    . /etc/smart-fec.env
    procd_open_instance
    set -- /usr/bin/smart-fec-tunnel client \
        --listen 127.0.0.1:3333 \
        --server "$SMART_FEC_SERVER" \
        --rate-mbps "$SMART_FEC_RATE_MBPS"
    [ -z "${SMART_FEC_KEY_ID:-}" ] || set -- "$@" --key-id "$SMART_FEC_KEY_ID"
    procd_set_param command "$@"
    envs="SMART_FEC_KEY=$SMART_FEC_KEY RUST_LOG=info"
    # 以下三项都是 FEC 层的开关，只有本进程读。空值不传，以免覆盖二进制的默认值。
    [ -z "${SMART_FEC_TRAFFIC_LOG:-}" ] || envs="$envs SMART_FEC_TRAFFIC_LOG=$SMART_FEC_TRAFFIC_LOG"
    [ -z "${SMART_FEC_MAX_PARITY:-}" ] || envs="$envs SMART_FEC_MAX_PARITY=$SMART_FEC_MAX_PARITY"
    [ -z "${SMART_FEC_INTERLEAVE:-}" ] || envs="$envs SMART_FEC_INTERLEAVE=$SMART_FEC_INTERLEAVE"
    procd_set_param env $envs
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
success=1

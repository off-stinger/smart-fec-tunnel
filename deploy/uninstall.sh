#!/bin/sh
set -eu

case "$(uname -s)" in
    Linux) ;;
    *) echo "Unsupported system" >&2; exit 1;;
esac

if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now smart-fec-server smart-warp-balance smart-fec-google-route.timer 2>/dev/null || true
    rm -f /etc/systemd/system/smart-fec-server.service /etc/systemd/system/smart-warp-balance.service
    rm -f /etc/systemd/system/smart-fec-google-route.service /etc/systemd/system/smart-fec-google-route.timer
    systemctl daemon-reload
    echo "Server services removed. Binary and secrets were retained for recovery."
elif [ -x /etc/init.d/smart-fec-client ]; then
    /etc/init.d/smart-fec-client disable || true
    /etc/init.d/smart-fec-client stop || true
    rm -f /etc/init.d/smart-fec-client
    echo "OpenWrt service removed. Binary and secrets were retained for recovery."
else
    echo "No installation detected"
fi

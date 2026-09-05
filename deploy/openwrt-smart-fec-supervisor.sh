#!/bin/sh
set -u

SOCKS_ADDRESS="${SMART_FEC_HEALTH_SOCKS:-127.0.0.1:1071}"
FAILURE_LIMIT="${SMART_FEC_FAILURE_LIMIT:-3}"
PROBE_INTERVAL="${SMART_FEC_PROBE_INTERVAL:-10}"
RECOVERY_COOLDOWN="${SMART_FEC_RECOVERY_COOLDOWN:-30}"

probe() {
    curl --socks5-hostname "$SOCKS_ADDRESS" --silent --show-error \
        --output /dev/null --connect-timeout 4 --max-time 8 \
        --write-out '%{http_code}' https://www.google.com/generate_204 2>/dev/null |
        grep -qx '204'
}

recover() {
    logger -t smart-fec-supervisor -p daemon.warning \
        "end-to-end probe failed ${FAILURE_LIMIT} times; rebuilding QUIC and FEC sessions"
    /etc/init.d/smart-fec-quic restart
    sleep 2
    /etc/init.d/smart-fec-client restart
}

failures=0
while true; do
    if probe; then
        if [ "$failures" -gt 0 ]; then
            logger -t smart-fec-supervisor -p daemon.notice \
                "end-to-end SMART-FEC path recovered"
        fi
        failures=0
        sleep "$PROBE_INTERVAL"
        continue
    fi

    failures=$((failures + 1))
    if [ "$failures" -lt "$FAILURE_LIMIT" ]; then
        sleep "$PROBE_INTERVAL"
        continue
    fi

    recover
    sleep 8
    if probe; then
        logger -t smart-fec-supervisor -p daemon.notice \
            "automatic session rebuild succeeded"
        failures=0
    else
        logger -t smart-fec-supervisor -p daemon.err \
            "automatic session rebuild did not restore end-to-end health"
        failures="$FAILURE_LIMIT"
    fi
    sleep "$RECOVERY_COOLDOWN"
done

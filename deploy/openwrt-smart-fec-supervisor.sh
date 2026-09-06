#!/bin/sh
set -u

SOCKS_ADDRESS="${SMART_FEC_HEALTH_SOCKS:-127.0.0.1:1070}"
PASSWALL_RUNTIME="${SMART_FEC_PASSWALL_RUNTIME:-/tmp/etc/passwall/acl/default/TCP_UDP_SOCKS_DNS.json}"
FAILURE_LIMIT="${SMART_FEC_FAILURE_LIMIT:-3}"
PROBE_INTERVAL="${SMART_FEC_PROBE_INTERVAL:-10}"
RECOVERY_COOLDOWN="${SMART_FEC_RECOVERY_COOLDOWN:-30}"
QUIC_ENV="${SMART_FEC_QUIC_ENV:-/etc/smart-fec-quic.env}"

probe() {
    curl --socks5-hostname "$SOCKS_ADDRESS" --silent --show-error \
        --output /dev/null --connect-timeout 4 --max-time 8 \
        --write-out '%{http_code}' https://www.google.com/generate_204 2>/dev/null |
        grep -qx '204'
}

smart_path_active() {
    [ -r "$PASSWALL_RUNTIME" ] &&
        grep -q '"server"[[:space:]]*:[[:space:]]*"127\.0\.0\.1"' "$PASSWALL_RUNTIME" &&
        grep -q '"server_port"[[:space:]]*:[[:space:]]*3333' "$PASSWALL_RUNTIME"
}

recover() {
    local direct_carrier=0
    if [ -r "$QUIC_ENV" ]; then
        . "$QUIC_ENV"
        [ "${SMART_QUIC_LOCAL_PORT:-8444}" = 3333 ] && direct_carrier=1
    fi
    if [ "$direct_carrier" -eq 1 ]; then
        logger -t smart-fec-supervisor -p daemon.warning \
            "end-to-end probe failed ${FAILURE_LIMIT} times; rebuilding direct QUIC carrier"
        /etc/init.d/smart-fec-quic restart
        return
    fi
    logger -t smart-fec-supervisor -p daemon.warning \
        "end-to-end probe failed ${FAILURE_LIMIT} times; rebuilding QUIC and FEC sessions"
    /etc/init.d/smart-fec-quic restart
    sleep 2
    /etc/init.d/smart-fec-client restart
}

failures=0
while true; do
    # The FEC client currently has one application peer.  Never attach a
    # second probe-side TUIC client to port 3333 because it could steal replies
    # from Passwall.  Probe Passwall's own SOCKS listener only while SMART-FEC
    # is the runtime-selected path.
    if ! smart_path_active; then
        failures=0
        sleep "$PROBE_INTERVAL"
        continue
    fi

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

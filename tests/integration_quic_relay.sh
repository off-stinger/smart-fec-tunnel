#!/bin/sh
set -eu

BIN=${BIN:-target/debug/smart-fec-tunnel}
TEST_DIR=$(mktemp -d)
PIDS=""

cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        for log in "$TEST_DIR"/*.log; do
            echo "--- $log ---" >&2
            sed -n '1,160p' "$log" >&2 || true
        done
    fi
    for pid in $PIDS; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    rm -rf "$TEST_DIR"
    exit "$status"
}
trap cleanup EXIT INT TERM

SECRET=integration-device-secret-32-bytes
printf '1 %s\n' "$SECRET" > "$TEST_DIR/keys"
chmod 600 "$TEST_DIR/keys"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
    -addext 'extendedKeyUsage=serverAuth' \
    -keyout "$TEST_DIR/key.pem" -out "$TEST_DIR/cert.pem" >/dev/null 2>&1

python3 -c 'import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("127.0.0.1",19000))
while True:
 d,a=s.recvfrom(65535); s.sendto(d,a)' &
PIDS="$PIDS $!"

"$BIN" server --listen 127.0.0.1:18443 --upstream 127.0.0.1:19000 \
    --keyring "$TEST_DIR/keys" --rate-mbps 100 >"$TEST_DIR/fec-server.log" 2>&1 &
PIDS="$PIDS $!"
"$BIN" quic-server --listen 127.0.0.1:14443 --upstream 127.0.0.1:18443 \
    --cert "$TEST_DIR/cert.pem" --private-key "$TEST_DIR/key.pem" \
    --keyring "$TEST_DIR/keys" >"$TEST_DIR/quic-server.log" 2>&1 &
QUIC_SERVER_PID=$!
PIDS="$PIDS $QUIC_SERVER_PID"
SMART_FEC_KEY="$SECRET" "$BIN" quic-client --listen 127.0.0.1:18444 \
    --server 127.0.0.1:14443 --server-name localhost --ca-cert "$TEST_DIR/cert.pem" \
    --key-id 1 >"$TEST_DIR/quic-client.log" 2>&1 &
PIDS="$PIDS $!"
SMART_FEC_KEY="$SECRET" "$BIN" client --listen 127.0.0.1:13333 \
    --server 127.0.0.1:18444 --key-id 1 --rate-mbps 100 \
    >"$TEST_DIR/fec-client.log" 2>&1 &
PIDS="$PIDS $!"

sleep 2
python3 -c 'import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(5)
payloads=[b"SFT-QUIC end-to-end authenticated FEC relay"]
payloads += [bytes([i % 251]) * size for i,size in enumerate([0,1,127,1280,4096,16384,60000])]
payloads += [("message-%03d" % i).encode() for i in range(100)]
for p in payloads:
 s.sendto(p,("127.0.0.1",13333)); d,_=s.recvfrom(65535); assert d==p,(len(p),len(d))
print("QUIC relay end-to-end payloads verified:",len(payloads))'

grep -q 'QUIC device authenticated' "$TEST_DIR/quic-server.log"
grep -q 'QUIC relay connected and authenticated' "$TEST_DIR/quic-client.log"
echo 'QUIC channel authentication verified'

kill "$QUIC_SERVER_PID"
wait "$QUIC_SERVER_PID" 2>/dev/null || true
"$BIN" quic-server --listen 127.0.0.1:14443 --upstream 127.0.0.1:18443 \
    --cert "$TEST_DIR/cert.pem" --private-key "$TEST_DIR/key.pem" \
    --keyring "$TEST_DIR/keys" >>"$TEST_DIR/quic-server.log" 2>&1 &
QUIC_SERVER_PID=$!
PIDS="$PIDS $QUIC_SERVER_PID"
python3 -c 'import socket,time
p=b"automatic reconnect after QUIC server restart"
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(.5); deadline=time.monotonic()+20
while time.monotonic()<deadline:
 s.sendto(p,("127.0.0.1",13333))
 try:
  d,_=s.recvfrom(65535)
  if d==p: print("QUIC reconnect verified"); break
 except TimeoutError: pass
else: raise RuntimeError("QUIC relay did not recover within 20 seconds")'

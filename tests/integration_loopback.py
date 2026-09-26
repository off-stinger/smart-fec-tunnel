#!/usr/bin/env python3
import os, socket, subprocess, tempfile, threading, time

BIN = os.environ.get("SMART_FEC_BIN", "./target/release/smart-fec-tunnel")
SERVER_BIN = os.environ.get("SMART_FEC_SERVER_BIN", BIN)
CLIENT_BIN = os.environ.get("SMART_FEC_CLIENT_BIN", BIN)
KEY = "integration-test-key-32bytes-long-enough"

def echo_server(stop):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 5555)); s.settimeout(.2)
    while not stop.is_set():
        try:
            data, peer = s.recvfrom(65535); s.sendto(data, peer)
        except socket.timeout: pass
    s.close()

def relay(stop):
    """Blind UDP relay: V3 encrypts frame metadata, so don't inspect payloads."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 4096)); s.settimeout(.05)
    server = ("127.0.0.1", 4097); client = None
    while not stop.is_set():
        try:
            data, peer = s.recvfrom(65535)
        except socket.timeout:
            continue
        from_server = peer == server
        if not from_server:
            client = peer
        target = client if from_server else server
        if target is None:
            continue
        s.sendto(data, target)
    s.close()

def main():
    stop = threading.Event()
    threading.Thread(target=echo_server, args=(stop,), daemon=True).start()
    threading.Thread(target=relay, args=(stop,), daemon=True).start()
    env = dict(os.environ, SMART_FEC_KEY=KEY, SMART_FEC_KEY_ID="1", RUST_LOG="warn")
    with tempfile.TemporaryDirectory() as directory:
        keyring = os.path.join(directory, "server.keys")
        with open(keyring, "w", encoding="ascii") as handle:
            handle.write(f"1 {KEY}\n")
        if os.name != "nt":
            os.chmod(keyring, 0o600)
        server = subprocess.Popen([SERVER_BIN, "server", "--listen", "127.0.0.1:4097", "--upstream", "127.0.0.1:5555", "--keyring", keyring], env=env)
        client = subprocess.Popen([CLIENT_BIN, "client", "--listen", "127.0.0.1:3333", "--server", "127.0.0.1:4096", "--key-id", "1"], env=env)
        try:
            time.sleep(.5)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
            sizes = [1, 20, 512, 1036, 1037, 1400, 4096, 8192]
            for n in range(400):
                size = sizes[n % len(sizes)]
                payload = n.to_bytes(4, "big") + os.urandom(size)
                s.sendto(payload, ("127.0.0.1", 3333))
                deadline = time.monotonic() + 2
                while True:
                    s.settimeout(max(.01, deadline - time.monotonic()))
                    got, _ = s.recvfrom(65535)
                    if got == payload:
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError(f"mismatch packet={n} size={size}")
            print("integration_v3_loopback_ok packets=400 max_payload=8196")
        finally:
            client.terminate(); server.terminate(); stop.set()
            client.wait(timeout=3); server.wait(timeout=3)
            s.close()

if __name__ == "__main__": main()

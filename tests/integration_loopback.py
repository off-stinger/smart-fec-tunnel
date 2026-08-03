#!/usr/bin/env python3
import os, socket, subprocess, threading, time, sys

BIN = os.environ.get("SMART_FEC_BIN", "./target/release/smart-fec-tunnel")
KEY = "integration-test-key"

def echo_server(stop):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 5555)); s.settimeout(.2)
    while not stop.is_set():
        try:
            data, peer = s.recvfrom(65535); s.sendto(data, peer)
        except socket.timeout: pass
    s.close()

def lossy_relay(stop):
    """Drop data shard index 0 once per FEC group in both directions."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 4096)); s.settimeout(.05)
    server = ("127.0.0.1", 4097); client = None
    dropped = set()
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
        # Wire header: magic[4], version[1], kind[1], session[8], seq[8], group[8], index[2].
        if len(data) >= 32 and data[:4] == b"SFT1" and data[5] == 1:
            group = int.from_bytes(data[22:30], "big")
            index = int.from_bytes(data[30:32], "big")
            marker = (from_server, group)
            if index == 0 and marker not in dropped:
                dropped.add(marker)
                continue
        s.sendto(data, target)
    s.close()

def main():
    stop = threading.Event()
    threading.Thread(target=echo_server, args=(stop,), daemon=True).start()
    threading.Thread(target=lossy_relay, args=(stop,), daemon=True).start()
    env = dict(os.environ, SMART_FEC_KEY=KEY, RUST_LOG="warn")
    server = subprocess.Popen([BIN, "server", "--listen", "127.0.0.1:4097", "--upstream", "127.0.0.1:5555"], env=env)
    client = subprocess.Popen([BIN, "client", "--listen", "127.0.0.1:3333", "--server", "127.0.0.1:4096"], env=env)
    try:
        time.sleep(.5)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
        sizes = [1, 20, 512, 1036, 1037, 1400, 4096, 8192]
        duplicates = 0
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
                duplicates += 1
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"mismatch packet={n} size={size}")
        print(f"integration_loss_recovery_ok packets=400 max_payload=8196 duplicates={duplicates}")
    finally:
        client.terminate(); server.terminate(); stop.set()
        client.wait(timeout=3); server.wait(timeout=3)

if __name__ == "__main__": main()

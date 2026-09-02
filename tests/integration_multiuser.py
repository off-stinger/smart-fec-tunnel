#!/usr/bin/env python3
import os
import socket
import subprocess
import tempfile
import threading
import time

BIN = os.environ.get("SMART_FEC_BIN", "./target/release/smart-fec-tunnel")
DEVICES = ((101, "device-one-integration-key-32bytes"), (202, "device-two-integration-key-32bytes"))


def reserve_udp_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def echo_server(stop, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    sock.settimeout(0.2)
    while not stop.is_set():
        try:
            data, peer = sock.recvfrom(65535)
            sock.sendto(data, peer)
        except socket.timeout:
            pass
    sock.close()


def main():
    stop = threading.Event()
    upstream_port, server_port = reserve_udp_port(), reserve_udp_port()
    client_ports = (reserve_udp_port(), reserve_udp_port())
    threading.Thread(target=echo_server, args=(stop, upstream_port), daemon=True).start()

    with tempfile.TemporaryDirectory() as directory:
        keyring = os.path.join(directory, "server.keys")
        with open(keyring, "w", encoding="ascii") as handle:
            for key_id, secret in DEVICES:
                handle.write(f"{key_id} {secret}\n")
        if os.name != "nt":
            os.chmod(keyring, 0o600)

        env = dict(os.environ, RUST_LOG="warn")
        server = subprocess.Popen(
            [BIN, "server", "--listen", f"127.0.0.1:{server_port}", "--upstream",
             f"127.0.0.1:{upstream_port}", "--keyring", keyring], env=env
        )
        clients = []
        for (key_id, secret), port in zip(DEVICES, client_ports):
            client_env = dict(env, SMART_FEC_KEY=secret, SMART_FEC_KEY_ID=str(key_id))
            clients.append(subprocess.Popen(
                [BIN, "client", "--listen", f"127.0.0.1:{port}", "--server",
                 f"127.0.0.1:{server_port}"], env=client_env
            ))
        try:
            time.sleep(0.6)
            sockets = []
            for index, port in enumerate(client_ports):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                sockets.append(sock)
                for sequence in range(40):
                    payload = f"device={index};sequence={sequence}".encode() + os.urandom(64)
                    sock.sendto(payload, ("127.0.0.1", port))
                    received, _ = sock.recvfrom(65535)
                    if received != payload:
                        raise RuntimeError(f"session isolation failure device={index} sequence={sequence}")
            print("integration_multiuser_ok devices=2 packets=80")
        finally:
            for process in clients:
                process.terminate()
            server.terminate()
            stop.set()
            for process in clients + [server]:
                process.wait(timeout=3)


if __name__ == "__main__":
    main()

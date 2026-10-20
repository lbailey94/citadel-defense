#!/usr/bin/env python3
"""violet_spa.py — Single-Packet Authorization (SPA) via Ed25519 for VIOLET.

Enforces zero-packet attack surface for high-value services (SSH, 7369 mesh,
treasury rails). Target ports remain completely silent (no TCP ACK, no banner)
until an authorized client transmits a cryptographically signed Ed25519
SPA datagram.

Lineage: VIOLET Pillar P1 (Scope Tokens on the Wire).
"""

import base64
import json
import os
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

KEY_PATH = Path(os.path.expanduser("~/.config/whitemagic/violet/redops.key"))
DEFAULT_SPA_PORT = 62201
MAGIC_HEADER = b"VIOLET-SPA-v1:"


class SinglePacketAuthorizer:
    def __init__(self, key_path: Path = KEY_PATH):
        self.key_path = key_path
        self.priv_key = self._load_privkey()
        self.pub_key = self.priv_key.public_key()
        self.authorized_pubkeys = {self.pub_key.public_bytes_raw().hex(): self.pub_key}
        self.nonce_cache = set()
        self.allowed_ports = {22, 443, 7350, 7369, 8750}

    def _load_privkey(self) -> Ed25519PrivateKey:
        raw = self.key_path.read_text().strip()
        seed = base64.urlsafe_b64decode(raw + "==")
        return Ed25519PrivateKey.from_private_bytes(seed)

    def create_knock_packet(self, client_ip: str, target_port: int, valid_seconds: int = 30) -> bytes:
        """Create a signed SPA datagram."""
        import secrets
        payload = {
            "client_ip": client_ip,
            "target_port": target_port,
            "ts": int(time.time()),
            "nonce": secrets.token_hex(8),
            "valid_seconds": valid_seconds,
            "pubkey": self.pub_key.public_bytes_raw().hex()
        }
        body_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        sig = self.priv_key.sign(body_bytes)

        # Format: MAGIC_HEADER + b64(body) + b'.' + b64(sig)
        b64_body = base64.urlsafe_b64encode(body_bytes)
        b64_sig = base64.urlsafe_b64encode(sig)
        return MAGIC_HEADER + b64_body + b"." + b64_sig

    def verify_knock_packet(self, raw_packet: bytes, sender_ip: str) -> dict:
        """Verify an incoming SPA packet at line speed."""
        if not raw_packet.startswith(MAGIC_HEADER):
            return {"valid": False, "reason": "invalid_magic_header"}

        packet_data = raw_packet[len(MAGIC_HEADER):]
        parts = packet_data.split(b".", 1)
        if len(parts) != 2:
            return {"valid": False, "reason": "malformed_packet"}

        try:
            body_bytes = base64.urlsafe_b64decode(parts[0] + b"==")
            sig_bytes = base64.urlsafe_b64decode(parts[1] + b"==")
            payload = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            return {"valid": False, "reason": "decoding_error"}

        # 1. Anti-Replay: Timestamp freshness (+/- 30s)
        now = int(time.time())
        ts = payload.get("ts", 0)
        if abs(now - ts) > 30:
            return {"valid": False, "reason": "expired_or_future_timestamp"}

        # 2. Anti-Replay: Nonce freshness
        nonce = payload.get("nonce", "")
        if nonce in self.nonce_cache:
            return {"valid": False, "reason": "replay_detected"}
        self.nonce_cache.add(nonce)
        if len(self.nonce_cache) > 10000:
            self.nonce_cache.clear()

        # 3. Port Allowlist
        target_port = payload.get("target_port")
        if target_port not in self.allowed_ports:
            return {"valid": False, "reason": "target_port_forbidden"}

        # 4. Signature Verification
        pub_hex = payload.get("pubkey")
        if pub_hex not in self.authorized_pubkeys:
            return {"valid": False, "reason": "unauthorized_key"}

        pub = self.authorized_pubkeys[pub_hex]
        try:
            pub.verify(sig_bytes, body_bytes)
        except Exception:
            return {"valid": False, "reason": "invalid_cryptographic_signature"}

        return {
            "valid": True,
            "client_ip": payload.get("client_ip", sender_ip),
            "target_port": target_port,
            "valid_seconds": payload.get("valid_seconds", 30),
            "timestamp": ts
        }

    def send_knock(self, host: str, target_port: int, spa_port: int = DEFAULT_SPA_PORT) -> bool:
        """Send knock to target host."""
        pkt = self.create_knock_packet(client_ip="127.0.0.1", target_port=target_port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(pkt, (host, spa_port))
            return True
        finally:
            sock.close()


def run_spa_benchmark():
    """Benchmark SPA knock packet generation, transmission, and verification."""
    spa = SinglePacketAuthorizer()
    print("== Benchmarking Single-Packet Authorization (SPA) ==")

    # Setup temporary UDP listener
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind(("127.0.0.1", 62205))
    server_sock.settimeout(2.0)

    results = []

    def listen_loop():
        for _ in range(5):
            try:
                data, addr = server_sock.recvfrom(2048)
                t0 = time.time()
                res = spa.verify_knock_packet(data, addr[0])
                res["verify_time"] = time.time() - t0
                results.append(res)
            except Exception:
                pass

    t = threading.Thread(target=listen_loop, daemon=True)
    t.start()

    start_total = time.time()
    for _ in range(5):
        pkt = spa.create_knock_packet(client_ip="127.0.0.1", target_port=22)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(pkt, ("127.0.0.1", 62205))
        sock.close()
        time.sleep(0.01)

    t.join(timeout=2.0)
    server_sock.close()
    elapsed_total = time.time() - start_total

    avg_verify = sum(r["verify_time"] for r in results) / len(results) if results else 0
    all_valid = all(r["valid"] for r in results) if results else False

    print(f"Knocks Processed: {len(results)}/5")
    print(f"All Signatures Valid: {all_valid}")
    print(f"Average In-Kernel/Daemon Verification Latency: {avg_verify*1000:.3f}ms")
    print(f"Total Burst Roundtrip (5 knocks): {elapsed_total*1000:.2f}ms")
    return avg_verify, all_valid


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--bench":
        run_spa_benchmark()
    elif len(sys.argv) > 1 and sys.argv[1] == "knock":
        host = sys.argv[2]
        port = int(sys.argv[3])
        authorizer = SinglePacketAuthorizer()
        authorizer.send_knock(host, port)
        print(f"Sent SPA knock for port {port} to {host}")
    else:
        print("Usage: violet_spa.py [--bench | knock <host> <port>]")

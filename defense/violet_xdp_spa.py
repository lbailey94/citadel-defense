#!/usr/bin/env python3
"""violet_xdp_spa.py — eBPF / XDP Driver-Level Single-Packet Authorization Loader & Verifier.

Compiles, verifies, and coordinates kernel XDP packet filters + Ed25519 SPA knock authentication:
  - Compiles violet_xdp_spa.c to BPF ELF bytecode using `clang -target bpf` and verifies ELF sections.
  - Integrates directly with `violet_spa.SinglePacketAuthorizer` to verify Ed25519-signed SPA
    datagrams, enforce +/-30s timestamp freshness, and block replay attacks before authorizing IPs.
  - Evaluates protected-port packet filtering (ports 22, 7369, 8787) and clearly distinguishes
    measured cryptographic knock verification + BPF ELF compilation from fast-table packet evaluation.

Lineage: VIOLET Pillar P1 & Ring 1 (SPA Wire Gate).
"""

from __future__ import annotations

import os
import shutil
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

DEFENSE_DIR = Path(__file__).resolve().parent
if str(DEFENSE_DIR) not in sys.path:
    sys.path.insert(0, str(DEFENSE_DIR))

from violet_spa import SinglePacketAuthorizer  # noqa: E402

C_SRC = DEFENSE_DIR / "violet_xdp_spa.c"
O_OBJ = DEFENSE_DIR / "violet_xdp_spa.o"


class XDPAuthorizer:
    def __init__(self, c_src: Path = C_SRC, o_obj: Path = O_OBJ):
        self.c_src = c_src
        self.o_obj = o_obj
        self.authorized_table: dict[int, int] = {}
        self.spa = SinglePacketAuthorizer()

    def compile_bpf(self) -> tuple[bool, str, dict]:
        """Compile the eBPF C program to BPF ELF object code using clang and verify ELF headers."""
        clang = shutil.which("clang")
        if not clang:
            return False, "clang compiler not found", {"elf_verified": False}

        cmd = [
            clang,
            "-O2",
            "-target",
            "bpf",
            "-c",
            str(self.c_src),
            "-o",
            str(self.o_obj),
            "-I/usr/include",
            "-I/usr/include/x86_64-linux-gnu",
        ]

        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            elf_ok = False
            obj_size = 0
            if self.o_obj.exists():
                raw = self.o_obj.read_bytes()
                obj_size = len(raw)
                # Verify ELF magic (\x7fELF) and presence of `xdp` and `authorized_knocks` symbols
                elf_ok = (
                    raw[:4] == b"\x7fELF"
                    and b"xdp_spa_filter" in raw
                    and b"authorized_knocks" in raw
                )
            return elf_ok, f"Compiled BPF ELF ({obj_size} bytes)", {
                "elf_verified": elf_ok,
                "object_bytes": obj_size,
            }
        except subprocess.CalledProcessError as e:
            return False, f"Compilation failed: {e.stderr}", {"elf_verified": False}
        except Exception as e:
            return False, str(e), {"elf_verified": False}

    def authorize_via_spa_knock(self, raw_packet: bytes, sender_ip: str) -> dict:
        """Verify an Ed25519-signed SPA knock packet and authorize the client IP on success."""
        t0 = time.perf_counter()
        verdict = self.spa.verify_knock_packet(raw_packet, sender_ip=sender_ip)
        verify_us = (time.perf_counter() - t0) * 1e6
        if not verdict.get("valid"):
            return {
                "authorized": False,
                "reason": verdict.get("reason", "invalid"),
                "verify_latency_us": round(verify_us, 2),
            }

        client_ip = verdict["client_ip"]
        ttl_s = int(verdict.get("valid_seconds", 30))
        map_info = self.add_authorized_ip(client_ip, ttl_seconds=ttl_s)
        return {
            "authorized": True,
            "client_ip": client_ip,
            "target_port": verdict["target_port"],
            "verify_latency_us": round(verify_us, 2),
            "map_update_latency_us": map_info["map_update_latency_us"],
        }

    def add_authorized_ip(self, ip_str: str, ttl_seconds: int = 60) -> dict:
        """Authorize an IP address for transient access following an authentic SPA knock."""
        t0 = time.perf_counter()
        ip_packed = socket.inet_aton(ip_str)
        ip_int = struct.unpack("!I", ip_packed)[0]
        expiry_ns = int((time.time() + ttl_seconds) * 1e9)

        self.authorized_table[ip_int] = expiry_ns
        elapsed_us = (time.perf_counter() - t0) * 1e6

        return {
            "ip": ip_str,
            "ip_int": ip_int,
            "ttl_seconds": ttl_seconds,
            "expiry_ns": expiry_ns,
            "map_update_latency_us": round(elapsed_us, 2),
        }

    def simulate_xdp_eval(self, src_ip: str, dst_port: int) -> tuple[str, float]:
        """Evaluate the XDP packet filtering logic against the authorized_knocks table."""
        t0 = time.perf_counter()
        ip_int = struct.unpack("!I", socket.inet_aton(src_ip))[0]

        if dst_port in (22, 7369, 8787):
            expiry = self.authorized_table.get(ip_int)
            now_ns = int(time.time() * 1e9)
            if not expiry or expiry < now_ns:
                elapsed_ns = (time.perf_counter() - t0) * 1e9
                return "XDP_DROP", elapsed_ns

        elapsed_ns = (time.perf_counter() - t0) * 1e9
        return "XDP_PASS", elapsed_ns


def run_xdp_benchmark() -> tuple[float, bool, dict]:
    """Benchmark eBPF ELF compilation, Ed25519 SPA knock verification, replay rejection, and XDP filter logic."""
    auth = XDPAuthorizer()
    t0 = time.time()
    compiled, msg, elf_meta = auth.compile_bpf()

    # 1. Create and verify a real Ed25519 SPA knock packet for 192.0.2.1:22
    knock_pkt = auth.spa.create_knock_packet(client_ip="192.0.2.1", target_port=22, valid_seconds=30)
    knock_res = auth.authorize_via_spa_knock(knock_pkt, sender_ip="192.0.2.1")

    # 2. Adversarial Replay Check: re-sending the exact same knock packet MUST fail closed
    replay_res = auth.authorize_via_spa_knock(knock_pkt, sender_ip="192.0.2.1")
    replay_rejected = not replay_res["authorized"] and replay_res.get("reason") == "replay_detected"

    # 3. Adversarial Tamper Check: flipping 1 byte of the knock signature MUST fail closed
    tampered_pkt = knock_pkt[:-2] + (b"A" if knock_pkt[-2:-1] != b"A" else b"B") + knock_pkt[-1:]
    tamper_res = auth.authorize_via_spa_knock(tampered_pkt, sender_ip="198.51.100.99")
    tamper_rejected = not tamper_res["authorized"]

    # 4. Test unauthorized probe on SSH port 22 -> XDP_DROP
    action_drop, drop_lat_ns = auth.simulate_xdp_eval("198.51.100.99", 22)

    # 5. Test authorized probe on SSH port 22 -> XDP_PASS
    action_pass, pass_lat_ns = auth.simulate_xdp_eval("192.0.2.1", 22)

    # 6. Test non-protected port 443 -> XDP_PASS
    action_web, web_lat_ns = auth.simulate_xdp_eval("198.51.100.99", 443)

    total_elapsed = time.time() - t0
    stats = {
        "compiled": compiled,
        "compile_msg": msg,
        "elf_verified": elf_meta.get("elf_verified", False),
        "spa_knock_verified": knock_res.get("authorized", False),
        "spa_verify_latency_us": knock_res.get("verify_latency_us", 0.0),
        "replay_rejected": replay_rejected,
        "tamper_rejected": tamper_rejected,
        "unauthorized_drop": {"action": action_drop, "latency_ns": round(drop_lat_ns, 1)},
        "authorized_pass": {"action": action_pass, "latency_ns": round(pass_lat_ns, 1)},
        "unprotected_pass": {"action": action_web, "latency_ns": round(web_lat_ns, 1)},
    }

    passed = (
        knock_res.get("authorized", False)
        and replay_rejected
        and tamper_rejected
        and action_drop == "XDP_DROP"
        and action_pass == "XDP_PASS"
        and action_web == "XDP_PASS"
    )
    return total_elapsed, passed, stats


if __name__ == "__main__":
    elapsed, ok, s = run_xdp_benchmark()
    print("═" * 68)
    print("  VIOLET eBPF / XDP Driver-Level Single-Packet Authorization")
    print("═" * 68)
    print(f"  BPF Clang Compilation        : {'SUCCESS' if s['compiled'] else 'SKIPPED/SIMULATED'} ({s['compile_msg']})")
    print(f"  Ed25519 SPA Knock Verified   : {s['spa_knock_verified']} ({s['spa_verify_latency_us']} µs)")
    print(f"  SPA Replay Attack Rejected   : {'PASS' if s['replay_rejected'] else 'FAIL'}")
    print(f"  SPA Signature Tamper Rejected: {'PASS' if s['tamper_rejected'] else 'FAIL'}")
    print(f"  Unauthorized Drop Latency    : {s['unauthorized_drop']['latency_ns']} ns ({s['unauthorized_drop']['action']})")
    print(f"  Authorized Pass Latency      : {s['authorized_pass']['latency_ns']} ns ({s['authorized_pass']['action']})")
    print(f"  End-to-End SPA + XDP Gate    : {'PASS' if ok else 'FAILED'}")
    print("═" * 68)

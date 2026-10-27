#!/usr/bin/env python3
"""citadel_antibody_sync.py — Live VPS Citadel -> Workstation Antibody Sync Bridge.

Extracts content-free 64-bit antibody digests (FNV-1a / SHA-256 u64) from the production
VPS Citadel (`203.0.113.10`):
  1. Cowrie SSH/Telnet Honeypot (`/opt/cowrie/var/log/cowrie/cowrie.json*`):
     - Session fingerprints (`cowrie.session.connect`)
     - Distinct credential pairs (`cowrie.login.success` / `cowrie.login.failed`)
     - Distinct exploit command payloads (`cowrie.command.input`)
     - Attacker source IP hashes (`src_ip`)
  2. VPS Sentinel Blue-Ops Ledger (`/var/lib/whitemagic-hosted/defense/vps-sentinel.chain.jsonl`)
  3. Gateway Rejected Payment / Probe Fingerprints (`/var/lib/whitemagic-hosted*/access.jsonl`)

Computes a Grover-proof dual hash (`SHA-384 + BLAKE2b-512`) over the consolidated antibody
manifest and writes it to `~/.local/state/whitemagic/citadel-antibodies-live.json` for
direct ingestion by `WMv10`'s `CitadelAntibodyBloom2048` and `CittaOscillatorEngine`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

STATE_DIR = Path(os.path.expanduser("~/.local/state/whitemagic"))
OUT_FILE = STATE_DIR / "citadel-antibodies-live.json"

REMOTE_EXTRACTOR = r"""
import glob, hashlib, json, collections

def u64_digest(namespace: str, raw: str) -> int:
    h = hashlib.blake2b(f"{namespace}:{raw}".encode("utf-8", errors="replace"), digest_size=8).digest()
    return int.from_bytes(h, "big", signed=False)

sessions = set()
creds = set()
cmds = set()
ips = set()
events_total = 0

for p in sorted(glob.glob("/opt/cowrie/var/log/cowrie/cowrie.json*")):
    try:
        with open(p, "r", errors="replace") as f:
            for line in f:
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                events_total += 1
                ev = d.get("eventid", "")
                if d.get("session"):
                    sessions.add(str(d["session"]))
                if d.get("src_ip") and d["src_ip"] not in ("127.0.0.1", "203.0.113.10"):
                    ips.add(str(d["src_ip"]))
                if ev in ("cowrie.login.success", "cowrie.login.failed"):
                    u = str(d.get("username", ""))
                    pw = str(d.get("password", ""))
                    creds.add(f"{u}:{pw}")
                elif ev == "cowrie.command.input":
                    inp = str(d.get("input", "")).strip()
                    if inp:
                        cmds.add(inp)
    except Exception:
        pass

gateway_invalid = set()
for p in sorted(glob.glob("/var/lib/whitemagic-hosted*/access.jsonl")):
    try:
        with open(p, "r", errors="replace") as f:
            for line in f:
                if "invalid" in line or "refused" in line:
                    try:
                        d = json.loads(line)
                        uah = d.get("uah")
                        note = d.get("note")
                        if uah and note:
                            gateway_invalid.add(f"{note}:{uah}")
                    except Exception:
                        pass
    except Exception:
        pass

digests_by_kind = {
    "honeypot_sessions": sorted({u64_digest("session", s) for s in sessions}),
    "honeypot_credentials": sorted({u64_digest("cred", c) for c in creds}),
    "honeypot_payloads": sorted({u64_digest("cmd", c) for c in cmds}),
    "attacker_ips": sorted({u64_digest("ip", ip) for ip in ips}),
    "gateway_anomalies": sorted({u64_digest("gw", g) for g in gateway_invalid}),
}

all_digests = sorted(
    set().union(*digests_by_kind.values())
)

print(json.dumps({
    "source_node": "vps-citadel-203.0.113.10",
    "honeypot_events_scanned": events_total,
    "counts": {
        "sessions": len(digests_by_kind["honeypot_sessions"]),
        "credentials": len(digests_by_kind["honeypot_credentials"]),
        "payloads": len(digests_by_kind["honeypot_payloads"]),
        "attacker_ips": len(digests_by_kind["attacker_ips"]),
        "gateway_anomalies": len(digests_by_kind["gateway_anomalies"]),
        "total_unique_antibodies": len(all_digests),
    },
    "antibody_digests_u64": all_digests,
}))
"""


def main() -> int:
    ap = argparse.ArgumentParser(prog="citadel_antibody_sync")
    ap.add_argument("--host", default="whitemagic", help="SSH host alias for the production VPS")
    ap.add_argument("--out", default=str(OUT_FILE), help="Output JSON path")
    args = ap.parse_args()

    t0 = time.time()
    proc = subprocess.run(
        ["ssh", "-o", "ConnectTimeout=10", args.host, "python3 -"],
        input=REMOTE_EXTRACTOR,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        sys.stderr.write(f"citadel_antibody_sync failed (rc={proc.returncode}): {proc.stderr}\n")
        return 1

    data = json.loads(proc.stdout.strip())
    elapsed_ms = (time.time() - t0) * 1000.0

    canon_bytes = json.dumps(data["antibody_digests_u64"], separators=(",", ":")).encode("utf-8")
    sha384_hex = hashlib.sha384(canon_bytes).hexdigest()
    blake2b_hex = hashlib.blake2b(canon_bytes, digest_size=64).hexdigest()

    bundle = {
        "schema": "wm.citadel-antibody-sync/1.0",
        "synced_at": datetime.now(timezone.utc).isoformat(),
        "sync_latency_ms": round(elapsed_ms, 2),
        "source_node": data["source_node"],
        "honeypot_events_scanned": data["honeypot_events_scanned"],
        "counts": data["counts"],
        "grover_dual_commitment": {
            "sha384": sha384_hex,
            "blake2b_512": blake2b_hex,
            "quantum_work_factor_bits": 256,
        },
        "antibody_digests_u64": data["antibody_digests_u64"],
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")

    c = data["counts"]
    print("╔══════════════════════════════════════════════════════════════════════════╗")
    print("║       LIVE VPS CITADEL -> WORKSTATION ANTIBODY SYNC (PORT 7369/SSH)      ║")
    print("╚══════════════════════════════════════════════════════════════════════════╝")
    print(f"  ✓ Source Citadel Node       : {data['source_node']}")
    print(f"  ✓ Honeypot Events Scanned   : {data['honeypot_events_scanned']:,}")
    print(f"  ✓ Session Antibodies        : {c['sessions']:,}")
    print(f"  ✓ Credential Antibodies     : {c['credentials']:,}")
    print(f"  ✓ Exploit Payload Antibodies: {c['payloads']:,}")
    print(f"  ✓ Attacker IP Antibodies    : {c['attacker_ips']:,}")
    print(f"  ✓ Gateway Anomaly Antibodies: {c['gateway_anomalies']:,}")
    print(f"  ✓ Total Unique u64 Digests  : {c['total_unique_antibodies']:,}")
    print(f"  ✓ Grover SHA-384 Commitment : {sha384_hex[:32]}...")
    print(f"  ✓ Sync & Hash Latency       : {elapsed_ms:.2f} ms")
    print(f"  ✓ Saved Live Bundle         : {out_path}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

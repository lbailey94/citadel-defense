#!/usr/bin/env python3
"""violet_immunize.py — Replay-Driven Fast-Path Synthesizer for VIOLET.

Bridges the Deliberative Path (local SLM) to the sub-second Fast Path (Caddy/Fail2ban/nftables)
WITHOUT putting the LLM inline and WITHOUT risking false-positive outages.

Methodology:
1. Receives an anomaly probe pattern flagged by sentinel or wm-judge.
2. Synthesizes a candidate deterministic rule (Caddy matcher or Fail2ban regex).
3. Replays candidate rule against historical clean traffic logs.
4. Requires invariant: True Positives >= 1 AND False Positives == 0.
5. If verified, signs the rule with Ed25519 (redops.key) and stages it for fast-path promotion.

Lineage: VIOLET Pillar P3 (Fail-Closed) & P5 (Explain-or-Execute).
"""

import base64
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

STATE_DIR = Path(os.environ.get("VIOLET_STATE_DIR", os.path.expanduser("~/.local/state/whitemagic")))
RULES_DIR = STATE_DIR / "active-rules"
KEY_PATH = Path(os.environ.get("VIOLET_KEY_PATH", os.path.expanduser("~/.config/whitemagic/violet/redops.key")))
CHAIN_PATH = STATE_DIR / "vps-sentinel.chain.jsonl"


class FastPathImmunizer:
    def __init__(self, key_path: Path = KEY_PATH):
        self.key_path = key_path
        RULES_DIR.mkdir(parents=True, exist_ok=True)
        self.priv_key = self._load_privkey()

    def _load_privkey(self) -> Ed25519PrivateKey:
        if not self.key_path.exists():
            raise FileNotFoundError(f"Missing signing key at {self.key_path}")
        raw = self.key_path.read_text().strip()
        seed = base64.urlsafe_b64decode(raw + "==")
        return Ed25519PrivateKey.from_private_bytes(seed)

    def synthesize_rule(self, probe_sample: str, rule_type: str = "caddy") -> dict:
        """Synthesize a deterministic blocking rule from an attack probe sample."""
        # Sanitize and extract core malicious token/path
        cleaned = probe_sample.strip().split()[0] if " " in probe_sample else probe_sample
        path_match = re.search(r"(/[a-zA-Z0-9_\-\.\/]+)", cleaned)
        target_path = path_match.group(1) if path_match else cleaned
        target_path = target_path.split("?")[0]  # strip query params for base path match

        rule_id = f"rule_{abs(hash(target_path)) % 1000000:06d}"
        now = datetime.now(timezone.utc).isoformat()

        if rule_type == "caddy":
            definition = {
                "rule_id": rule_id,
                "type": "caddy",
                "matcher": f"@block_{rule_id}",
                "pattern": target_path,
                "caddy_directive": f"@block_{rule_id} path {target_path}*\nrespond @block_{rule_id} 403\n",
                "created_at": now
            }
        else:
            escaped = re.escape(target_path)
            definition = {
                "rule_id": rule_id,
                "type": "fail2ban",
                "pattern": target_path,
                "failregex": f'^<HOST> -.*"(GET|POST|HEAD) {escaped}.*" (?:400|403|404)',
                "created_at": now
            }

        return definition

    def replay_verify(self, rule: dict, attack_samples: list, clean_traffic_log: list) -> dict:
        """Replay candidate rule against attack samples and clean traffic logs."""
        pattern = rule.get("pattern", "")
        regex = re.compile(re.escape(pattern))

        true_positives = 0
        false_positives = []

        # 1. Test against attack samples
        for sample in attack_samples:
            if regex.search(sample):
                true_positives += 1

        # 2. Test against historical clean traffic
        for log_line in clean_traffic_log:
            if regex.search(log_line):
                false_positives.append(log_line)

        is_safe = (true_positives >= 1) and (len(false_positives) == 0)

        result = {
            "rule_id": rule["rule_id"],
            "pattern": pattern,
            "true_positives": true_positives,
            "false_positives_count": len(false_positives),
            "false_positives_samples": false_positives[:3],
            "verified_safe": is_safe,
            "evaluated_at": datetime.now(timezone.utc).isoformat()
        }

        return result

    def sign_and_promote(self, rule: dict, verification: dict) -> Path:
        """Sign verified rule with Ed25519 and save to active-rules."""
        if not verification.get("verified_safe"):
            raise ValueError(f"Cannot promote unsafe rule: {verification}")

        bundle = {
            "rule": rule,
            "verification": verification,
            "promoted_at": datetime.now(timezone.utc).isoformat()
        }

        bundle_bytes = json.dumps(bundle, sort_keys=True).encode("utf-8")
        sig = self.priv_key.sign(bundle_bytes)
        bundle["signature"] = base64.urlsafe_b64encode(sig).decode("ascii")
        bundle["pubkey"] = self.priv_key.public_key().public_bytes_raw().hex()

        out_path = RULES_DIR / f"{rule['rule_id']}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)

        # Append to Blue-Ops evidence chain
        self._record_immunization_evidence(bundle)
        return out_path

    def _record_immunization_evidence(self, bundle: dict):
        try:
            import hashlib
            prev_hash = ""
            if CHAIN_PATH.exists():
                lines = CHAIN_PATH.read_text().strip().splitlines()
                if lines:
                    last_entry = json.loads(lines[-1])
                    prev_hash = last_entry.get("hash", "")

            snapshot = f"IMMUNIZE_PROMOTION:{bundle['rule']['rule_id']}:{bundle['rule']['pattern']}:{bundle['promoted_at']}"
            entry_hash = hashlib.sha256((prev_hash + snapshot).encode("utf-8")).hexdigest()
            entry = {
                "ts": bundle["promoted_at"],
                "snapshot": snapshot,
                "prev": prev_hash,
                "hash": entry_hash,
                "detail": bundle
            }
            with open(CHAIN_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            sys.stderr.write(f"Chain record failed: {e}\n")


def run_immunization_benchmark():
    """Benchmark the synthesis and replay-verification pipeline."""
    immunizer = FastPathImmunizer()
    print("== Benchmarking Replay-Driven Rule Synthesis ==")

    attack_samples = [
        "GET /.env HTTP/1.1",
        "POST /app/.env.production HTTP/2.0",
        "GET /core/.env.local HTTP/1.1"
    ]

    clean_traffic = [
        '127.0.0.1 - - [18/Oct/2026:10:00:00 +0000] "GET /api/v1/health HTTP/1.1" 200 120',
        '127.0.0.1 - - [18/Oct/2026:10:01:00 +0000] "GET /index.html HTTP/1.1" 200 4500',
        '127.0.0.1 - - [18/Oct/2026:10:02:00 +0000] "POST /api/v2/messages HTTP/1.1" 201 80',
        '127.0.0.1 - - [18/Oct/2026:10:03:00 +0000] "GET /static/app.js HTTP/1.1" 200 120000',
        '127.0.0.1 - - [18/Oct/2026:10:04:00 +0000] "GET /favicon.ico HTTP/1.1" 200 420'
    ]

    start = time.time()
    # 1. Synthesize candidate rule
    rule = immunizer.synthesize_rule("/.env", rule_type="caddy")

    # 2. Replay verify against clean traffic
    verification = immunizer.replay_verify(rule, attack_samples, clean_traffic)

    # 3. Promote & sign
    promoted_file = immunizer.sign_and_promote(rule, verification)
    elapsed = time.time() - start

    print(f"Rule ID: {rule['rule_id']}")
    print(f"Pattern: {rule['pattern']}")
    print(f"True Positives: {verification['true_positives']} | False Positives: {verification['false_positives_count']}")
    print(f"Verified Safe: {verification['verified_safe']}")
    print(f"Promoted and Signed to: {promoted_file}")
    print(f"Synthesis + Replay + Signature Duration: {elapsed*1000:.2f}ms")
    return elapsed, rule, verification


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--bench":
        run_immunization_benchmark()
    elif len(sys.argv) > 1 and sys.argv[1] == "synthesize":
        pattern = sys.argv[2]
        imm = FastPathImmunizer()
        r = imm.synthesize_rule(pattern)
        print(json.dumps(r, indent=2))
    else:
        print("Usage: violet_immunize.py [--bench | synthesize <pattern>]")

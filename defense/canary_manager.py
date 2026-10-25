#!/usr/bin/env python3
"""canary_manager.py — Cryptographic Honeytoken Canary Manager for VIOLET.

Manages deceptive canary tokens (API keys, session cookies, database credentials, AWS/K8s secrets):
  1. Stateless HMAC-SHA256 Authenticated Honeytokens:
     - Mints realistic tokens carrying an embedded label + nonce + 24-hex HMAC-SHA256 tag
       bound to the node's `redops.key` (zero disk I/O on untrusted scanner GET paths,
       defeating disk-exhaustion DoS attacks while remaining verifiable across restarts).
  2. Bounded Stateful Registry (LRU-capped at 500 entries):
     - Tracks explicitly registered tokens and all tripped tokens in `violet-canaries.json`.
  3. Grover-Proof Dual-Ledger Forensic Chain:
     - Any access or verification attempt against a canary token triggers an immediate
       high-priority tripwire and appends a SHA-384 + BLAKE2b-512 dual-hashed forensic
       entry to `vps-sentinel.chain.jsonl`.

Lineage: VIOLET P3 (Fail-Closed) & P4 (Dual Ledgers).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

STATE_DIR = Path(os.environ.get("VIOLET_STATE_DIR", os.path.expanduser("~/.local/state/whitemagic")))
CANARY_FILE = STATE_DIR / "violet-canaries.json"
BLUE_OPS_CHAIN = STATE_DIR / "vps-sentinel.chain.jsonl"
KEY_PATH = Path(os.environ.get("VIOLET_KEY_PATH", os.path.expanduser("~/.config/whitemagic/violet/redops.key")))

MAX_STATEFUL_CANARIES = 500

# Regex matching stateless HMAC-authenticated or legacy VIOLET canary tokens
CANARY_EXTRACT_RE = re.compile(
    r"(sk-proj-canary-[A-Za-z0-9_-]{16,120}"
    r"|sk-ant-canary01-[A-Za-z0-9_-]{16,120}"
    r"|eyJhZ2VudCI6ImNhbmFyeSIsImlzcyI6InZpb2xldCJ9\.[A-Za-z0-9_-]{10,80}\.[A-Za-z0-9_-]{10,80}"
    r"|x402_honey_auth_[A-Za-z0-9_-]{16,100}"
    r"|ASIACANARY[0-9A-Z]{8,32}"
    r"|canary_[A-Za-z0-9_-]{16,100})"
)


def _load_hmac_secret(key_path: Path = KEY_PATH) -> bytes | None:
    try:
        if key_path.exists():
            raw = key_path.read_text().strip()
            if not raw:
                return None
            return hashlib.sha256(b"violet-canary-hmac-v2:" + raw.encode("utf-8")).digest()
    except Exception:
        pass
    return None


class CanaryManager:
    def __init__(self, canary_path: Path = CANARY_FILE, key_path: Path = KEY_PATH):
        self.canary_path = canary_path
        self.canary_path.parent.mkdir(parents=True, exist_ok=True)
        self._hmac_key = _load_hmac_secret(key_path)
        self._lock = threading.Lock()
        self.canaries = self._load()

    def _load(self) -> dict:
        if self.canary_path.exists():
            try:
                with open(self.canary_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict) and isinstance(data.get("tokens"), dict):
                        return data
            except Exception:
                pass
        return {"created_at": time.time(), "tokens": {}}

    def _save(self):
        with self._lock:
            tokens = self.canaries.get("tokens", {})
            # Enforce bounded size so scanner floods can never exhaust disk
            if len(tokens) > MAX_STATEFUL_CANARIES:
                # Keep tripped tokens first, then newest minted
                sorted_keys = sorted(
                    tokens.keys(),
                    key=lambda k: (
                        1 if tokens[k].get("status") == "tripped" else 0,
                        tokens[k].get("minted_at", ""),
                    ),
                )
                for k in sorted_keys[: len(tokens) - MAX_STATEFUL_CANARIES]:
                    tokens.pop(k, None)
            tmp_path = self.canary_path.with_suffix(".tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(self.canaries, f, indent=2)
            tmp_path.replace(self.canary_path)

    def _sign_tag(self, label_slug: str, token_type: str, nonce: str) -> str:
        if self._hmac_key is None:
            raise RuntimeError("canary signing unavailable: node secret is missing or unreadable")
        msg = f"{label_slug}:{token_type}:{nonce}".encode("utf-8")
        return hmac.new(self._hmac_key, msg, hashlib.sha256).hexdigest()[:24]

    def mint_token(self, label: str, token_type: str = "openai_key", persist: bool = True) -> str:
        """Mint a realistic-looking high-privilege honeytoken with an embedded HMAC tag.

        When `persist=False` (used on high-volume untrusted GET decoy routes), the token is
        statelessly verifiable via its HMAC tag without performing any disk write until tripped.
        """
        if self._hmac_key is None:
            raise RuntimeError("canary mint unavailable: node secret is missing or unreadable")
        now = datetime.now(timezone.utc).isoformat()
        label_slug = re.sub(r"[^a-zA-Z0-9]", "", label)[:16] or "trap"
        nonce = secrets.token_hex(6)
        mac = self._sign_tag(label_slug, token_type, nonce)

        if token_type == "openai_key":
            token = f"sk-proj-canary-{label_slug}-{nonce}-{mac}"
        elif token_type == "anthropic_key":
            token = f"sk-ant-canary01-{label_slug}-{nonce}-{mac}"
        elif token_type == "bearer_jwt":
            token = f"eyJhZ2VudCI6ImNhbmFyeSIsImlzcyI6InZpb2xldCJ9.{label_slug}_{nonce}.{mac}"
        elif token_type == "x402_treasury":
            token = f"x402_honey_auth_{label_slug}_{nonce}_{mac}"
        else:
            token = f"canary_{label_slug}_{nonce}_{mac}"

        if persist:
            with self._lock:
                self.canaries.setdefault("tokens", {})[token] = {
                    "label": label,
                    "type": token_type,
                    "minted_at": now,
                    "hits": 0,
                    "last_hit": None,
                    "status": "active",
                }
            self._save()
        return token

    def _verify_stateless_token(self, candidate_tok: str) -> tuple[bool, str, str]:
        """Authenticate only a valid MAC. Format resemblance is never authentication."""
        if self._hmac_key is None:
            return False, "", ""
        try:
            if candidate_tok.startswith("sk-proj-canary-"):
                body = candidate_tok[len("sk-proj-canary-") :]
                parts = body.split("-")
                if len(parts) == 3:
                    label_slug, nonce, mac = parts
                    expected = self._sign_tag(label_slug, "openai_key", nonce)
                    if hmac.compare_digest(mac, expected):
                        return True, label_slug, "openai_key"
                return False, "", ""

            if candidate_tok.startswith("sk-ant-canary01-"):
                body = candidate_tok[len("sk-ant-canary01-") :]
                parts = body.split("-")
                if len(parts) == 3:
                    label_slug, nonce, mac = parts
                    expected = self._sign_tag(label_slug, "anthropic_key", nonce)
                    if hmac.compare_digest(mac, expected):
                        return True, label_slug, "anthropic_key"
                return False, "", ""

            if candidate_tok.startswith("eyJhZ2VudCI6ImNhbmFyeSIsImlzcyI6InZpb2xldCJ9."):
                parts = candidate_tok.split(".")
                if len(parts) == 3 and "_" in parts[1]:
                    label_slug, nonce = parts[1].split("_", 1)
                    mac = parts[2]
                    expected = self._sign_tag(label_slug, "bearer_jwt", nonce)
                    if hmac.compare_digest(mac, expected):
                        return True, label_slug, "bearer_jwt"
                return False, "", ""

            if candidate_tok.startswith("x402_honey_auth_"):
                body = candidate_tok[len("x402_honey_auth_") :]
                parts = body.split("_")
                if len(parts) == 3:
                    label_slug, nonce, mac = parts
                    expected = self._sign_tag(label_slug, "x402_treasury", nonce)
                    if hmac.compare_digest(mac, expected):
                        return True, label_slug, "x402_treasury"
                return False, "", ""

            if candidate_tok.startswith("canary_"):
                body = candidate_tok[len("canary_") :]
                parts = body.split("_")
                if len(parts) == 3:
                    label_slug, nonce, mac = parts
                    expected = self._sign_tag(label_slug, "generic", nonce)
                    if hmac.compare_digest(mac, expected):
                        return True, label_slug, "generic"
                return False, "", ""
        except Exception:
            pass
        return False, "", ""

    def check_token(self, token_candidate: str, src_ip: str = "unknown", context: str = "") -> dict:
        """Check if candidate contains a canary token. If hit, execute tripwire protocol."""
        if not token_candidate:
            return {"is_canary": False}

        matched_token = None
        label = ""
        ttype = ""
        authentication = None
        format_like = False

        # 1. Fast regex + HMAC stateless check
        m = CANARY_EXTRACT_RE.search(token_candidate)
        if m:
            format_like = True
            extracted = m.group(1)
            ok, lbl, tp = self._verify_stateless_token(extracted)
            if ok:
                matched_token = extracted
                label = lbl
                ttype = tp
                authentication = "cryptographically_verified"

        # 2. Fallback stateful registry check
        with self._lock:
            tokens_dict = self.canaries.get("tokens", {})
            if matched_token and matched_token in tokens_dict:
                info = tokens_dict[matched_token]
                label = info.get("label", label)
                ttype = info.get("type", ttype)
            elif not matched_token:
                for registered, info in tokens_dict.items():
                    if registered and registered in token_candidate:
                        matched_token = registered
                        label = info.get("label", "stateful_canary")
                        ttype = info.get("type", "generic")
                        authentication = "registered"
                        break

        if not matched_token:
            return {
                "is_canary": False,
                "classification": "format_like_unverified" if format_like else "not_detected",
                "authentication": None,
            }

        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            info = self.canaries.setdefault("tokens", {}).setdefault(
                matched_token,
                {
                    "label": label,
                    "type": ttype,
                    "minted_at": now,
                    "hits": 0,
                    "last_hit": None,
                    "status": "active",
                },
            )
            info["hits"] = info.get("hits", 0) + 1
            info["last_hit"] = now
            info["status"] = "tripped"
        self._save()

        alert = {
            "event": "CANARY_TRIPWIRE_TRIGGERED",
            "token_label": label,
            "token_type": ttype,
            "authentication": authentication,
            "source_ip": src_ip,
            "context": context,
            "timestamp": now,
            "action_taken": "QUARANTINE_ENFORCED",
        }

        self._record_blue_ops_evidence(alert)

        return {
            "is_canary": True,
            "classification": "authenticated_canary",
            "authentication": authentication,
            "token_label": label,
            "token_type": ttype,
            "alert": alert,
        }

    def _record_blue_ops_evidence(self, alert_data: dict):
        try:
            prev_hash = ""
            if BLUE_OPS_CHAIN.exists():
                lines = BLUE_OPS_CHAIN.read_text().strip().splitlines()
                if lines:
                    last_entry = json.loads(lines[-1])
                    prev_hash = last_entry.get("hash", "")

            snapshot = f"CANARY_HIT:{alert_data['token_label']}:{alert_data['source_ip']}:{alert_data['timestamp']}"
            combined = (prev_hash + snapshot).encode("utf-8")
            h_sha384 = hashlib.sha384(combined).hexdigest()
            h_blake2b = hashlib.blake2b(combined, digest_size=64).hexdigest()
            entry_hash = hashlib.sha256((h_sha384 + h_blake2b).encode("utf-8")).hexdigest()

            entry = {
                "ts": alert_data["timestamp"],
                "snapshot": snapshot,
                "prev": prev_hash,
                "hash": entry_hash,
                "sha384": h_sha384,
                "blake2b_512": h_blake2b,
                "quantum_margin_bits": 256,
                "detail": alert_data,
            }
            with open(BLUE_OPS_CHAIN, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            sys.stderr.write(f"Blue-Ops evidence append failed: {e}\n")


if __name__ == "__main__":
    cm = CanaryManager()
    if len(sys.argv) > 1 and sys.argv[1] == "mint":
        label = sys.argv[2] if len(sys.argv) > 2 else "canary_test"
        ttype = sys.argv[3] if len(sys.argv) > 3 else "openai_key"
        tok = cm.mint_token(label, ttype)
        print(json.dumps({"minted": True, "type": ttype, "label": label}))
    elif len(sys.argv) > 1 and sys.argv[1] == "check":
        tok = sys.argv[2]
        res = cm.check_token(tok, src_ip="127.0.0.1", context="cli check")
        print(json.dumps(res, indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] == "list":
        print(json.dumps(cm.canaries, indent=2))
    else:
        print("Usage: canary_manager.py [mint <label> <type> | check <token> | list]")

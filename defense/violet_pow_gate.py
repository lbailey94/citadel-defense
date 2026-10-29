"""violet_pow_gate.py — Cryptographic Proof-of-Work (PoW) client puzzle gate for Citadel.

Enforces severe computational cost asymmetry against automated scanners, brute-force worms,
and rogue swarms.

Mathematical Invariant:
  - Defender verification cost: O(1) single SHA-256 computation (< 5 microseconds).
  - Attacker puzzle solving cost: O(2^difficulty) iterative hash computations (100ms to 30s+ CPU).
  - Stateless: Server does not store issued challenges in memory or disk. The challenge is
    bound to the client IP and timestamp with a keyed HMAC-SHA256 signature.

Lineage: Edgerunner Violet Counter-Economics & Active Tarpitting.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path
from typing import Any

try:
    import violet_bounty_ledger as vbl
    HAS_BOUNTY_LEDGER = True
except Exception:
    HAS_BOUNTY_LEDGER = False


DEFAULT_SECRET_PATH = Path("/var/lib/whitemagic-hosted/defense/pow_gate.secret")
DEFAULT_CHALLENGE_TTL = 120  # 2 minutes


def _load_or_create_secret(secret_path: Path = DEFAULT_SECRET_PATH) -> bytes:
    try:
        if secret_path.exists():
            data = secret_path.read_bytes().strip()
            if len(data) >= 32:
                return data
    except Exception:
        pass
    # Ephemeral memory secret fallback
    return hashlib.sha256(b"citadel-pow-fallback-secret-seed").digest()


class PoWGate:
    def __init__(self, secret: bytes | None = None, ttl_seconds: int = DEFAULT_CHALLENGE_TTL,
                 bounty_ledger: Any | None = None):
        self.secret = secret or _load_or_create_secret()
        self.ttl = ttl_seconds
        self.bounty_ledger = bounty_ledger

    def _sign(self, payload: str) -> str:
        return hmac.new(self.secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def generate_challenge(self, client_ip: str, difficulty: int = 4, now: int | None = None) -> dict:
        """Mint a stateless cryptographic client puzzle.
        
        difficulty: number of required leading hexadecimal zeros in sha256(salt + nonce).
          - difficulty 3: ~4,096 hashes (~1-10 ms)   - lightweight bot friction
          - difficulty 4: ~65,536 hashes (~50-250 ms) - standard scanner dampener
          - difficulty 5: ~1,048,576 hashes (~1-4 s)  - heavy brute-force throttle
          - difficulty 6: ~16,777,216 hashes (~15-60 s) - aggressive swarm freeze
        """
        now = int(time.time() if now is None else now)
        cid = secrets.token_hex(8)
        salt = secrets.token_hex(16)
        sig_body = f"{client_ip}:{cid}:{now}:{difficulty}:{salt}"
        sig = self._sign(sig_body)

        return {
            "challenge_id": cid,
            "client_ip": client_ip,
            "created_at": now,
            "expires_at": now + self.ttl,
            "difficulty": difficulty,
            "prefix": "0" * difficulty,
            "salt": salt,
            "sig": sig,
            "algorithm": "sha256(salt + nonce) with leading prefix",
        }

    def verify_solution(self, challenge: dict, nonce: str, client_ip: str) -> tuple[bool, str]:
        """Stateless O(1) verification of the client's submitted solution."""
        now = int(time.time())
        cid = challenge.get("challenge_id", "")
        created_at = int(challenge.get("created_at", 0))
        difficulty = int(challenge.get("difficulty", 0))
        salt = challenge.get("salt", "")
        sig = challenge.get("sig", "")
        prefix = "0" * difficulty

        # 1. TTL Check
        if now - created_at > self.ttl:
            return False, "challenge_expired"
        if created_at > now + 30:
            return False, "clock_skew"

        # 2. IP & HMAC Signature Check
        if challenge.get("client_ip") != client_ip:
            return False, "client_ip_mismatch"
        expected_sig = self._sign(f"{client_ip}:{cid}:{created_at}:{difficulty}:{salt}")
        if not hmac.compare_digest(sig, expected_sig):
            return False, "invalid_signature"

        # 3. Work Verification (single SHA-256 computation)
        preimage = f"{salt}:{str(nonce).strip()}".encode("utf-8")
        h = hashlib.sha256(preimage).hexdigest()
        if not h.startswith(prefix):
            return False, "insufficient_proof_of_work"

        if self.bounty_ledger is not None:
            try:
                estimated_iters = 16 ** difficulty
                self.bounty_ledger.record_pow_tax(
                    difficulty=difficulty,
                    iterations=estimated_iters,
                    source_ip=client_ip,
                )
            except Exception:
                pass

        return True, "verified"

    @staticmethod
    def solve(challenge: dict, max_iterations: int = 20_000_000) -> tuple[str | None, int, float]:
        """Reference solver for clients / testing. Returns (nonce, iterations, elapsed_seconds)."""
        salt = challenge["salt"]
        prefix = challenge["prefix"]
        t0 = time.perf_counter()

        for nonce_int in range(max_iterations):
            nonce_str = hex(nonce_int)[2:]
            preimage = f"{salt}:{nonce_str}".encode("utf-8")
            if hashlib.sha256(preimage).hexdigest().startswith(prefix):
                elapsed = time.perf_counter() - t0
                return nonce_str, nonce_int + 1, elapsed

        return None, max_iterations, time.perf_counter() - t0

"""violet_pow_gate.py — Cryptographic Proof-of-Work (PoW) client puzzle gate for Citadel.

Issues client puzzles for opt-in request admission. A valid solution proves a
hash met the target; it does not identify an attacker or measure their cost.

Verification boundaries:
  - Bounded input and one SHA-256 work check; replay bookkeeping is bounded by the cache cap.
  - Expected brute-force solving cost: O(16^difficulty) hashes for hexadecimal-zero difficulty.
  - Stateless challenge issuance: Bound to client IP and timestamp with a keyed HMAC-SHA256 signature.
  - Replay-safe accounting: Bounded TTL cache prevents double-crediting computational tax or reusing solutions.

Lineage: Edgerunner Violet Counter-Economics & Active Tarpitting.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any

try:
    from defense import violet_bounty_ledger as vbl
    HAS_BOUNTY_LEDGER = True
except Exception:
    try:
        import violet_bounty_ledger as vbl
        HAS_BOUNTY_LEDGER = True
    except Exception:
        HAS_BOUNTY_LEDGER = False


DEFAULT_SECRET_PATH = Path("/var/lib/whitemagic-hosted/defense/pow_gate.secret")
DEFAULT_CHALLENGE_TTL = 120  # 2 minutes
MIN_POW_DIFFICULTY = 1
MAX_POW_DIFFICULTY = 8
MAX_REPLAY_CACHE_SIZE = 16384
MAX_NONCE_LENGTH = 256


def _load_or_create_secret(secret_path: Path = DEFAULT_SECRET_PATH, fail_closed: bool | None = None) -> bytes:
    if fail_closed is None:
        fail_closed = os.environ.get("VIOLET_POW_FAIL_CLOSED", "").lower() in ("1", "true", "yes")
    try:
        if secret_path.exists():
            data = secret_path.read_bytes().strip()
            if len(data) >= 32:
                return data
    except Exception:
        pass
    if fail_closed:
        raise RuntimeError(f"Configured PoW secret is missing or unreadable at {secret_path}")
    # Ephemeral per-process cryptographic random key fallback (never a deterministic public constant!)
    return secrets.token_bytes(32)


class PoWGate:
    def __init__(
        self,
        secret: bytes | None = None,
        ttl_seconds: int = DEFAULT_CHALLENGE_TTL,
        bounty_ledger: Any | None = None,
        fail_closed: bool | None = None,
    ):
        self.secret = secret if secret is not None else _load_or_create_secret(fail_closed=fail_closed)
        self.ttl = ttl_seconds
        self.bounty_ledger = bounty_ledger
        self._consumed_lock = threading.Lock()
        # Maps replay_token -> expiration_timestamp
        self._consumed_challenges: dict[str, int] = {}

    def _sign(self, payload: str) -> str:
        return hmac.new(self.secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def _prune_consumed_cache(self, now: int) -> None:
        # Caller must hold self._consumed_lock
        expired = [token for token, exp in self._consumed_challenges.items() if exp <= now]
        for token in expired:
            self._consumed_challenges.pop(token, None)

    def generate_challenge(self, client_ip: str, difficulty: int = 4, now: int | None = None) -> dict:
        """Mint a stateless cryptographic client puzzle.
        
        difficulty is the required number of leading hexadecimal zeros in
        sha256(salt + ':' + nonce). Expected brute-force work is 16**difficulty
        hashes; elapsed time varies with the solver and hardware.
        """
        if type(difficulty) is not int or difficulty < MIN_POW_DIFFICULTY or difficulty > MAX_POW_DIFFICULTY:
            raise ValueError(f"difficulty {difficulty} out of bounds [{MIN_POW_DIFFICULTY}, {MAX_POW_DIFFICULTY}]")
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
            "algorithm": "sha256(salt + ':' + nonce) with leading prefix",
        }

    def verify_solution(
        self,
        challenge: dict,
        nonce: str,
        client_ip: str,
        record_tax: bool = True,
        check_replay: bool = False,
    ) -> tuple[bool, str]:
        """Verify a bounded solution, with process-local atomic replay protection.
        
        Validates difficulty bounds, timestamp TTL, IP binding, and HMAC signature
        BEFORE allocating the prefix string or computing hashes.
        
        If check_replay is True, verifies that the challenge has not been
        previously consumed. Even if check_replay is False, tax accounting is
        strictly deduplicated so replayed solutions never double-credit work tax.
        A full cache rejects new challenges rather than forgetting live replay
        entries. Shared keys across workers still require shared replay custody.
        """
        now = int(time.time())
        if not isinstance(challenge, dict):
            return False, "malformed_challenge"
        created_at = challenge.get("created_at")
        difficulty = challenge.get("difficulty")
        if type(created_at) is not int or type(difficulty) is not int:
            return False, "invalid_numeric_fields"

        # 0. Numeric bounds validation (O(1), before memory allocation or hashing)
        if difficulty < MIN_POW_DIFFICULTY or difficulty > MAX_POW_DIFFICULTY:
            return False, "difficulty_out_of_bounds"
        cid, salt, sig = (challenge.get(key) for key in ("challenge_id", "salt", "sig"))
        if any(not isinstance(value, str) or not value or len(value) > limit or not value.isascii()
               for value, limit in ((cid, 64), (salt, 128), (sig, 64))):
            return False, "malformed_challenge"
        if (not isinstance(nonce, str) or len(nonce) > MAX_NONCE_LENGTH or not nonce.isascii()):
            return False, "malformed_nonce"
        nonce = nonce.strip()
        if not isinstance(client_ip, str) or len(client_ip) > 128 or not client_ip.isascii():
            return False, "malformed_client_ip"

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

        # 3. Work Verification (single SHA-256 computation) after bounds/signature checks.
        prefix = "0" * difficulty
        preimage = f"{salt}:{nonce}".encode("utf-8")
        h = hashlib.sha256(preimage).hexdigest()
        if not h.startswith(prefix):
            return False, "insufficient_proof_of_work"

        # 4. Claim the challenge atomically. All valid nonces share one admission
        # and one accounting credit; the check and insert cannot race.
        replay_token = sig
        with self._consumed_lock:
            self._prune_consumed_cache(now)
            is_consumed = replay_token in self._consumed_challenges
            if check_replay and is_consumed:
                return False, "challenge_already_consumed"
            if not is_consumed:
                if len(self._consumed_challenges) >= MAX_REPLAY_CACHE_SIZE:
                    return False, "replay_cache_full"
                self._consumed_challenges[replay_token] = created_at + self.ttl + 30
        if not is_consumed:
            if record_tax and self.bounty_ledger is not None:
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

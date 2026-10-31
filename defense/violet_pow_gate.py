"""violet_pow_gate.py — Cryptographic Proof-of-Work (PoW) client puzzle gate for Citadel.

Enforces severe computational cost asymmetry against automated scanners, brute-force worms,
and rogue swarms.

Mathematical Invariant:
  - Defender verification cost: O(1) single SHA-256 computation (< 5 microseconds).
  - Attacker puzzle solving cost: O(2^difficulty) iterative hash computations (100ms to 30s+ CPU).
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
        if len(self._consumed_challenges) > MAX_REPLAY_CACHE_SIZE:
            excess = len(self._consumed_challenges) - MAX_REPLAY_CACHE_SIZE
            oldest = sorted(self._consumed_challenges.items(), key=lambda x: x[1])[:excess]
            for token, _ in oldest:
                self._consumed_challenges.pop(token, None)

    def generate_challenge(self, client_ip: str, difficulty: int = 4, now: int | None = None) -> dict:
        """Mint a stateless cryptographic client puzzle.
        
        difficulty: number of required leading hexadecimal zeros in sha256(salt + nonce).
          - difficulty 3: ~4,096 hashes (~1-10 ms)   - lightweight bot friction
          - difficulty 4: ~65,536 hashes (~50-250 ms) - standard scanner dampener
          - difficulty 5: ~1,048,576 hashes (~1-4 s)  - heavy brute-force throttle
          - difficulty 6: ~16,777,216 hashes (~15-60 s) - aggressive swarm freeze
        """
        if difficulty < MIN_POW_DIFFICULTY or difficulty > MAX_POW_DIFFICULTY:
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
            "algorithm": "sha256(salt + nonce) with leading prefix",
        }

    def verify_solution(
        self,
        challenge: dict,
        nonce: str,
        client_ip: str,
        record_tax: bool = True,
        check_replay: bool = False,
    ) -> tuple[bool, str]:
        """Stateless O(1) verification of the client's submitted solution.
        
        Validates difficulty bounds, timestamp TTL, IP binding, and HMAC signature
        BEFORE allocating the prefix string or computing hashes.
        
        If check_replay is True, verifies that the challenge/nonce has not been
        previously consumed. Even if check_replay is False, tax accounting is
        strictly deduplicated so replayed solutions never double-credit work tax.
        """
        now = int(time.time())
        cid = str(challenge.get("challenge_id", "")).strip()
        salt = str(challenge.get("salt", "")).strip()
        sig = str(challenge.get("sig", "")).strip()

        try:
            created_at = int(challenge.get("created_at", 0))
            difficulty = int(challenge.get("difficulty", 0))
        except (ValueError, TypeError):
            return False, "invalid_numeric_fields"

        # 0. Numeric bounds validation (O(1), before memory allocation or hashing)
        if difficulty < MIN_POW_DIFFICULTY or difficulty > MAX_POW_DIFFICULTY:
            return False, "difficulty_out_of_bounds"
        if not cid or not salt or not sig:
            return False, "malformed_challenge"

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

        # 3. Replay Check
        replay_token = f"{sig}:{str(nonce).strip()}"
        with self._consumed_lock:
            self._prune_consumed_cache(now)
            is_consumed = replay_token in self._consumed_challenges

        if check_replay and is_consumed:
            return False, "challenge_already_consumed"

        # 4. Work Verification (single SHA-256 computation) - allocation only happens here after sig check
        prefix = "0" * difficulty
        preimage = f"{salt}:{str(nonce).strip()}".encode("utf-8")
        h = hashlib.sha256(preimage).hexdigest()
        if not h.startswith(prefix):
            return False, "insufficient_proof_of_work"

        # 5. Idempotent Accounting: credit tax and mark consumed on first valid verification
        if not is_consumed:
            with self._consumed_lock:
                self._consumed_challenges[replay_token] = created_at + self.ttl + 30
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

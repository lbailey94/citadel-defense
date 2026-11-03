"""Unit tests for violet_pow_gate.py."""
import os
import hashlib
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock, patch

import violet_pow_gate as pow_gate


class TestPoWGate(unittest.TestCase):
    def setUp(self):
        self.gate = pow_gate.PoWGate(secret=b"test-pow-secret-key-32bytes-long!!")
        self.client_ip = "198.51.100.77"

    def test_challenge_generation_and_verification(self):
        # Difficulty 3 is fast enough for unit test (~4096 hashes)
        chal = self.gate.generate_challenge(self.client_ip, difficulty=3)
        self.assertEqual(chal["client_ip"], self.client_ip)
        self.assertEqual(chal["prefix"], "000")

        nonce, iters, duration = pow_gate.PoWGate.solve(chal)
        self.assertIsNotNone(nonce)
        self.assertGreater(iters, 0)

        # Verification must succeed
        ok, msg = self.gate.verify_solution(chal, nonce, self.client_ip)
        self.assertTrue(ok)
        self.assertEqual(msg, "verified")

    def test_client_ip_mismatch_rejected(self):
        chal = self.gate.generate_challenge(self.client_ip, difficulty=3)
        nonce, _, _ = pow_gate.PoWGate.solve(chal)
        ok, msg = self.gate.verify_solution(chal, nonce, "203.0.113.88")
        self.assertFalse(ok)
        self.assertEqual(msg, "client_ip_mismatch")

    def test_tampered_challenge_signature_rejected(self):
        chal = self.gate.generate_challenge(self.client_ip, difficulty=3)
        nonce, _, _ = pow_gate.PoWGate.solve(chal)
        # Tamper with salt
        chal["salt"] = "0" * 32
        ok, msg = self.gate.verify_solution(chal, nonce, self.client_ip)
        self.assertFalse(ok)
        self.assertEqual(msg, "invalid_signature")

    def test_expired_challenge_rejected(self):
        short_gate = pow_gate.PoWGate(secret=b"short-ttl-secret", ttl_seconds=1)
        chal = short_gate.generate_challenge(self.client_ip, difficulty=2, now=int(time.time()) - 10)
        nonce, _, _ = pow_gate.PoWGate.solve(chal)
        ok, msg = short_gate.verify_solution(chal, nonce, self.client_ip)
        self.assertFalse(ok)
        self.assertEqual(msg, "challenge_expired")

    def test_bad_nonce_rejected(self):
        chal = self.gate.generate_challenge(self.client_ip, difficulty=4)
        ok, msg = self.gate.verify_solution(chal, "bad_nonce_12345", self.client_ip)
        self.assertFalse(ok)
        self.assertEqual(msg, "insufficient_proof_of_work")

    def test_difficulty_bounds_rejected_before_allocation(self):
        # 1. Negative or zero difficulty
        chal_zero = {"challenge_id": "c1", "client_ip": self.client_ip, "created_at": int(time.time()),
                     "difficulty": 0, "salt": "s1", "sig": "fake"}
        ok, msg = self.gate.verify_solution(chal_zero, "nonce", self.client_ip)
        self.assertFalse(ok)
        self.assertEqual(msg, "difficulty_out_of_bounds")

        # 2. Exorbitant difficulty (e.g. 10_000_000) that would OOM / DoS without bounds check
        chal_huge = {"challenge_id": "c1", "client_ip": self.client_ip, "created_at": int(time.time()),
                     "difficulty": 10_000_000, "salt": "s1", "sig": "fake"}
        t0 = time.perf_counter()
        ok, msg = self.gate.verify_solution(chal_huge, "nonce", self.client_ip)
        elapsed = time.perf_counter() - t0
        self.assertFalse(ok)
        self.assertEqual(msg, "difficulty_out_of_bounds")
        self.assertLess(elapsed, 0.005, "Bounds rejection must be instantaneous O(1)")

        # 3. Generator also bounds difficulty
        with self.assertRaises(ValueError):
            self.gate.generate_challenge(self.client_ip, difficulty=12)

    def test_ephemeral_fallback_secret_is_cryptographic_not_deterministic(self):
        nonexistent = Path("/nonexistent/path/for/secret.key")
        # In default mode, two calls produce distinct random keys
        k1 = pow_gate._load_or_create_secret(nonexistent, fail_closed=False)
        k2 = pow_gate._load_or_create_secret(nonexistent, fail_closed=False)
        self.assertEqual(len(k1), 32)
        self.assertEqual(len(k2), 32)
        self.assertNotEqual(k1, k2, "Ephemeral secret must be randomly generated, not a static constant")

        # In fail_closed mode, raises RuntimeError
        with self.assertRaises(RuntimeError):
            pow_gate._load_or_create_secret(nonexistent, fail_closed=True)

    def test_replay_protection_and_tax_accounting(self):
        ledger = MagicMock()
        gate = pow_gate.PoWGate(secret=b"test-replay-accounting-secret!!!", bounty_ledger=ledger)
        chal = gate.generate_challenge(self.client_ip, difficulty=2)
        nonce, _, _ = pow_gate.PoWGate.solve(chal)
        self.assertIsNotNone(nonce)

        # First verification succeeds and records tax exactly once
        ok1, msg1 = gate.verify_solution(chal, nonce, self.client_ip, check_replay=True)
        self.assertTrue(ok1)
        self.assertEqual(msg1, "verified")
        self.assertEqual(ledger.record_pow_tax.call_count, 1)

        # Second verification of the exact same challenge + nonce within TTL is rejected when check_replay=True
        ok2, msg2 = gate.verify_solution(chal, nonce, self.client_ip, check_replay=True)
        self.assertFalse(ok2)
        self.assertEqual(msg2, "challenge_already_consumed")
        # Must NOT call record_pow_tax again
        self.assertEqual(ledger.record_pow_tax.call_count, 1)

        # Even in stateless math-only mode (check_replay=False), tax accounting remains strictly single-use
        ok3, msg3 = gate.verify_solution(chal, nonce, self.client_ip, check_replay=False)
        self.assertTrue(ok3)
        self.assertEqual(msg3, "verified")
        self.assertEqual(ledger.record_pow_tax.call_count, 1, "Replayed verification must not double-count tax")

    def test_concurrent_redeemers_admit_and_credit_only_once(self):
        ledger = MagicMock()
        gate = pow_gate.PoWGate(secret=self.gate.secret, bounty_ledger=ledger)
        challenge = gate.generate_challenge(self.client_ip, difficulty=1)
        nonce, _, _ = gate.solve(challenge)
        preimage = f"{challenge['salt']}:{nonce}".encode()
        real_sha256 = hashlib.sha256
        rendezvous = threading.Barrier(8)

        def simultaneous_work_check(data=b""):
            if data == preimage:
                rendezvous.wait(timeout=10)
            return real_sha256(data)

        with patch.object(pow_gate.hashlib, "sha256", simultaneous_work_check):
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(
                    lambda _: gate.verify_solution(challenge, nonce, self.client_ip, check_replay=True),
                    range(8),
                ))
        self.assertEqual(results.count((True, "verified")), 1)
        self.assertEqual(results.count((False, "challenge_already_consumed")), 7)
        self.assertEqual(ledger.record_pow_tax.call_count, 1)

    def test_different_valid_nonces_cannot_redeem_one_challenge_twice(self):
        challenge = self.gate.generate_challenge(self.client_ip, difficulty=1)
        nonces = []
        for i in range(10000):
            nonce = str(i)
            if hashlib.sha256(f"{challenge['salt']}:{nonce}".encode()).hexdigest().startswith("0"):
                nonces.append(nonce)
                if len(nonces) == 2:
                    break
        self.assertEqual(len(nonces), 2)
        self.assertEqual(self.gate.verify_solution(challenge, nonces[0], self.client_ip, check_replay=True), (True, "verified"))
        self.assertEqual(self.gate.verify_solution(challenge, nonces[1], self.client_ip, check_replay=True), (False, "challenge_already_consumed"))

    def test_full_cache_retains_live_replays_and_recovers_after_expiry(self):
        now = int(time.time())
        with patch.object(pow_gate, "MAX_REPLAY_CACHE_SIZE", 2), patch.object(pow_gate.time, "time", return_value=now):
            solved = []
            for _ in range(3):
                challenge = self.gate.generate_challenge(self.client_ip, difficulty=1)
                nonce, _, _ = self.gate.solve(challenge)
                solved.append((challenge, nonce))
            self.assertTrue(self.gate.verify_solution(*solved[0], self.client_ip, check_replay=True)[0])
            self.assertTrue(self.gate.verify_solution(*solved[1], self.client_ip, check_replay=True)[0])
            self.assertEqual(self.gate.verify_solution(*solved[2], self.client_ip, check_replay=True), (False, "replay_cache_full"))
            self.assertEqual(self.gate.verify_solution(*solved[0], self.client_ip, check_replay=True), (False, "challenge_already_consumed"))
            self.assertEqual(len(self.gate._consumed_challenges), 2)
        with patch.object(pow_gate, "MAX_REPLAY_CACHE_SIZE", 2), patch.object(pow_gate.time, "time", return_value=now + self.gate.ttl + 31):
            challenge = self.gate.generate_challenge(self.client_ip, difficulty=1)
            nonce, _, _ = self.gate.solve(challenge)
            self.assertTrue(self.gate.verify_solution(challenge, nonce, self.client_ip, check_replay=True)[0])
            self.assertEqual(len(self.gate._consumed_challenges), 1)

    def test_malformed_inputs_return_rejections(self):
        challenge = self.gate.generate_challenge(self.client_ip, difficulty=1)
        for key, value in [("salt", "s" * 129), ("sig", "é" * 64), ("challenge_id", []),
                           ("created_at", float("inf")), ("difficulty", True)]:
            with self.subTest(key=key):
                malformed = dict(challenge, **{key: value})
                self.assertFalse(self.gate.verify_solution(malformed, "n", self.client_ip)[0])
        for nonce in [None, {}, "n" * 257, "\ud800"]:
            with self.subTest(nonce=repr(nonce)):
                self.assertEqual(self.gate.verify_solution(challenge, nonce, self.client_ip), (False, "malformed_nonce"))
        self.assertEqual(self.gate.verify_solution([], "n", self.client_ip), (False, "malformed_challenge"))


if __name__ == "__main__":
    unittest.main()

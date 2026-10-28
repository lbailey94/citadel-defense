"""Unit tests for violet_pow_gate.py."""
import time
import unittest

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
        self.assertEqual(msg, "challenge_expired")

    def test_bad_nonce_rejected(self):
        chal = self.gate.generate_challenge(self.client_ip, difficulty=4)
        ok, msg = self.gate.verify_solution(chal, "bad_nonce_12345", self.client_ip)
        self.assertFalse(ok)
        self.assertEqual(msg, "insufficient_proof_of_work")


if __name__ == "__main__":
    unittest.main()
